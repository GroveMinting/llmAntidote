"""Enforced fleet-admission deployment gate for the runtime plugin.

Two supported modes exist:

* **Standalone guardrails** (default): runtime settings come from local plugin
  configuration. This is convenient for development and does not claim a signed
  deployment guarantee.
* **Enforced fleet admission**: a signed fleet policy and a verified deployed
  model binding must load successfully before the plugin will register. Failures
  raise, so a protected Hermes instance cannot silently start without its
  guardrails. Signed runtime settings (``mode`` and ``taint_ttl_minutes``) take
  effect, and conflicting local overrides are refused.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .fleet_crypto import (
    SIGNATURE_SCHEMA,
    load_json_document,
    load_json_snapshot,
    sha256_file,
    verify_document,
)
from .fleet_policy import POLICY_SCHEMA, policy_digest, validate_policy
from .model_lock import load_lock, verify_lock
from .policy import PolicyConfig

ENFORCED_VALUES = {"enforced", "enforce", "required", "true", "yes", "on"}

_REQUIRED_ENFORCED_KEYS = (
    "admission_policy_path",
    "admission_policy_signature_path",
    "admission_policy_public_key",
    "admission_trusted_policy_sha256",
)


@dataclass(frozen=True)
class RuntimePolicyBinding:
    enforced: bool
    mode: str
    taint_ttl_minutes: int
    policy_name: str = ""
    policy_version: int = 0
    policy_sha256: str = ""
    model_name: str = ""
    model_lock_sha256: str = ""
    verified: bool = False
    require_route_observation: bool = False

    def summary(self) -> dict[str, Any]:
        return {
            "enforcement": "enforced" if self.enforced else "standalone",
            "mode": self.mode,
            "taint_ttl_minutes": self.taint_ttl_minutes,
            "policy": {
                "name": self.policy_name,
                "version": self.policy_version,
                "sha256": self.policy_sha256,
            },
            "admitted_model": self.model_name,
            "model_lock_sha256": self.model_lock_sha256,
            "verified": self.verified,
            "require_route_observation": self.require_route_observation,
        }


@dataclass(frozen=True)
class RuntimeSettings:
    policy: PolicyConfig
    taint_ttl_minutes: int
    pending_ttl_minutes: int
    audit_capacity: int
    binding: RuntimePolicyBinding


def _bounded_int(value: Any, default: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, min(parsed, maximum))


def _is_enforced(settings: dict[str, Any]) -> bool:
    return str(settings.get("admission_enforcement", "")).strip().lower() in ENFORCED_VALUES


def _as_bool(value: Any, default: bool) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _load_signed_policy(settings: dict[str, Any]) -> tuple[dict[str, Any], str]:
    missing = [key for key in _REQUIRED_ENFORCED_KEYS if not str(settings.get(key, "")).strip()]
    if missing:
        raise ValueError(
            "Enforced admission requires settings: " + ", ".join(sorted(missing))
        )
    policy, _digest, _size = load_json_snapshot(
        settings["admission_policy_path"], expected_schema=POLICY_SCHEMA
    )
    validate_policy(policy)
    signature = load_json_document(
        settings["admission_policy_signature_path"], expected_schema=SIGNATURE_SCHEMA
    )
    valid, reason = verify_document(policy, signature, settings["admission_policy_public_key"])
    if not valid:
        raise ValueError(f"Enforced admission policy signature invalid: {reason}")
    actual_digest = policy_digest(policy)
    trusted = str(settings.get("admission_trusted_policy_sha256", "")).strip().lower()
    if trusted != actual_digest:
        raise ValueError("Enforced admission policy does not match the trusted digest")
    return policy, actual_digest


def _verify_model_binding(settings: dict[str, Any]) -> str:
    lock_path = str(settings.get("admission_model_lock_path", "")).strip()
    source = str(settings.get("admission_model_source", "")).strip()
    if not lock_path or not source:
        raise ValueError(
            "Enforced admission requires admission_model_lock_path and admission_model_source"
        )
    lock = load_lock(lock_path)
    result = verify_lock(lock, source=source)
    if not result["ok"]:
        raise ValueError(
            "Deployed model does not match the admitted lockfile "
            f"(changed={len(result['changed'])}, missing={len(result['missing'])}, "
            f"unexpected={len(result['unexpected'])})"
        )
    return sha256_file(lock_path)


def load_runtime_settings(
    settings: dict[str, Any] | None,
    *,
    verifier: Callable[[dict[str, Any]], str] | None = None,
) -> RuntimeSettings:
    """Resolve runtime policy settings, enforcing signed admission when configured."""
    settings = settings or {}
    local = PolicyConfig.from_settings(settings)
    capacity = _bounded_int(settings.get("audit_capacity", 200), 200, 10_000)

    if not _is_enforced(settings):
        ttl = _bounded_int(settings.get("taint_ttl_minutes", 60), 60, 24 * 60)
        pending_ttl = _bounded_int(settings.get("pending_ttl_minutes", 5), 5, 24 * 60)
        binding = RuntimePolicyBinding(
            enforced=False, mode=local.mode, taint_ttl_minutes=ttl, verified=False
        )
        return RuntimeSettings(local, ttl, pending_ttl, capacity, binding)

    policy, policy_sha256 = _load_signed_policy(settings)
    runtime = policy["runtime"]
    mode = str(runtime["mode"])
    ttl = int(runtime["taint_ttl_minutes"])
    pending_ttl = _bounded_int(settings.get("pending_ttl_minutes", 5), 5, 24 * 60)

    if "mode" in settings and str(settings["mode"]).strip().lower() != mode:
        raise ValueError("Local mode conflicts with the signed fleet policy runtime mode")
    if "taint_ttl_minutes" in settings and _bounded_int(
        settings["taint_ttl_minutes"], ttl, 24 * 60
    ) != ttl:
        raise ValueError("Local taint_ttl_minutes conflicts with the signed fleet policy")

    require_binding = _as_bool(settings.get("admission_require_model_binding"), True)
    lock_digest = ""
    if require_binding:
        lock_digest = (verifier or _verify_model_binding)(settings)
    elif settings.get("admission_model_lock_path"):
        lock_digest = sha256_file(settings["admission_model_lock_path"])

    enforced_policy = PolicyConfig(
        mode=mode,
        safe_read_roots=local.safe_read_roots,
        sensitive_roots=local.sensitive_roots,
        allow_outbound_tools=local.allow_outbound_tools,
    )
    require_route_observation = _as_bool(
        settings.get("admission_require_route_observation"), True
    )
    binding = RuntimePolicyBinding(
        enforced=True,
        mode=mode,
        taint_ttl_minutes=ttl,
        policy_name=str(policy["name"]),
        policy_version=int(policy["version"]),
        policy_sha256=policy_sha256,
        model_name=str(settings.get("admission_model_name", "")).strip(),
        model_lock_sha256=lock_digest,
        verified=require_binding,
        require_route_observation=require_route_observation,
    )
    return RuntimeSettings(enforced_policy, ttl, pending_ttl, capacity, binding)
