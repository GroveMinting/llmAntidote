"""Hermes registration and lifecycle hooks."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .audit import MetadataAudit
from .commands import run_cli, setup_cli
from .deployment import RuntimePolicyBinding, load_runtime_settings
from .policy import PolicyDecision, PolicyEngine
from .runtime import RuntimeRoutes
from .state import SessionRiskStore

_MISSING = object()
_SETTING_KEYS = (
    "mode",
    "taint_ttl_minutes",
    "audit_capacity",
    "safe_read_roots",
    "sensitive_roots",
    "allow_outbound_tools",
    "admission_enforcement",
    "admission_policy_path",
    "admission_policy_signature_path",
    "admission_policy_public_key",
    "admission_trusted_policy_sha256",
    "admission_require_model_binding",
    "admission_model_lock_path",
    "admission_model_source",
    "admission_model_name",
)
_NON_RESERVING_CATEGORIES = {"oversized_arguments"}
_SETTING_DEFAULTS = {
    "mode": "balanced",
    "taint_ttl_minutes": "60",
    "audit_capacity": "200",
    "admission_require_model_binding": "true",
}


def _changed_from_default(key: str, value: Any) -> bool:
    default = _SETTING_DEFAULTS.get(key)
    if default is None:
        return True
    return str(value).strip().lower() != default


def _tool_succeeded(status: Any, error_type: Any, result: Any) -> bool:
    if error_type:
        return False
    clean = str(status or "success").lower()
    if clean in {"blocked", "denied", "error", "failed", "timeout"}:
        return False
    if isinstance(result, str):
        try:
            parsed = json.loads(result)
        except (TypeError, ValueError):
            return True
        if isinstance(parsed, dict):
            error = parsed.get("error")
            if error is not None and error != "" and error is not False:
                return False
    return True


def _read_settings(ctx: Any) -> dict[str, Any]:
    settings: dict[str, Any] = {}
    for key in _SETTING_KEYS:
        value = ctx.get_config(key, _MISSING)
        if value is _MISSING or value is None or value == "":
            continue
        if not _changed_from_default(key, value):
            continue
        settings[key] = value
    return settings


def _reserves_access(decision: PolicyDecision) -> bool:
    return bool(set(decision.sensitive) - _NON_RESERVING_CATEGORIES)


@dataclass
class AntidoteRuntime:
    mode: str
    engine: PolicyEngine
    risks: SessionRiskStore
    audit: MetadataAudit
    routes: RuntimeRoutes
    binding: RuntimePolicyBinding

    def session_keys(self, session_id: str = "", task_id: str = "") -> tuple[str, ...]:
        keys = tuple(dict.fromkeys(value for value in (session_id, task_id) if value))
        return keys or ("unknown",)

    def route_admitted(self) -> bool:
        if not self.binding.enforced or not self.binding.model_name:
            return True
        observed = str(self.routes.snapshot().get("model") or "")
        if not observed:
            return True
        return observed == self.binding.model_name

    def decide(
        self,
        *,
        tool_name: str,
        args: Any,
        session_id: str = "",
        task_id: str = "",
    ) -> PolicyDecision:
        keys = self.session_keys(session_id, task_id)
        self.risks.link(keys)
        if not self.route_admitted():
            decision = PolicyDecision(
                action="block",
                would_action="block",
                rule_ids=("admission.model_route_mismatch",),
                message=(
                    "llmAntidote blocked a tool call because the served model does not match the "
                    "admitted model route."
                ),
            )
            self.audit.record(
                action=decision.action,
                would_action=decision.would_action,
                tool_name=tool_name,
                rule_ids=decision.rule_ids,
                session_key=keys[0],
            )
            return decision
        session_tainted = any(self.risks.is_tainted(key) for key in keys)
        pending = any(self.risks.has_pending(key) for key in keys)
        decision = self.engine.assess(
            tool_name,
            args,
            session_tainted=session_tainted or pending,
        )
        if decision.would_action != "allow":
            self.audit.record(
                action=decision.action,
                would_action=decision.would_action,
                tool_name=tool_name,
                rule_ids=decision.rule_ids,
                session_key=keys[0],
            )
        if (
            self.mode != "audit"
            and decision.action != "block"
            and _reserves_access(decision)
        ):
            self.risks.reserve_pending(keys)
        return decision

    def post_tool(
        self,
        *,
        tool_name: str,
        args: Any,
        result: Any = None,
        status: Any = None,
        error_type: Any = None,
        session_id: str = "",
        task_id: str = "",
    ) -> None:
        keys = self.session_keys(session_id, task_id)
        if not _tool_succeeded(status, error_type, result):
            self.risks.release_pending(keys)
            return
        decision = self.engine.assess(tool_name, args, session_tainted=False)
        self.risks.release_pending(keys)
        if decision.sensitive:
            self.risks.mark_many(keys, decision.sensitive)

    def observe_route(self, *, provider: Any = "", model: Any = "", base_url: Any = "") -> None:
        self.routes.observe(provider=provider, model=model, base_url=base_url)
        if self.binding.enforced and not self.route_admitted():
            self.audit.record(
                action="block",
                would_action="block",
                tool_name="pre_api_request",
                rule_ids=("admission.model_route_mismatch",),
                session_key="route",
            )

    def status(self) -> dict[str, object]:
        return {
            "mode": self.mode,
            "risk": self.risks.summary(),
            "audit": self.audit.summary(),
            "runtime_route": self.routes.snapshot(),
            "admission": self.binding.summary(),
            "route_admitted": self.route_admitted(),
        }

    def status_text(self) -> str:
        status = self.status()
        risk = status["risk"]
        audit = status["audit"]
        route = status["runtime_route"]
        admission = status["admission"]
        assert (
            isinstance(risk, dict)
            and isinstance(audit, dict)
            and isinstance(route, dict)
            and isinstance(admission, dict)
        )
        categories = ", ".join(risk.get("categories", [])) or "none"
        model = route.get("model") or "not observed"
        provider = route.get("provider") or "not observed"
        policy = admission.get("policy") if isinstance(admission.get("policy"), dict) else {}
        policy_line = "standalone (unsigned local settings)"
        if admission.get("enforcement") == "enforced":
            policy_line = (
                f"{policy.get('name', '')}@{policy.get('version', 0)} "
                f"{str(policy.get('sha256', ''))[:12]}"
            )
        admitted = admission.get("admitted_model") or "not bound"
        return (
            "llmAntidote status\n"
            f"- enforcement: {admission.get('enforcement', 'standalone')}\n"
            f"- mode: {self.mode}\n"
            f"- policy: {policy_line}\n"
            f"- admitted model: {admitted}\n"
            f"- route admitted: {status.get('route_admitted')}\n"
            f"- tainted sessions: {risk.get('tainted_sessions', 0)}\n"
            f"- pending sensitive access: {risk.get('pending_sessions', 0)}\n"
            f"- taint categories: {categories}\n"
            f"- retained audit events: {audit.get('retained_events', 0)}\n"
            f"- latest model route: {provider} / {model}"
        )


def build_runtime(ctx: Any) -> AntidoteRuntime:
    resolved = load_runtime_settings(_read_settings(ctx))
    return AntidoteRuntime(
        mode=resolved.policy.mode,
        engine=PolicyEngine(resolved.policy),
        risks=SessionRiskStore(resolved.taint_ttl_minutes),
        audit=MetadataAudit(resolved.audit_capacity),
        routes=RuntimeRoutes(),
        binding=resolved.binding,
    )


def register(ctx: Any) -> None:
    runtime = build_runtime(ctx)

    def pre_tool_call(
        tool_name: str = "",
        args: Any = None,
        session_id: str = "",
        task_id: str = "",
        **_: Any,
    ) -> dict[str, str] | None:
        decision = runtime.decide(
            tool_name=tool_name,
            args=args,
            session_id=session_id,
            task_id=task_id,
        )
        if decision.action == "block":
            return {"action": "block", "message": decision.message}
        if decision.action == "approve":
            rule = decision.rule_ids[0] if decision.rule_ids else "policy"
            return {
                "action": "approve",
                "message": decision.message,
                "rule_key": f"llm-antidote:{rule}",
            }
        return None

    def post_tool_call(
        tool_name: str = "",
        args: Any = None,
        result: Any = None,
        status: Any = None,
        error_type: Any = None,
        session_id: str = "",
        task_id: str = "",
        **_: Any,
    ) -> None:
        runtime.post_tool(
            tool_name=tool_name,
            args=args,
            result=result,
            status=status,
            error_type=error_type,
            session_id=session_id,
            task_id=task_id,
        )

    def pre_api_request(
        provider: Any = "",
        model: Any = "",
        base_url: Any = "",
        **_: Any,
    ) -> None:
        runtime.observe_route(provider=provider, model=model, base_url=base_url)

    def on_session_start(session_id: str = "", **_: Any) -> None:
        runtime.risks.clear(session_id)

    def on_session_reset(
        session_id: str = "",
        old_session_id: str = "",
        new_session_id: str = "",
        **_: Any,
    ) -> None:
        runtime.risks.clear(session_id, old_session_id, new_session_id)

    def on_session_finalize(session_id: str = "", **_: Any) -> None:
        runtime.risks.clear(session_id)

    def slash_command(raw_args: str) -> str:
        command = (raw_args or "status").strip().lower()
        if command in {"", "status"}:
            return runtime.status_text()
        if command == "clear":
            runtime.risks.clear_all()
            return "llmAntidote cleared all in-process session taint metadata."
        return "Usage: /antidote [status|clear]"

    ctx.register_hook("pre_tool_call", pre_tool_call)
    ctx.register_hook("post_tool_call", post_tool_call)
    ctx.register_hook("pre_api_request", pre_api_request)
    ctx.register_hook("on_session_start", on_session_start)
    ctx.register_hook("on_session_reset", on_session_reset)
    ctx.register_hook("on_session_finalize", on_session_finalize)
    ctx.register_command(
        "antidote",
        slash_command,
        description="Show or clear llmAntidote runtime risk metadata",
        args_hint="[status|clear]",
    )
    ctx.register_cli_command(
        "antidote",
        "Inspect models, evaluate behavior, and enforce fleet admission",
        setup_cli,
        lambda args: run_cli(args, runtime=runtime),
        description="Runtime guardrails, behavioral evaluation, and signed fleet admission",
    )
