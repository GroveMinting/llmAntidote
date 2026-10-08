"""Strict, signable fleet policy bundles."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from .eval_runner import (
    INCONCLUSIVE,
    NO_BACKDOOR_DETECTED,
    SUSPICIOUS_BEHAVIOR,
    TRIGGER_RECOVERED,
)
from .fleet_crypto import canonical_json, load_json_document, sha256_bytes

POLICY_SCHEMA = "llm-antidote.fleet-policy.v1"
KNOWN_VERDICTS = {
    TRIGGER_RECOVERED,
    SUSPICIOUS_BEHAVIOR,
    NO_BACKDOOR_DETECTED,
    INCONCLUSIVE,
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _valid_name(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value) <= 128
        and not any(ord(character) < 32 or ord(character) == 127 for character in value)
    )


def default_policy(name: str = "default-production") -> dict[str, Any]:
    clean_name = name.strip()
    if not _valid_name(clean_name):
        raise ValueError("Policy name must contain 1-128 characters")
    return {
        "schema": POLICY_SCHEMA,
        "name": clean_name,
        "version": 1,
        "issued_at": datetime.now(UTC).isoformat(),
        "runtime": {
            "mode": "balanced",
            "taint_ttl_minutes": 60,
        },
        "admission": {
            "allowed_verdicts": [NO_BACKDOOR_DETECTED],
            "require_model_lock_binding": True,
            "max_evidence_age_hours": 168,
            "min_completed_trials": 10,
            "max_error_rate": 0.2,
            "required_suite_sha256": [],
        },
    }


def validate_policy(value: dict[str, Any]) -> dict[str, Any]:
    if value.get("schema") != POLICY_SCHEMA:
        raise ValueError(f"Expected policy schema {POLICY_SCHEMA}")
    name = value.get("name")
    version = value.get("version")
    if not _valid_name(name):
        raise ValueError("Policy name must contain 1-128 characters")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise ValueError("Policy version must be a positive integer")
    issued_at = value.get("issued_at")
    if not isinstance(issued_at, str):
        raise ValueError("Policy issued_at must be an ISO-8601 string")
    try:
        parsed_issued_at = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Policy issued_at must be valid ISO-8601") from exc
    if parsed_issued_at.tzinfo is None:
        raise ValueError("Policy issued_at must include a timezone")

    runtime = value.get("runtime")
    if not isinstance(runtime, dict):
        raise ValueError("Policy runtime must be an object")
    if runtime.get("mode") not in {"balanced", "strict", "audit"}:
        raise ValueError("Policy runtime mode must be balanced, strict, or audit")
    ttl = runtime.get("taint_ttl_minutes")
    if not isinstance(ttl, int) or isinstance(ttl, bool) or not 1 <= ttl <= 24 * 60:
        raise ValueError("Policy taint_ttl_minutes must be between 1 and 1440")

    admission = value.get("admission")
    if not isinstance(admission, dict):
        raise ValueError("Policy admission must be an object")
    verdicts = admission.get("allowed_verdicts")
    if not isinstance(verdicts, list) or not verdicts:
        raise ValueError("Policy allowed_verdicts must be a non-empty list")
    if any(not isinstance(item, str) or item not in KNOWN_VERDICTS for item in verdicts):
        raise ValueError("Policy allowed_verdicts contains an unknown verdict")
    if len(set(verdicts)) != len(verdicts):
        raise ValueError("Policy allowed_verdicts contains duplicates")
    if not isinstance(admission.get("require_model_lock_binding"), bool):
        raise ValueError("Policy require_model_lock_binding must be boolean")
    age = admission.get("max_evidence_age_hours")
    if not isinstance(age, int) or isinstance(age, bool) or not 1 <= age <= 8760:
        raise ValueError("Policy max_evidence_age_hours must be between 1 and 8760")
    minimum = admission.get("min_completed_trials")
    if not isinstance(minimum, int) or isinstance(minimum, bool) or not 1 <= minimum <= 1_000_000:
        raise ValueError("Policy min_completed_trials must be between 1 and 1000000")
    error_rate = admission.get("max_error_rate")
    if (
        not isinstance(error_rate, (int, float))
        or isinstance(error_rate, bool)
        or not 0.0 <= float(error_rate) <= 0.95
    ):
        raise ValueError("Policy max_error_rate must be between 0 and 0.95")
    suites = admission.get("required_suite_sha256")
    if not isinstance(suites, list) or any(
        not isinstance(item, str) or not _SHA256.fullmatch(item) for item in suites
    ):
        raise ValueError("Policy required_suite_sha256 must contain lowercase SHA-256 values")
    if len(set(suites)) != len(suites):
        raise ValueError("Policy required_suite_sha256 contains duplicates")
    return value


def load_policy(path: str) -> dict[str, Any]:
    return validate_policy(load_json_document(path, expected_schema=POLICY_SCHEMA))


def policy_digest(policy: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json(validate_policy(policy)))
