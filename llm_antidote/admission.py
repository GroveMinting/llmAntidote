"""Fleet admission gate binding signed policy, attestation, lock, and evaluation evidence."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .eval_runner import REPORT_SCHEMA
from .evidence_validation import (
    validate_attestation_document,
    validate_evaluation_report,
    validate_model_lock_document,
)
from .fleet_crypto import (
    ATTESTATION_SCHEMA,
    SIGNATURE_SCHEMA,
    canonical_json,
    load_json_snapshot,
    sha256_bytes,
    verify_document,
)
from .fleet_policy import POLICY_SCHEMA, policy_digest, validate_policy
from .model_lock import LOCK_SCHEMA

RECEIPT_SCHEMA = "llm-antidote.admission-receipt.v1"
ADMISSION_CHECK_IDS = (
    "policy.signature",
    "policy.trusted_digest",
    "attestation.signature",
    "attestation.schema",
    "evaluation.schema",
    "model_lock.schema",
    "attestation.subject",
    "attestation.predicate",
    "attestation.evaluation",
    "evaluation.verdict",
    "evaluation.coverage",
    "evaluation.error_rate",
    "evaluation.resource_limits",
    "evaluation.suite",
    "evaluation.model_lock_binding",
    "evaluation.freshness",
)


@dataclass(frozen=True)
class AdmissionCheck:
    id: str
    passed: bool
    detail: str


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def _check(checks: list[AdmissionCheck], check_id: str, passed: bool, detail: str) -> None:
    checks.append(AdmissionCheck(check_id, bool(passed), detail))


def evaluate_admission(
    *,
    policy: dict[str, Any],
    policy_signature: dict[str, Any],
    policy_public_key: str | Path,
    trusted_policy_sha256: str,
    attestation: dict[str, Any],
    attestation_signature: dict[str, Any],
    attestation_public_key: str | Path,
    evaluation_report: dict[str, Any],
    evaluation_report_sha256: str,
    model_lock: dict[str, Any],
    model_lock_sha256: str,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> dict[str, Any]:
    validate_policy(policy)
    validate_attestation_document(attestation)
    validate_evaluation_report(evaluation_report)
    validate_model_lock_document(model_lock)
    checks: list[AdmissionCheck] = []

    policy_valid, policy_reason = verify_document(policy, policy_signature, policy_public_key)
    _check(checks, "policy.signature", policy_valid, policy_reason)
    actual_policy_digest = policy_digest(policy)
    _check(
        checks,
        "policy.trusted_digest",
        trusted_policy_sha256 == actual_policy_digest,
        "policy matches the out-of-band trusted digest",
    )
    attestation_valid, attestation_reason = verify_document(
        attestation, attestation_signature, attestation_public_key
    )
    _check(checks, "attestation.signature", attestation_valid, attestation_reason)
    _check(
        checks,
        "attestation.schema",
        attestation.get("schema") == ATTESTATION_SCHEMA,
        "attestation schema is supported",
    )
    _check(
        checks,
        "evaluation.schema",
        evaluation_report.get("schema") == REPORT_SCHEMA,
        "evaluation schema is supported",
    )
    _check(
        checks,
        "model_lock.schema",
        model_lock.get("schema") == LOCK_SCHEMA,
        "model lock schema is supported",
    )

    subject = attestation.get("subject")
    subject = subject if isinstance(subject, dict) else {}
    _check(
        checks,
        "attestation.subject",
        subject.get("sha256") == model_lock_sha256 and subject.get("schema") == LOCK_SCHEMA,
        "attestation subject binds the supplied model lock",
    )
    predicate = attestation.get("predicate")
    predicate = predicate if isinstance(predicate, dict) else {}
    evidence = predicate.get("evidence")
    evidence = evidence if isinstance(evidence, list) else []
    _check(
        checks,
        "attestation.predicate",
        predicate.get("type") == "https://github.com/GroveMinting/llmAntidote/attestation/v1",
        "attestation predicate type is supported",
    )
    evidence_digests = {
        item.get("sha256") for item in evidence if isinstance(item, dict) and item.get("sha256")
    }
    _check(
        checks,
        "attestation.evaluation",
        evaluation_report_sha256 in evidence_digests,
        "attestation binds the supplied evaluation report",
    )

    admission = policy["admission"]
    verdict = evaluation_report.get("verdict")
    _check(
        checks,
        "evaluation.verdict",
        isinstance(verdict, str) and verdict in admission["allowed_verdicts"],
        "evaluation verdict is allowed by fleet policy",
    )
    coverage = evaluation_report.get("coverage")
    coverage = coverage if isinstance(coverage, dict) else {}
    completed = coverage.get("completed_trials")
    completed_valid = isinstance(completed, (int, float)) and not isinstance(completed, bool)
    _check(
        checks,
        "evaluation.coverage",
        completed_valid
        and completed is not None
        and float(completed) >= admission["min_completed_trials"],
        "evaluation completed enough trials",
    )
    error_rate = coverage.get("error_rate")
    error_valid = isinstance(error_rate, (int, float)) and not isinstance(error_rate, bool)
    _check(
        checks,
        "evaluation.error_rate",
        error_valid
        and error_rate is not None
        and 0.0 <= float(error_rate) <= float(admission["max_error_rate"]),
        "evaluation error rate is within policy",
    )
    _check(
        checks,
        "evaluation.resource_limits",
        coverage.get("resource_limit_hit") is False,
        "evaluation completed without a main-suite resource limit",
    )
    required_suites = admission["required_suite_sha256"]
    suite_digest = evaluation_report.get("suite_sha256")
    _check(
        checks,
        "evaluation.suite",
        not required_suites or suite_digest in required_suites,
        "evaluation suite is allowed by fleet policy",
    )
    lock_binding = evaluation_report.get("model_lock_sha256")
    binding_required = admission["require_model_lock_binding"]
    _check(
        checks,
        "evaluation.model_lock_binding",
        (not binding_required) or lock_binding == model_lock_sha256,
        "evaluation report binds the supplied model lock",
    )
    generated_at = _parse_time(evaluation_report.get("generated_at"))
    current = now().astimezone(UTC)
    age_hours = (current - generated_at).total_seconds() / 3600 if generated_at else -1
    _check(
        checks,
        "evaluation.freshness",
        generated_at is not None and 0 <= age_hours <= float(admission["max_evidence_age_hours"]),
        "evaluation evidence is fresh and not future-dated",
    )

    decision = "PASS" if all(item.passed for item in checks) else "DENY"
    receipt_core = {
        "schema": RECEIPT_SCHEMA,
        "issued_at": current.isoformat(),
        "decision": decision,
        "policy": {
            "name": policy["name"],
            "version": policy["version"],
            "sha256": actual_policy_digest,
            "key_id": policy_signature.get("key_id", ""),
        },
        "subject": {
            "name": str(subject.get("name") or "")[:256],
            "sha256": model_lock_sha256,
        },
        "evidence": {
            "evaluation_sha256": evaluation_report_sha256,
            "evaluation_verdict": str(verdict or "")[:128],
            "suite_sha256": str(suite_digest or "")[:64],
            "attestation_sha256": sha256_bytes(canonical_json(attestation)),
            "attestation_key_id": str(attestation_signature.get("key_id") or "")[:128],
        },
        "checks": [asdict(item) for item in checks],
    }
    receipt_core["receipt_id"] = sha256_bytes(canonical_json(receipt_core))
    return receipt_core


def admit_files(
    *,
    policy_path: str | Path,
    policy_signature_path: str | Path,
    policy_public_key: str | Path,
    trusted_policy_sha256: str,
    attestation_path: str | Path,
    attestation_signature_path: str | Path,
    attestation_public_key: str | Path,
    evaluation_report_path: str | Path,
    model_lock_path: str | Path,
) -> dict[str, Any]:
    policy, _policy_digest, _policy_size = load_json_snapshot(
        policy_path, expected_schema=POLICY_SCHEMA
    )
    policy_signature, _policy_signature_digest, _policy_signature_size = load_json_snapshot(
        policy_signature_path, expected_schema=SIGNATURE_SCHEMA
    )
    attestation, _attestation_digest, _attestation_size = load_json_snapshot(
        attestation_path, expected_schema=ATTESTATION_SCHEMA
    )
    attestation_signature, _attestation_signature_digest, _attestation_signature_size = (
        load_json_snapshot(attestation_signature_path, expected_schema=SIGNATURE_SCHEMA)
    )
    evaluation, evaluation_digest, _evaluation_size = load_json_snapshot(
        evaluation_report_path, expected_schema=REPORT_SCHEMA
    )
    model_lock, model_lock_digest, _model_lock_size = load_json_snapshot(
        model_lock_path, expected_schema=LOCK_SCHEMA
    )
    return evaluate_admission(
        policy=policy,
        policy_signature=policy_signature,
        policy_public_key=policy_public_key,
        trusted_policy_sha256=trusted_policy_sha256,
        attestation=attestation,
        attestation_signature=attestation_signature,
        attestation_public_key=attestation_public_key,
        evaluation_report=evaluation,
        evaluation_report_sha256=evaluation_digest,
        model_lock=model_lock,
        model_lock_sha256=model_lock_digest,
    )
