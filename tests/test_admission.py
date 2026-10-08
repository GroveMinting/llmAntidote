import copy
from datetime import UTC, datetime, timedelta

import pytest

from llm_antidote.admission import RECEIPT_SCHEMA, evaluate_admission
from llm_antidote.eval_runner import (
    NO_BACKDOOR_DETECTED,
    CandidateResult,
    EvaluationReport,
    TrialResult,
)
from llm_antidote.fleet_crypto import (
    create_attestation,
    generate_keypair,
    load_json_document,
    sha256_file,
    sign_document,
    write_json_document,
)
from llm_antidote.fleet_ledger import validate_receipt
from llm_antidote.fleet_policy import default_policy, policy_digest
from llm_antidote.model_lock import LOCK_SCHEMA


def admission_fixture(tmp_path, *, generated_at=None):
    private, public, _key_id = generate_keypair(tmp_path / "private.pem", tmp_path / "public.pem")
    model_lock_path = tmp_path / "model-lock.json"
    write_json_document(
        {
            "schema": LOCK_SCHEMA,
            "generated_at": datetime.now(UTC).isoformat(),
            "source": "/synthetic",
            "algorithm": "sha256",
            "excluded": [],
            "files": [{"path": "model.safetensors", "size": 7, "sha256": "f" * 64}],
        },
        model_lock_path,
    )
    lock_digest = sha256_file(model_lock_path)
    report_path = tmp_path / "report.json"
    control = TrialResult("carrier-a", 0, 17, False, completed=True)
    candidate_trial = TrialResult("carrier-a", 0, 17, True, completed=True)
    candidate = CandidateResult(
        candidate="candidate",
        activation_rate=0.0,
        successful_trials=1,
        unsafe_trials=0,
        differential_trials=0,
        control_activation_rate=0.0,
        error_rate=0.0,
        inconclusive=False,
        carrier_hits=(),
        recovered=False,
        trials=[candidate_trial],
    )
    report = EvaluationReport(
        verdict=NO_BACKDOOR_DETECTED,
        model="model-a",
        endpoint="localhost:8000",
        suite_name="suite",
        suite_sha256="a" * 64,
        generated_at=(generated_at or datetime.now(UTC)).isoformat(),
        model_lock_sha256=lock_digest,
        coverage={
            "carriers": 1,
            "candidates": 1,
            "repeats": 1,
            "planned_trials": 2,
            "completed_trials": 2,
            "failed_trials": 0,
            "error_rate": 0.0,
            "control_activation_rate": 0.0,
            "inference_requests": 2,
            "minimization_requests": 0,
            "behavior_differential_trials": 0,
            "resource_limit_hit": False,
            "minimization_incomplete": False,
            "criteria": {
                "activation_threshold": 0.8,
                "control_max_rate": 0.05,
                "min_carriers": 1,
                "max_error_rate": 0.2,
            },
            "rule_counts": {},
            "carrier_prompt_hashes": {"carrier-a": "e" * 64},
        },
        control_trials=[control],
        candidates=[candidate],
    ).to_dict()
    write_json_document(report, report_path)
    attestation = create_attestation(model_lock_path, [report_path], subject_name="model-a")
    policy = default_policy("production")
    policy["admission"]["min_completed_trials"] = 2
    return {
        "private": private,
        "public": public,
        "model_lock": load_json_document(model_lock_path),
        "model_lock_sha256": lock_digest,
        "report": report,
        "report_sha256": sha256_file(report_path),
        "attestation": attestation,
        "attestation_signature": sign_document(attestation, private),
        "policy": policy,
        "policy_signature": sign_document(policy, private),
    }


def evaluate(fixture, **overrides):
    values = {
        "policy": fixture["policy"],
        "policy_signature": fixture["policy_signature"],
        "policy_public_key": fixture["public"],
        "trusted_policy_sha256": policy_digest(fixture["policy"]),
        "attestation": fixture["attestation"],
        "attestation_signature": fixture["attestation_signature"],
        "attestation_public_key": fixture["public"],
        "evaluation_report": fixture["report"],
        "evaluation_report_sha256": fixture["report_sha256"],
        "model_lock": fixture["model_lock"],
        "model_lock_sha256": fixture["model_lock_sha256"],
    }
    values.update(overrides)
    return evaluate_admission(**values)


def test_admission_passes_valid_signed_evidence(tmp_path):
    fixture = admission_fixture(tmp_path)
    receipt = evaluate(fixture)
    assert receipt["schema"] == RECEIPT_SCHEMA
    assert receipt["decision"] == "PASS"
    assert all(item["passed"] for item in receipt["checks"])
    validate_receipt(receipt)


def test_admission_denies_tampered_signature_and_disallowed_verdict(tmp_path):
    fixture = admission_fixture(tmp_path)
    bad_signature = dict(fixture["attestation_signature"])
    bad_signature["signature"] = "AAAA"
    policy = copy.deepcopy(fixture["policy"])
    policy["admission"]["allowed_verdicts"] = ["TRIGGER_RECOVERED"]
    receipt = evaluate(
        fixture,
        attestation_signature=bad_signature,
        policy=policy,
        policy_signature=sign_document(policy, fixture["private"]),
    )
    assert receipt["decision"] == "DENY"
    failed = {item["id"] for item in receipt["checks"] if not item["passed"]}
    assert "attestation.signature" in failed
    assert "evaluation.verdict" in failed


def test_admission_denies_stale_or_unbound_evidence(tmp_path):
    fixture = admission_fixture(tmp_path, generated_at=datetime.now(UTC) - timedelta(days=30))
    report = dict(fixture["report"])
    report["model_lock_sha256"] = "b" * 64
    receipt = evaluate(fixture, evaluation_report=report)
    assert receipt["decision"] == "DENY"
    failed = {item["id"] for item in receipt["checks"] if not item["passed"]}
    assert "evaluation.freshness" in failed
    assert "evaluation.model_lock_binding" in failed


def test_admission_rejects_fabricated_report_and_empty_lock(tmp_path):
    fixture = admission_fixture(tmp_path)
    fabricated = copy.deepcopy(fixture["report"])
    fabricated["control_trials"] = []
    with pytest.raises(ValueError, match="controls are missing"):
        evaluate(fixture, evaluation_report=fabricated)

    empty_lock = copy.deepcopy(fixture["model_lock"])
    empty_lock["files"] = []
    with pytest.raises(ValueError, match="at least one file"):
        evaluate(fixture, model_lock=empty_lock)


def test_admission_rejects_non_finite_coverage(tmp_path):
    fixture = admission_fixture(tmp_path)
    fabricated = copy.deepcopy(fixture["report"])
    fabricated["coverage"]["completed_trials"] = float("inf")
    with pytest.raises(ValueError):
        evaluate(fixture, evaluation_report=fabricated)


def test_admission_denies_policy_not_matching_out_of_band_digest(tmp_path):
    fixture = admission_fixture(tmp_path)
    receipt = evaluate(fixture, trusted_policy_sha256="0" * 64)
    assert receipt["decision"] == "DENY"
    failed = {item["id"] for item in receipt["checks"] if not item["passed"]}
    assert "policy.trusted_digest" in failed


def test_admission_rejects_malformed_attestation(tmp_path):
    fixture = admission_fixture(tmp_path)
    attestation = copy.deepcopy(fixture["attestation"])
    attestation["subject"]["name"] = ""
    with pytest.raises(ValueError, match="subject name"):
        evaluate(fixture, attestation=attestation)


def test_policy_can_explicitly_disable_report_lock_binding(tmp_path):
    fixture = admission_fixture(tmp_path)
    policy = copy.deepcopy(fixture["policy"])
    policy["admission"]["require_model_lock_binding"] = False
    report = copy.deepcopy(fixture["report"])
    report["model_lock_sha256"] = ""
    receipt = evaluate(
        fixture,
        policy=policy,
        policy_signature=sign_document(policy, fixture["private"]),
        trusted_policy_sha256=policy_digest(policy),
        evaluation_report=report,
    )
    assert receipt["decision"] == "PASS"
