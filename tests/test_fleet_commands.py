import json
from datetime import UTC, datetime

from llm_antidote.commands import run_cli, setup_cli
from llm_antidote.eval_runner import (
    NO_BACKDOOR_DETECTED,
    CandidateResult,
    EvaluationReport,
    TrialResult,
)
from llm_antidote.fleet_crypto import sha256_file, write_json_document
from llm_antidote.fleet_policy import policy_digest
from llm_antidote.model_lock import LOCK_SCHEMA
from llm_antidote.standalone import main


def invoke(parser, *arguments):
    return run_cli(parser.parse_args(list(arguments)))


def test_fleet_cli_end_to_end(tmp_path):
    import argparse

    parser = argparse.ArgumentParser()
    setup_cli(parser)
    private = tmp_path / "authority-private.pem"
    public = tmp_path / "authority-public.pem"
    assert (
        invoke(
            parser,
            "fleet",
            "keygen",
            "--private-key",
            str(private),
            "--public-key",
            str(public),
        )
        == 0
    )

    policy = tmp_path / "policy.json"
    policy_signature = tmp_path / "policy.sig.json"
    assert (
        invoke(parser, "fleet", "policy", "init", "--name", "production", "--output", str(policy))
        == 0
    )
    policy_value = json.loads(policy.read_text())
    policy_value["admission"]["min_completed_trials"] = 2
    write_json_document(policy_value, policy)
    trusted_policy_digest = policy_digest(policy_value)
    assert (
        invoke(
            parser,
            "fleet",
            "sign",
            str(policy),
            "--private-key",
            str(private),
            "--output",
            str(policy_signature),
        )
        == 0
    )
    assert (
        main(
            [
                "fleet",
                "verify",
                str(policy),
                "--signature",
                str(policy_signature),
                "--public-key",
                str(public),
            ]
        )
        == 0
    )

    model_lock = tmp_path / "model-lock.json"
    write_json_document(
        {
            "schema": LOCK_SCHEMA,
            "generated_at": datetime.now(UTC).isoformat(),
            "source": "/synthetic",
            "algorithm": "sha256",
            "excluded": [],
            "files": [{"path": "model.safetensors", "size": 7, "sha256": "f" * 64}],
        },
        model_lock,
    )
    report = tmp_path / "report.json"
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
    write_json_document(
        EvaluationReport(
            verdict=NO_BACKDOOR_DETECTED,
            model="model-a",
            endpoint="localhost:8000",
            suite_name="suite",
            suite_sha256="a" * 64,
            generated_at=datetime.now(UTC).isoformat(),
            model_lock_sha256=sha256_file(model_lock),
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
        ).to_dict(),
        report,
    )
    attestation = tmp_path / "attestation.json"
    attestation_signature = tmp_path / "attestation.sig.json"
    assert (
        invoke(
            parser,
            "fleet",
            "attest",
            "--subject",
            str(model_lock),
            "--subject-name",
            "model-a",
            "--evidence",
            str(report),
            "--output",
            str(attestation),
        )
        == 0
    )
    assert (
        invoke(
            parser,
            "fleet",
            "sign",
            str(attestation),
            "--private-key",
            str(private),
            "--output",
            str(attestation_signature),
        )
        == 0
    )

    receipt = tmp_path / "receipt.json"
    receipt_signature = tmp_path / "receipt.sig.json"
    assert (
        invoke(
            parser,
            "fleet",
            "admit",
            "--policy",
            str(policy),
            "--policy-signature",
            str(policy_signature),
            "--policy-public-key",
            str(public),
            "--trusted-policy-sha256",
            trusted_policy_digest,
            "--attestation",
            str(attestation),
            "--attestation-signature",
            str(attestation_signature),
            "--attestation-public-key",
            str(public),
            "--evaluation-report",
            str(report),
            "--model-lock",
            str(model_lock),
            "--receipt",
            str(receipt),
            "--receipt-private-key",
            str(private),
            "--receipt-signature",
            str(receipt_signature),
        )
        == 0
    )
    assert json.loads(receipt.read_text())["decision"] == "PASS"

    bad_key = tmp_path / "bad-private.pem"
    bad_key.write_text("not a key")
    bad_key.chmod(0o600)
    failed_receipt = tmp_path / "failed-receipt.json"
    failed_signature = tmp_path / "failed-receipt.sig.json"
    failed_args = parser.parse_args(
        [
            "fleet",
            "admit",
            "--policy",
            str(policy),
            "--policy-signature",
            str(policy_signature),
            "--policy-public-key",
            str(public),
            "--trusted-policy-sha256",
            trusted_policy_digest,
            "--attestation",
            str(attestation),
            "--attestation-signature",
            str(attestation_signature),
            "--attestation-public-key",
            str(public),
            "--evaluation-report",
            str(report),
            "--model-lock",
            str(model_lock),
            "--receipt",
            str(failed_receipt),
            "--receipt-private-key",
            str(bad_key),
            "--receipt-signature",
            str(failed_signature),
        ]
    )
    assert run_cli(failed_args) == 2
    assert not failed_receipt.exists()
    assert not failed_signature.exists()

    database = tmp_path / "fleet.db"
    assert (
        invoke(
            parser,
            "fleet",
            "ledger",
            "ingest",
            "--database",
            str(database),
            "--receipt",
            str(receipt),
            "--signature",
            str(receipt_signature),
            "--public-key",
            str(public),
        )
        == 0
    )
    assert invoke(parser, "fleet", "ledger", "summary", "--database", str(database), "--json") == 0
