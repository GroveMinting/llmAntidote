import stat

import pytest

from llm_antidote.eval_runner import NO_BACKDOOR_DETECTED, REPORT_SCHEMA
from llm_antidote.fleet_crypto import (
    ATTESTATION_SCHEMA,
    create_attestation,
    generate_keypair,
    load_json_document,
    sha256_file,
    sign_document,
    sign_json_file,
    verify_document,
    write_json_document,
)
from llm_antidote.model_lock import LOCK_SCHEMA


def test_generate_sign_verify_and_detect_tampering(tmp_path):
    private, public, key_id = generate_keypair(tmp_path / "private.pem", tmp_path / "public.pem")
    assert key_id.startswith("ed25519:")
    assert stat.S_IMODE(private.stat().st_mode) == 0o600
    document = {"schema": "test.v1", "value": 42}
    signature = sign_document(document, private)
    assert verify_document(document, signature, public) == (True, "signature.valid")
    valid, reason = verify_document({**document, "value": 43}, signature, public)
    assert not valid
    assert reason == "signature.digest_mismatch"

    with pytest.raises(ValueError, match="already exists"):
        generate_keypair(private, tmp_path / "other-public.pem")
    with pytest.raises(ValueError, match="distinct"):
        generate_keypair(tmp_path / "same.pem", tmp_path / "same.pem")


def test_private_key_permissions_and_output_aliases_are_enforced(tmp_path):
    private, _public, _key_id = generate_keypair(tmp_path / "private.pem", tmp_path / "public.pem")
    document = write_json_document({"schema": "test.v1"}, tmp_path / "document.json")
    with pytest.raises(ValueError, match="distinct"):
        sign_json_file(document, private, private)
    private.chmod(0o644)
    with pytest.raises(ValueError, match="permissions"):
        sign_document({"schema": "test.v1"}, private)


def test_json_loader_rejects_duplicate_keys_and_non_finite_numbers(tmp_path):
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema":"one","schema":"two"}')
    with pytest.raises(ValueError, match="valid JSON"):
        load_json_document(duplicate)
    non_finite = tmp_path / "nan.json"
    non_finite.write_text('{"schema":"test.v1","value":NaN}')
    with pytest.raises(ValueError, match="valid JSON"):
        load_json_document(non_finite)


def test_key_and_document_inputs_reject_symlinks(tmp_path):
    source = tmp_path / "source.json"
    write_json_document({"schema": "test.v1"}, source)
    linked = tmp_path / "linked.json"
    linked.symlink_to(source)
    with pytest.raises(ValueError, match="non-symlink"):
        load_json_document(linked)
    with pytest.raises(ValueError, match="symlinked output"):
        write_json_document({"schema": "test.v1"}, linked)


def test_output_parent_symlink_is_refused(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(ValueError, match="parent directory"):
        generate_keypair(alias / "private.pem", real / "public.pem")


def test_attestation_binds_subject_and_evidence_digests(tmp_path):
    model_lock = tmp_path / "model-lock.json"
    write_json_document({"schema": LOCK_SCHEMA, "source": "/synthetic", "files": []}, model_lock)
    report = tmp_path / "report.json"
    write_json_document(
        {
            "schema": REPORT_SCHEMA,
            "verdict": NO_BACKDOOR_DETECTED,
            "suite_name": "suite",
        },
        report,
    )
    attestation = create_attestation(model_lock, [report], subject_name="model-a")
    assert attestation["schema"] == ATTESTATION_SCHEMA
    assert attestation["subject"]["name"] == "model-a"
    assert attestation["subject"]["sha256"] == sha256_file(model_lock)
    assert attestation["predicate"]["evidence"][0]["sha256"] == sha256_file(report)
    assert "/synthetic" not in str(attestation)
