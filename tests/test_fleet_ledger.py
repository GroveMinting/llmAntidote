import sqlite3
import stat

import pytest

from llm_antidote.fleet_crypto import (
    canonical_json,
    generate_keypair,
    sha256_bytes,
    sign_document,
    write_json_document,
)
from llm_antidote.fleet_ledger import (
    fleet_summary,
    ingest_receipt,
    list_receipts,
    validate_receipt,
)

from .test_admission import admission_fixture, evaluate


def test_ledger_ingests_signed_receipt_idempotently(tmp_path):
    fixture = admission_fixture(tmp_path)
    receipt = evaluate(fixture)
    receipt_path = write_json_document(receipt, tmp_path / "receipt.json")
    signature_path = write_json_document(
        sign_document(receipt, fixture["private"]), tmp_path / "receipt.sig.json"
    )
    database = tmp_path / "fleet.db"
    assert ingest_receipt(database, receipt_path, signature_path, fixture["public"])
    assert not ingest_receipt(database, receipt_path, signature_path, fixture["public"])
    rows = list_receipts(database)
    assert len(rows) == 1
    assert rows[0]["decision"] == "PASS"
    assert rows[0]["subject_name"] == "model-a"
    assert fleet_summary(database)["pass"] == 1
    assert stat.S_IMODE(database.stat().st_mode) == 0o600
    with sqlite3.connect(database) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(receipts)")}
    assert "receipt_json" not in columns


def test_ledger_rejects_signature_from_wrong_key(tmp_path):
    fixture = admission_fixture(tmp_path)
    receipt = evaluate(fixture)
    receipt_path = write_json_document(receipt, tmp_path / "receipt.json")
    other_private, other_public, _key_id = generate_keypair(
        tmp_path / "other-private.pem", tmp_path / "other-public.pem"
    )
    signature_path = write_json_document(
        sign_document(receipt, other_private), tmp_path / "receipt.sig.json"
    )
    with pytest.raises(ValueError, match="verification failed"):
        ingest_receipt(
            tmp_path / "fleet.db",
            receipt_path,
            signature_path,
            fixture["public"],
        )
    assert other_public.exists()


def test_ledger_pins_first_receipt_signer(tmp_path):
    fixture = admission_fixture(tmp_path)
    receipt = evaluate(fixture)
    receipt_path = write_json_document(receipt, tmp_path / "receipt.json")
    signature_path = write_json_document(
        sign_document(receipt, fixture["private"]), tmp_path / "receipt.sig.json"
    )
    database = tmp_path / "fleet.db"
    assert ingest_receipt(database, receipt_path, signature_path, fixture["public"])

    other_private, other_public, _key_id = generate_keypair(
        tmp_path / "other-private.pem", tmp_path / "other-public.pem"
    )
    other_signature = write_json_document(
        sign_document(receipt, other_private), tmp_path / "other-receipt.sig.json"
    )
    with pytest.raises(ValueError, match="trust root"):
        ingest_receipt(database, receipt_path, other_signature, other_public)


def test_ledger_rejects_receipt_decision_or_unknown_field_inconsistency(tmp_path):
    fixture = admission_fixture(tmp_path)
    receipt = evaluate(fixture)
    inconsistent = dict(receipt)
    inconsistent["decision"] = "DENY"
    inconsistent.pop("receipt_id")
    inconsistent["receipt_id"] = sha256_bytes(canonical_json(inconsistent))
    with pytest.raises(ValueError, match="does not match"):
        validate_receipt(inconsistent)

    extra = dict(receipt)
    extra["raw_prompt"] = "must not be stored"
    with pytest.raises(ValueError, match="unknown fields"):
        validate_receipt(extra)


def test_ledger_refuses_symlink_database(tmp_path):
    fixture = admission_fixture(tmp_path)
    receipt = evaluate(fixture)
    receipt_path = write_json_document(receipt, tmp_path / "receipt.json")
    signature_path = write_json_document(
        sign_document(receipt, fixture["private"]), tmp_path / "receipt.sig.json"
    )
    target = tmp_path / "actual.db"
    target.touch()
    linked = tmp_path / "fleet.db"
    linked.symlink_to(target)
    with pytest.raises(ValueError, match="non-symlink"):
        ingest_receipt(linked, receipt_path, signature_path, fixture["public"])
