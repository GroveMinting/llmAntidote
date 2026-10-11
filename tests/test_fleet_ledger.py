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
    ledger_allow_signer,
    ledger_revoke_signer,
    ledger_rotate_signer,
    ledger_trust_state,
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


def _signed_receipt(tmp_path, fixture, receipt, private, name):
    document = sign_document(receipt, private)
    path = write_json_document(document, tmp_path / name)
    return document["key_id"], path


def test_ledger_signer_allowlist_and_revocation(tmp_path):
    fixture = admission_fixture(tmp_path)
    receipt = evaluate(fixture)
    receipt_path = write_json_document(receipt, tmp_path / "receipt.json")
    first_key_id, first_sig = _signed_receipt(
        tmp_path, fixture, receipt, fixture["private"], "first.sig.json"
    )
    database = tmp_path / "fleet.db"
    assert ingest_receipt(database, receipt_path, first_sig, fixture["public"])

    other_private, other_public, _ = generate_keypair(
        tmp_path / "other-private.pem", tmp_path / "other-public.pem"
    )
    other_key_id, other_sig = _signed_receipt(
        tmp_path, fixture, receipt, other_private, "other.sig.json"
    )
    with pytest.raises(ValueError, match="trust root"):
        ingest_receipt(database, receipt_path, other_sig, other_public)

    ledger_allow_signer(database, other_key_id)
    ingest_receipt(database, receipt_path, other_sig, other_public)
    assert set(ledger_trust_state(database)["allowed"]) == {first_key_id, other_key_id}

    ledger_revoke_signer(database, first_key_id)
    with pytest.raises(ValueError, match="revoked"):
        ingest_receipt(database, receipt_path, first_sig, fixture["public"])


def test_ledger_rotate_signer(tmp_path):
    fixture = admission_fixture(tmp_path)
    receipt = evaluate(fixture)
    receipt_path = write_json_document(receipt, tmp_path / "receipt.json")
    first_key_id, first_sig = _signed_receipt(
        tmp_path, fixture, receipt, fixture["private"], "first.sig.json"
    )
    database = tmp_path / "fleet.db"
    assert ingest_receipt(database, receipt_path, first_sig, fixture["public"])

    other_private, _other_public, _ = generate_keypair(
        tmp_path / "other-private.pem", tmp_path / "other-public.pem"
    )
    other_key_id, _other_sig = _signed_receipt(
        tmp_path, fixture, receipt, other_private, "other.sig.json"
    )
    state = ledger_rotate_signer(
        database, new_key_id=other_key_id, old_key_id=first_key_id
    )
    assert state["allowed"] == [other_key_id]
    assert first_key_id in state["revoked"]


def test_ledger_migrates_legacy_signer_pin(tmp_path):
    fixture = admission_fixture(tmp_path)
    receipt = evaluate(fixture)
    receipt_path = write_json_document(receipt, tmp_path / "receipt.json")
    key_id, sig = _signed_receipt(
        tmp_path, fixture, receipt, fixture["private"], "first.sig.json"
    )
    database = tmp_path / "fleet.db"
    assert ingest_receipt(database, receipt_path, sig, fixture["public"])
    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM metadata WHERE key = 'receipt_signer_key_ids'")
        connection.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES('receipt_signer_key_id', ?)",
            (key_id,),
        )
        connection.commit()
    summary = fleet_summary(database)
    assert summary["receipt_signer_key_ids"] == [key_id]
