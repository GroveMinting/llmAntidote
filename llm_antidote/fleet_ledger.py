"""Metadata-only SQLite ledger for signed fleet admission receipts."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .admission import ADMISSION_CHECK_IDS, RECEIPT_SCHEMA
from .fleet_crypto import (
    SIGNATURE_SCHEMA,
    canonical_json,
    ensure_distinct_paths,
    load_json_document,
    sha256_bytes,
    verify_document,
)

SCHEMA_VERSION = 1
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _safe_text(value: Any, *, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"Receipt {name} is invalid")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"Receipt {name} contains control characters")
    return value


def _database_path(path: str | Path) -> Path:
    destination = Path(os.path.abspath(Path(path).expanduser()))
    destination.parent.mkdir(parents=True, exist_ok=True)
    parent_metadata = destination.parent.stat()
    if hasattr(os, "getuid") and parent_metadata.st_uid != os.getuid():
        raise ValueError("Fleet database directory must be owned by the current user")
    if stat.S_IMODE(parent_metadata.st_mode) & 0o022:
        raise ValueError("Fleet database directory must not be group or world writable")
    if destination.exists() or destination.is_symlink():
        metadata = destination.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"Fleet database must be a regular non-symlink file: {destination}")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise ValueError("Fleet database must be owned by the current user")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError("Fleet database permissions must be owner-only")
    else:
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(destination, flags, 0o600)
        os.close(descriptor)
    return destination


def _harden_database_files(destination: Path) -> None:
    for candidate in (destination, Path(f"{destination}-wal"), Path(f"{destination}-shm")):
        if candidate.exists() and not candidate.is_symlink():
            os.chmod(candidate, 0o600)


def _connect(path: str | Path) -> sqlite3.Connection:
    destination = _database_path(path)
    connection = sqlite3.connect(destination, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 10000")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS receipts (
            receipt_id TEXT PRIMARY KEY,
            ingested_at TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            decision TEXT NOT NULL CHECK(decision IN ('PASS', 'DENY')),
            policy_name TEXT NOT NULL,
            policy_version INTEGER NOT NULL,
            policy_sha256 TEXT NOT NULL,
            subject_name TEXT NOT NULL,
            subject_sha256 TEXT NOT NULL,
            evaluation_verdict TEXT NOT NULL,
            suite_sha256 TEXT NOT NULL,
            signer_key_id TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS receipts_decision_idx ON receipts(decision);
        CREATE INDEX IF NOT EXISTS receipts_subject_idx ON receipts(subject_sha256);
        """
    )
    connection.execute(
        "INSERT OR IGNORE INTO metadata(key, value) VALUES('schema_version', ?)",
        (str(SCHEMA_VERSION),),
    )
    _migrate_trust_root(connection)
    connection.commit()
    _harden_database_files(destination)
    return connection


def _key_ids(connection: sqlite3.Connection, key: str) -> list[str]:
    row = connection.execute("SELECT value FROM metadata WHERE key = ?", (key,)).fetchone()
    if row is None:
        return []
    try:
        value = json.loads(row[0])
    except (TypeError, ValueError):
        return []
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _store_key_ids(connection: sqlite3.Connection, key: str, values: list[str]) -> None:
    connection.execute(
        "INSERT OR REPLACE INTO metadata(key, value) VALUES(?, ?)",
        (key, json.dumps(sorted(set(values)))),
    )


def _migrate_trust_root(connection: sqlite3.Connection) -> None:
    """Migrate the legacy single-signer pin to the allowlist metadata."""
    legacy = connection.execute(
        "SELECT value FROM metadata WHERE key = 'receipt_signer_key_id'"
    ).fetchone()
    if legacy is None:
        return
    allowed = _key_ids(connection, "receipt_signer_key_ids")
    if legacy[0] and legacy[0] not in allowed:
        allowed.append(legacy[0])
        _store_key_ids(connection, "receipt_signer_key_ids", allowed)
    connection.execute("DELETE FROM metadata WHERE key = 'receipt_signer_key_id'")


def validate_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    if set(receipt) != {
        "schema",
        "issued_at",
        "decision",
        "policy",
        "subject",
        "evidence",
        "checks",
        "receipt_id",
    }:
        raise ValueError("Receipt contains missing or unknown fields")
    if receipt.get("schema") != RECEIPT_SCHEMA:
        raise ValueError(f"Expected receipt schema {RECEIPT_SCHEMA}")
    if receipt.get("decision") not in {"PASS", "DENY"}:
        raise ValueError("Receipt decision must be PASS or DENY")
    for key in ("policy", "subject", "evidence"):
        if not isinstance(receipt.get(key), dict):
            raise ValueError(f"Receipt {key} must be an object")
    checks = receipt.get("checks")
    if not isinstance(checks, list) or len(checks) != len(ADMISSION_CHECK_IDS):
        raise ValueError("Receipt checks must be a list")
    if any(
        not isinstance(item, dict)
        or not isinstance(item.get("id"), str)
        or set(item) != {"id", "passed", "detail"}
        or not isinstance(item.get("passed"), bool)
        or not isinstance(item.get("detail"), str)
        or len(item["detail"]) > 256
        or any(ord(character) < 32 or ord(character) == 127 for character in item["detail"])
        for item in checks
    ):
        raise ValueError("Receipt checks contain invalid entries")
    policy = receipt["policy"]
    if set(policy) != {"name", "version", "sha256", "key_id"}:
        raise ValueError("Receipt policy metadata is invalid")
    if (
        not isinstance(policy.get("name"), str)
        or not isinstance(policy.get("version"), int)
        or isinstance(policy.get("version"), bool)
        or policy["version"] < 1
    ):
        raise ValueError("Receipt policy metadata is invalid")
    _safe_text(policy["name"], name="policy name", maximum=128)
    _safe_text(policy.get("key_id"), name="policy key id", maximum=128)
    if not isinstance(policy.get("sha256"), str) or not _SHA256.fullmatch(policy["sha256"]):
        raise ValueError("Receipt policy digest is invalid")
    subject = receipt["subject"]
    if set(subject) != {"name", "sha256"}:
        raise ValueError("Receipt subject metadata is invalid")
    _safe_text(subject["name"], name="subject name", maximum=256)
    if not isinstance(subject.get("sha256"), str) or not _SHA256.fullmatch(subject["sha256"]):
        raise ValueError("Receipt subject digest is invalid")
    evidence = receipt["evidence"]
    if set(evidence) != {
        "evaluation_sha256",
        "evaluation_verdict",
        "suite_sha256",
        "attestation_sha256",
        "attestation_key_id",
    }:
        raise ValueError("Receipt evidence metadata is invalid")
    for key in ("evaluation_sha256", "suite_sha256", "attestation_sha256"):
        if not isinstance(evidence.get(key), str) or not _SHA256.fullmatch(evidence[key]):
            raise ValueError(f"Receipt evidence {key} is invalid")
    _safe_text(evidence.get("evaluation_verdict"), name="evaluation verdict", maximum=128)
    _safe_text(evidence.get("attestation_key_id"), name="attestation key id", maximum=128)
    check_ids = [item["id"] for item in checks]
    if len(set(check_ids)) != len(check_ids) or set(check_ids) != set(ADMISSION_CHECK_IDS):
        raise ValueError("Receipt checks do not match the admission contract")
    if (receipt["decision"] == "PASS") is not all(item["passed"] for item in checks):
        raise ValueError("Receipt decision does not match its checks")
    _safe_text(receipt.get("issued_at"), name="issued_at", maximum=64)
    receipt_id = receipt.get("receipt_id")
    if not isinstance(receipt_id, str) or len(receipt_id) != 64:
        raise ValueError("Receipt id must be a SHA-256 value")
    unsigned = dict(receipt)
    unsigned.pop("receipt_id", None)
    if receipt_id != sha256_bytes(canonical_json(unsigned)):
        raise ValueError("Receipt id does not match its canonical content")
    return receipt


def ingest_receipt(
    database: str | Path,
    receipt_path: str | Path,
    signature_path: str | Path,
    public_key_path: str | Path,
) -> bool:
    ensure_distinct_paths(database, receipt_path, signature_path, public_key_path)
    receipt = validate_receipt(load_json_document(receipt_path, expected_schema=RECEIPT_SCHEMA))
    signature = load_json_document(signature_path, expected_schema=SIGNATURE_SCHEMA)
    valid, reason = verify_document(receipt, signature, public_key_path)
    if not valid:
        raise ValueError(f"Receipt signature verification failed: {reason}")
    policy = receipt["policy"]
    subject = receipt["subject"]
    evidence = receipt["evidence"]
    row = (
        receipt["receipt_id"],
        datetime.now(UTC).isoformat(),
        str(receipt.get("issued_at") or "")[:64],
        receipt["decision"],
        str(policy.get("name") or "")[:128],
        int(policy.get("version") or 0),
        str(policy.get("sha256") or "")[:64],
        str(subject.get("name") or "")[:256],
        str(subject.get("sha256") or "")[:64],
        str(evidence.get("evaluation_verdict") or "")[:128],
        str(evidence.get("suite_sha256") or "")[:64],
        str(signature.get("key_id") or "")[:128],
    )
    with closing(_connect(database)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        signer_key_id = str(signature.get("key_id") or "")
        allowed = _key_ids(connection, "receipt_signer_key_ids")
        revoked = _key_ids(connection, "receipt_revoked_key_ids")
        if signer_key_id in revoked:
            connection.rollback()
            raise ValueError("Receipt signer key id is revoked")
        if not allowed:
            allowed = [signer_key_id]
            _store_key_ids(connection, "receipt_signer_key_ids", allowed)
        elif signer_key_id not in allowed:
            connection.rollback()
            raise ValueError("Receipt signer is not in the ledger trust root")
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO receipts(
                receipt_id, ingested_at, issued_at, decision, policy_name,
                policy_version, policy_sha256, subject_name, subject_sha256,
                evaluation_verdict, suite_sha256, signer_key_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            row,
        )
        connection.commit()
        return cursor.rowcount == 1


def ledger_trust_state(database: str | Path) -> dict[str, Any]:
    with closing(_connect(database)) as connection:
        return {
            "schema": "llm-antidote.fleet-trust.v1",
            "allowed": _key_ids(connection, "receipt_signer_key_ids"),
            "revoked": _key_ids(connection, "receipt_revoked_key_ids"),
        }


def ledger_allow_signer(database: str | Path, key_id: str) -> dict[str, Any]:
    clean = _safe_text(key_id, name="key id", maximum=128)
    with closing(_connect(database)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        allowed = _key_ids(connection, "receipt_signer_key_ids")
        revoked = _key_ids(connection, "receipt_revoked_key_ids")
        if clean in revoked:
            connection.rollback()
            raise ValueError("Signer key id is revoked; clear the revocation first")
        if clean not in allowed:
            allowed.append(clean)
            _store_key_ids(connection, "receipt_signer_key_ids", allowed)
        connection.commit()
    return {"allowed": allowed, "revoked": revoked}


def ledger_revoke_signer(database: str | Path, key_id: str) -> dict[str, Any]:
    clean = _safe_text(key_id, name="key id", maximum=128)
    with closing(_connect(database)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        allowed = [item for item in _key_ids(connection, "receipt_signer_key_ids") if item != clean]
        revoked = _key_ids(connection, "receipt_revoked_key_ids")
        if clean not in revoked:
            revoked.append(clean)
        _store_key_ids(connection, "receipt_signer_key_ids", allowed)
        _store_key_ids(connection, "receipt_revoked_key_ids", revoked)
        connection.commit()
    return {"allowed": allowed, "revoked": revoked}


def ledger_rotate_signer(
    database: str | Path, *, new_key_id: str, old_key_id: str = ""
) -> dict[str, Any]:
    ledger_allow_signer(database, new_key_id)
    if old_key_id:
        ledger_revoke_signer(database, old_key_id)
    return ledger_trust_state(database)


def list_receipts(
    database: str | Path, *, limit: int = 100, decision: str = ""
) -> list[dict[str, Any]]:
    bounded_limit = max(1, min(int(limit), 1000))
    clean_decision = decision.upper().strip()
    if clean_decision and clean_decision not in {"PASS", "DENY"}:
        raise ValueError("Decision filter must be PASS or DENY")
    query = (
        "SELECT receipt_id, ingested_at, issued_at, decision, policy_name, policy_version, "
        "subject_name, subject_sha256, evaluation_verdict, suite_sha256, signer_key_id "
        "FROM receipts"
    )
    parameters: list[Any] = []
    if clean_decision:
        query += " WHERE decision = ?"
        parameters.append(clean_decision)
    query += " ORDER BY ingested_at DESC LIMIT ?"
    parameters.append(bounded_limit)
    with closing(_connect(database)) as connection:
        rows = connection.execute(query, parameters).fetchall()
    return [dict(row) for row in rows]


def fleet_summary(database: str | Path) -> dict[str, Any]:
    with closing(_connect(database)) as connection:
        total = int(connection.execute("SELECT COUNT(*) FROM receipts").fetchone()[0])
        pass_count = int(
            connection.execute("SELECT COUNT(*) FROM receipts WHERE decision = 'PASS'").fetchone()[
                0
            ]
        )
        deny_count = total - pass_count
        subjects = int(
            connection.execute("SELECT COUNT(DISTINCT subject_sha256) FROM receipts").fetchone()[0]
        )
        latest = connection.execute(
            "SELECT issued_at, decision, receipt_id FROM receipts ORDER BY ingested_at DESC LIMIT 1"
        ).fetchone()
        allowed = _key_ids(connection, "receipt_signer_key_ids")
        revoked = _key_ids(connection, "receipt_revoked_key_ids")
    return {
        "schema": "llm-antidote.fleet-summary.v1",
        "receipts": total,
        "pass": pass_count,
        "deny": deny_count,
        "subjects": subjects,
        "receipt_signer_key_id": allowed[0] if allowed else None,
        "receipt_signer_key_ids": allowed,
        "receipt_revoked_key_ids": revoked,
        "latest": dict(latest) if latest is not None else None,
    }
