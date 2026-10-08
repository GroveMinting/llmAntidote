"""Canonical JSON, Ed25519 signatures, and evidence attestations."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import tempfile
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SIGNATURE_SCHEMA = "llm-antidote.signature.v1"
ATTESTATION_SCHEMA = "llm-antidote.attestation.v1"
MAX_DOCUMENT_BYTES = 32 * 1024 * 1024
MAX_KEY_BYTES = 64 * 1024


def _absolute_path(path: str | Path) -> Path:
    return Path(os.path.abspath(Path(path).expanduser()))


def _safe_output_path(path: str | Path) -> Path:
    destination = _absolute_path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        resolved_parent = destination.parent.resolve(strict=True)
    except OSError as exc:
        raise ValueError("Could not resolve output parent directory") from exc
    if resolved_parent != destination.parent:
        raise ValueError("Output parent directory must not traverse symlinks")
    return destination


def path_identity(path: str | Path) -> Path:
    value = _absolute_path(path)
    try:
        parent = value.parent.resolve(strict=True)
    except OSError as exc:
        raise ValueError("Could not resolve path parent directory") from exc
    return parent / value.name


def ensure_distinct_paths(*paths: str | Path) -> None:
    normalized = [_safe_output_path(path) for path in paths]
    if len(set(normalized)) != len(normalized):
        raise ValueError("Input and output paths must be distinct")


def _open_regular(path: str | Path) -> tuple[int, os.stat_result, Path]:
    source = _absolute_path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise ValueError(f"Could not open regular non-symlink file: {source.name}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"Artifact is not a regular file: {source.name}")
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, metadata, source


def _read_regular(path: str | Path, maximum: int) -> tuple[bytes, os.stat_result, Path]:
    descriptor, metadata, source = _open_regular(path)
    try:
        with os.fdopen(descriptor, "rb") as stream:
            payload = stream.read(maximum + 1)
    except OSError as exc:
        raise ValueError(f"Could not read regular file: {source.name}") from exc
    if len(payload) > maximum:
        raise ValueError(f"File exceeds {maximum} bytes: {source.name}")
    return payload, metadata, source


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"Duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise ValueError(f"Non-finite JSON number is not allowed: {value}")


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("Document cannot be represented as canonical JSON") from exc


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: str | Path) -> str:
    descriptor, _metadata, source = _open_regular(path)
    digest = hashlib.sha256()
    try:
        with os.fdopen(descriptor, "rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise ValueError(f"Could not hash regular file: {source.name}") from exc
    return digest.hexdigest()


def parse_json_document(payload: bytes, *, expected_schema: str = "") -> dict[str, Any]:
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ValueError("Document is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("JSON document must be an object")
    if expected_schema and value.get("schema") != expected_schema:
        raise ValueError(f"Expected document schema {expected_schema}")
    return value


def load_json_snapshot(
    path: str | Path, *, expected_schema: str = ""
) -> tuple[dict[str, Any], str, int]:
    payload, metadata, _source = _read_regular(path, MAX_DOCUMENT_BYTES)
    return (
        parse_json_document(payload, expected_schema=expected_schema),
        sha256_bytes(payload),
        len(payload),
    )


def load_json_document(path: str | Path, *, expected_schema: str = "") -> dict[str, Any]:
    document, _digest, _size = load_json_snapshot(path, expected_schema=expected_schema)
    return document


def _atomic_write(path: str | Path, content: bytes, *, private: bool = False) -> Path:
    destination = _safe_output_path(path)
    if destination.is_symlink():
        raise ValueError(f"Refusing to replace symlinked output: {destination}")
    handle, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        if private:
            os.fchmod(handle, 0o600)
        with os.fdopen(handle, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        if private:
            os.chmod(destination, 0o600)
    except Exception:
        with suppress(OSError):
            os.unlink(temporary)
        raise
    return destination


def write_json_document(value: dict[str, Any], path: str | Path) -> Path:
    rendered = json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode("utf-8") + b"\n"
    if len(rendered) > MAX_DOCUMENT_BYTES:
        raise ValueError(f"JSON document output exceeds {MAX_DOCUMENT_BYTES} bytes")
    return _atomic_write(path, rendered)


def generate_keypair(private_path: str | Path, public_path: str | Path) -> tuple[Path, Path, str]:
    ensure_distinct_paths(private_path, public_path)
    private_destination = _safe_output_path(private_path)
    public_destination = _safe_output_path(public_path)
    if private_destination.exists() or private_destination.is_symlink():
        raise ValueError(f"Private key output already exists: {private_destination}")
    if public_destination.exists() or public_destination.is_symlink():
        raise ValueError(f"Public key output already exists: {public_destination}")
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_result = _atomic_write(private_destination, private_bytes, private=True)
    try:
        public_result = _atomic_write(public_destination, public_bytes)
    except Exception:
        with suppress(OSError):
            private_result.unlink()
        raise
    return private_result, public_result, public_key_id(public_key)


def _load_private_key(path: str | Path) -> Ed25519PrivateKey:
    payload, metadata, _source = _read_regular(path, MAX_KEY_BYTES)
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise ValueError("Private key must be owned by the current user")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError("Private key permissions must not grant group or world access")
    try:
        key = serialization.load_pem_private_key(payload, password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError("Could not load an unencrypted Ed25519 private key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Private key is not Ed25519")
    return key


def _load_public_key(path: str | Path) -> Ed25519PublicKey:
    payload, _metadata, _source = _read_regular(path, MAX_KEY_BYTES)
    try:
        key = serialization.load_pem_public_key(payload)
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError("Could not load an Ed25519 public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Public key is not Ed25519")
    return key


def public_key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return f"ed25519:{sha256_bytes(raw)[:32]}"


def sign_document(document: dict[str, Any], private_key_path: str | Path) -> dict[str, Any]:
    payload = canonical_json(document)
    private_key = _load_private_key(private_key_path)
    signature = private_key.sign(payload)
    return {
        "schema": SIGNATURE_SCHEMA,
        "algorithm": "Ed25519",
        "key_id": public_key_id(private_key.public_key()),
        "document_sha256": sha256_bytes(payload),
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def verify_document(
    document: dict[str, Any], signature: dict[str, Any], public_key_path: str | Path
) -> tuple[bool, str]:
    if signature.get("schema") != SIGNATURE_SCHEMA or signature.get("algorithm") != "Ed25519":
        return False, "signature.invalid_schema"
    public_key = _load_public_key(public_key_path)
    if signature.get("key_id") != public_key_id(public_key):
        return False, "signature.key_mismatch"
    payload = canonical_json(document)
    if signature.get("document_sha256") != sha256_bytes(payload):
        return False, "signature.digest_mismatch"
    try:
        encoded = signature.get("signature")
        if not isinstance(encoded, str):
            return False, "signature.missing"
        if len(encoded) > 256:
            return False, "signature.invalid_length"
        raw_signature = base64.b64decode(encoded, validate=True)
        if len(raw_signature) != 64:
            return False, "signature.invalid_length"
        public_key.verify(raw_signature, payload)
    except (InvalidSignature, ValueError, TypeError):
        return False, "signature.verification_failed"
    return True, "signature.valid"


def sign_json_file(
    document_path: str | Path, private_key_path: str | Path, signature_output: str | Path
) -> Path:
    ensure_distinct_paths(document_path, private_key_path, signature_output)
    document = load_json_document(document_path)
    return write_json_document(sign_document(document, private_key_path), signature_output)


def verify_json_file(
    document_path: str | Path, signature_path: str | Path, public_key_path: str | Path
) -> tuple[bool, str]:
    document = load_json_document(document_path)
    signature = load_json_document(signature_path, expected_schema=SIGNATURE_SCHEMA)
    return verify_document(document, signature, public_key_path)


def _artifact_summary(path: str | Path) -> dict[str, Any]:
    source = _absolute_path(path)
    document, digest, size = load_json_snapshot(source)
    summary: dict[str, Any] = {
        "name": source.name,
        "sha256": digest,
        "size": size,
        "schema": str(document.get("schema") or ""),
    }
    if summary["schema"] == "llm-antidote.eval-report.v1":
        verdict = document.get("verdict")
        if isinstance(verdict, str) and verdict in {
            "TRIGGER_RECOVERED",
            "SUSPICIOUS_BEHAVIOR_DETECTED",
            "NO_BACKDOOR_DETECTED_WITHIN_TEST_COVERAGE",
            "INCONCLUSIVE",
        }:
            summary["verdict"] = verdict
    elif summary["schema"] == "llm-antidote.admission-receipt.v1":
        decision = document.get("decision")
        if decision in {"PASS", "DENY"}:
            summary["decision"] = decision
    return summary


def create_attestation(
    subject_path: str | Path,
    evidence_paths: list[str | Path],
    *,
    subject_name: str = "",
) -> dict[str, Any]:
    if not evidence_paths:
        raise ValueError("At least one evidence document is required")
    subject = _absolute_path(subject_path)
    subject_document, subject_digest, subject_size = load_json_snapshot(subject)
    evidence = [_artifact_summary(path) for path in evidence_paths]
    clean_subject_name = subject_name.strip() or subject.name
    if (
        not clean_subject_name
        or len(clean_subject_name) > 256
        or any(ord(character) < 32 or ord(character) == 127 for character in clean_subject_name)
    ):
        raise ValueError("Attestation subject name is invalid")
    return {
        "schema": ATTESTATION_SCHEMA,
        "created_at": datetime.now(UTC).isoformat(),
        "subject": {
            "name": clean_subject_name,
            "sha256": subject_digest,
            "size": subject_size,
            "schema": str(subject_document.get("schema") or ""),
        },
        "predicate": {
            "type": "https://github.com/GroveMinting/llmAntidote/attestation/v1",
            "generator": "llmAntidote/3.0.0",
            "evidence": evidence,
        },
    }
