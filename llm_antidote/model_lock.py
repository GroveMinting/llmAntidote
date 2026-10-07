"""Immutable SHA-256 manifests for local model directories."""

from __future__ import annotations

import json
import os
import tempfile
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .model_inspector import iter_model_files, sha256_file

LOCK_SCHEMA = "llm-antidote.model-lock.v1"


def create_lock(source: str | Path, *, exclude: tuple[str, ...] = ()) -> dict[str, Any]:
    root = Path(source).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Model source is not a directory: {root}")
    excluded = {Path(item).as_posix() for item in exclude}
    files: list[dict[str, Any]] = []
    for path, relative in iter_model_files(root):
        if relative in excluded:
            continue
        if path.is_symlink():
            raise ValueError(f"Model directory contains a symlink: {relative}")
        if not path.is_file():
            continue
        files.append(
            {
                "path": relative,
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return {
        "schema": LOCK_SCHEMA,
        "generated_at": datetime.now(UTC).isoformat(),
        "source": str(root),
        "algorithm": "sha256",
        "excluded": sorted(excluded),
        "files": files,
    }


def write_lock(lock: dict[str, Any], output: str | Path) -> Path:
    destination = Path(os.path.abspath(Path(output).expanduser()))
    if destination.is_symlink():
        raise ValueError(f"Refusing to replace symlinked lockfile output: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(lock, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    except Exception:
        with suppress(OSError):
            os.unlink(temporary)
        raise
    return destination


def load_lock(path: str | Path) -> dict[str, Any]:
    lock_path = Path(path).expanduser().resolve()
    try:
        value = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read model lockfile: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema") != LOCK_SCHEMA:
        raise ValueError(f"Unsupported model lock schema; expected {LOCK_SCHEMA}")
    if not isinstance(value.get("files"), list):
        raise ValueError("Model lockfile has no file inventory")
    return value


def verify_lock(lock: dict[str, Any], *, source: str | Path | None = None) -> dict[str, Any]:
    root = Path(source or lock.get("source", "")).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Model source is not a directory: {root}")

    expected = {
        str(item.get("path")): item
        for item in lock["files"]
        if isinstance(item, dict) and item.get("path")
    }
    excluded = {str(item) for item in lock.get("excluded", [])}
    actual = {
        relative: path
        for path, relative in iter_model_files(root)
        if (path.is_file() or path.is_symlink()) and relative not in excluded
    }
    missing = sorted(set(expected) - set(actual))
    unexpected = sorted(set(actual) - set(expected))
    changed: list[str] = []
    for relative in sorted(set(expected) & set(actual)):
        item = expected[relative]
        path = actual[relative]
        if (
            path.is_symlink()
            or path.stat().st_size != item.get("size")
            or sha256_file(path) != item.get("sha256")
        ):
            changed.append(relative)
    return {
        "ok": not (missing or unexpected or changed),
        "source": str(root),
        "checked": len(expected),
        "missing": missing,
        "unexpected": unexpected,
        "changed": changed,
    }
