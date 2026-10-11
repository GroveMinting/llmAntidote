"""Model provenance inspection that never deserializes model artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

_PICKLE_SUFFIXES = {".bin", ".ckpt", ".pickle", ".pkl", ".pt", ".pth"}
_SAFE_WEIGHT_SUFFIXES = {".gguf", ".safetensors"}
_CODE_SUFFIXES = {".bat", ".cmd", ".dll", ".dylib", ".exe", ".ps1", ".py", ".sh", ".so"}
_METADATA_NAMES = {
    "adapter_config.json",
    "config.json",
    "generation_config.json",
    "model_index.json",
    "README.md",
    "tokenizer.json",
    "tokenizer_config.json",
}
_FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_MAX_METADATA_BYTES = 4 * 1024 * 1024
_MAX_REMOTE_METADATA_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    message: str
    path: str = ""


@dataclass(frozen=True)
class ModelFile:
    path: str
    size: int | None = None
    digest: str = ""
    digest_kind: str = ""


@dataclass
class InspectionReport:
    source: str
    source_kind: str
    requested_revision: str = ""
    resolved_revision: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    files: list[ModelFile] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "source_kind": self.source_kind,
            "requested_revision": self.requested_revision,
            "resolved_revision": self.resolved_revision,
            "metadata": self.metadata,
            "files": [asdict(item) for item in self.files],
            "findings": [asdict(item) for item in self.findings],
        }


def sha256_stream(stream: BinaryIO, chunk_size: int = 8 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(chunk_size):
        digest.update(chunk)
    return digest.hexdigest()


def sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return sha256_stream(stream)


def iter_model_files(root: Path) -> Iterator[tuple[Path, str]]:
    for current, dirs, names in os.walk(root, followlinks=False):
        base = Path(current)
        retained_dirs = []
        for name in sorted(name for name in dirs if name not in {".git", "__pycache__"}):
            path = base / name
            if path.is_symlink():
                yield path, path.relative_to(root).as_posix()
            else:
                retained_dirs.append(name)
        dirs[:] = retained_dirs
        for name in sorted(names):
            path = base / name
            yield path, path.relative_to(root).as_posix()


def _classify_inventory(report: InspectionReport) -> None:
    pickle_files = [
        item.path for item in report.files if Path(item.path).suffix.lower() in _PICKLE_SUFFIXES
    ]
    safe_weights = [
        item.path
        for item in report.files
        if Path(item.path).suffix.lower() in _SAFE_WEIGHT_SUFFIXES
    ]
    code_files = [
        item.path for item in report.files if Path(item.path).suffix.lower() in _CODE_SUFFIXES
    ]

    for path in pickle_files:
        report.findings.append(
            Finding(
                "high",
                "format.pickle_weights",
                "Pickle-compatible model artifacts can execute code when deserialized.",
                path,
            )
        )
    for path in code_files:
        report.findings.append(
            Finding(
                "medium",
                "repository.executable_code",
                "Repository code or executable content requires independent review.",
                path,
            )
        )
    if not pickle_files and not safe_weights:
        report.findings.append(
            Finding(
                "medium",
                "inventory.no_weight_files",
                "No recognized model weight files were found.",
            )
        )


def _read_json(path: Path, report: InspectionReport) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            payload = stream.read(_MAX_METADATA_BYTES + 1)
        if len(payload) > _MAX_METADATA_BYTES:
            raise ValueError(f"metadata exceeds {_MAX_METADATA_BYTES} bytes")
        value = json.loads(payload)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        report.findings.append(
            Finding(
                "medium",
                "metadata.invalid_json",
                f"Metadata JSON could not be parsed: {exc}",
                path.name,
            )
        )
        return {}
    return value if isinstance(value, dict) else {}


def inspect_local(source: str | Path, *, deep: bool = False) -> InspectionReport:
    root = Path(source).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Model source is not a directory: {root}")

    report = InspectionReport(source=str(root), source_kind="local")
    for path, relative in iter_model_files(root):
        if path.is_symlink():
            report.files.append(ModelFile(relative))
            report.findings.append(
                Finding(
                    "high",
                    "filesystem.symlink",
                    "Symlinked model content is not self-contained.",
                    relative,
                )
            )
            continue
        if not path.is_file():
            continue
        size = path.stat().st_size
        should_hash = deep or path.name in _METADATA_NAMES or size <= 4 * 1024 * 1024
        digest = sha256_file(path) if should_hash else ""
        report.files.append(ModelFile(relative, size, digest, "sha256" if digest else ""))

    config_path = root / "config.json"
    adapter_path = root / "adapter_config.json"
    config = (
        _read_json(config_path, report)
        if config_path.is_file() and not config_path.is_symlink()
        else {}
    )
    adapter = (
        _read_json(adapter_path, report)
        if adapter_path.is_file() and not adapter_path.is_symlink()
        else {}
    )
    report.metadata = {
        "architectures": config.get("architectures", []),
        "model_type": config.get("model_type", ""),
        "base_model": adapter.get("base_model_name_or_path") or config.get("_name_or_path", ""),
        "adapter": bool(adapter),
        "deep_hashes": deep,
    }
    if not config and not adapter:
        report.findings.append(
            Finding(
                "medium",
                "metadata.missing_lineage",
                "No config or adapter lineage metadata was found.",
            )
        )
    _classify_inventory(report)
    return report


class HuggingFaceClient:
    def __init__(self, opener: Callable[..., Any] = urllib.request.urlopen) -> None:
        self._opener = opener

    def model_info(self, repo: str, revision: str = "main") -> dict[str, Any]:
        repo_path = urllib.parse.quote(repo, safe="/")
        revision_path = urllib.parse.quote(revision, safe="")
        url = f"https://huggingface.co/api/models/{repo_path}/revision/{revision_path}"
        request = urllib.request.Request(url, headers={"User-Agent": "llmAntidote/3.1.0"})
        try:
            response = self._opener(request, timeout=20)
            payload = response.read(_MAX_REMOTE_METADATA_BYTES + 1)
        except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
            raise ValueError(f"Hugging Face metadata request failed: {exc}") from exc
        if len(payload) > _MAX_REMOTE_METADATA_BYTES:
            raise ValueError("Hugging Face metadata response exceeds the size limit")
        try:
            value = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Hugging Face returned invalid JSON metadata") from exc
        if not isinstance(value, dict):
            raise ValueError("Hugging Face returned an unexpected metadata response")
        return value


def inspect_huggingface(
    repo: str,
    *,
    revision: str = "main",
    client: HuggingFaceClient | None = None,
) -> InspectionReport:
    clean_repo = repo.removeprefix("hf:").strip("/")
    if clean_repo.count("/") != 1:
        raise ValueError("Hugging Face sources must use hf:owner/repository")
    info = (client or HuggingFaceClient()).model_info(clean_repo, revision)
    resolved = str(info.get("sha") or "")
    report = InspectionReport(
        source=f"hf:{clean_repo}",
        source_kind="huggingface",
        requested_revision=revision,
        resolved_revision=resolved,
    )
    for sibling in info.get("siblings", []):
        if not isinstance(sibling, dict) or not sibling.get("rfilename"):
            continue
        lfs = sibling.get("lfs") if isinstance(sibling.get("lfs"), dict) else {}
        digest = str(lfs.get("oid") or sibling.get("blobId") or "")
        digest_kind = "sha256" if len(digest) == 64 else ("git-blob" if digest else "")
        size = lfs.get("size", sibling.get("size"))
        report.files.append(ModelFile(str(sibling["rfilename"]), size, digest, digest_kind))

    card = info.get("cardData") if isinstance(info.get("cardData"), dict) else {}
    report.metadata = {
        "author": info.get("author", ""),
        "private": bool(info.get("private")),
        "gated": info.get("gated", False),
        "pipeline_tag": info.get("pipeline_tag", ""),
        "library_name": info.get("library_name", ""),
        "base_model": card.get("base_model", ""),
        "downloads": info.get("downloads"),
    }
    if not _FULL_SHA.fullmatch(revision):
        report.findings.append(
            Finding(
                "medium",
                "revision.mutable_reference",
                "The requested revision was not an immutable 40-character commit SHA.",
            )
        )
    if not _FULL_SHA.fullmatch(resolved):
        report.findings.append(
            Finding(
                "high",
                "revision.unresolved",
                "The repository did not resolve to an immutable commit SHA.",
            )
        )
    elif _FULL_SHA.fullmatch(revision) and revision.lower() != resolved.lower():
        report.findings.append(
            Finding(
                "high",
                "revision.mismatch",
                "The repository resolved to a different commit than the requested "
                "immutable revision.",
            )
        )
    if not report.metadata["base_model"]:
        report.findings.append(
            Finding(
                "medium",
                "metadata.missing_lineage",
                "The model card does not declare base-model lineage.",
            )
        )
    if any(not item.digest for item in report.files):
        report.findings.append(
            Finding(
                "low",
                "inventory.missing_digests",
                "Some repository files lack API-provided digests.",
            )
        )
    _classify_inventory(report)
    return report


def inspect_model(
    source: str,
    *,
    revision: str = "main",
    deep: bool = False,
    client: HuggingFaceClient | None = None,
) -> InspectionReport:
    if source.startswith("hf:"):
        return inspect_huggingface(source, revision=revision, client=client)
    return inspect_local(source, deep=deep)
