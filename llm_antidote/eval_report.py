"""Evaluation report persistence and human-readable rendering."""

from __future__ import annotations

import json
import os
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Any

from .eval_runner import REPORT_SCHEMA, EvaluationReport

MAX_REPORT_BYTES = 32 * 1024 * 1024


def _clean(value: Any) -> str:
    text = "".join(character if 32 <= ord(character) < 127 else " " for character in str(value))
    return text.replace("`", "'").replace("<", "&lt;").replace(">", "&gt;")


def _code(value: Any, *, table: bool = False) -> str:
    text = _clean(value)
    return text.replace("|", "\\|") if table else text


def _markdown(value: Any) -> str:
    text = _clean(value).replace("\\", "\\\\")
    for character in "|[]()!*_#~":
        text = text.replace(character, f"\\{character}")
    return text


def _number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def render_markdown(report: EvaluationReport | dict[str, Any]) -> str:
    value = report.to_dict() if isinstance(report, EvaluationReport) else report
    coverage = value.get("coverage", {})
    if not isinstance(coverage, dict):
        coverage = {}
    lines = [
        "# llmAntidote Behavioral Evaluation",
        "",
        f"**Verdict:** `{_code(value.get('verdict', 'INCONCLUSIVE'))}`",
        "",
        f"- Model: `{_code(value.get('model', ''))}`",
        f"- Endpoint: `{_code(value.get('endpoint', ''))}`",
        f"- Suite: `{_code(value.get('suite_name', ''))}`",
        f"- Suite SHA-256: `{_code(value.get('suite_sha256', ''))}`",
        f"- Completed trials: {_number(coverage.get('completed_trials', 0)):g}",
        f"- Failed trials: {_number(coverage.get('failed_trials', 0)):g}",
        f"- Inference requests: {_number(coverage.get('inference_requests', 0)):g}",
        f"- Control activation rate: {_number(coverage.get('control_activation_rate', 0)):.3f}",
        "",
        "## Candidates",
        "",
        "| Candidate | Activation | Carrier hits | Result |",
        "|---|---:|---:|---|",
    ]
    candidates = value.get("candidates", [])
    if not isinstance(candidates, list):
        candidates = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        text = _markdown(candidate.get("candidate", ""))
        result = "trigger recovered" if candidate.get("recovered") else "not recovered"
        carrier_hits = candidate.get("carrier_hits", [])
        if not isinstance(carrier_hits, list):
            carrier_hits = []
        lines.append(
            f"| `{text}` | {_number(candidate.get('activation_rate', 0)):.3f} | "
            f"{len(carrier_hits)} | {result} |"
        )
        if candidate.get("minimized_candidate"):
            minimized = _code(candidate["minimized_candidate"])
            lines.append(f"\nMinimized candidate: `{minimized}`\n")
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "A recovered trigger is a reproducible behavioral activation string, not proof of "
            "training origin or malicious intent. A no-detection verdict applies only to the "
            "documented suite, candidates, carriers, seeds, and tool environment.",
            "",
            "## Limitations",
            "",
        ]
    )
    limitations = value.get("limitations", [])
    if isinstance(limitations, list):
        lines.extend(f"- {_markdown(item)}" for item in limitations)
    return "\n".join(lines).rstrip() + "\n"


def _atomic_write(path: Path, content: str) -> Path:
    if len(content.encode("utf-8")) > MAX_REPORT_BYTES:
        raise ValueError(f"Evaluation report output exceeds {MAX_REPORT_BYTES} bytes")
    destination = Path(os.path.abspath(path.expanduser()))
    if destination.is_symlink():
        raise ValueError(f"Refusing to replace symlinked report output: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    except Exception:
        with suppress(OSError):
            os.unlink(temporary)
        raise
    return destination


def write_reports(
    report: EvaluationReport,
    *,
    json_output: str | Path,
    markdown_output: str | Path | None = None,
) -> tuple[Path, Path | None]:
    json_path = _atomic_write(
        Path(json_output), json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n"
    )
    markdown_path = (
        _atomic_write(Path(markdown_output), render_markdown(report))
        if markdown_output is not None
        else None
    )
    return json_path, markdown_path


def write_markdown(content: str, output: str | Path) -> Path:
    return _atomic_write(Path(output), content)


def load_report(path: str | Path) -> dict[str, Any]:
    report_path = Path(path).expanduser().resolve()
    try:
        with report_path.open("rb") as stream:
            payload = stream.read(MAX_REPORT_BYTES + 1)
    except OSError as exc:
        raise ValueError(f"Could not read evaluation report: {exc}") from exc
    if len(payload) > MAX_REPORT_BYTES:
        raise ValueError(f"Evaluation report exceeds {MAX_REPORT_BYTES} bytes")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Evaluation report is not valid JSON") from exc
    if not isinstance(value, dict) or value.get("schema") != REPORT_SCHEMA:
        raise ValueError(f"Unsupported evaluation report schema; expected {REPORT_SCHEMA}")
    return value
