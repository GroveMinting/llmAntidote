"""Hermes CLI and slash-command handlers."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .model_inspector import InspectionReport, inspect_model
from .model_lock import create_lock, load_lock, verify_lock, write_lock


def setup_cli(parser: argparse.ArgumentParser) -> None:
    subcommands = parser.add_subparsers(dest="antidote_action", required=True)

    status = subcommands.add_parser("status", help="Show plugin policy status")
    status.set_defaults(antidote_handler="status")

    model = subcommands.add_parser("model", help="Inspect and lock model artifacts")
    model_commands = model.add_subparsers(dest="model_action", required=True)

    inspect = model_commands.add_parser("inspect", help="Inspect local or Hugging Face provenance")
    inspect.add_argument("source", help="Local directory or hf:owner/repository")
    inspect.add_argument("--revision", default="main", help="Hugging Face revision")
    inspect.add_argument("--deep", action="store_true", help="SHA-256 hash every local file")
    inspect.add_argument("--json", action="store_true", dest="as_json", help="Print JSON")
    inspect.set_defaults(antidote_handler="model_inspect")

    lock = model_commands.add_parser("lock", help="Create a SHA-256 lockfile for a local model")
    lock.add_argument("source", help="Local model directory")
    lock.add_argument("--output", default="model-lock.json", help="Lockfile output path")
    lock.set_defaults(antidote_handler="model_lock")

    verify = model_commands.add_parser("verify", help="Verify a local model lockfile")
    verify.add_argument("lockfile", help="Path to model-lock.json")
    verify.add_argument("--source", help="Override the model directory stored in the lockfile")
    verify.add_argument("--json", action="store_true", dest="as_json", help="Print JSON")
    verify.set_defaults(antidote_handler="model_verify")


def format_report(report: InspectionReport) -> str:
    severities = {"high": 0, "medium": 0, "low": 0}
    for finding in report.findings:
        severities[finding.severity] = severities.get(finding.severity, 0) + 1
    lines = [
        f"Source: {report.source}",
        f"Type: {report.source_kind}",
    ]
    if report.requested_revision:
        lines.append(f"Requested revision: {report.requested_revision}")
    if report.resolved_revision:
        lines.append(f"Resolved revision: {report.resolved_revision}")
    lines.extend(
        [
            f"Files: {len(report.files)}",
            "Findings: " + ", ".join(f"{key}={value}" for key, value in severities.items()),
        ]
    )
    for finding in report.findings:
        location = f" ({finding.path})" if finding.path else ""
        lines.append(f"[{finding.severity.upper()}] {finding.code}{location}: {finding.message}")
    if not report.findings:
        lines.append("No static provenance findings. This does not certify model behavior.")
    return "\n".join(lines)


def _lock_exclusion(source: Path, output: Path) -> tuple[str, ...]:
    try:
        absolute_output = Path(output.expanduser().absolute())
        return (absolute_output.relative_to(source.resolve()).as_posix(),)
    except ValueError:
        return ()


def run_cli(args: argparse.Namespace, *, runtime: Any = None) -> int:
    handler = getattr(args, "antidote_handler", "")
    try:
        if handler == "status":
            print(runtime.status_text() if runtime is not None else "llmAntidote is loaded.")
            return 0
        if handler == "model_inspect":
            report = inspect_model(args.source, revision=args.revision, deep=args.deep)
            rendered = (
                json.dumps(report.to_dict(), indent=2, sort_keys=True)
                if args.as_json
                else format_report(report)
            )
            print(rendered)
            return 0
        if handler == "model_lock":
            source = Path(args.source).expanduser().resolve()
            output = Path(args.output).expanduser().absolute()
            lock = create_lock(source, exclude=_lock_exclusion(source, output))
            destination = write_lock(lock, output)
            print(f"Wrote {len(lock['files'])} SHA-256 entries to {destination}")
            return 0
        if handler == "model_verify":
            result = verify_lock(load_lock(args.lockfile), source=args.source)
            if args.as_json:
                print(json.dumps(result, indent=2, sort_keys=True))
            elif result["ok"]:
                print(f"PASS: verified {result['checked']} files under {result['source']}")
            else:
                print(
                    "FAIL: "
                    f"changed={len(result['changed'])} missing={len(result['missing'])} "
                    f"unexpected={len(result['unexpected'])}"
                )
                for category in ("changed", "missing", "unexpected"):
                    for path in result[category]:
                        print(f"  {category}: {path}")
            return 0 if result["ok"] else 1
    except (OSError, ValueError) as exc:
        print(f"llmAntidote error: {exc}")
        return 2
    print("llmAntidote error: no command selected")
    return 2
