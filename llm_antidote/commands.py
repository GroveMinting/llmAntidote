"""Hermes CLI and slash-command handlers."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from .admission import admit_files
from .deployment import load_runtime_settings
from .eval_client import OpenAICompatClient
from .eval_report import load_report, render_markdown, write_markdown, write_reports
from .eval_runner import INCONCLUSIVE, NO_BACKDOOR_DETECTED, EvaluationRunner
from .eval_suite import load_suite, with_overrides
from .fleet_crypto import (
    create_attestation,
    ensure_distinct_paths,
    generate_keypair,
    path_identity,
    sign_document,
    sign_json_file,
    verify_json_file,
    write_json_document,
)
from .fleet_ledger import (
    fleet_summary,
    ingest_receipt,
    ledger_allow_signer,
    ledger_revoke_signer,
    ledger_rotate_signer,
    ledger_trust_state,
    list_receipts,
)
from .fleet_policy import default_policy, load_policy, policy_digest
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

    evaluation = subcommands.add_parser("eval", help="Run synthetic behavioral evaluations")
    eval_commands = evaluation.add_subparsers(dest="eval_action", required=True)

    eval_run = eval_commands.add_parser("run", help="Run paired control and candidate trials")
    eval_run.add_argument("--endpoint", required=True, help="OpenAI-compatible API base URL")
    eval_run.add_argument("--model", required=True, help="Model id sent to the endpoint")
    eval_run.add_argument("--suite", help="Evaluation suite JSON; defaults to the standard suite")
    eval_run.add_argument(
        "--candidate", action="append", dest="candidates", help="Replace suite candidates"
    )
    eval_run.add_argument("--repeats", type=int, help="Override repeats per carrier")
    eval_run.add_argument("--max-candidates", type=int, help="Limit candidate count")
    eval_run.add_argument("--timeout", type=float, default=60.0, help="Request timeout seconds")
    eval_run.add_argument("--api-key-env", default="", help="Environment variable holding API key")
    eval_run.add_argument(
        "--trusted-host",
        action="append",
        dest="trusted_hosts",
        default=[],
        help="Allow plaintext HTTP for this explicit host (repeatable; cleartext)",
    )
    eval_run.add_argument("--output", default="antidote-eval-report.json", help="JSON report path")
    eval_run.add_argument("--markdown-output", help="Optional Markdown report path")
    eval_run.add_argument("--model-lock", help="Optional model lockfile to bind by SHA-256")
    eval_run.add_argument("--minimize", action="store_true", help="Minimize recovered candidates")
    eval_run.set_defaults(antidote_handler="eval_run")

    replay = eval_commands.add_parser("replay", help="Render an existing JSON report")
    replay.add_argument("report", help="Evaluation report JSON")
    replay.add_argument("--markdown-output", help="Write rendered Markdown instead of stdout")
    replay.set_defaults(antidote_handler="eval_replay")

    fleet = subcommands.add_parser("fleet", help="Manage signed fleet admission artifacts")
    fleet_commands = fleet.add_subparsers(dest="fleet_action", required=True)

    keygen = fleet_commands.add_parser("keygen", help="Generate an Ed25519 keypair")
    keygen.add_argument("--private-key", required=True, help="Private key PEM output")
    keygen.add_argument("--public-key", required=True, help="Public key PEM output")
    keygen.set_defaults(antidote_handler="fleet_keygen")

    sign = fleet_commands.add_parser("sign", help="Sign a canonical JSON document")
    sign.add_argument("document", help="JSON document to sign")
    sign.add_argument("--private-key", required=True, help="Ed25519 private key PEM")
    sign.add_argument("--output", required=True, help="Detached signature JSON output")
    sign.set_defaults(antidote_handler="fleet_sign")

    signature_verify = fleet_commands.add_parser("verify", help="Verify a detached signature")
    signature_verify.add_argument("document", help="Signed JSON document")
    signature_verify.add_argument("--signature", required=True, help="Signature JSON")
    signature_verify.add_argument("--public-key", required=True, help="Ed25519 public key PEM")
    signature_verify.set_defaults(antidote_handler="fleet_verify")

    attest = fleet_commands.add_parser("attest", help="Create an evidence attestation")
    attest.add_argument("--subject", required=True, help="Model lock or subject JSON")
    attest.add_argument(
        "--evidence", action="append", required=True, help="Evidence JSON; repeat as needed"
    )
    attest.add_argument("--subject-name", default="", help="Stable fleet subject name")
    attest.add_argument("--output", required=True, help="Attestation JSON output")
    attest.set_defaults(antidote_handler="fleet_attest")

    policy = fleet_commands.add_parser("policy", help="Create or validate fleet policy")
    policy_commands = policy.add_subparsers(dest="policy_action", required=True)
    policy_init = policy_commands.add_parser("init", help="Create a default fleet policy")
    policy_init.add_argument("--name", default="default-production", help="Policy name")
    policy_init.add_argument("--output", required=True, help="Policy JSON output")
    policy_init.set_defaults(antidote_handler="fleet_policy_init")
    policy_validate = policy_commands.add_parser("validate", help="Validate fleet policy")
    policy_validate.add_argument("policy", help="Fleet policy JSON")
    policy_validate.set_defaults(antidote_handler="fleet_policy_validate")

    runtime_verify = fleet_commands.add_parser(
        "runtime-verify", help="Verify enforced admission runtime settings without Hermes"
    )
    runtime_verify.add_argument(
        "--settings", required=True, help="JSON file of llm-antidote plugin settings"
    )
    runtime_verify.add_argument("--json", action="store_true", dest="as_json")
    runtime_verify.set_defaults(antidote_handler="fleet_runtime_verify")

    admit = fleet_commands.add_parser("admit", help="Evaluate signed evidence against policy")
    admit.add_argument("--policy", required=True)
    admit.add_argument("--policy-signature", required=True)
    admit.add_argument("--policy-public-key", required=True)
    admit.add_argument("--trusted-policy-sha256", required=True)
    admit.add_argument("--attestation", required=True)
    admit.add_argument("--attestation-signature", required=True)
    admit.add_argument("--attestation-public-key", required=True)
    admit.add_argument("--evaluation-report", required=True)
    admit.add_argument("--model-lock", required=True)
    admit.add_argument("--receipt", required=True, help="Admission receipt JSON output")
    admit.add_argument("--receipt-private-key", required=True)
    admit.add_argument("--receipt-signature", required=True, help="Receipt signature JSON output")
    admit.set_defaults(antidote_handler="fleet_admit")

    ledger = fleet_commands.add_parser("ledger", help="Ingest and query signed receipts")
    ledger_commands = ledger.add_subparsers(dest="ledger_action", required=True)
    ledger_ingest = ledger_commands.add_parser("ingest", help="Ingest a signed receipt")
    ledger_ingest.add_argument("--database", required=True)
    ledger_ingest.add_argument("--receipt", required=True)
    ledger_ingest.add_argument("--signature", required=True)
    ledger_ingest.add_argument("--public-key", required=True)
    ledger_ingest.set_defaults(antidote_handler="fleet_ledger_ingest")
    ledger_list = ledger_commands.add_parser("list", help="List fleet receipts")
    ledger_list.add_argument("--database", required=True)
    ledger_list.add_argument("--limit", type=int, default=100)
    ledger_list.add_argument("--decision", default="")
    ledger_list.add_argument("--json", action="store_true", dest="as_json")
    ledger_list.set_defaults(antidote_handler="fleet_ledger_list")
    ledger_summary = ledger_commands.add_parser("summary", help="Show fleet receipt summary")
    ledger_summary.add_argument("--database", required=True)
    ledger_summary.add_argument("--json", action="store_true", dest="as_json")
    ledger_summary.set_defaults(antidote_handler="fleet_ledger_summary")
    ledger_trust = ledger_commands.add_parser("trust", help="Show the ledger signer trust root")
    ledger_trust.add_argument("--database", required=True)
    ledger_trust.add_argument("--json", action="store_true", dest="as_json")
    ledger_trust.set_defaults(antidote_handler="fleet_ledger_trust")
    ledger_allow = ledger_commands.add_parser("allow-signer", help="Allow a receipt signer key id")
    ledger_allow.add_argument("--database", required=True)
    ledger_allow.add_argument("--key-id", required=True, dest="key_id")
    ledger_allow.set_defaults(antidote_handler="fleet_ledger_allow")
    ledger_revoke = ledger_commands.add_parser(
        "revoke-signer", help="Revoke a receipt signer key id"
    )
    ledger_revoke.add_argument("--database", required=True)
    ledger_revoke.add_argument("--key-id", required=True, dest="key_id")
    ledger_revoke.set_defaults(antidote_handler="fleet_ledger_revoke")
    ledger_rotate = ledger_commands.add_parser(
        "rotate-signer", help="Allow a new signer and revoke the previous one"
    )
    ledger_rotate.add_argument("--database", required=True)
    ledger_rotate.add_argument("--new-key-id", required=True, dest="new_key_id")
    ledger_rotate.add_argument("--old-key-id", default="", dest="old_key_id")
    ledger_rotate.set_defaults(antidote_handler="fleet_ledger_rotate")


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


def _file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).expanduser().resolve().open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _terminal_text(value: Any, maximum: int = 256) -> str:
    return "".join(
        character if 32 <= ord(character) < 127 else "?" for character in str(value)[:maximum]
    )


def _protect_outputs(outputs: list[str], inputs: list[str]) -> None:
    ensure_distinct_paths(*outputs)
    output_paths = {path_identity(item) for item in outputs}
    input_paths = {path_identity(item) for item in inputs}
    if output_paths & input_paths:
        raise ValueError("Output paths must not overwrite input artifacts or keys")


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
        if handler == "eval_run":
            suite = with_overrides(
                load_suite(args.suite),
                candidates=args.candidates,
                repeats=args.repeats,
                max_candidates=args.max_candidates,
            )
            client = OpenAICompatClient(
                args.endpoint,
                api_key_env=args.api_key_env,
                timeout=args.timeout,
                trusted_hosts=tuple(getattr(args, "trusted_hosts", None) or ()),
            )
            evaluation = EvaluationRunner(client, model=args.model, suite=suite).run(
                minimize=args.minimize,
                model_lock_sha256=_file_sha256(args.model_lock) if args.model_lock else "",
            )
            json_path, markdown_path = write_reports(
                evaluation,
                json_output=args.output,
                markdown_output=args.markdown_output,
            )
            print(f"Verdict: {evaluation.verdict}")
            print(f"JSON report: {json_path}")
            if markdown_path:
                print(f"Markdown report: {markdown_path}")
            if evaluation.verdict == NO_BACKDOOR_DETECTED:
                return 0
            return 2 if evaluation.verdict == INCONCLUSIVE else 1
        if handler == "eval_replay":
            rendered = render_markdown(load_report(args.report))
            if args.markdown_output:
                destination = write_markdown(rendered, args.markdown_output)
                print(f"Markdown report: {destination}")
            else:
                print(rendered, end="")
            return 0
        if handler == "fleet_keygen":
            private_path, public_path, key_id = generate_keypair(args.private_key, args.public_key)
            print(f"Private key: {private_path}")
            print(f"Public key: {public_path}")
            print(f"Key id: {key_id}")
            return 0
        if handler == "fleet_sign":
            destination = sign_json_file(args.document, args.private_key, args.output)
            print(f"Signature: {destination}")
            return 0
        if handler == "fleet_verify":
            valid, reason = verify_json_file(args.document, args.signature, args.public_key)
            print(f"{'PASS' if valid else 'FAIL'}: {reason}")
            return 0 if valid else 1
        if handler == "fleet_attest":
            _protect_outputs([args.output], [args.subject, *args.evidence])
            attestation = create_attestation(
                args.subject,
                args.evidence,
                subject_name=args.subject_name,
            )
            destination = write_json_document(attestation, args.output)
            print(f"Attestation: {destination}")
            return 0
        if handler == "fleet_policy_init":
            destination = write_json_document(default_policy(args.name), args.output)
            print(f"Policy: {destination}")
            return 0
        if handler == "fleet_policy_validate":
            policy = load_policy(args.policy)
            print(f"PASS: policy sha256 {policy_digest(policy)}")
            return 0
        if handler == "fleet_runtime_verify":
            settings = json.loads(Path(args.settings).read_text(encoding="utf-8"))
            if not isinstance(settings, dict):
                raise ValueError("Runtime settings must be a JSON object")
            try:
                resolved = load_runtime_settings(settings)
            except ValueError as exc:
                print(f"llmAntidote runtime gate FAIL: {exc}")
                return 1
            summary = resolved.binding.summary()
            if args.as_json:
                print(json.dumps(summary, indent=2, sort_keys=True))
            else:
                print(
                    "llmAntidote runtime gate PASS: "
                    f"{summary['enforcement']} mode={resolved.policy.mode}"
                )
            return 0
        if handler == "fleet_admit":
            _protect_outputs(
                [args.receipt, args.receipt_signature],
                [
                    args.policy,
                    args.policy_signature,
                    args.policy_public_key,
                    args.attestation,
                    args.attestation_signature,
                    args.attestation_public_key,
                    args.evaluation_report,
                    args.model_lock,
                    args.receipt_private_key,
                ],
            )
            receipt = admit_files(
                policy_path=args.policy,
                policy_signature_path=args.policy_signature,
                policy_public_key=args.policy_public_key,
                trusted_policy_sha256=args.trusted_policy_sha256,
                attestation_path=args.attestation,
                attestation_signature_path=args.attestation_signature,
                attestation_public_key=args.attestation_public_key,
                evaluation_report_path=args.evaluation_report,
                model_lock_path=args.model_lock,
            )
            signature = sign_document(receipt, args.receipt_private_key)
            signature_path = write_json_document(signature, args.receipt_signature)
            receipt_path = write_json_document(receipt, args.receipt)
            print(f"Decision: {receipt['decision']}")
            print(f"Receipt: {receipt_path}")
            print(f"Receipt signature: {signature_path}")
            return 0 if receipt["decision"] == "PASS" else 1
        if handler == "fleet_ledger_ingest":
            inserted = ingest_receipt(args.database, args.receipt, args.signature, args.public_key)
            print("Ingested" if inserted else "Already present")
            return 0
        if handler == "fleet_ledger_list":
            rows = list_receipts(args.database, limit=args.limit, decision=args.decision)
            if args.as_json:
                print(json.dumps(rows, indent=2, sort_keys=True))
            else:
                for row in rows:
                    print(
                        f"{_terminal_text(row['decision'])} "
                        f"{_terminal_text(row['subject_name'])} "
                        f"policy={_terminal_text(row['policy_name'])}@{row['policy_version']} "
                        f"receipt={row['receipt_id'][:12]}"
                    )
            return 0
        if handler == "fleet_ledger_summary":
            summary = fleet_summary(args.database)
            if args.as_json:
                print(json.dumps(summary, indent=2, sort_keys=True))
            else:
                print(
                    f"Receipts: {summary['receipts']} "
                    f"PASS={summary['pass']} DENY={summary['deny']} "
                    f"subjects={summary['subjects']}"
                )
            return 0
        if handler == "fleet_ledger_trust":
            state = ledger_trust_state(args.database)
            if args.as_json:
                print(json.dumps(state, indent=2, sort_keys=True))
            else:
                allowed = ", ".join(_terminal_text(item) for item in state["allowed"]) or "none"
                revoked = ", ".join(_terminal_text(item) for item in state["revoked"]) or "none"
                print(f"Allowed signers: {allowed}")
                print(f"Revoked signers: {revoked}")
            return 0
        if handler == "fleet_ledger_allow":
            ledger_allow_signer(args.database, args.key_id)
            print(f"Allowed receipt signer {args.key_id[:12]}")
            return 0
        if handler == "fleet_ledger_revoke":
            ledger_revoke_signer(args.database, args.key_id)
            print(f"Revoked receipt signer {args.key_id[:12]}")
            return 0
        if handler == "fleet_ledger_rotate":
            state = ledger_rotate_signer(
                args.database, new_key_id=args.new_key_id, old_key_id=args.old_key_id
            )
            print(f"Trust root now allows {len(state['allowed'])} signer(s)")
            return 0
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(f"llmAntidote error: {exc}")
        return 2
    print("llmAntidote error: no command selected")
    return 2
