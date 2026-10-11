# Changelog

All notable changes to this project will be documented here.

## 3.1.0 - 2026-10-10

- Add a versioned tool-capability classifier that reasons about what a tool can do, not only its argument text.
- Require approval for reads outside operator-configured safe roots, including unlisted secret filenames.
- Classify outbound connector/message and unknown plugin tools as egress-capable.
- Reserve pending sensitive access atomically to close the concurrent-read decision window.
- Add enforced fleet-admission mode: signed policy and verified model binding are required at plugin startup.
- Bind runtime `mode`/`taint_ttl_minutes` to the signed fleet policy and refuse conflicting local overrides.
- Block tool calls when the served model route does not match the admitted model.
- Add `fleet runtime-verify` for an external startup/supervisor health probe.
- Allow explicit `--trusted-host` plaintext HTTP evaluation endpoints with cleartext warnings.
- Document residual batch-ordering, restart, and serving-integration limits.

## 3.0.0 - 2026-10-08

- Add Ed25519 key generation and detached canonical-JSON signatures.
- Add evidence attestations binding model locks and evaluation reports.
- Add strict, signable fleet policy bundles.
- Add evidence-bound PASS/DENY admission receipts and signed receipt output.
- Add metadata-only SQLite receipt ingestion and fleet status reporting.
- Add CI/CD admission examples and fleet trust-model documentation.
- Add the `hermes antidote fleet` command family.

## 0.2.0 - 2026-10-07

- Add paired behavioral evaluation against explicit OpenAI-compatible endpoints.
- Add synthetic file, terminal, write, and HTTP tools with no real side effects.
- Add reproducibility scoring across carrier prompts, repeats, and matched controls.
- Add trigger minimization and coverage-scoped evaluation verdicts.
- Add bounded JSON suites plus JSON and Markdown reports.
- Add `hermes antidote eval run` and `eval replay` commands.

## 0.1.0 - 2026-10-06

- Add deterministic Hermes tool-call policy hooks.
- Add session-scoped sensitive-data taint tracking.
- Add metadata-only audit events and runtime status command.
- Add local and Hugging Face model provenance inspection.
- Add local model lockfile creation and verification.
