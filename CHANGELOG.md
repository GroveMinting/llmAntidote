# Changelog

All notable changes to this project will be documented here.

## 3.2.0 - 2026-10-11

Hardening pass derived from `docs/IMPROVEMENT_LIST.md` (live-review findings
against v3.1.0). See `docs/ROADMAP.md`.

- Fail closed on the enforced model route: an unobserved or empty model string is
  no longer treated as admitted. New rule `admission.model_route_unobserved`
  distinguishes "not verified yet" from `admission.model_route_mismatch`; add
  `admission_require_route_observation` (default true in enforced mode).
- Refuse tool arguments that exceed the scan limit instead of approving them;
  the whole argument text is scanned within the limit so a pattern buried
  mid-payload is caught. The cap is operator-configurable via `max_scan_bytes`.
- Stop treating written file content as egress intent: `write_file`/`patch`
  content is no longer scanned for exfiltration patterns; writes to sensitive
  roots are flagged separately (`access.sensitive_root_write`).
- Scope session taint to capabilities via `taint_scope`
  (`egress` | `egress_persist_shell` | `all`, default `egress_persist_shell`), so a
  secret read no longer blocks harmless local reads/writes.
- Classify the real Hermes tool surface: add a `persist` capability
  (memory/skills/scheduled jobs), recognize vision/browser-vault egress, and make
  `llm_antidote/capabilities.py` the single source of truth for names and audit
  families. Add a maintained inventory fixture and coverage test.
- Correlate pending sensitive access by `tool_call_id` (Hermes supplies it) and
  stop merging `session_id`/`task_id`, so shared task ids no longer join unrelated
  sessions and id-less sessions no longer collapse into one bucket.
- Add `pending_ttl_minutes` so an orphaned reservation (e.g. a denied approval
  whose post hook never fires) expires quickly instead of lasting the taint TTL.
- Ledger: replace the single pinned receipt signer with a `key_id` allowlist plus
  revocation and rotation (`fleet ledger trust|allow-signer|revoke-signer|rotate-signer`);
  auto-migrate the legacy pin.
- Trusted plain-HTTP eval endpoints can now pin `host:port`; add tests for
  same-host redirects, credential URLs, and unexpected ports.
- Add a real-Hermes end-to-end hook harness (`tests/integration/hermes_e2e.py`)
  and a CI job that drives standalone and enforced scenarios through Hermes'
  plugin manager.
- Tooling: `mypy`, coverage floor (85%), `pip-audit`, and `ruff` `S` rules in CI;
  add Python 3.13 to the matrix.

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
- Move development tooling to `requirements-dev.txt`; the previous `[dev]` extra
  was folded into Hermes' `--all-extras` install and conflicted with its pinned pytest.
- Relax the `cryptography` pin so the plugin co-installs with the version Hermes ships.
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
