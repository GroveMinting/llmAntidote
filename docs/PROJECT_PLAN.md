# Project Plan

## Goal

Build a Hermes Agent plugin that inspects local-model provenance and limits the
consequences of malicious model-generated tool calls.

## MVP

- Deterministic `pre_tool_call` policy with block, approval, and audit outcomes.
- Session-scoped sensitive-read taint tracking from successful tool calls.
- Metadata-only audit history and `/antidote` status command.
- Local and Hugging Face model inspection without deserialization.
- Immutable local model lockfiles with SHA-256 verification.
- Unit tests, CI, security policy, and operator documentation.

## Acceptance Criteria

- The ProjectDiscovery-style `.env` plus `curl` chain is blocked before execution.
- Ordinary local development commands pass in balanced mode.
- Sensitive values never enter plugin audit records.
- Local lock verification detects changed, missing, and unexpected files.
- Plugin registration passes Hermes Plugin Doctor on Hermes 0.21.5 or newer.

## Post-MVP

- Signed attestations and Sigstore verification.
- Optional organization policy bundles.
- Expanded command normalization and differential bypass corpus.
- Hermes plugin catalog submission at an immutable commit.
- Support for additional model registries.

## v0.2 Behavioral Evaluation

- OpenAI-compatible endpoint client with loopback-only plain HTTP.
- Matched control and candidate trials across unrelated carrier prompts.
- Synthetic tools that never execute shell, file, or network side effects.
- Existing deterministic policy reused as the behavioral oracle.
- Reproducibility thresholds, trigger minimization, and explicit inconclusive runs.
- JSON and Markdown reports with prompt hashes rather than prompt bodies.

## v3 Fleet Admission

- Canonical JSON and Ed25519 signatures for policy, attestations, and receipts.
- Evidence attestations binding model locks to behavioral reports.
- Strict admission policy for verdict, suite, coverage, freshness, and error rate.
- PASS/DENY receipts with CI-compatible exit status.
- Metadata-only SQLite ledger that ingests only verified signed receipts.
- No automatic policy update channel or remote execution surface.

## v3.1 Capability Policy and Enforced Admission

- Versioned tool-capability classifier with safe/sensitive read roots.
- Approval for reads outside safe roots, including unlisted secret filenames.
- Capability-based detection of outbound connector and unknown plugin tools.
- Pending-sensitive-access reservations that close the concurrent-read window.
- Enforced runtime admission binding signed policy and a verified model lock.
- Model-route binding that blocks tool calls when the served model changes.
- External `fleet runtime-verify` startup/supervisor health probe.
- Explicit trusted-host opt-in for plaintext evaluation endpoints.

