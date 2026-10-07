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
