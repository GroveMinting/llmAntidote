# Roadmap

Seeded from the v3.1.0 review captured in `docs/IMPROVEMENT_LIST.md`. Items are
grouped by priority (P1 security/correctness, P2 robustness, P3 tooling/docs) and
marked with their status.

## Shipped in 3.2.0

- **P1.1 Route binding fails open** - unobserved/empty model now fails closed;
  `admission_require_route_observation`; distinct `unobserved` vs `mismatch` rules.
- **P1.2 Oversized arguments** - arguments over `max_scan_bytes` are refused; the
  full bounded text is scanned so a mid-payload pattern is caught.
- **P1.3/P1.4 Correlation** - pending/taint keyed by `tool_call_id`; session/task
  ids are no longer merged and id-less sessions use a per-instance sentinel.
- **P1.5 Pending leak** - `pending_ttl_minutes` bounds orphaned reservations.
- **P1 classifier coverage** - real tool inventory fixture, `persist` capability,
  single name/family table shared with `audit`, inventory coverage test.
- **P1 false positives** - write content is not scanned as egress; sensitive-path
  writes flagged; `taint_scope` makes balanced mode livable.
- **P2 ledger rotation** - `key_id` allowlist, revocation, rotation, migration.
- **P2 tests** - real-Hermes e2e harness, Hypothesis property tests, oversized/
  unknown-key/trusted-host regression tests.
- **P3 tooling** - mypy, coverage floor, pip-audit, ruff `S`, Python 3.13.

## Open

### P2 - Evaluation / fleet
- Signed revocation list (revoked `key_id`s / policy digests) as the step before a
  transparency log.
- Bridge (`tool_call`) introspection: currently classified as intentionally unknown
  (exec/egress approval); inspecting the underlying deferred target is future work.
- Weight-level model binding: `pre_api_request` exposes the route, not weight
  hashes; depends on a controlled serving process.

### P2 - Robustness
- Indirection-resistant exfil detection: token assembly (`"cu"+"rl"`) still evades
  the deterministic rules by design; consider shell-aware normalization.
- Audit/decision telemetry beyond the bounded in-memory ring (opt-in exporters).

### P3 - Tooling / docs
- Faster e2e job (sparse Hermes cache) and Windows coverage.
- Additional fuzzing of `evidence_validation` and `fleet_crypto` parsers.
