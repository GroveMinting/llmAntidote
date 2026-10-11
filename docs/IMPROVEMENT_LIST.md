# llmAntidote v3.1.0 - review findings and improvement list

Source: static review of the v3.1.0 tree plus local probes run against the repo's
`.venv` (Python 3.12). `pytest` passes (143 tests) and `ruff check .` is clean, so
everything below is a gap beyond what the current suite guards, not a failing test.

Severity: **P1** = security/correctness gap worth fixing next; **P2** =
usability/robustness; **P3** = tooling/docs polish.

---

## P1 - Policy correctness and fail-closed gaps

### 1. Enforced-admission route binding fails open
`AntidoteRuntime.route_admitted()` returns `True` in three cases that should
arguably deny in enforced mode: enforcement off / no `admission_model_name`;
**no `pre_api_request` has fired yet**; and **the observed model string is
empty**. Probed with an enforced binding for `model_name="local-model"`:

    enforced, no api request seen yet -> route_admitted: True  | terminal: allow
    after WRONG model observed        -> route_admitted: False | terminal: block
    after EMPTY model observed        -> route_admitted: True  | terminal: allow

Only a positively wrong, non-empty model blocks. An endpoint that omits `model`,
or any window before the first API call, is treated as admitted.
`docs/FLEET_ADMISSION.md` claims rechecking catches a reload or endpoint swap;
that holds only for a non-empty mismatch.
**Fix:** in enforced mode treat "not yet observed" and "observed empty" as
unadmitted (fail closed), or require a startup handshake that establishes the
route before tool calls are permitted. Distinguish "no request seen" from
"route verified".

### 2. Oversized tool arguments are a policy blind spot
`_argument_text()` keeps only the first and last 128 KB of a 256 KB budget;
anything in the omitted middle is invisible to every rule. A malicious pattern
placed mid-payload is not recognized - it degrades to `approve`
(`input.oversized_arguments`). The deterministic classifier the design relies on
misses it (a human may still see the call in the UI).
**Fix:** for arguments over the scan limit, deny/refuse rather than approve, or
scan in a sliding window and let any match win. Add a test proving a mid-payload
pattern is caught.

### 3. Pending/taint correlation is by session alias, not tool-call id
`SessionRiskStore` reserves pending access with a counter keyed by session alias,
and `session_keys()` builds keys from `(session_id, task_id)` then `link()`s
them. Two issues: the brief's WP2 asked for a **tool-call id** so concurrent
calls are not confused (there is none; a sibling benign outbound call in the same
batch is blocked while any sensitive read is pending - fail-closed but coarse);
and `link()` unconditionally merges `session_id` and `task_id`, so a shared or
global `task_id` would merge unrelated sessions (WP2 warned against exactly this).
**Fix:** carry a tool-call id through the hooks if Hermes exposes one; make alias
linking conditional on trustworthy parent/child context; test two concurrent
sessions and a shared task id.

### 4. "unknown" session-key collision
`SessionRiskStore.key("", "")` and `session_keys("","")` both collapse to the
literal `"unknown"`, so every session that omits both ids shares one taint
bucket - cross-session false positives, and one tainted anonymous session taints
all.
**Fix:** use a per-call unique alias when ids are absent, or fail closed rather
than merge.

### 5. Pending reservations can leak on denied approval
`reserve_pending` increments in `decide()` for any non-blocked sensitive read and
is released only in `post_tool_call`. If Hermes denies an approval and does not
invoke `post_tool_call`, the reservation persists until the taint TTL (default 60
min), blocking all outbound in that session.
**Fix:** test the denied-approval path; consider a shorter pending-specific TTL.

---

## P1 - Capability classifier coverage is thin

`classify_tool()` knows a short exact list plus a few prefixes and
`connectors__`/`mcp__`. Everything else falls through to `UNKNOWN`, and
`requires_egress_approval` routes UNKNOWN to approval on **every call**. Probed
against the real Hermes tool surface:

    todo_list       unknown  (naming drift: repo knows todo_read/todo_write)
    memory          unknown  (persistent write - a durable backdoor vector)
    skill_manage    unknown  (writes executable skill code)
    cronjob_manage  unknown  (schedules future arbitrary execution)
    delegate_task   unknown  (spawns subagents that can do anything)
    tool_call       unknown  (invokes arbitrary deferred tools, incl. egress)
    vision_analyze  unknown  (loads remote URLs - a real egress channel)
    session_search  unknown  (reads prior conversation content)
    computer_use    unknown  (in audit's exact set, missing here)
    process_manage  unknown
    text_to_speech  unknown

Two problems: (a) **coverage/naming drift** - `_ALWAYS_SAFE` lists `todo_read`/
`todo_write` but the real tool is `todo_list`, and `capabilities.py` vs
`audit.py` carry different exact-name sets that can disagree about a tool's
family; (b) **fail-closed but unusable, and mis-scoped** - `memory`,
`skill_manage` and `cronjob_manage` are local-write/persistence capabilities, not
outbound, so "maybe outbound" is both noisy and misses that they are the
*durable* side effects a backdoor wants.
**Fix:** enumerate the real Hermes tool surface; add the unused `LOCAL_WRITE`
plus a `SCHEDULE`/`PERSIST` notion for `cronjob_manage`/`memory`/`skill_manage`;
recognize `vision_analyze`/`browser_vault_*`/`tool_call` as egress; make the
classifier the single source of truth shared with `audit.tool_identity`; add a
test asserting every name in a maintained inventory has a non-UNKNOWN profile.

---

## P1 - False positives: the scanner cannot tell text from intent

Rules match substrings in tool arguments and in written file content, not data
flow. Demonstrated live: llmAntidote blocked its own reviewer's `terminal` probe
twice, then blocked the `write_file` for THIS document.

    terminal(cmd with a secret filename token AND an url-ish token) -> block (exfil)
    terminal(cmd carrying a literal download-and-execute string)    -> block (payload)
    write_file(README content mentioning a secret filename + url)   -> block

The probe then succeeded by assembling the tokens (`"cu"+"rl"`, `"."+"en"+"v"`)
so no literal matched - i.e. trivial indirection bypasses it, which the threat
model already concedes. Practical costs: documentation/config writes are blocked
when they mention a secret filename and a URL (`write_file` scans `content`, not
just `path`); and one approved secret-name read taints the whole session:

    read_file(secret name) -> approve (environment_secret, read_outside_safe_root)
    web_search tainted     -> block
    web_search clean       -> allow

**Fix:** (a) do not run the exfil/egress sink rules over `write_file`/`patch`
content - those are not egress; (b) scope taint to the capability that could
carry the secret, or compare read-source class against egress-destination class;
(c) consider an operator-tunable taint scope (`session` vs `next-egress-only`) so
stock `balanced` mode is livable. At minimum, document the write-content behavior
and add regression tests for the benign-write and benign-after-taint cases.

---

## P2 - Evaluation, fleet, packaging

- Ledger: one pinned receipt signer; rotation needs a manual migration. Add a
  documented migration command and a `key_id` allowlist instead of a single pin.
- No revocation/transparency (listed as a limitation). A signed revocation list
  (revoked `key_id`s / policy digests) is the smallest useful step before a log.
- `trusted-host` plaintext http: add explicit tests that a redirect to a
  different host is rejected and that a trusted host with an unexpected port or
  credentials-in-URL is refused.

## P2 - Testing gaps

- **No end-to-end Hermes integration test.** CI validates the plugin *manifest*
  only; nothing drives real hooks (parallel tool calls, denied approval,
  plugin-disabled path, route swap) - exactly what WP5.2 asked for. Highest-value
  test to add.
- **No property-based/fuzz tests** for the regexes and `extract_read_paths` /
  `_argument_text`. A regex-heavy classifier is a natural Hypothesis target.
- **No assertion over the tool inventory**, so coverage silently rots when Hermes
  adds a tool.
- No test for the oversized-middle blind spot or the `"unknown"` key collision.

## P3 - CI and developer tooling

- No static type check despite full annotations - add `mypy --strict`/`pyright`.
- No coverage gate - add `pytest --cov` with a floor on security-critical modules.
- No dependency/security scan - add `pip-audit` and `bandit` (or ruff `S`).
- Python matrix is 3.11/3.12; add 3.13 and state the floor explicitly.
- Dev deps in `requirements-dev.txt` are unpinned - a lockfile would make CI
  reproducible.

## P3 - Docs / repo hygiene

- `llmAntidote_OpenCode_Implementation_Brief.md` is untracked at the repo root -
  commit it under `docs/` as a historical work order or delete it.
- README "Safeguards" is ~18 bullets; split into runtime / provenance /
  evaluation / fleet sections.
- Add a `docs/ROADMAP.md` seeded from this list.

---

## Suggested order of work

1. Route-binding fail closed (P1.1).
2. Classifier inventory + naming fix (P1 coverage) - unblocks the end-to-end test
   and stops the approval storm.
3. Oversized-args deny-by-default (P1.2) + content-vs-path in `write_file`.
4. End-to-end Hermes hook integration test (P2).
5. Tool-call-id correlation and alias-linking tightening (P1.3-5).
6. mypy + coverage + `pip-audit` wiring (P3).
