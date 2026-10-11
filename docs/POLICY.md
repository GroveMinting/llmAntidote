# Runtime Policy

## Balanced Mode

Balanced mode blocks high-confidence exfiltration, remote payload execution,
and reverse shells. Sensitive reads, reads outside configured safe roots,
outbound message/upload capabilities, persistent writes, and unknown plugin tools
require Hermes approval. A successful approved sensitive read taints only
metadata for that session; later capabilities selected by `taint_scope` are
blocked until expiry or reset.

## Taint Scope

`taint_scope` controls which capabilities a completed sensitive read blocks in
balanced mode:

- `egress` (most permissive): outbound network/message/unknown tools.
- `egress_persist_shell` (default): the above plus persistence
  (`memory`, `skill_manage`, `cronjob_manage`) and shell/code execution.
- `all`: every non-read-only tool.

`strict` blocks every approval-class operation regardless of scope; `audit`
records without directing. Local reads are never blocked by taint.

## Strict Mode

Strict mode converts approval decisions into blocks. It is appropriate for
unattended operation where no person should authorize sensitive access.

## Audit Mode

Audit mode records the decision that balanced mode would have made but returns
no directive to Hermes. It is intended for policy evaluation, not containment.

## Tool Capabilities

Policy is driven by a versioned capability classifier
(`llm_antidote.capabilities`) rather than familiar filenames alone. It is the
single source of truth for tool names and audit families. Tools are grouped as
local read, local write, persistent side effect (`persist`), shell/code
execution, outbound network, outbound message/upload, and unknown. Unknown plugin
tools (`mcp__*`, `connectors__*`, and other plugins) are treated as potentially
outbound, so they cannot silently acquire unrestricted egress. The classifier is
reconciled against a maintained inventory of the real Hermes tool surface
(`tests/data/hermes_tool_inventory.json`); a test fails when a known tool falls
through to `unknown`.

Speech output (`text_to_speech`) is classified as outbound network: its text is
sent to a provider, and the built-in providers (`edge`, `elevenlabs`, `openai`,
`minimax`, `xai`, `mistral`, `gemini`) are remote. A user-configured local
`command` provider is still classified outbound conservatively. Like other
outbound tools it is scanned in full and blocked by session taint.

The classifier is a static, name-based heuristic. Regexes remain useful for
recognizing obvious malicious command shapes, but cannot prove that arbitrary
shell or Python code is harmless.

## Read Roots

Operators configure two path lists:

- `safe_read_roots`: directories where file reads are ordinary. Reads inside a
  safe root are allowed unless the name matches a known secret pattern.
- `sensitive_roots`: directories that always require approval.

Reads outside every safe root require approval in balanced mode and are blocked
in strict mode, even when the file is named `token.json`, `settings.json`, or
something unrecognized. Path traversal is resolved before comparison; symlinks
are resolved where the platform allows. Docker and WSL mount paths should be
listed explicitly.

## Outbound Capabilities

A send-email or upload connector is outbound because of what it does, not
because its arguments contain `http` or a URL. Outbound message/upload
capabilities require approval in balanced mode. Operators may narrow this with
`allow_outbound_tools`, a comma-separated allow-list of exact tool names.

## Content Versus Intent

Exfiltration and payload rules are applied to what a tool *does*, not to data it
merely carries. For the file-write tools (`write_file`, `patch`, `apply_patch`)
the written content is not scanned for egress patterns; only the target path is
checked, and writes into `sensitive_roots` are flagged
(`access.sensitive_root_write`). The exemption applies to those file-write tools
specifically, not to every local-write capability, so payloads of other tools
(such as `text_to_speech`) are scanned and size-gated normally. Shell and code
tools are still scanned as command intent. This avoids blocking documentation
that quotes an example command while keeping genuine egress paths covered.

Argument scanning is bounded by `max_scan_bytes` (default 1 MiB). The entire
bounded text is scanned, so a pattern buried mid-payload is matched; arguments
that exceed the limit are refused (`input.arguments_exceed_scan_limit`) rather
than approved.

## Pending Sensitive Access

A permitted sensitive read is reserved as **pending** before it executes. Any
capability selected by `taint_scope` in a session with pending or completed
sensitive access is blocked. Reservations are keyed by Hermes' `tool_call_id`
(falling back to `turn_id`), so concurrent calls in one session release
independently. The reservation is released on success (which then marks taint),
on denial, error, timeout, cancellation, reset, or finalization. Orphaned
reservations expire with `pending_ttl_minutes` (default 5) rather than the taint
TTL. This closes the window in which an outbound call could be authorized before
the read's post hook runs.

If Hermes can authorize an outbound call *before* it invokes the sensitive-read
pre-hook in the same batch, per-call state cannot cover the batch. Outbound
message tools still require approval regardless of order, and in a single batch
the model cannot include the not-yet-returned secret. A batch-level preflight is
used when Hermes exposes one; otherwise operate with a container and
deny-by-default egress. See [`THREAT_MODEL.md`](THREAT_MODEL.md).

## Audit Data

Each record contains a timestamp, action, fixed tool family, rule IDs, and
truncated SHA-256 pseudonyms of the tool and session identifiers. Raw tool
names, tool arguments, command text, paths, model output, and tool results are
never recorded.

## Taint Categories

- `credential_file`: SSH, cloud, Kubernetes, netrc, and token-store paths.
- `environment_secret`: `.env`, process environment, and environment-dump commands.
- `auth_material`: common authentication and private-key filenames.
- `read_outside_safe_root`: a file outside every configured safe read root.
- `sensitive_root_read`: a file inside a configured sensitive root.
- `sensitive_root_write`: a write into a configured sensitive root.
- `unclassified_read`: a read whose target path could not be extracted.
- `oversized_arguments`: tool input exceeded the bounded policy scan.

Rules that may appear: `access.read_outside_safe_root`,
`access.sensitive_root_read`, `access.sensitive_root_write`,
`egress.outbound_message`, `egress.unknown_plugin_tool`, `egress.upload`,
`egress.network_command`, `persist.durable_write`,
`exfil.tainted_session_egress`, `execution.remote_payload`,
`execution.reverse_shell`, and `input.arguments_exceed_scan_limit`.

Taint is metadata about an approved operation, not captured file content.
