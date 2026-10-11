# Runtime Policy

## Balanced Mode

Balanced mode blocks high-confidence exfiltration, remote payload execution,
and reverse shells. Sensitive reads, reads outside configured safe roots,
outbound message/upload capabilities, and unknown plugin tools require Hermes
approval. A successful approved sensitive read taints only metadata for that
session; later outbound-capable calls are blocked until expiry or reset.

## Strict Mode

Strict mode converts approval decisions into blocks. It is appropriate for
unattended operation where no person should authorize sensitive access.

## Audit Mode

Audit mode records the decision that balanced mode would have made but returns
no directive to Hermes. It is intended for policy evaluation, not containment.

## Tool Capabilities

Policy is driven by a versioned capability classifier
(`llm_antidote.capabilities`) rather than familiar filenames alone. Tools are
grouped as local read, local write, shell/code execution, outbound network,
outbound message/upload, and unknown. Unknown plugin tools (`mcp__*`,
`connectors__*`, and other plugins) are treated as potentially outbound, so they
cannot silently acquire unrestricted egress.

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

## Pending Sensitive Access

A permitted sensitive read is reserved as **pending** before it executes. Any
outbound-capable call in a session with pending or completed sensitive access is
blocked. The reservation is released on success (which then marks taint), on
denial, error, timeout, cancellation, reset, or finalization. Orphaned
reservations expire with the taint TTL. This closes the window in which an
outbound call could be authorized before the read's post hook runs.

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
- `unclassified_read`: a read whose target path could not be extracted.
- `oversized_arguments`: tool input exceeded the bounded policy scan and was approved explicitly.

Taint is metadata about an approved operation, not captured file content.
