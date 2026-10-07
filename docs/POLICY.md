# Runtime Policy

## Balanced Mode

Balanced mode blocks high-confidence exfiltration, remote payload execution,
and reverse shells. Sensitive reads and standalone upload operations require
Hermes approval. A successful approved sensitive read taints only metadata for
that session; later outbound-capable calls are blocked until expiry or reset.

## Strict Mode

Strict mode converts approval decisions into blocks. It is appropriate for
unattended operation where no person should authorize sensitive access.

## Audit Mode

Audit mode records the decision that balanced mode would have made but returns
no directive to Hermes. It is intended for policy evaluation, not containment.

## Audit Data

Each record contains a timestamp, action, fixed tool family, rule IDs, and
truncated SHA-256 pseudonyms of the tool and session identifiers. Raw tool
names, tool arguments, command text, paths, model output, and tool results are
never recorded.

## Taint Categories

- `credential_file`: SSH, cloud, Kubernetes, netrc, and token-store paths.
- `environment_secret`: `.env`, process environment, and environment-dump commands.
- `auth_material`: common authentication and private-key filenames.
- `oversized_arguments`: tool input exceeded the bounded policy scan and was approved explicitly.

Taint is metadata about an approved operation, not captured file content.
