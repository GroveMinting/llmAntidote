# Fleet Admission

## Purpose

v3 turns llmAntidote evidence into a local promotion gate. It signs immutable
JSON artifacts, applies signed policy to signed attestations, emits signed
PASS/DENY receipts, and aggregates verified receipt metadata in SQLite.

This is a control-plane primitive, not a hosted service. llmAntidote does not
upload reports, distribute keys, fetch policy, or execute deployment actions.

## Trust Chain

```text
Policy authority public key
        |
        +-- verifies fleet-policy.json

Attestation authority public key
        |
        +-- verifies model attestation
                |
                +-- binds model-lock.json SHA-256
                +-- binds evaluation-report.json SHA-256
Receipt signer public key
        |
        +-- verifies signed admission receipts

Admission gate
        |
        +-- applies signed policy and attestation
                |
                +-- emits PASS or DENY receipt
                +-- receipt is signed
                +-- signed receipt enters fleet ledger
```

Signatures prove that a key approved exact bytes represented by canonical JSON.
They do not prove that the evidence is truthful or that a model lacks a
backdoor.

## Key Generation

```bash
hermes antidote fleet keygen \
  --private-key authority-private.pem \
  --public-key authority-public.pem
```

Private keys are written with mode `0600`; signing refuses keys with group or
world access. Existing files, path aliases, and symlink outputs are refused.
Keys are unencrypted Ed25519 PKCS#8 PEM so automation can use them. Use separate
keys for policy, attestation, and receipts. Keep policy and attestation keys
offline or hardware-isolated; scope the online receipt key only to admission.

## Generic Signing

```bash
hermes antidote fleet sign DOCUMENT.json \
  --private-key authority-private.pem \
  --output DOCUMENT.sig.json

hermes antidote fleet verify DOCUMENT.json \
  --signature DOCUMENT.sig.json \
  --public-key authority-public.pem
```

Signatures cover canonical JSON rather than whitespace or key ordering. Detached
signature envelopes contain only algorithm, key id, document digest, and
signature bytes.

## Fleet Policy

Create a conservative default policy:

```bash
hermes antidote fleet policy init \
  --name production \
  --output fleet-policy.json
```

The policy controls:

- allowed behavioral verdicts;
- required model-lock binding;
- maximum evidence age;
- minimum completed trials;
- maximum evaluation error rate;
- optional allowed suite SHA-256 values;
- desired runtime policy mode and taint lifetime.

Policy does not rewrite llmAntidote's hardcoded exfiltration rules. Runtime
settings are distribution intent for operators and profile-management tooling.

## Attestation

```bash
hermes antidote fleet attest \
  --subject model-lock.json \
  --subject-name model-a \
  --evidence antidote-eval-report.json \
  --output model-a.attestation.json
```

Attestations store artifact names, schemas, sizes, digests, and selected verdict
metadata. They do not embed raw evidence or absolute source paths. Sign the
attestation before admission.

## Admission

`fleet admit` verifies both signatures, confirms that the attestation binds the
supplied lock and report, and evaluates every policy condition. It always writes
and signs a receipt when inputs are structurally valid. Exit status is `0` for
PASS, `1` for DENY, and `2` for malformed inputs or command failure.

Admission also requires `--trusted-policy-sha256`. Distribute this digest through
protected configuration independently of workspace policy files. A valid policy
signature alone does not prevent replay of an older policy signed by the same
authority.

The receipt contains controlled check identifiers and metadata only. It does
not copy prompt text, tool arguments, model output, API keys, or raw reports.

## Fleet Ledger

```bash
hermes antidote fleet ledger ingest \
  --database antidote-fleet.db \
  --receipt model-a.receipt.json \
  --signature model-a.receipt.sig.json \
  --public-key authority-public.pem

hermes antidote fleet ledger summary --database antidote-fleet.db
hermes antidote fleet ledger list --database antidote-fleet.db --decision DENY
```

The ledger verifies signatures and canonical receipt IDs before ingestion. The
first receipt signer becomes the ledger's pinned trust root; later signers are
rejected. Duplicate receipts are idempotent. Stored data is selected receipt
metadata only, never raw receipts or underlying evidence.

## CI/CD

Use `fleet admit` as the deployment gate and preserve its signed receipt as a
build artifact. Keep the public trust root in the repository or managed
configuration. Supply signing keys only from protected CI secrets when signed
receipts are required. Configure the `llm-antidote-admission` GitHub environment
with required reviewers, protected branches, a protected full commit SHA in
`LLM_ANTIDOTE_REF`, and only the receipt-signing secret. See
[`examples/github-admission.yml`](../examples/github-admission.yml).

The installed package exposes `llm-antidote` as a standalone CI entry point;
the same subcommands remain available through `hermes antidote` for an enabled
directory plugin.

## Enforced Runtime Admission

Admission can gate the running agent, not only CI promotion. Set
`admission_enforcement: enforced` in the plugin settings (or the equivalent
`~/.hermes/config.yaml` entry) and provide:

```yaml
plugins:
  entries:
    llm-antidote:
      settings:
        admission_enforcement: enforced
        admission_policy_path: /etc/llm-antidote/fleet-policy.json
        admission_policy_signature_path: /etc/llm-antidote/fleet-policy.sig.json
        admission_policy_public_key: /etc/llm-antidote/policy-public.pem
        admission_trusted_policy_sha256: <trusted-policy-sha256>
        admission_model_lock_path: /etc/llm-antidote/model-lock.json
        admission_model_source: /models/my-model
        admission_model_name: local-model
```

In enforced mode the plugin will not register unless the signed policy verifies
against the trusted digest and the deployed model directory matches the admitted
lockfile. The signed policy's `runtime.mode` and `runtime.taint_ttl_minutes`
become authoritative; a conflicting local override is refused. `/antidote
status` shows the active enforcement state, mode, policy digest, and admitted
model route without exposing private material.

This protects the Hermes agent process. It does not secure other clients that
reach the model endpoint directly, such as Open WebUI, OpenCode, or raw API
calls; those paths need their own controls.

### Model Route Binding

The OpenAI-compatible `/v1` model name is not proof of loaded weights. Enforced
mode verifies the deployed files against the admitted lockfile and records the
model name Hermes is configured to serve. If `pre_api_request` observes a
different model than `admission_model_name`, tool calls are blocked until the
route matches again. Rechecking occurs on every API request, so a model reload
or endpoint swap is caught without a restart. Establishing that a served route
corresponds to the admitted lockfile requires a controlled serving/deployment
process; llmAntidote verifies the binding you configure, not the serving stack
itself.

### Startup Health Probe

A pre-tool hook only fails closed after the plugin has registered. Add an
external supervisor or deployment gate that runs the same verification and fails
the deployment if protection is missing:

```bash
llm-antidote fleet runtime-verify --settings /etc/llm-antidote/settings.json
```

Exit status is `0` for PASS, `1` for a gate failure, and `2` for malformed input.
Run it from a systemd `ExecStartPre`, a Kubernetes init container, or the deploy
script, and refuse to start Hermes when it fails.

## Current Limitations

- No key revocation list or transparency log.
- No hardware-key, PKCS#11, KMS, or Sigstore backend.
- No remote policy fetch or automatic policy rollout.
- One pinned receipt signer per ledger; rotation requires an operator migration.
- No multi-user authorization layer around the SQLite ledger.
- Receipt signing uses an unencrypted PEM key supplied explicitly by the operator.
- Process restart reloads in-memory taint and pending state; enforced admission
  re-verifies at startup, but a crash cannot preserve mid-session reservations.
- Batch-level ordering guarantees depend on the Hermes hook contract; outbound
  message capabilities still require approval regardless of call order.

