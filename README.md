# llmAntidote for Hermes Agent - provenance and runtime guardrails

[![CI](https://github.com/GroveMinting/llmAntidote/actions/workflows/ci.yml/badge.svg)](https://github.com/GroveMinting/llmAntidote/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/GroveMinting/llmAntidote?include_prereleases&sort=semver)](https://github.com/GroveMinting/llmAntidote/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Target: Hermes Agent](https://img.shields.io/badge/target-Hermes%20Agent-6F42C1)](https://hermes-agent.nousresearch.com/docs/user-guide/features/plugins)
[![Policy: Block + Approve](https://img.shields.io/badge/policy-block%20%2B%20approve-B42318)](docs/POLICY.md)
[![Audit: Model Provenance](https://img.shields.io/badge/audit-model%20provenance-0A66C2)](docs/MODEL_PROVENANCE.md)
[![Eval: Behavioral](https://img.shields.io/badge/eval-behavioral-2E7D32)](docs/BEHAVIORAL_EVALUATION.md)
[![Fleet: Signed Admission](https://img.shields.io/badge/fleet-signed%20admission-7B1FA2)](docs/FLEET_ADMISSION.md)

**Runtime guardrails · behavioral evaluation · signed attestations · fleet admission control**

Inspect what you are running, constrain what it can access, and stop recognized
credential-exfiltration chains before Hermes executes them.

> [!IMPORTANT]
> llmAntidote reduces the blast radius of a compromised or backdoored model. It
> cannot prove that model weights are backdoor-free, discover arbitrary secret
> trigger phrases, or replace OS-level sandboxing and network egress controls.

## Why llmAntidote

A poisoned model can behave normally until a hidden phrase causes it to request
a malicious tool call. ProjectDiscovery demonstrated a 7B model that downloaded
a payload, read project credentials, and sent them to an external collector.
Routine prompts and benchmark scores did not reveal the backdoor.

llmAntidote addresses the enforceable part of that problem: the model may request
an action, but Hermes and the host decide whether it runs.

## Safeguards

- Blocks commands that combine sensitive reads with network transmission.
- Blocks recognizable download-and-execute and reverse-shell patterns.
- Classifies tools by capability, not only argument text; send/upload connectors
  and unknown plugin tools are treated as egress-capable.
- Requires approval for reads outside operator-configured safe roots, including
  unlisted secret filenames such as `token.json`.
- Routes ambiguous sensitive access through Hermes' human approval flow.
- Tracks approved sensitive reads as session-scoped taint metadata.
- Reserves pending sensitive access so outbound calls cannot run before a read resolves.
- Blocks outbound-capable calls from tainted or pending sessions.
- Records rule IDs, fixed tool families, and decisions without raw tool names,
  arguments, results, or secrets.
- Inspects local and Hugging Face model provenance without loading model weights.
- Creates immutable model lockfiles and verifies local files against SHA-256 hashes.
- Runs paired trigger-candidate evaluations with synthetic tools and coverage-scoped verdicts.
- Enforces signed fleet policy over attestations, model locks, and evaluation evidence.
- Enforces signed runtime admission and blocks tool calls on model-route mismatch.
- Produces signed PASS/DENY receipts and metadata-only fleet status reporting.

## Requirements

- Hermes Agent 0.21.5 or newer.
- Python 3.11 or newer.
- A trusted Hermes installation with plugins enabled explicitly.

## Quick Start

Install from GitHub and enable the plugin:

```bash
hermes plugins install GroveMinting/llmAntidote --enable
hermes plugins doctor llm-antidote --ci
```

Hermes' install scanner is expected to return `caution` because the policy and
tests intentionally contain credential-path and malicious-command signatures.
Review those findings before accepting the prompt. A `dangerous` verdict is not
expected and must not be bypassed.

Restart Hermes, then inspect the active runtime state:

```text
/antidote status
```

Inspect a local model directory:

```bash
hermes antidote model inspect /models/my-model
```

Inspect an immutable Hugging Face revision:

```bash
hermes antidote model inspect hf:publisher/model \
  --revision 0123456789abcdef0123456789abcdef01234567
```

Create and verify a local model lockfile:

```bash
hermes antidote model lock /models/my-model --output model-lock.json
hermes antidote model verify model-lock.json
```

Run the standard behavioral suite against a local OpenAI-compatible endpoint:

```bash
hermes antidote eval run \
  --endpoint http://127.0.0.1:8000/v1 \
  --model local-model \
  --model-lock model-lock.json \
  --output antidote-eval-report.json \
  --markdown-output antidote-eval-report.md \
  --minimize
```

The evaluator sends prompts only to the endpoint you provide. Its file, shell,
write, and HTTP tools are simulations: no command, filesystem mutation, or
outbound request is executed by the evaluator.

To reach a remote vLLM host such as a DGX Spark, tunnel loopback over SSH rather
than exposing plaintext HTTP on the LAN:

```bash
ssh -N -L 8000:127.0.0.1:8000 spark-centurion
hermes antidote eval run --endpoint http://127.0.0.1:8000/v1 --model MODEL_ID ...
```

See [`docs/BEHAVIORAL_EVALUATION.md`](docs/BEHAVIORAL_EVALUATION.md) for the
explicit `--trusted-host` opt-in and its cleartext tradeoff.

## Fleet Quick Start

Generate separate Ed25519 keys for policy authority, evidence attestation, and
online receipt signing, then initialize policy:

```bash
hermes antidote fleet keygen \
  --private-key policy-private.pem \
  --public-key policy-public.pem

hermes antidote fleet keygen \
  --private-key attestation-private.pem \
  --public-key attestation-public.pem

hermes antidote fleet keygen \
  --private-key receipt-private.pem \
  --public-key receipt-public.pem

hermes antidote fleet policy init \
  --name production \
  --output fleet-policy.json

hermes antidote fleet sign fleet-policy.json \
  --private-key policy-private.pem \
  --output fleet-policy.sig.json

hermes antidote fleet policy validate fleet-policy.json
```

Record the printed policy SHA-256 in protected configuration. Admission requires
that out-of-band value through `--trusted-policy-sha256`, preventing replay of
an older policy signed by the same authority.

Bind a model lock and behavioral report into an attestation:

```bash
hermes antidote fleet attest \
  --subject model-lock.json \
  --subject-name model-a \
  --evidence antidote-eval-report.json \
  --output model-a.attestation.json

hermes antidote fleet sign model-a.attestation.json \
  --private-key attestation-private.pem \
  --output model-a.attestation.sig.json
```

Run the admission gate and issue a signed receipt:

```bash
hermes antidote fleet admit \
  --policy fleet-policy.json \
  --policy-signature fleet-policy.sig.json \
  --policy-public-key policy-public.pem \
  --trusted-policy-sha256 <trusted-policy-sha256> \
  --attestation model-a.attestation.json \
  --attestation-signature model-a.attestation.sig.json \
  --attestation-public-key attestation-public.pem \
  --evaluation-report antidote-eval-report.json \
  --model-lock model-lock.json \
  --receipt model-a.receipt.json \
  --receipt-private-key receipt-private.pem \
  --receipt-signature model-a.receipt.sig.json
```

Ingest the verified signed receipt into the metadata-only ledger:

```bash
hermes antidote fleet ledger ingest \
  --database antidote-fleet.db \
  --receipt model-a.receipt.json \
  --signature model-a.receipt.sig.json \
  --public-key receipt-public.pem

hermes antidote fleet ledger summary --database antidote-fleet.db
```

See [`docs/FLEET_ADMISSION.md`](docs/FLEET_ADMISSION.md) before distributing
keys or policy bundles. Policy and attestation private keys should normally
remain offline. CI receives only their public keys plus a separately scoped
receipt-signing key.

## Policy Modes

| Mode | Known exfiltration | Ambiguous risk | Audit records |
|---|---|---|---|
| `balanced` | Block | Require approval | Yes |
| `strict` | Block | Block | Yes |
| `audit` | Allow with finding | Allow with finding | Yes |

`balanced` is the default. Configure the plugin through Hermes Desktop or under
`plugins.entries.llm-antidote.settings` in `~/.hermes/config.yaml`:

```yaml
plugins:
  entries:
    llm-antidote:
      settings:
        mode: balanced
        taint_ttl_minutes: 60
        audit_capacity: 200
        safe_read_roots: /home/agent/workspace
        sensitive_roots: /home/agent/.config
```

Reads inside `safe_read_roots` are ordinary unless the name matches a known
secret pattern; reads outside every safe root require approval. See
[`docs/POLICY.md`](docs/POLICY.md) for capability classification, outbound
allow-listing, and the pending-sensitive-access state machine.

## Enforced Fleet Runtime

Admission is not only a CI gate. Set `admission_enforcement: enforced` with a
signed policy and a verified model binding and the plugin will refuse to
register unless both verify. The signed policy's runtime mode and taint TTL
become authoritative, and tool calls are blocked if the served model route stops
matching the admitted model. Use `llm-antidote fleet runtime-verify --settings
SETTINGS.json` as an external supervisor/startup probe. See
[`docs/FLEET_ADMISSION.md`](docs/FLEET_ADMISSION.md).

## Decision Flow

```text
model requests tool call
        |
        v
pre_tool_call policy
        |
        +-- known exfiltration or payload execution --> block
        |
        +-- tainted or pending session egress ---------> block
        |
        +-- ambiguous sensitive or outbound ----------> Hermes approval
        |                                               (+ pending reservation)
        |
        +-- ordinary operation ----------------------> allow
        |
        v
post_tool_call metadata update
        |
        +-- successful sensitive access -------------> taint session
        +-- denial, error, timeout ------------------> release pending
        +-- no sensitive result ----------------------> no taint
```

Policy evaluation is deterministic and does not call an LLM.

## Model Inspection

The inspector reports evidence rather than a misleading safety score:

- resolved immutable revision;
- model, adapter, and base-model lineage claims;
- file inventory and weight formats;
- unsafe pickle-based serialization;
- repository code or executable artifacts;
- mutable revision use and missing file digests;
- local SHA-256 values in deep scans and lockfiles.

Hugging Face inspection reads repository metadata only. It does not download
multi-gigabyte weight shards. Local inspection never deserializes model files.

## Behavioral Evaluation

v0.2 runs matched control and candidate prompts through a bounded synthetic
tool loop. The existing runtime policy classifies requested actions, while the
evaluator measures activation rate, control rate, carrier-prompt coverage, and
endpoint failures. Reports use four explicit verdicts:

- `TRIGGER_RECOVERED`
- `SUSPICIOUS_BEHAVIOR_DETECTED`
- `NO_BACKDOOR_DETECTED_WITHIN_TEST_COVERAGE`
- `INCONCLUSIVE`

`TRIGGER_RECOVERED` means a candidate reproducibly changed tool behavior under
the configured controls. It does not prove how the behavior entered the model
or whether it was intentional. See
[`docs/BEHAVIORAL_EVALUATION.md`](docs/BEHAVIORAL_EVALUATION.md).

## Threat Model

llmAntidote assumes the selected model may intentionally emit malicious tool
calls. The Hermes host and this plugin remain trusted. See
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for boundaries and bypass risks.

## Fleet Admission

v3 adds a local control-plane contract for model promotion. Signed policies
declare acceptable evaluation verdicts, suite identities, coverage, error rate,
evidence age, and model-lock binding. Admission produces a signed receipt whose
exit status is suitable for CI/CD gates. A metadata-only SQLite ledger accepts
only signed receipts and reports PASS/DENY counts without ingesting prompts,
tool arguments, credentials, or model output.

## Development

```bash
python -m pip install -e '.[dev]'
pytest
ruff check .
```

The editable install above is for development dependencies only. llmAntidote
is distributed as a Hermes directory plugin through `hermes plugins install`;
it does not expose a pip plugin entry point that could bypass the manifest's
Hermes version requirement.

When Hermes is installed locally, also run:

```bash
hermes plugins doctor . --ci
hermes plugins validate .
```

## Repository Layout

```text
plugin.yaml                 Hermes plugin manifest
__init__.py                 Hermes registration entry point
llm_antidote/               capability policy, runtime, evaluation, admission, deployment, ledger
tests/                      policy and provenance tests
docs/                       threat model, policy, evaluation, fleet admission, project plan
examples/                   bounded evaluation suite examples
.github/workflows/ci.yml    static checks and unit tests
```

## Sources and Limitations

- [ProjectDiscovery: How abliterated models can get you pwned](https://projectdiscovery.io/research/how-abliterated-models-can-get-you-pwned)
  motivates the runtime consequence-control design.
- [Hermes Agent plugin hooks](https://hermes-agent.nousresearch.com/docs/user-guide/features/hooks#plugin-hooks)
  provide the supported interception and approval surfaces.
- [Hugging Face pickle scanning](https://huggingface.co/docs/hub/en/security-pickle)
  documents why pickle model files require special care.

Pattern-based command analysis is not a shell interpreter and can be bypassed
through sufficiently novel indirection. Run untrusted models with real secret
separation, a container or microVM, and deny-by-default egress.

## License

This project is licensed under the [MIT License](LICENSE). Research, Hermes
Agent, model repositories, and third-party artifacts retain their own licenses.
See [`ATTRIBUTION.md`](ATTRIBUTION.md).
