# Threat Model

## Trusted

- The Hermes Agent host and plugin loader.
- The installed llmAntidote revision.
- The human responding to approval prompts.
- The operating system controls configured by the operator.
- Fleet authority private keys while they remain under operator control.
- Public keys explicitly distributed as fleet trust roots.

## Untrusted

- Local and remote model weights.
- Model-generated tool names and arguments.
- Model cards, repository metadata, and claimed lineage.
- Files and instructions in an agent workspace.
- Responses and tool calls returned by an evaluation endpoint.

## Protected Outcomes

- Prevent recognizable credential reads from being combined with egress.
- Prevent known remote payload and reverse-shell command shapes.
- Require approval for reads outside operator-configured safe roots.
- Reserve pending sensitive access so outbound calls cannot run before a read resolves.
- Preserve enough metadata to explain policy decisions without retaining secrets.
- Detect changes relative to an operator-created model lockfile.
- Refuse to start an enforced deployment without a verified signed policy and model binding.
- Block tool calls when the served model route stops matching the admitted model,
  including before any route has been observed.
- Refuse arguments that exceed the policy scan limit rather than approving them.
- Scope taint to the capabilities that could carry a secret, including outbound
  speech (`text_to_speech`), whose text is sent to a remote provider by default.
- Correlate pending sensitive access by tool-call id so concurrent calls release
  independently.
- Exercise candidate triggers without executing model-requested side effects.
- Refuse promotion when signed evidence does not satisfy signed fleet policy.

## Out of Scope

- Proving the absence of weight-level behavioral backdoors.
- Discovering arbitrary trigger phrases.
- Parsing every shell language or interpreter.
- Restricting network activity initiated directly by a model server.
- Proving that a served `/v1` route corresponds to specific weights without a
  controlled serving or deployment process.
- Protecting a deployment where the operator disables enforcement or omits the
  external health probe.
- Replacing containers, microVMs, file permissions, or network policy.
- Proving that a recovered behavioral trigger was intentionally trained.
- Protecting an authority private key after host compromise.
- Hardware-backed key custody. Distributable revocation lists or transparency
  logs are also out of scope; the ledger carries a local signer allowlist and
  revocation set, and distributing or enforcing it fleet-wide is an operator
  process today.

## Residual Risk

An attacker can use novel interpreters, renamed binaries, indirect scripts,
token assembly (`"cu"+"rl"`), allowed services, or covert channels that do not
match static rules. The capability classifier is a name-based heuristic: an
unknown plugin tool is treated as potentially outbound and routed to approval,
which can be noisy but fails closed. The bridge `tool_call` is treated as an
intentionally-unknown egress/exec tool rather than inspecting its deferred
target. Path classification applies to the dedicated read tools
(`read_file`/`list_files`/`search_files`), so a single `terminal`/`execute_code`
call that reads an unrecognized filename and sends it through a method outside
the sink regex (raw socket, arbitrary subprocess, DNS) is not caught in that same
call; the cross-call read-then-exfil sequence is caught by pending/taint, and the
single-call shape relies on OS egress controls. If Hermes authorizes an outbound
call before the sensitive-read pre-hook
in the same batch, per-call state cannot cover the batch; outbound message tools
still require approval, and in a batch the model cannot include a secret the read
has not yet returned. Run untrusted agents without production secrets and enforce
egress outside Hermes.

The behavioral evaluator necessarily sends test prompts to the configured model
endpoint. It refuses credentials in endpoint URLs, permits plain HTTP only on
loopback or explicitly trusted hosts, disables redirects, bounds responses, and
never records authorization header values. Trusting a plaintext LAN host exposes
prompts and credentials to the network; operators remain responsible for
trusting the endpoint itself.

Fleet signatures establish artifact integrity and signer identity, not factual
truth. A trusted signer can still approve misleading evidence. Keep authority
keys offline or hardware-backed, review policy changes separately, distribute
public keys through a trusted channel, and treat key revocation as an operator
process until a future transparency mechanism exists.
