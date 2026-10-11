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
- Block tool calls when the served model route stops matching the admitted model.
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
- Revocation distribution, hardware-backed key custody, or transparency logs.

## Residual Risk

An attacker can use novel interpreters, renamed binaries, indirect scripts,
allowed services, or covert channels that do not match static rules. The
capability classifier is a name-based heuristic: an unknown plugin tool is
treated as potentially outbound and routed to approval, which can be noisy but
fails closed. If Hermes authorizes an outbound call before the sensitive-read
pre-hook in the same batch, per-call state cannot cover the batch; outbound
message tools still require approval, and in a batch the model cannot include a
secret the read has not yet returned. Run untrusted agents without production
secrets and enforce egress outside Hermes.

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
