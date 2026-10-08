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
- Preserve enough metadata to explain policy decisions without retaining secrets.
- Detect changes relative to an operator-created model lockfile.
- Exercise candidate triggers without executing model-requested side effects.
- Refuse promotion when signed evidence does not satisfy signed fleet policy.

## Out of Scope

- Proving the absence of weight-level behavioral backdoors.
- Discovering arbitrary trigger phrases.
- Parsing every shell language or interpreter.
- Restricting network activity initiated directly by a model server.
- Replacing containers, microVMs, file permissions, or network policy.
- Proving that a recovered behavioral trigger was intentionally trained.
- Protecting an authority private key after host compromise.
- Revocation distribution, hardware-backed key custody, or transparency logs.

## Residual Risk

An attacker can use novel interpreters, renamed binaries, indirect scripts,
allowed services, or covert channels that do not match static rules. Run
untrusted agents without production secrets and enforce egress outside Hermes.

The behavioral evaluator necessarily sends test prompts to the configured model
endpoint. It refuses credentials in endpoint URLs, permits plain HTTP only on
loopback, disables redirects, bounds responses, and never records authorization
header values. Operators remain responsible for trusting the endpoint itself.

Fleet signatures establish artifact integrity and signer identity, not factual
truth. A trusted signer can still approve misleading evidence. Keep authority
keys offline or hardware-backed, review policy changes separately, distribute
public keys through a trusted channel, and treat key revocation as an operator
process until a future transparency mechanism exists.
