# Threat Model

## Trusted

- The Hermes Agent host and plugin loader.
- The installed llmAntidote revision.
- The human responding to approval prompts.
- The operating system controls configured by the operator.

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

## Out of Scope

- Proving the absence of weight-level behavioral backdoors.
- Discovering arbitrary trigger phrases.
- Parsing every shell language or interpreter.
- Restricting network activity initiated directly by a model server.
- Replacing containers, microVMs, file permissions, or network policy.
- Proving that a recovered behavioral trigger was intentionally trained.

## Residual Risk

An attacker can use novel interpreters, renamed binaries, indirect scripts,
allowed services, or covert channels that do not match static rules. Run
untrusted agents without production secrets and enforce egress outside Hermes.

The behavioral evaluator necessarily sends test prompts to the configured model
endpoint. It refuses credentials in endpoint URLs, permits plain HTTP only on
loopback, disables redirects, bounds responses, and never records authorization
header values. Operators remain responsible for trusting the endpoint itself.
