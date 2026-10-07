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

## Protected Outcomes

- Prevent recognizable credential reads from being combined with egress.
- Prevent known remote payload and reverse-shell command shapes.
- Preserve enough metadata to explain policy decisions without retaining secrets.
- Detect changes relative to an operator-created model lockfile.

## Out of Scope

- Proving the absence of weight-level behavioral backdoors.
- Discovering arbitrary trigger phrases.
- Parsing every shell language or interpreter.
- Restricting network activity initiated directly by a model server.
- Replacing containers, microVMs, file permissions, or network policy.

## Residual Risk

An attacker can use novel interpreters, renamed binaries, indirect scripts,
allowed services, or covert channels that do not match static rules. Run
untrusted agents without production secrets and enforce egress outside Hermes.
