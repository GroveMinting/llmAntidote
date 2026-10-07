# Security Policy

## Reporting

Do not open a public issue for a bypass that enables credential disclosure or
code execution. Use GitHub's private vulnerability reporting for this
repository.

Include the llmAntidote version, Hermes Agent version, policy mode, tool name,
and a minimized synthetic reproduction. Never include real secrets.

## Scope

Supported releases are the latest tagged release. llmAntidote is a
defense-in-depth control, not a security boundary. Host sandboxing and egress
policy remain required for hostile-model containment.
