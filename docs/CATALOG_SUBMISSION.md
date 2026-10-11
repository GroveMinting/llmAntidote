# Submitting llmAntidote to the Hermes plugin catalog

This is the local, ready-to-submit material for a
[Hermes plugin catalog](https://hermes-agent.nousresearch.com/docs/developer-guide/plugins/catalog-submission)
entry. Nothing here is a self-serve registry: the entry below is opened as a PR
against `NousResearch/hermes-agent` (one file, `plugin-catalog/llm-antidote.yaml`)
by the repository owner and merged by a Hermes maintainer.

## Pre-submission checks

Run the same gate catalog CI runs, against a clean checkout at the pin:

```bash
hermes plugins doctor /path/to/llmAntidote --ci
hermes plugins validate /path/to/llmAntidote --install-deps
```

Both pass at the pinned commit. The security scan reports `caution` (not
`dangerous`) for three detection regexes — `dump_all_env` and `sudo_usage` — in
`llm_antidote/policy.py`: they are patterns that recognize `env`/`printenv` and
`sudo` in a model's tool call, not behavior the plugin performs.

## Entry file

Place this at `plugin-catalog/llm-antidote.yaml` in `NousResearch/hermes-agent`.
Pin `sha` to the full 40-character commit of the release being submitted (the
tagged `v3.2.3` commit) and keep `version` in step with it.

```yaml
name: llm-antidote
repo: https://github.com/GroveMinting/llmAntidote
sha: "<40-hex commit sha of the submitted release>"
description: Runtime guardrails, behavioral evaluation, and signed fleet admission for Hermes Agent.
maintainer: GroveMinting
tier: community
category: tools
requires_hermes: ">=0.21.5"
version: "3.2.3"
capabilities:
  provides_tools: []
  provides_hooks:
    - pre_tool_call
    - post_tool_call
    - pre_api_request
    - on_session_start
    - on_session_reset
    - on_session_finalize
  provides_middleware: []
  requires_env: []
```

Notes:

- `provides_tools` is empty: the plugin registers no tools. It acts through
  hooks (policy interception) plus a `/antidote` slash command and a
  `hermes antidote` CLI command.
- `tier: community` (third-party project), and `maintainer` is the repository
  owner, satisfying the owner-or-major-contributor rule.
- `category` has no security shelf; `tools` is the closest fit.

## PR description / disclosure (rule 13)

> **llm-antidote** adds runtime guardrails, behavioral evaluation, and signed
> fleet admission to Hermes. It registers six hooks (`pre_tool_call`,
> `post_tool_call`, `pre_api_request`, `on_session_start`, `on_session_reset`,
> `on_session_finalize`), a `/antidote` slash command, and a `hermes antidote`
> CLI command. It registers no tools and does not touch Hermes internals.
>
> Disclosures:
> - **Network**: runtime hooks make no network calls. The optional evaluation
>   CLI sends synthetic prompts to an operator-specified OpenAI-compatible
>   endpoint; `model inspect` with an `hf:` source fetches metadata from Hugging
>   Face.
> - **Reads**: runtime reads tool-call arguments in memory only (never
>   persisted). The CLI reads operator-specified model directories and signed
>   policy/lock/attestation/report files.
> - **Credentials**: `fleet keygen` writes unencrypted Ed25519 PKCS#8 private
>   keys to operator paths (mode 0600). The evaluation CLI reads its API key via
>   `agent.secret_scope.get_secret` inside Hermes, falling back to the named
>   environment variable only in the standalone entry point. The runtime never
>   reads secrets, `.env`, or `auth.json`.
> - **Storage**: signed admission receipts/ledger in a local SQLite database.
> - **No** shell, subprocesses, background processes, or telemetry.
> - Security-scan `caution` findings (`dump_all_env`, `sudo_usage`) are detection
>   regexes, not behavior.
