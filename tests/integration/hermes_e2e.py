#!/usr/bin/env python3
"""End-to-end integration check that drives llmAntidote through real Hermes hooks.

This loads the plugin through Hermes' own plugin manager (a temporary
``HERMES_HOME`` with the repo symlinked into ``plugins/``), then exercises the
same dispatch path Hermes uses at runtime:
``plugins._get_pre_tool_call_directive_details`` / ``plugins.invoke_hook``.

Run from the repo root with a Hermes checkout on ``PYTHONPATH``:

    PYTHONPATH=/path/to/hermes-agent python tests/integration/hermes_e2e.py
    PYTHONPATH=/path/to/hermes-agent python tests/integration/hermes_e2e.py --mode enforced

Exits non-zero on the first failed expectation so it can gate CI.
"""

from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]


def _write_config(home: Path, settings: dict[str, str]) -> None:
    lines = ["plugins:", "  enabled:", "    - llm-antidote", "  entries:", "    llm-antidote:",
             "      settings:"]
    for key, value in settings.items():
        lines.append(f"        {key}: {value}")
    (home / "config.yaml").write_text("\n".join(lines) + "\n")


def _prepare_home(mode: str) -> Path:
    home = Path(tempfile.mkdtemp(prefix=f"hermes-e2e-{mode}-"))
    plugins_dir = home / "plugins"
    plugins_dir.mkdir()
    (plugins_dir / "llm-antidote").symlink_to(_REPO, target_is_directory=True)
    (home / "empty-bundled").mkdir(parents=True, exist_ok=True)

    settings = {"safe_read_roots": "/work"}
    if mode == "enforced":
        (home / "artifacts").mkdir()
        settings.update(_enforced_settings(home / "artifacts"))
    _write_config(home, settings)
    return home


def _enforced_settings(artifacts: Path) -> dict[str, str]:
    from llm_antidote.fleet_crypto import generate_keypair, sign_document, write_json_document
    from llm_antidote.fleet_policy import default_policy, policy_digest
    from llm_antidote.model_lock import create_lock, write_lock

    private, public, _ = generate_keypair(
        artifacts / "policy-private.pem", artifacts / "policy-public.pem"
    )
    policy = default_policy("e2e")
    policy["runtime"]["mode"] = "balanced"
    policy_path = artifacts / "fleet-policy.json"
    write_json_document(policy, policy_path)
    write_json_document(sign_document(policy, private), artifacts / "fleet-policy.sig.json")

    model = artifacts / "model"
    model.mkdir()
    (model / "model.safetensors").write_bytes(b"weights-v1")
    (model / "config.json").write_bytes(b"{}")
    lock_path = artifacts / "model-lock.json"
    write_lock(create_lock(model), lock_path)
    return {
        "admission_enforcement": "enforced",
        "admission_policy_path": str(policy_path),
        "admission_policy_signature_path": str(artifacts / "fleet-policy.sig.json"),
        "admission_policy_public_key": str(public),
        "admission_trusted_policy_sha256": policy_digest(policy),
        "admission_model_lock_path": str(lock_path),
        "admission_model_source": str(model),
        "admission_model_name": "e2e-model",
    }


class _Checker:
    def __init__(self) -> None:
        self.failures: list[str] = []

    def eq(self, label: str, actual: object, expected: object) -> None:
        status = "ok" if actual == expected else "FAIL"
        print(f"[{status}] {label}: {actual!r} (expected {expected!r})")
        if actual != expected:
            self.failures.append(label)


def _directive(plugins, name, args, *, session="s1", call="c1", task="t1"):
    return plugins._get_pre_tool_call_directive_details(
        name, args, task_id=task, session_id=session, tool_call_id=call
    )


def run_standalone(plugins, check: _Checker) -> None:
    check.eq("hook registered", plugins.has_hook("pre_tool_call"), True)

    allowed = _directive(plugins, "read_file", {"path": "/work/src/app.py"})
    check.eq("safe-root read", allowed.action, None)

    read = _directive(plugins, "read_file", {"path": "/etc/hosts"}, session="s2", call="r1")
    check.eq("unlisted read approved", read.action, "approve")
    check.eq("read rule key", str(getattr(read, "rule_key", "")).startswith("llm-antidote:"), True)

    pending = _directive(plugins, "web_extract", {"url": "https://example.com"}, session="s2",
                         call="e1")
    check.eq("outbound blocked while read pending", pending.action, "block")

    plugins.invoke_hook(
        "post_tool_call", tool_name="read_file", args={"path": "/etc/hosts"}, result=None,
        status="error", error_type="denied", session_id="s2", task_id="t2", tool_call_id="r1",
    )
    released = _directive(plugins, "web_extract", {"url": "https://example.com"}, session="s2",
                          call="e2")
    check.eq("denied approval releases pending", released.action, None)

    plugins.invoke_hook(
        "post_tool_call", tool_name="read_file", args={"path": "/work/.env"},
        result='{"content":"not retained"}', status="success", session_id="s3", task_id="t3",
        tool_call_id="r2",
    )
    tainted = _directive(plugins, "web_search", {"query": "x"}, session="s3", call="w1")
    check.eq("tainted session blocks egress", tainted.action, "block")

    connector = _directive(plugins, "connectors__gmail__send_email",
                           {"to": "x@example.invalid"}, session="s4", call="m1")
    check.eq("connector requires approval", connector.action, "approve")

    unknown = _directive(plugins, "mcp__filesystem__write", {"path": "/tmp/x"}, session="s5",
                         call="u1")
    check.eq("unknown plugin tool requires approval", unknown.action, "approve")

    persist = _directive(plugins, "memory", {"key": "k", "value": "v"}, session="s6", call="p1")
    check.eq("persist tool requires approval", persist.action, "approve")


def run_enforced(plugins, check: _Checker) -> None:
    check.eq("hook registered", plugins.has_hook("pre_tool_call"), True)

    unobserved = _directive(plugins, "read_file", {"path": "/work/x"}, session="s1", call="c1")
    check.eq("route unobserved fails closed", unobserved.action, "block")

    plugins.invoke_hook(
        "pre_api_request", provider="local", model="e2e-model",
        base_url="http://127.0.0.1:8000/v1",
    )
    admitted = _directive(plugins, "read_file", {"path": "/work/x"}, session="s1", call="c2")
    check.eq("admitted route allows safe read", admitted.action, None)

    plugins.invoke_hook(
        "pre_api_request", provider="local", model="evil-model",
        base_url="http://127.0.0.1:8000/v1",
    )
    swapped = _directive(plugins, "read_file", {"path": "/work/x"}, session="s1", call="c3")
    check.eq("route swap blocks tools", swapped.action, "block")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["standalone", "enforced"], default="standalone")
    args = parser.parse_args()

    home = _prepare_home(args.mode)
    os.environ["HERMES_HOME"] = str(home)
    os.environ["HERMES_BUNDLED_PLUGINS"] = str(home / "empty-bundled")

    from hermes_cli import plugins

    plugins.get_plugin_manager().discover_and_load(force=True)

    check = _Checker()
    if args.mode == "standalone":
        run_standalone(plugins, check)
    else:
        run_enforced(plugins, check)

    if check.failures:
        print(f"\n{len(check.failures)} expectation(s) failed: {check.failures}")
        return 1
    print("\nall Hermes e2e expectations passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
