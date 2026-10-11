import argparse
import json

import pytest

from llm_antidote.commands import run_cli, setup_cli
from llm_antidote.deployment import load_runtime_settings
from llm_antidote.fleet_crypto import (
    generate_keypair,
    sign_document,
    write_json_document,
)
from llm_antidote.fleet_policy import default_policy, policy_digest
from llm_antidote.model_lock import create_lock, write_lock
from llm_antidote.plugin import build_runtime, register


class FakeContext:
    def __init__(self, config=None):
        self.config = config or {}
        self.hooks = {}
        self.commands = {}
        self.cli_commands = {}

    def get_config(self, key, default=None):
        return self.config.get(key, default)

    def register_hook(self, name, callback):
        self.hooks[name] = callback

    def register_command(self, name, handler, **metadata):
        self.commands[name] = (handler, metadata)

    def register_cli_command(self, name, help, fn, handler_fn, description=""):
        self.cli_commands[name] = (help, fn, handler_fn, description)


def enforced_fixture(tmp_path, *, mode="strict", ttl=30):
    private, public, _ = generate_keypair(tmp_path / "policy-private.pem", tmp_path / "policy.pem")
    policy = default_policy("production")
    policy["runtime"]["mode"] = mode
    policy["runtime"]["taint_ttl_minutes"] = ttl
    policy_path = tmp_path / "fleet-policy.json"
    write_json_document(policy, policy_path)
    write_json_document(sign_document(policy, private), tmp_path / "fleet-policy.sig.json")

    model = tmp_path / "model"
    model.mkdir()
    (model / "model.safetensors").write_bytes(b"weights-v1")
    (model / "config.json").write_bytes(b"{}")
    lock = create_lock(model)
    lock_path = tmp_path / "model-lock.json"
    write_lock(lock, lock_path)

    return {
        "private": private,
        "public": public,
        "policy_path": str(policy_path),
        "signature_path": str(tmp_path / "fleet-policy.sig.json"),
        "trusted": policy_digest(policy),
        "model_dir": str(model),
        "lock_path": str(lock_path),
        "settings": {
            "admission_enforcement": "enforced",
            "admission_policy_path": str(policy_path),
            "admission_policy_signature_path": str(tmp_path / "fleet-policy.sig.json"),
            "admission_policy_public_key": str(public),
            "admission_trusted_policy_sha256": policy_digest(policy),
            "admission_model_lock_path": str(lock_path),
            "admission_model_source": str(model),
            "admission_model_name": "model-a",
            "safe_read_roots": "/work",
        },
    }


def test_enforced_settings_apply_signed_runtime_policy(tmp_path):
    fixture = enforced_fixture(tmp_path)
    resolved = load_runtime_settings(fixture["settings"])
    assert resolved.binding.enforced is True
    assert resolved.binding.verified is True
    assert resolved.policy.mode == "strict"
    assert resolved.taint_ttl_minutes == 30
    assert resolved.binding.model_lock_sha256


def test_enforced_rejects_tampered_signature(tmp_path):
    fixture = enforced_fixture(tmp_path)
    signature_path = tmp_path / "fleet-policy.sig.json"
    signature = json.loads(signature_path.read_text())
    signature["signature"] = "AAAA"
    signature_path.write_text(json.dumps(signature))
    with pytest.raises(ValueError, match="signature"):
        load_runtime_settings(fixture["settings"])


def test_enforced_rejects_wrong_trusted_digest(tmp_path):
    fixture = enforced_fixture(tmp_path)
    settings = dict(fixture["settings"], admission_trusted_policy_sha256="0" * 64)
    with pytest.raises(ValueError, match="trusted digest"):
        load_runtime_settings(settings)


def test_enforced_refuses_conflicting_local_mode(tmp_path):
    fixture = enforced_fixture(tmp_path, mode="strict")
    settings = dict(fixture["settings"], mode="audit")
    with pytest.raises(ValueError, match="conflicts"):
        load_runtime_settings(settings)


def test_enforced_requires_all_admission_settings(tmp_path):
    fixture = enforced_fixture(tmp_path)
    settings = dict(fixture["settings"])
    del settings["admission_policy_public_key"]
    with pytest.raises(ValueError, match="requires settings"):
        load_runtime_settings(settings)


def test_enforced_detects_altered_model_shard(tmp_path):
    fixture = enforced_fixture(tmp_path)
    (tmp_path / "model" / "model.safetensors").write_bytes(b"weights-v2-tampered")
    with pytest.raises(ValueError, match="does not match the admitted lockfile"):
        load_runtime_settings(fixture["settings"])


def test_enforced_detects_unexpected_model_file(tmp_path):
    fixture = enforced_fixture(tmp_path)
    (tmp_path / "model" / "backdoor.bin").write_bytes(b"x")
    with pytest.raises(ValueError, match="does not match"):
        load_runtime_settings(fixture["settings"])


def test_enforced_can_skip_model_binding_explicitly(tmp_path):
    fixture = enforced_fixture(tmp_path)
    settings = dict(fixture["settings"], admission_require_model_binding="false")
    del settings["admission_model_lock_path"]
    del settings["admission_model_source"]
    resolved = load_runtime_settings(settings)
    assert resolved.binding.enforced is True
    assert resolved.binding.verified is False


def test_standalone_settings_remain_unsigned(tmp_path):
    resolved = load_runtime_settings({"mode": "balanced", "taint_ttl_minutes": 15})
    assert resolved.binding.enforced is False
    assert resolved.policy.mode == "balanced"
    assert resolved.taint_ttl_minutes == 15


def test_plugin_register_enforces_admission_and_blocks_route_swap(tmp_path):
    fixture = enforced_fixture(tmp_path)
    ctx = FakeContext(fixture["settings"])
    register(ctx)
    runtime = build_runtime(ctx)
    assert runtime.binding.enforced is True
    assert "enforcement: enforced" in runtime.status_text()
    assert "production" in runtime.status_text()

    pre_api = ctx.hooks["pre_api_request"]
    pre = ctx.hooks["pre_tool_call"]
    pre_api(provider="local", model="model-a", base_url="http://127.0.0.1:8000/v1")
    assert pre(tool_name="read_file", args={"path": "/work/x"}) is None

    pre_api(provider="local", model="evil-model", base_url="http://127.0.0.1:8000/v1")
    blocked = pre(tool_name="read_file", args={"path": "/work/x"})
    assert blocked["action"] == "block"


def test_enforced_mode_strict_blocks_outbound_connector(tmp_path):
    fixture = enforced_fixture(tmp_path, mode="strict")
    ctx = FakeContext(fixture["settings"])
    register(ctx)
    result = ctx.hooks["pre_tool_call"](
        tool_name="connectors__gmail__send_email", args={"to": "x@example.invalid"}
    )
    assert result["action"] == "block"


def test_standalone_mode_is_not_labeled_enforced():
    resolved = load_runtime_settings({"mode": "balanced"})
    assert resolved.binding.summary()["enforcement"] == "standalone"
    assert resolved.binding.summary()["verified"] is False
    assert "issued_at" not in resolved.binding.summary()


def test_plugin_register_fails_closed_when_enforcement_invalid(tmp_path):
    fixture = enforced_fixture(tmp_path)
    (tmp_path / "model" / "model.safetensors").write_bytes(b"tampered")
    ctx = FakeContext(fixture["settings"])
    with pytest.raises(ValueError, match="does not match the admitted lockfile"):
        register(ctx)


def test_cli_runtime_verify_passes_then_fails_on_tamper(tmp_path):
    fixture = enforced_fixture(tmp_path)
    settings_file = tmp_path / "settings.json"
    settings_file.write_text(json.dumps(fixture["settings"]))
    parser = argparse.ArgumentParser()
    setup_cli(parser)
    args = parser.parse_args(
        ["fleet", "runtime-verify", "--settings", str(settings_file)]
    )
    assert run_cli(args) == 0
    (tmp_path / "model" / "model.safetensors").write_bytes(b"tampered")
    assert run_cli(args) == 1


def test_enforced_route_binding_fails_closed_before_observation(tmp_path):
    fixture = enforced_fixture(tmp_path)
    ctx = FakeContext(fixture["settings"])
    register(ctx)
    blocked = ctx.hooks["pre_tool_call"](tool_name="read_file", args={"path": "/work/x"})
    assert blocked["action"] == "block"
    assert "has not been verified" in blocked["message"]


def test_enforced_route_binding_fails_closed_on_empty_model(tmp_path):
    fixture = enforced_fixture(tmp_path)
    ctx = FakeContext(fixture["settings"])
    register(ctx)
    ctx.hooks["pre_api_request"](provider="local", model="", base_url="http://127.0.0.1:8000/v1")
    blocked = ctx.hooks["pre_tool_call"](tool_name="read_file", args={"path": "/work/x"})
    assert blocked["action"] == "block"
    assert "has not been verified" in blocked["message"]


def test_enforced_route_observation_optional(tmp_path):
    fixture = enforced_fixture(tmp_path)
    settings = dict(fixture["settings"], admission_require_route_observation="false")
    ctx = FakeContext(settings)
    register(ctx)
    assert ctx.hooks["pre_tool_call"](tool_name="read_file", args={"path": "/work/x"}) is None


def test_enforced_route_binding_fails_closed_without_configured_model(tmp_path):
    fixture = enforced_fixture(tmp_path)
    settings = dict(fixture["settings"], admission_model_name="")
    ctx = FakeContext(settings)
    register(ctx)
    runtime = build_runtime(ctx)
    assert runtime.status()["route_admitted"] is False
    assert runtime.status()["route_reason"] == "admission.model_route_unconfigured"
    assert "route reason: admission.model_route_unconfigured" in runtime.status_text()
    blocked = ctx.hooks["pre_tool_call"](tool_name="read_file", args={"path": "/work/x"})
    assert blocked["action"] == "block"
    assert "no admitted model is configured" in blocked["message"]


def test_standalone_resolves_pending_ttl_default(tmp_path):
    resolved = load_runtime_settings({"mode": "balanced"})
    assert resolved.pending_ttl_minutes == 5
