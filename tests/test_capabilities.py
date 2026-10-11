import json
from pathlib import Path

from llm_antidote.audit import MetadataAudit
from llm_antidote.capabilities import (
    CAPABILITY_CLASSIFIER_VERSION,
    ToolCapability,
    classify_tool,
    tool_family,
)
from llm_antidote.policy import PolicyEngine

_INVENTORY = json.loads(
    (Path(__file__).parent / "data" / "hermes_tool_inventory.json").read_text()
)


def test_inventory_tools_are_classified_or_explicitly_unknown():
    intentionally_unknown = set(_INVENTORY["intentionally_unknown"])
    unclassified = [
        name
        for name in _INVENTORY["tools"]
        if name not in intentionally_unknown
        and classify_tool(name).capability is ToolCapability.UNKNOWN
    ]
    assert unclassified == [], f"unclassified Hermes tools: {unclassified}"


def test_classifier_version_is_bumped():
    assert CAPABILITY_CLASSIFIER_VERSION == "2"


def test_real_tool_surface_capabilities():
    cases = {
        "read_file": ToolCapability.LOCAL_READ,
        "session_search": ToolCapability.LOCAL_READ,
        "todo_list": ToolCapability.LOCAL_READ,
        "write_file": ToolCapability.LOCAL_WRITE,
        "text_to_speech": ToolCapability.LOCAL_WRITE,
        "memory": ToolCapability.PERSIST,
        "skill_manage": ToolCapability.PERSIST,
        "cronjob_manage": ToolCapability.PERSIST,
        "terminal": ToolCapability.SHELL_EXEC,
        "computer_use": ToolCapability.SHELL_EXEC,
        "process_manage": ToolCapability.SHELL_EXEC,
        "delegate_task": ToolCapability.SHELL_EXEC,
        "vision_analyze": ToolCapability.OUTBOUND_NETWORK,
        "browser_exec": ToolCapability.OUTBOUND_NETWORK,
        "browser_vault_fill": ToolCapability.OUTBOUND_NETWORK,
        "tool_call": ToolCapability.UNKNOWN,
    }
    for name, capability in cases.items():
        assert classify_tool(name).capability is capability, name


def test_persist_capability_is_not_marked_outbound():
    profile = classify_tool("memory")
    assert profile.requires_persist_approval is True
    assert profile.requires_egress_approval is False


def test_persist_tool_requires_approval():
    decision = PolicyEngine().assess("memory", {"key": "note", "value": "x"})
    assert decision.action == "approve"
    assert decision.rule_ids == ("persist.durable_write",)


def test_tool_family_is_shared_with_audit():
    assert tool_family("terminal") == "shell_exec"
    assert tool_family("memory") == "persist"
    assert tool_family("web_search") == "web"
    assert tool_family("browser_exec") == "browser"
    assert tool_family("mcp__filesystem__read") == "mcp"
    assert tool_family("connectors__gmail__send_email") == "connector"
    assert tool_family("totally-made-up") == "plugin_or_unknown"
    assert MetadataAudit.tool_identity("terminal")[0] == "shell_exec"
