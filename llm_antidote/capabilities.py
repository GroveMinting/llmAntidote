"""Versioned, centralized classification of Hermes tools by side-effect capability.

The classifier deliberately reasons about what a tool *can* do, not only what its
arguments contain. A connector that sends mail is outbound even when no argument
contains an ``http`` token, and a shell tool can read arbitrary files and open
sockets regardless of the command text. Unknown plugin tools are treated as
potentially outbound so they cannot silently acquire unrestricted egress.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

CAPABILITY_CLASSIFIER_VERSION = "1"


class ToolCapability(StrEnum):
    LOCAL_READ = "local_read"
    LOCAL_WRITE = "local_write"
    SHELL_EXEC = "shell_exec"
    OUTBOUND_NETWORK = "outbound_network"
    OUTBOUND_MESSAGE = "outbound_message"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ToolProfile:
    """Static capability profile for one tool name."""

    name: str
    capability: ToolCapability
    read_only: bool
    outbound: bool
    executes: bool
    plugin_defined: bool

    @property
    def requires_egress_approval(self) -> bool:
        """True when the capability itself warrants approval regardless of arguments."""
        return self.capability in {
            ToolCapability.OUTBOUND_MESSAGE,
            ToolCapability.UNKNOWN,
        }


_ALWAYS_SAFE = frozenset({"clarify", "skills_list", "skill_view", "todo_read", "todo_write"})

_EXACT: dict[str, ToolProfile] = {
    "read_file": ToolProfile(
        "read_file", ToolCapability.LOCAL_READ, True, False, False, False
    ),
    "search_files": ToolProfile(
        "search_files", ToolCapability.LOCAL_READ, True, False, False, False
    ),
    "list_files": ToolProfile(
        "list_files", ToolCapability.LOCAL_READ, True, False, False, False
    ),
    "write_file": ToolProfile(
        "write_file", ToolCapability.LOCAL_WRITE, False, False, False, False
    ),
    "patch": ToolProfile("patch", ToolCapability.LOCAL_WRITE, False, False, False, False),
    "apply_patch": ToolProfile(
        "apply_patch", ToolCapability.LOCAL_WRITE, False, False, False, False
    ),
    "terminal": ToolProfile(
        "terminal", ToolCapability.SHELL_EXEC, False, True, True, False
    ),
    "execute_code": ToolProfile(
        "execute_code", ToolCapability.SHELL_EXEC, False, True, True, False
    ),
    "http_request": ToolProfile(
        "http_request", ToolCapability.OUTBOUND_NETWORK, False, True, False, False
    ),
}

_MESSAGE_ACTION_TOKENS = (
    "send",
    "email",
    "message",
    "upload",
    "publish",
    "post",
    "reply",
    "forward",
    "share",
    "notify",
    "webhook",
    "tweet",
    "comment",
    "invite",
)


def _unknown(name: str, *, plugin_defined: bool) -> ToolProfile:
    return ToolProfile(name, ToolCapability.UNKNOWN, False, True, False, plugin_defined)


def classify_tool(tool_name: str) -> ToolProfile:
    """Return the static capability profile for a tool name.

    Classification is name-based and intentionally conservative. It never
    inspects tool arguments, result content, or implementation internals.
    """
    clean = (tool_name or "").lower().strip()
    if not clean:
        return ToolProfile("", ToolCapability.UNKNOWN, False, True, False, True)
    if clean in _ALWAYS_SAFE:
        return ToolProfile(clean, ToolCapability.LOCAL_READ, True, False, False, False)
    if clean in _EXACT:
        return _EXACT[clean]
    if clean.startswith(("web_", "browser_", "http_", "fetch_", "download_")):
        return ToolProfile(clean, ToolCapability.OUTBOUND_NETWORK, False, True, False, True)
    if clean.startswith("connectors__"):
        action = clean.rsplit("__", 1)[-1]
        if any(token in action for token in _MESSAGE_ACTION_TOKENS):
            return ToolProfile(clean, ToolCapability.OUTBOUND_MESSAGE, False, True, False, True)
        return _unknown(clean, plugin_defined=True)
    if clean.startswith("mcp__"):
        return _unknown(clean, plugin_defined=True)
    return _unknown(clean, plugin_defined=True)


def is_taint_safe_tool(tool_name: str) -> bool:
    """True when a tool may run in a tainted or pending session without egress risk."""
    return classify_tool(tool_name).read_only
