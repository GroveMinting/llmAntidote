"""Versioned, centralized classification of Hermes tools by side-effect capability.

The classifier deliberately reasons about what a tool *can* do, not only what its
arguments contain. A connector that sends mail is outbound even when no argument
contains an ``http`` token, a shell tool can read arbitrary files and open sockets
regardless of the command text, and a persistence tool (memory, skills, scheduled
jobs) can leave durable side effects a backdoor later relies on. Unknown plugin
tools are treated as potentially outbound so they cannot silently acquire egress.

This module is the single source of truth for tool names and families; keep the
maintained inventory in ``tests/data/hermes_tool_inventory.json`` in sync and let
the inventory test flag drift when Hermes adds tools.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

CAPABILITY_CLASSIFIER_VERSION = "3"


class ToolCapability(StrEnum):
    LOCAL_READ = "local_read"
    LOCAL_WRITE = "local_write"
    PERSIST = "persist"
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
    persists: bool
    plugin_defined: bool

    @property
    def requires_egress_approval(self) -> bool:
        """True when the capability itself warrants approval regardless of arguments."""
        return self.capability in {
            ToolCapability.OUTBOUND_MESSAGE,
            ToolCapability.UNKNOWN,
        }

    @property
    def requires_persist_approval(self) -> bool:
        """True when the tool leaves durable state a backdoor could rely on."""
        return self.capability is ToolCapability.PERSIST


def _profile(name: str, capability: ToolCapability, *, plugin_defined: bool = False) -> ToolProfile:
    return ToolProfile(
        name=name,
        capability=capability,
        read_only=capability is ToolCapability.LOCAL_READ,
        outbound=capability
        in {
            ToolCapability.OUTBOUND_NETWORK,
            ToolCapability.OUTBOUND_MESSAGE,
            ToolCapability.SHELL_EXEC,
            ToolCapability.UNKNOWN,
        },
        executes=capability is ToolCapability.SHELL_EXEC,
        persists=capability is ToolCapability.PERSIST,
        plugin_defined=plugin_defined,
    )


# Read-only tools. `clarify`/`show_tip` only surface text; the search/describe
# bridge tools read a catalog; the desktop previews render, they do not drive I/O.
_READ_ONLY: frozenset[str] = frozenset(
    {
        "read_file",
        "search_files",
        "list_files",
        "session_search",
        "skills_list",
        "skill_view",
        "read_terminal",
        "read_window_below",
        "todo_list",
        "clarify",
        "show_tip",
        "tool_search",
        "tool_describe",
        "desktop_preview",
        "drive_preview",
        "annotate_preview",
    }
)

# Local writes that touch disk but are not the durable persistence a backdoor wants.
_LOCAL_WRITE: frozenset[str] = frozenset(
    {
        "write_file",
        "patch",
        "apply_patch",
        "desktop_project",
    }
)

# Durable side effects: agent memory, executable skills, scheduled jobs.
_PERSIST: frozenset[str] = frozenset(
    {
        "memory",
        "skill_manage",
        "cronjob_manage",
    }
)

# Tools that execute arbitrary code/commands or drive the machine, and can thus
# read anything and open sockets. Browser automation is egress-capable too.
_SHELL_EXEC: frozenset[str] = frozenset(
    {
        "terminal",
        "execute_code",
        "computer_use",
        "process_manage",
        "delegate_task",
        "gui_tour",
        "apply_layout",
        "focus_pane",
        "close_terminal",
    }
)

_OUTBOUND_NETWORK: frozenset[str] = frozenset(
    {
        "web_search",
        "web_extract",
        "vision_analyze",
        "video_analyze",
        "browser_exec",
        # TTS sends the spoken text to a provider. The built-in providers
        # (edge/elevenlabs/openai/minimax/xai/mistral/gemini) are remote; only a
        # user-configured `command` provider is local. Treated as egress
        # conservatively so it is scanned and taint-blocked like other network tools.
        "text_to_speech",
    }
)

_EXACT: dict[str, ToolProfile] = {
    **{name: _profile(name, ToolCapability.LOCAL_READ) for name in _READ_ONLY},
    **{name: _profile(name, ToolCapability.LOCAL_WRITE) for name in _LOCAL_WRITE},
    **{name: _profile(name, ToolCapability.PERSIST) for name in _PERSIST},
    **{name: _profile(name, ToolCapability.SHELL_EXEC) for name in _SHELL_EXEC},
    **{name: _profile(name, ToolCapability.OUTBOUND_NETWORK) for name in _OUTBOUND_NETWORK},
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

_EGRESS_PREFIXES = ("web_", "browser_vault_", "http_", "fetch_", "download_")


def _unknown(name: str, *, plugin_defined: bool) -> ToolProfile:
    return _profile(name, ToolCapability.UNKNOWN, plugin_defined=plugin_defined)


def classify_tool(tool_name: str) -> ToolProfile:
    """Return the static capability profile for a tool name.

    Classification is name-based and intentionally conservative. It never
    inspects tool arguments, result content, or implementation internals.
    """
    clean = (tool_name or "").lower().strip()
    if not clean:
        return _profile("", ToolCapability.UNKNOWN, plugin_defined=True)
    if clean in _EXACT:
        return _EXACT[clean]
    if clean.startswith("connectors__"):
        action = clean.rsplit("__", 1)[-1]
        if any(token in action for token in _MESSAGE_ACTION_TOKENS):
            return _profile(clean, ToolCapability.OUTBOUND_MESSAGE, plugin_defined=True)
        return _unknown(clean, plugin_defined=True)
    if clean.startswith("mcp__"):
        return _unknown(clean, plugin_defined=True)
    if clean.startswith(_EGRESS_PREFIXES):
        return _profile(clean, ToolCapability.OUTBOUND_NETWORK, plugin_defined=True)
    return _unknown(clean, plugin_defined=True)


def is_taint_safe_tool(tool_name: str) -> bool:
    """True when a tool may run in a tainted or pending session without egress risk."""
    return classify_tool(tool_name).read_only


def tool_family(tool_name: str) -> str:
    """Coarse family label for metadata-only audit records (never the raw name)."""
    clean = (tool_name or "").lower().strip()
    if clean.startswith("connectors__"):
        return "connector"
    if clean.startswith("mcp__"):
        return "mcp"
    if clean.startswith("browser_"):
        return "browser"
    if clean.startswith(("web_", "http_", "fetch_", "download_")):
        return "web"
    profile = classify_tool(clean)
    if profile.capability is ToolCapability.UNKNOWN:
        return "plugin_or_unknown"
    return profile.capability.value
