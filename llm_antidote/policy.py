"""Deterministic tool-call policy for hostile-model consequence control."""

from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass
from typing import Any, Literal

from .capabilities import ToolCapability, classify_tool, is_taint_safe_tool

Action = Literal["allow", "approve", "block"]
Mode = Literal["balanced", "strict", "audit"]

_SENSITIVE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "environment_secret",
        re.compile(
            r"(?ix)(?:^|[/\\\s'\"])(?:\.env(?:\.(?!example\b)[a-z0-9_-]+)?|\.envrc)"
            r"(?:$|[/\\\s'\";&|)}\]])|/proc/(?:self|\d+)/environ\b|\bprintenv\b|"
            r"(?:^|[\s;&|])(?:\S*/)?env\b|"
            r"\b(?:export\s+-p|declare\s+-x)\b"
        ),
    ),
    (
        "credential_file",
        re.compile(
            r"(?ix)(?:^|[/\\\s'\"])(?:\.ssh|\.aws|\.kube|\.gnupg|\.docker|"
            r"\.config/gcloud|\.azure)(?:[/\\\s'\"]|$)|(?:^|[/\\])\.netrc\b"
        ),
    ),
    (
        "auth_material",
        re.compile(
            r"(?ix)(?:^|[/\\\s'\"])(?:id_rsa|id_ed25519|id_ecdsa|credentials\.json|"
            r"service[_-]?account[^/\\\s]*\.json|auth\.json|\.credentials\.json|"
            r"private[_-]?key)(?:$|[/\\\s'\";&|])"
        ),
    ),
)

_NETWORK_SINK = re.compile(
    r"(?is)\b(?:curl|wget|http|https|xh|nc|ncat|netcat|socat|scp|sftp|rsync|ftp)\b|"
    r"\b(?:requests|httpx)\s*\.\s*(?:post|put|patch)\s*\(|"
    r"\burllib\.request\.(?:urlopen|Request)\s*\(|"
    r"\bfetch\s*\(|\bXMLHttpRequest\b"
)

_UPLOAD_SINK = re.compile(
    r"(?is)\bcurl\b[^\n]{0,1200}(?:\s(?:-d|--data(?:-[a-z]+)?|-F|--form|-T|--upload-file)\b|"
    r"-X\s*(?:POST|PUT|PATCH)\b)|"
    r"\bwget\b[^\n]{0,1200}(?:--post-(?:data|file)|--method\s*=?(?:POST|PUT|PATCH))|"
    r"\b(?:nc|ncat|netcat|socat|scp|sftp|rsync|ftp)\b|"
    r"\b(?:requests|httpx)\s*\.\s*(?:post|put|patch)\s*\("
)

_DOWNLOAD_EXECUTE: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?is)\b(?:curl|wget)\b.{0,1500}\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b"),
    re.compile(r"(?is)\b(?:ba|z|k)?sh\s*<\(\s*(?:curl|wget)\b"),
    re.compile(
        r"(?is)\b(?:curl|wget)\b.{0,1500}(?:&&|;)\s*(?:sudo\s+)?"
        r"(?:sh|bash|zsh|python(?:3)?|perl|ruby|node)\s+(?:/tmp|/var/tmp|\$TMPDIR)"
    ),
    re.compile(r"(?is)\bbase64\b.{0,800}(?:--decode|-d)\s*\|\s*(?:ba|z|k)?sh\b"),
)

_REVERSE_SHELL: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?is)/dev/(?:tcp|udp)/[^\s/]+/\d+"),
    re.compile(r"(?is)\b(?:nc|ncat|netcat)\b.{0,500}\s-e\s*(?:/bin/)?(?:ba)?sh\b"),
    re.compile(r"(?is)\b(?:bash|sh)\s+-i\s+>&?\s*/dev/(?:tcp|udp)/"),
    re.compile(r"(?is)\bsocat\b.{0,500}\bexec:(?:ba)?sh\b"),
)

_NETWORK_CAPABLE_TOOLS = {"execute_code", "http_request", "terminal"}
_FILESYSTEM_READ_TOOLS = {"read_file", "list_files", "search_files"}
_READ_PATH_KEYS = {
    "path",
    "paths",
    "file",
    "files",
    "file_path",
    "filepath",
    "filename",
    "source",
    "target",
    "directory",
    "dir",
    "dirs",
    "root",
}
_MAX_POLICY_CHARS = 262_144


def _string_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        items = value.split(",")
    elif isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
    else:
        return ()
    return tuple(dict.fromkeys(item.strip() for item in items if str(item).strip()))


def _default_safe_roots() -> tuple[str, ...]:
    return tuple(dict.fromkeys((os.getcwd(), tempfile.gettempdir())))


def _argument_text(args: Any) -> tuple[str, bool]:
    """Produce bounded policy input; this value is never persisted or logged."""
    pieces: list[str] = []
    seen: set[int] = set()

    def visit(value: Any, depth: int = 0) -> None:
        if depth > 20:
            pieces.append("<max-depth>")
            return
        if isinstance(value, str):
            pieces.append(value)
            return
        if isinstance(value, bytes):
            pieces.append(value.decode("utf-8", errors="replace"))
            return
        if isinstance(value, dict):
            identity = id(value)
            if identity in seen:
                pieces.append("<cycle>")
                return
            seen.add(identity)
            for key in sorted(value, key=lambda item: str(item)):
                pieces.append(str(key))
                visit(value[key], depth + 1)
            seen.remove(identity)
            return
        if isinstance(value, (list, tuple, set, frozenset)):
            identity = id(value)
            if identity in seen:
                pieces.append("<cycle>")
                return
            seen.add(identity)
            for item in value:
                visit(item, depth + 1)
            seen.remove(identity)
            return
        pieces.append(repr(value))

    visit(args)
    value = "\n".join(pieces)
    if len(value) <= _MAX_POLICY_CHARS:
        return value, False
    half = _MAX_POLICY_CHARS // 2
    return value[:half] + value[-half:], True


def extract_read_paths(args: Any) -> tuple[str, ...]:
    """Collect candidate filesystem paths from read-tool arguments."""
    found: list[str] = []
    seen: set[int] = set()

    def visit(value: Any, depth: int = 0) -> None:
        if depth > 10:
            return
        if isinstance(value, dict):
            identity = id(value)
            if identity in seen:
                return
            seen.add(identity)
            for key, item in value.items():
                if str(key).lower() in _READ_PATH_KEYS:
                    if isinstance(item, str):
                        found.append(item)
                    elif isinstance(item, (list, tuple)):
                        found.extend(entry for entry in item if isinstance(entry, str))
                else:
                    visit(item, depth + 1)
            seen.remove(identity)
        elif isinstance(value, (list, tuple)):
            identity = id(value)
            if identity in seen:
                return
            seen.add(identity)
            for item in value:
                visit(item, depth + 1)
            seen.remove(identity)

    visit(args)
    return tuple(dict.fromkeys(path for path in found if path))


def _normalize_path(value: str) -> str:
    try:
        return os.path.realpath(os.path.abspath(os.path.expanduser(value)))
    except (OSError, ValueError):
        return ""


def _within(path: str, root: str) -> bool:
    if not path or not root:
        return False
    normalized_root = _normalize_path(root)
    if not normalized_root:
        return False
    return path == normalized_root or path.startswith(normalized_root + os.sep)


def classify_read_paths(
    paths: tuple[str, ...],
    *,
    safe_roots: tuple[str, ...],
    sensitive_roots: tuple[str, ...],
) -> tuple[str, ...]:
    """Return path-based access categories for a set of read targets."""
    categories: set[str] = set()
    if not paths:
        categories.add("unclassified_read")
        return tuple(sorted(categories))
    for raw in paths:
        resolved = _normalize_path(raw)
        if any(_within(resolved, root) for root in sensitive_roots):
            categories.add("sensitive_root_read")
        elif any(_within(resolved, root) for root in safe_roots):
            continue
        else:
            categories.add("read_outside_safe_root")
    return tuple(sorted(categories))


def sensitive_categories(text: str) -> tuple[str, ...]:
    """Return stable sensitive-source categories found in tool arguments."""
    return tuple(name for name, pattern in _SENSITIVE_PATTERNS if pattern.search(text))


@dataclass(frozen=True)
class PolicyConfig:
    mode: Mode = "balanced"
    safe_read_roots: tuple[str, ...] = ()
    sensitive_roots: tuple[str, ...] = ()
    allow_outbound_tools: tuple[str, ...] = ()
    classifier_version: int = 1

    @classmethod
    def from_value(cls, mode: Any) -> PolicyConfig:
        clean = str(mode or "balanced").lower().strip()
        return cls(mode=clean if clean in {"balanced", "strict", "audit"} else "balanced")

    @classmethod
    def from_settings(cls, settings: dict[str, Any] | None) -> PolicyConfig:
        settings = settings or {}
        config = cls.from_value(settings.get("mode", "balanced"))
        safe_roots = _string_tuple(settings.get("safe_read_roots")) or _default_safe_roots()
        return cls(
            mode=config.mode,
            safe_read_roots=safe_roots,
            sensitive_roots=_string_tuple(settings.get("sensitive_roots")),
            allow_outbound_tools=_string_tuple(settings.get("allow_outbound_tools")),
        )


@dataclass(frozen=True)
class PolicyDecision:
    action: Action
    would_action: Action
    rule_ids: tuple[str, ...] = ()
    sensitive: tuple[str, ...] = ()
    message: str = ""

    @property
    def should_direct(self) -> bool:
        return self.action in {"approve", "block"}


class PolicyEngine:
    """Classify one tool call without executing code or inspecting tool results."""

    def __init__(self, config: PolicyConfig | None = None) -> None:
        self.config = config or PolicyConfig()

    def _read_categories(
        self, tool_name: str, args: Any, known: tuple[str, ...]
    ) -> tuple[str, ...]:
        clean = tool_name.lower().strip()
        if clean not in _FILESYSTEM_READ_TOOLS:
            return known
        path_categories = classify_read_paths(
            extract_read_paths(args),
            safe_roots=self.config.safe_read_roots,
            sensitive_roots=self.config.sensitive_roots,
        )
        return tuple(sorted({*known, *path_categories}))

    def assess(self, tool_name: str, args: Any, *, session_tainted: bool = False) -> PolicyDecision:
        text, oversized = _argument_text(args)
        known = sensitive_categories(text)
        sensitive = self._read_categories(tool_name, args, known)
        profile = classify_tool(tool_name)
        allow_listed = profile.name in self.config.allow_outbound_tools
        rules: list[str] = []
        desired: Action = "allow"
        message = ""

        if any(pattern.search(text) for pattern in _REVERSE_SHELL):
            desired = "block"
            rules.append("execution.reverse_shell")
            message = "llmAntidote blocked a recognizable reverse-shell pattern."
        elif any(pattern.search(text) for pattern in _DOWNLOAD_EXECUTE):
            desired = "block"
            rules.append("execution.remote_payload")
            message = "llmAntidote blocked a recognizable download-and-execute chain."
        elif known and _NETWORK_SINK.search(text):
            desired = "block"
            rules.extend(f"exfil.{category}" for category in known)
            message = "llmAntidote blocked a tool call combining sensitive access with egress."
        elif session_tainted and not is_taint_safe_tool(tool_name):
            desired = "block"
            rules.append("exfil.tainted_session_egress")
            message = (
                "llmAntidote blocked a non-read-only tool after a sensitive read in this session."
            )
        elif oversized:
            desired = "approve"
            rules.append("input.oversized_arguments")
            sensitive = tuple(sorted((*sensitive, "oversized_arguments")))
            message = "llmAntidote requires approval because tool arguments exceed its scan limit."
        elif sensitive:
            desired = "approve"
            rules.extend(f"access.{category}" for category in sensitive)
            message = "llmAntidote requires approval for access to potentially sensitive material."
        elif profile.requires_egress_approval and not allow_listed:
            desired = "approve"
            if profile.capability is ToolCapability.OUTBOUND_MESSAGE:
                rules.append("egress.outbound_message")
                message = (
                    "llmAntidote requires approval for an outbound message or upload capability."
                )
            else:
                rules.append("egress.unknown_plugin_tool")
                message = (
                    "llmAntidote requires approval for an unclassified plugin tool that may "
                    "have outbound capability."
                )
        elif _UPLOAD_SINK.search(text):
            desired = "approve"
            rules.append("egress.upload")
            message = "llmAntidote requires approval for an outbound upload-capable operation."
        elif tool_name.lower().strip() in _NETWORK_CAPABLE_TOOLS and _NETWORK_SINK.search(text):
            desired = "approve"
            rules.append("egress.network_command")
            message = "llmAntidote requires approval for a network-capable operation."

        action = desired
        if self.config.mode == "strict" and desired == "approve":
            action = "block"
            message = (
                "llmAntidote strict mode blocked an operation that normally requires approval."
            )
        elif self.config.mode == "audit" and desired != "allow":
            action = "allow"

        return PolicyDecision(
            action=action,
            would_action=desired,
            rule_ids=tuple(rules),
            sensitive=sensitive,
            message=message,
        )


__all__ = [
    "Action",
    "Mode",
    "PolicyConfig",
    "PolicyDecision",
    "PolicyEngine",
    "classify_read_paths",
    "extract_read_paths",
    "is_taint_safe_tool",
    "sensitive_categories",
]
