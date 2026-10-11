"""Deterministic tool-call policy for hostile-model consequence control."""

from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass
from typing import Any, Literal, cast

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
_WRITE_PATH_TOOLS = {"write_file", "patch", "apply_patch"}
_CONTENT_KEYS = frozenset(
    {"content", "new_str", "old_str", "new_string", "old_string", "text", "patch", "diff"}
)
_TAINT_SCOPES = {"egress", "egress_persist_shell", "all"}
_DEFAULT_MAX_SCAN_BYTES = 1_048_576
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


def _bounded_scan_bytes(value: Any) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = _DEFAULT_MAX_SCAN_BYTES
    return max(4096, min(parsed, 16 * 1024 * 1024))


def _argument_text(
    args: Any, limit: int, *, exclude_keys: frozenset[str] = frozenset()
) -> tuple[str, bool]:
    """Produce bounded policy input; this value is never persisted or logged.

    Returns the assembled text (at most ``limit`` characters) and whether the
    argument set exceeded ``limit``. When it exceeds the limit the tool call is
    refused rather than scanned, so a pattern hidden mid-payload cannot slip past.
    """
    pieces: list[str] = []
    seen: set[int] = set()
    total = 0
    exceeded = False

    def add(piece: str) -> None:
        nonlocal total, exceeded
        if exceeded:
            return
        remaining = limit - total
        if len(piece) > remaining:
            if remaining > 0:
                pieces.append(piece[:remaining])
            total = limit
            exceeded = True
            return
        pieces.append(piece)
        total += len(piece)

    def visit(value: Any, depth: int = 0) -> None:
        if depth > 20:
            add("<max-depth>")
            return
        if isinstance(value, str):
            add(value)
            return
        if isinstance(value, bytes):
            add(value.decode("utf-8", errors="replace"))
            return
        if isinstance(value, dict):
            identity = id(value)
            if identity in seen:
                add("<cycle>")
                return
            seen.add(identity)
            for key in sorted(value, key=lambda item: str(item)):
                if str(key).lower() in exclude_keys:
                    continue
                add(str(key))
                visit(value[key], depth + 1)
            seen.remove(identity)
            return
        if isinstance(value, (list, tuple, set, frozenset)):
            identity = id(value)
            if identity in seen:
                add("<cycle>")
                return
            seen.add(identity)
            for item in value:
                visit(item, depth + 1)
            seen.remove(identity)
            return
        add(repr(value))

    visit(args)
    return "\n".join(pieces), exceeded


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


def classify_write_paths(
    paths: tuple[str, ...],
    *,
    sensitive_roots: tuple[str, ...],
) -> tuple[str, ...]:
    """Return write-specific categories for local-write tool targets."""
    categories: set[str] = set()
    for raw in paths:
        resolved = _normalize_path(raw)
        if any(_within(resolved, root) for root in sensitive_roots):
            categories.add("sensitive_root_write")
    return tuple(sorted(categories))


@dataclass(frozen=True)
class PolicyConfig:
    mode: Mode = "balanced"
    safe_read_roots: tuple[str, ...] = ()
    sensitive_roots: tuple[str, ...] = ()
    allow_outbound_tools: tuple[str, ...] = ()
    classifier_version: int = 2
    taint_scope: str = "egress_persist_shell"
    max_scan_bytes: int = _DEFAULT_MAX_SCAN_BYTES

    @classmethod
    def from_value(cls, mode: Any) -> PolicyConfig:
        clean = str(mode or "balanced").lower().strip()
        resolved = cast("Mode", clean if clean in {"balanced", "strict", "audit"} else "balanced")
        return cls(mode=resolved)

    @classmethod
    def from_settings(cls, settings: dict[str, Any] | None) -> PolicyConfig:
        settings = settings or {}
        config = cls.from_value(settings.get("mode", "balanced"))
        safe_roots = _string_tuple(settings.get("safe_read_roots")) or _default_safe_roots()
        scope = str(settings.get("taint_scope", "egress_persist_shell")).lower().strip()
        return cls(
            mode=config.mode,
            safe_read_roots=safe_roots,
            sensitive_roots=_string_tuple(settings.get("sensitive_roots")),
            allow_outbound_tools=_string_tuple(settings.get("allow_outbound_tools")),
            taint_scope=scope if scope in _TAINT_SCOPES else "egress_persist_shell",
            max_scan_bytes=_bounded_scan_bytes(settings.get("max_scan_bytes")),
        )


def _taint_blocks(profile: Any, scope: str) -> bool:
    """Whether a tainted session should block a tool of this capability."""
    if scope == "all":
        return not profile.read_only
    if scope == "egress":
        return profile.outbound
    return profile.outbound or profile.persists or profile.executes


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
        profile = classify_tool(tool_name)
        limit = self.config.max_scan_bytes
        is_write = profile.capability is ToolCapability.LOCAL_WRITE or (
            tool_name.lower().strip() in _WRITE_PATH_TOOLS
        )
        if is_write:
            scan_text, oversized = _argument_text(args, limit, exclude_keys=_CONTENT_KEYS)
            known = sensitive_categories(scan_text)
            write_categories = classify_write_paths(
                extract_read_paths(args), sensitive_roots=self.config.sensitive_roots
            )
            sensitive = tuple(sorted({*known, *write_categories}))
        else:
            scan_text, oversized = _argument_text(args, limit)
            known = sensitive_categories(scan_text)
            sensitive = self._read_categories(tool_name, args, known)
        allow_listed = profile.name in self.config.allow_outbound_tools
        rules: list[str] = []
        desired: Action = "allow"
        message = ""

        if any(pattern.search(scan_text) for pattern in _REVERSE_SHELL):
            desired = "block"
            rules.append("execution.reverse_shell")
            message = "llmAntidote blocked a recognizable reverse-shell pattern."
        elif any(pattern.search(scan_text) for pattern in _DOWNLOAD_EXECUTE):
            desired = "block"
            rules.append("execution.remote_payload")
            message = "llmAntidote blocked a recognizable download-and-execute chain."
        elif known and _NETWORK_SINK.search(scan_text):
            desired = "block"
            rules.extend(f"exfil.{category}" for category in known)
            message = "llmAntidote blocked a tool call combining sensitive access with egress."
        elif session_tainted and _taint_blocks(profile, self.config.taint_scope):
            desired = "block"
            rules.append("exfil.tainted_session_egress")
            message = (
                "llmAntidote blocked an egress-capable tool after a sensitive read in this session."
            )
        elif oversized:
            desired = "block"
            rules.append("input.arguments_exceed_scan_limit")
            sensitive = tuple(sorted((*sensitive, "oversized_arguments")))
            message = "llmAntidote blocked a tool call whose arguments exceed the scan limit."
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
        elif profile.requires_persist_approval:
            desired = "approve"
            rules.append("persist.durable_write")
            message = (
                "llmAntidote requires approval for a tool with durable persistence or "
                "scheduling capability."
            )
        elif _UPLOAD_SINK.search(scan_text):
            desired = "approve"
            rules.append("egress.upload")
            message = "llmAntidote requires approval for an outbound upload-capable operation."
        elif (
            tool_name.lower().strip() in _NETWORK_CAPABLE_TOOLS
            and _NETWORK_SINK.search(scan_text)
        ):
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
