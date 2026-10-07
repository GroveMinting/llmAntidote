"""Deterministic tool-call policy for hostile-model consequence control."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

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

_TAINT_SAFE_TOOLS = {
    "clarify",
    "read_file",
    "search_files",
    "skills_list",
    "skill_view",
    "todo_read",
}
_MAX_POLICY_CHARS = 262_144


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


def sensitive_categories(text: str) -> tuple[str, ...]:
    """Return stable sensitive-source categories found in tool arguments."""
    return tuple(name for name, pattern in _SENSITIVE_PATTERNS if pattern.search(text))


def is_taint_safe_tool(tool_name: str) -> bool:
    return tool_name.lower().strip() in _TAINT_SAFE_TOOLS


@dataclass(frozen=True)
class PolicyConfig:
    mode: Mode = "balanced"

    @classmethod
    def from_value(cls, mode: Any) -> PolicyConfig:
        clean = str(mode or "balanced").lower().strip()
        return cls(mode=clean if clean in {"balanced", "strict", "audit"} else "balanced")


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

    def assess(self, tool_name: str, args: Any, *, session_tainted: bool = False) -> PolicyDecision:
        text, oversized = _argument_text(args)
        sensitive = sensitive_categories(text)
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
        elif sensitive and _NETWORK_SINK.search(text):
            desired = "block"
            rules.extend(f"exfil.{category}" for category in sensitive)
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
        elif _UPLOAD_SINK.search(text):
            desired = "approve"
            rules.append("egress.upload")
            message = "llmAntidote requires approval for an outbound upload-capable operation."

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
