"""Minimal OpenAI-compatible client for isolated behavioral evaluations."""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_TOOL_CALLS = 16
MAX_TOOL_ARGUMENT_BYTES = 256 * 1024
MAX_CONTENT_CHARS = 16 * 1024


class EvaluationClientError(RuntimeError):
    """Sanitized endpoint failure safe to include in a local report."""


def resolve_api_key(name: str) -> str:
    """Resolve an API key by environment-variable name through Hermes' secret scope.

    Inside Hermes this reads the credential with ``agent.secret_scope.get_secret``,
    which honours the active profile and fails closed under multiplexing rather
    than leaking another profile's value. Outside Hermes (the standalone
    ``llm-antidote``/CI entry point, where ``agent`` is not importable) it falls
    back to ``os.environ`` for the process-injected credential. If a scoped read
    raises, it returns empty instead of falling through to a bare environment read.
    """
    clean = (name or "").strip()
    if not clean:
        return ""
    try:
        from agent.secret_scope import get_secret
    except Exception:
        return os.environ.get(clean, "")
    try:
        return get_secret(clean) or ""
    except Exception:
        return ""


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: Any
    raw_arguments: str
    parse_error: bool = False

    def as_message_value(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": "function",
            "function": {"name": self.name, "arguments": self.raw_arguments},
        }


@dataclass(frozen=True)
class Completion:
    content: str
    tool_calls: tuple[ToolCall, ...]
    finish_reason: str


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Any,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


def _is_loopback(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _is_trusted(hostname: str, host_port: str, trusted_hosts: tuple[str, ...]) -> bool:
    clean_host = hostname.lower().strip()
    clean_host_port = host_port.lower().strip()
    for host in trusted_hosts:
        candidate = host.lower().strip()
        if candidate and candidate in (clean_host, clean_host_port):
            return True
    return False


def normalize_endpoint(
    endpoint: str, *, trusted_hosts: tuple[str, ...] = ()
) -> tuple[str, str]:
    raw = endpoint.strip().rstrip("/")
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Evaluation endpoint must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Evaluation endpoint must not contain credentials, query, or fragment")
    display_host = parsed.hostname
    if parsed.port:
        display_host = f"{display_host}:{parsed.port}"
    if (
        parsed.scheme == "http"
        and not _is_loopback(parsed.hostname)
        and not _is_trusted(parsed.hostname, display_host, trusted_hosts)
    ):
        raise ValueError(
            "Plain HTTP evaluation endpoints are restricted to loopback hosts. "
            "Tunnel a remote endpoint (ssh -N -L 8000:127.0.0.1:8000 HOST) or pass "
            "--trusted-host HOST to opt in, accepting that prompts and credentials travel "
            "in cleartext."
        )
    path = parsed.path.rstrip("/")
    if path.endswith("/chat/completions"):
        request_path = path
    else:
        request_path = f"{path}/chat/completions" if path else "/v1/chat/completions"
    request_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, request_path, "", ""))
    return request_url, display_host


class OpenAICompatClient:
    def __init__(
        self,
        endpoint: str,
        *,
        api_key_env: str = "",
        timeout: float = 60.0,
        trusted_hosts: tuple[str, ...] = (),
        opener: Callable[..., Any] | None = None,
    ) -> None:
        self.request_url, self.endpoint_display = normalize_endpoint(
            endpoint, trusted_hosts=trusted_hosts
        )
        self.timeout = max(1.0, min(float(timeout), 600.0))
        self.api_key_env = api_key_env.strip()
        if self.api_key_env and not self.api_key_env.replace("_", "").isalnum():
            raise ValueError("API key environment variable name is invalid")
        if opener is not None:
            self._opener = opener
        else:
            hostname = urllib.parse.urlsplit(self.request_url).hostname or ""
            handlers: list[Any] = [_NoRedirect()]
            if _is_loopback(hostname):
                handlers.insert(0, urllib.request.ProxyHandler({}))
            self._opener = urllib.request.build_opener(*handlers).open

    def complete(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        temperature: float,
        seed: int,
    ) -> Completion:
        try:
            body = json.dumps(
                {
                    "model": model,
                    "messages": messages,
                    "tools": tools,
                    "tool_choice": "auto",
                    "temperature": temperature,
                    "seed": seed,
                    "max_tokens": 512,
                },
                separators=(",", ":"),
            ).encode()
        except (TypeError, ValueError, RecursionError) as exc:
            raise EvaluationClientError("Evaluation request could not be serialized") from exc
        if len(body) > MAX_REQUEST_BYTES:
            raise EvaluationClientError("Evaluation request exceeded the size limit")
        headers = {"Content-Type": "application/json", "User-Agent": "llmAntidote/3.2.3"}
        if self.api_key_env:
            value = resolve_api_key(self.api_key_env)
            if not value:
                raise EvaluationClientError(
                    f"Required API key environment variable is not set: {self.api_key_env}"
                )
            headers["Authorization"] = f"Bearer {value}"
        request = urllib.request.Request(  # noqa: S310 - scheme is restricted above
            self.request_url, data=body, headers=headers, method="POST"
        )
        try:
            response = self._opener(request, timeout=self.timeout)
            try:
                payload = response.read(MAX_RESPONSE_BYTES + 1)
            finally:
                close = getattr(response, "close", None)
                if callable(close):
                    close()
        except urllib.error.HTTPError as exc:
            raise EvaluationClientError(f"Endpoint returned HTTP {exc.code}") from exc
        except http.client.HTTPException as exc:
            raise EvaluationClientError("Endpoint returned a malformed HTTP response") from exc
        except (OSError, urllib.error.URLError) as exc:
            raise EvaluationClientError(f"Endpoint request failed: {type(exc).__name__}") from exc
        if len(payload) > MAX_RESPONSE_BYTES:
            raise EvaluationClientError("Endpoint response exceeded the size limit")
        try:
            value = json.loads(payload)
            if not isinstance(value, dict):
                raise TypeError("response is not an object")
            choices = value["choices"]
            if not isinstance(choices, list) or not choices:
                raise TypeError("choices is not a non-empty list")
            choice = choices[0]
            if not isinstance(choice, dict):
                raise TypeError("choice is not an object")
            message = choice["message"]
            if not isinstance(message, dict):
                raise TypeError("message is not an object")
        except (
            KeyError,
            IndexError,
            TypeError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            RecursionError,
        ) as exc:
            raise EvaluationClientError("Endpoint returned an invalid chat completion") from exc
        finish_reason = str(choice.get("finish_reason") or "")
        tool_calls = _parse_tool_calls(message)
        if finish_reason == "tool_calls" and not tool_calls:
            raise EvaluationClientError("Endpoint declared tool calls without valid tool data")
        return Completion(
            content=str(message.get("content") or "")[:MAX_CONTENT_CHARS],
            tool_calls=tool_calls,
            finish_reason=finish_reason,
        )


def _parse_tool_calls(message: dict[str, Any]) -> tuple[ToolCall, ...]:
    raw_calls = message.get("tool_calls")
    if raw_calls is None and isinstance(message.get("function_call"), dict):
        raw_calls = [{"id": "legacy-function-call", "function": message["function_call"]}]
    if raw_calls is None:
        return ()
    if not isinstance(raw_calls, list):
        raise EvaluationClientError("Endpoint returned malformed tool call data")
    if len(raw_calls) > MAX_TOOL_CALLS:
        raise EvaluationClientError(f"Endpoint returned more than {MAX_TOOL_CALLS} tool calls")
    calls: list[ToolCall] = []
    for index, raw in enumerate(raw_calls):
        if not isinstance(raw, dict) or not isinstance(raw.get("function"), dict):
            raise EvaluationClientError("Endpoint returned a malformed tool call")
        function = raw["function"]
        name = str(function.get("name") or "")
        if not name:
            raise EvaluationClientError("Endpoint returned a tool call without a name")
        raw_arguments = function.get("arguments", "{}")
        if not isinstance(raw_arguments, str):
            raise EvaluationClientError("Endpoint returned non-string tool arguments")
        if len(raw_arguments.encode("utf-8", errors="replace")) > MAX_TOOL_ARGUMENT_BYTES:
            raise EvaluationClientError("Endpoint tool arguments exceeded the size limit")
        parse_error = False
        try:
            arguments = json.loads(raw_arguments)
        except (TypeError, json.JSONDecodeError, RecursionError):
            arguments = {"_raw": raw_arguments}
            parse_error = True
        if not parse_error and not isinstance(arguments, dict):
            arguments = {"_raw": raw_arguments}
            parse_error = True
        calls.append(
            ToolCall(
                id=str(raw.get("id") or f"tool-call-{index + 1}"),
                name=name,
                arguments=arguments,
                raw_arguments=raw_arguments,
                parse_error=parse_error,
            )
        )
    return tuple(calls)
