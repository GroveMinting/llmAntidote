import http.client
import json
import urllib.error
import urllib.request

import pytest

from llm_antidote.eval_client import (
    MAX_TOOL_CALLS,
    EvaluationClientError,
    OpenAICompatClient,
    _NoRedirect,
    normalize_endpoint,
)


class FakeResponse:
    def __init__(self, value):
        self.payload = json.dumps(value).encode()

    def read(self, size):
        return self.payload[:size]


def test_normalize_endpoint_restricts_plain_http():
    url, display = normalize_endpoint("http://127.0.0.1:8000/v1")
    assert url == "http://127.0.0.1:8000/v1/chat/completions"
    assert display == "127.0.0.1:8000"
    assert normalize_endpoint("https://models.example/v1")[0].endswith("/v1/chat/completions")
    with pytest.raises(ValueError, match="loopback"):
        normalize_endpoint("http://models.example/v1")
    with pytest.raises(ValueError, match="credentials"):
        normalize_endpoint("https://user:secret@models.example/v1")


def test_plain_http_lan_rejection_guides_operator():
    with pytest.raises(ValueError, match="ssh -N -L"):
        normalize_endpoint("http://spark-centurion:8000/v1")


def test_explicit_trusted_host_permits_plain_http():
    url, display = normalize_endpoint(
        "http://spark-centurion:8000/v1", trusted_hosts=("spark-centurion",)
    )
    assert url == "http://spark-centurion:8000/v1/chat/completions"
    assert display == "spark-centurion:8000"
    with pytest.raises(ValueError):
        normalize_endpoint("http://other-host:8000/v1", trusted_hosts=("spark-centurion",))


def test_malformed_endpoint_is_rejected():
    with pytest.raises(ValueError, match="absolute"):
        normalize_endpoint("spark-centurion:8000/v1")


def test_redirects_are_refused_by_handler():
    handler = _NoRedirect()
    assert handler.redirect_request(None, None, 302, "", None, "https://evil.example") is None



def test_client_parses_tool_calls(monkeypatch):
    monkeypatch.setenv("LOCAL_MODEL_KEY", "secret-not-recorded")
    captured = {}

    def opener(request, timeout):
        captured["body"] = json.loads(request.data)
        captured["authorization"] = request.headers["Authorization"]
        captured["timeout"] = timeout
        return FakeResponse(
            {
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call-1",
                                    "type": "function",
                                    "function": {
                                        "name": "read_file",
                                        "arguments": '{"path":".env"}',
                                    },
                                }
                            ],
                        },
                    }
                ]
            }
        )

    client = OpenAICompatClient(
        "http://localhost:8000/v1",
        api_key_env="LOCAL_MODEL_KEY",
        timeout=12,
        opener=opener,
    )
    completion = client.complete(
        model="test-model",
        messages=[{"role": "user", "content": "test"}],
        tools=[],
        temperature=0,
        seed=1,
    )
    assert completion.tool_calls[0].arguments == {"path": ".env"}
    assert captured["body"]["max_tokens"] == 512
    assert captured["authorization"] == "Bearer secret-not-recorded"
    assert captured["timeout"] == 12


def test_client_sanitizes_http_errors():
    def opener(_request, timeout):
        del timeout
        raise urllib.error.HTTPError("https://models.example", 401, "secret", {}, None)

    client = OpenAICompatClient("https://models.example/v1", opener=opener)
    with pytest.raises(EvaluationClientError, match="HTTP 401") as caught:
        client.complete(model="m", messages=[], tools=[], temperature=0, seed=1)
    assert "secret" not in str(caught.value)


def test_client_sanitizes_malformed_http_framing():
    def opener(_request, timeout):
        del timeout
        raise http.client.BadStatusLine("endpoint-controlled-secret")

    client = OpenAICompatClient("https://models.example/v1", opener=opener)
    with pytest.raises(EvaluationClientError, match="malformed HTTP") as caught:
        client.complete(model="m", messages=[], tools=[], temperature=0, seed=1)
    assert "endpoint-controlled-secret" not in str(caught.value)


def test_client_rejects_malformed_advertised_tool_calls():
    responses = [
        {"choices": [{"finish_reason": "tool_calls", "message": {"tool_calls": None}}]},
        {"choices": [{"finish_reason": "tool_calls", "message": {"tool_calls": {}}}]},
        {"choices": [{"finish_reason": "tool_calls", "message": {"tool_calls": [{"id": "x"}]}}]},
    ]
    for value in responses:
        client = OpenAICompatClient(
            "https://models.example/v1",
            opener=lambda *_args, value=value, **_kwargs: FakeResponse(value),
        )
        with pytest.raises(EvaluationClientError):
            client.complete(model="m", messages=[], tools=[], temperature=0, seed=1)

    non_object_message = {
        "choices": [{"finish_reason": "stop", "message": ["not", "an", "object"]}]
    }
    client = OpenAICompatClient(
        "https://models.example/v1",
        opener=lambda *_args, **_kwargs: FakeResponse(non_object_message),
    )
    with pytest.raises(EvaluationClientError, match="invalid chat completion"):
        client.complete(model="m", messages=[], tools=[], temperature=0, seed=1)


def test_client_converts_deep_json_failure_to_sanitized_error():
    nested = "[" * 10_000 + "0" + "]" * 10_000
    payload = (
        '{"choices":[{"finish_reason":"tool_calls","message":{"tool_calls":'
        '[{"id":"x","function":{"name":"read_file","arguments":"'
        + nested.replace('"', '\\"')
        + '"}}]}}]}'
    )

    class RawResponse:
        def read(self, size):
            return payload.encode()[:size]

    client = OpenAICompatClient(
        "https://models.example/v1", opener=lambda *_args, **_kwargs: RawResponse()
    )
    completion = client.complete(model="m", messages=[], tools=[], temperature=0, seed=1)
    assert completion.tool_calls[0].parse_error is True


def test_client_caps_tool_calls_and_request_size():
    calls = [
        {"id": str(index), "function": {"name": "read_file", "arguments": "{}"}}
        for index in range(MAX_TOOL_CALLS + 1)
    ]
    client = OpenAICompatClient(
        "https://models.example/v1",
        opener=lambda *_args, **_kwargs: FakeResponse(
            {"choices": [{"finish_reason": "tool_calls", "message": {"tool_calls": calls}}]}
        ),
    )
    with pytest.raises(EvaluationClientError, match="more than"):
        client.complete(model="m", messages=[], tools=[], temperature=0, seed=1)

    with pytest.raises(EvaluationClientError, match="request exceeded"):
        client.complete(
            model="m",
            messages=[{"role": "user", "content": "x" * (5 * 1024 * 1024)}],
            tools=[],
            temperature=0,
            seed=1,
        )


def test_loopback_client_disables_environment_proxies(monkeypatch):
    captured = []

    class Director:
        def open(self, *_args, **_kwargs):
            raise AssertionError("not called")

    def build_opener(*handlers):
        captured.extend(handlers)
        return Director()

    monkeypatch.setenv("HTTP_PROXY", "http://proxy.example:8080")
    monkeypatch.setattr("urllib.request.build_opener", build_opener)
    OpenAICompatClient("http://127.0.0.1:8000/v1")
    proxy_handlers = [item for item in captured if isinstance(item, urllib.request.ProxyHandler)]
    assert len(proxy_handlers) == 1
    assert proxy_handlers[0].proxies == {}
