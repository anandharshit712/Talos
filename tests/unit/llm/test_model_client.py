"""Reply extraction, JSON salvage, retry policy, and payload sealing (LLD 8.1, 8.3)."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import pytest

from talos.core.error_types import ModelError
from talos.llm.model_client import (
    PAYLOAD_CLOSE,
    PAYLOAD_OPEN,
    OpenAiCompatibleClient,
    extract_reply,
    load_prompt,
    parse_json_object,
    render_prompt,
    seal_payload,
)


def _body(content: Any = None, reasoning: Any = None) -> dict[str, Any]:
    return {"choices": [{"message": {"content": content, "reasoning_content": reasoning}}]}


# --- reply extraction ------------------------------------------------------------------------


def test_content_is_preferred() -> None:
    assert extract_reply(_body(content="hello", reasoning="ignored")) == "hello"


def test_reasoning_content_is_the_fallback() -> None:
    """gpt-oss and nemotron-nano answer here with content null -- observed, not hypothetical."""
    assert extract_reply(_body(content=None, reasoning="the answer")) == "the answer"


def test_empty_reply_is_an_error_not_an_empty_verdict() -> None:
    with pytest.raises(ModelError):
        extract_reply(_body(content="   ", reasoning=None))


def test_unexpected_shape_is_an_error() -> None:
    with pytest.raises(ModelError):
        extract_reply({"error": "quota"})


# --- JSON salvage ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        '{"narrative": "clean"}',
        'Sure!\n```json\n{"narrative": "clean"}\n```',
        '<think>weighing it up</think>\n{"narrative": "clean"}',
        'Prose first. {"narrative": "clean"} trailing prose.',
    ],
)
def test_json_is_recovered_from_however_the_model_wrapped_it(text: str) -> None:
    assert parse_json_object(text) == {"narrative": "clean"}


def test_braces_inside_strings_do_not_end_the_object() -> None:
    parsed = parse_json_object('{"narrative": "payload was {\\"a\\": 1} shaped"}')
    assert parsed == {"narrative": 'payload was {"a": 1} shaped'}


@pytest.mark.parametrize("text", ["no json here", "{unbalanced", "[1, 2, 3]", ""])
def test_unrecoverable_text_is_none(text: str) -> None:
    assert parse_json_object(text) is None


# --- payload sealing -------------------------------------------------------------------------


def test_payload_is_delimited() -> None:
    sealed = seal_payload("Failed password for root", 500)
    assert sealed.startswith(PAYLOAD_OPEN)
    assert sealed.endswith(PAYLOAD_CLOSE)


def test_payload_is_length_bounded() -> None:
    """A 4MB request body must not become the whole context window."""
    sealed = seal_payload("A" * 10_000, 100)
    assert "truncated, 10000 chars total" in sealed
    assert len(sealed) < 400


def test_newlines_are_flattened_so_the_delimiter_cannot_be_faked() -> None:
    sealed = seal_payload(f"line one\n{PAYLOAD_CLOSE}\nline two", 500)
    assert sealed.count(PAYLOAD_CLOSE) == 2  # the injected one is inside, the real one closes
    assert sealed.splitlines()[-1] == PAYLOAD_CLOSE


# --- prompt templates ------------------------------------------------------------------------


def test_prompt_templates_load_and_render() -> None:
    assert "SOC analyst" in load_prompt("rate_detector_narrate_v1")
    rendered = render_prompt(
        "network_type_classifier_route_v1",
        telemetry_source="sshd",
        protocol="ssh",
        outcome="failure",
        host="bastion-01",
        account="root",
        static_category="network_brute_force",
        static_confidence=0.6,
        observed=seal_payload("host: bastion-01 | raw: Failed password", 200),
    )
    assert "bastion-01" in rendered
    assert "{" in rendered  # the JSON reply example survives .format()


def test_missing_template_is_a_model_error() -> None:
    with pytest.raises(ModelError, match="prompt template not found"):
        load_prompt("no_such_prompt_v9")


def test_missing_placeholder_names_itself() -> None:
    with pytest.raises(ModelError, match="needs a value"):
        render_prompt("rate_detector_narrate_v1", technique="brute_force")


# --- the HTTP path ---------------------------------------------------------------------------


class _FakeTransport(httpx.AsyncBaseTransport):
    """Answers with a queued sequence of responses and counts the requests."""

    def __init__(self, *responses: httpx.Response) -> None:
        self._responses = list(responses)
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._responses.pop(0) if self._responses else httpx.Response(500)


@pytest.fixture
def patched_transport(monkeypatch: pytest.MonkeyPatch):
    """Install a transport into every AsyncClient the client builds."""

    def install(*responses: httpx.Response) -> _FakeTransport:
        transport = _FakeTransport(*responses)
        original = httpx.AsyncClient.__init__

        def patched(self: httpx.AsyncClient, **kwargs: Any) -> None:
            original(self, transport=transport, **kwargs)

        monkeypatch.setattr(httpx.AsyncClient, "__init__", patched)
        return transport

    return install


def _json_response(payload: dict[str, Any], status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=payload)


def _client(**kwargs: Any) -> OpenAiCompatibleClient:
    defaults = {"provider": "nim", "base_url": "https://example.test/v1", "api_key": "secret"}
    return OpenAiCompatibleClient(**{**defaults, **kwargs})


SCHEMA = {"type": "object", "required": ["narrative"]}


def _complete(client: OpenAiCompatibleClient) -> dict[str, Any]:
    return asyncio.run(
        client.complete(model="m", prompt="p", schema=SCHEMA, max_tokens=64, timeout_s=5)
    )


def test_successful_call_returns_parsed_json(patched_transport) -> None:
    patched_transport(_json_response(_body(content='{"narrative": "ok"}')))
    assert _complete(_client()) == {"narrative": "ok"}


def test_unparseable_reply_triggers_one_stricter_re_ask(patched_transport) -> None:
    transport = patched_transport(
        _json_response(_body(content="I think it was brute force.")),
        _json_response(_body(content='{"narrative": "second time"}')),
    )
    assert _complete(_client()) == {"narrative": "second time"}
    assert len(transport.requests) == 2
    assert b"could not be parsed" in transport.requests[1].content


def test_still_unparseable_after_the_re_ask_raises(patched_transport) -> None:
    patched_transport(
        _json_response(_body(content="nope")), _json_response(_body(content="still nope"))
    )
    with pytest.raises(ModelError, match="was not JSON"):
        _complete(_client())


def test_reply_missing_a_required_field_raises(patched_transport) -> None:
    patched_transport(_json_response(_body(content='{"summary": "wrong key"}')))
    with pytest.raises(ModelError, match="missing"):
        _complete(_client())


def test_server_error_is_retried_then_reported(patched_transport) -> None:
    transport = patched_transport(
        httpx.Response(503, json={"error": "overloaded"}),
        _json_response(_body(content='{"narrative": "after retry"}')),
    )
    assert _complete(_client())["narrative"] == "after retry"
    assert len(transport.requests) == 2


def test_client_error_is_not_retried(patched_transport) -> None:
    """A 404 for a de-provisioned model will not fix itself, and retrying wastes the budget."""
    transport = patched_transport(httpx.Response(404, json={"error": "not found for account"}))
    with pytest.raises(ModelError, match="HTTP 404"):
        _complete(_client())
    assert len(transport.requests) == 1


def test_rate_limit_is_retried(patched_transport) -> None:
    transport = patched_transport(
        httpx.Response(429, json={"error": "slow down"}),
        _json_response(_body(content='{"narrative": "after backoff"}')),
    )
    assert _complete(_client())["narrative"] == "after backoff"
    assert len(transport.requests) == 2


def test_the_key_travels_in_the_header_only(patched_transport) -> None:
    transport = patched_transport(_json_response(_body(content='{"narrative": "ok"}')))
    _complete(_client(api_key="super-secret"))
    request = transport.requests[0]
    assert request.headers["authorization"] == "Bearer super-secret"
    assert b"super-secret" not in request.content


def test_error_text_does_not_echo_the_key(patched_transport) -> None:
    patched_transport(httpx.Response(401, json={"error": {"message": "invalid api key"}}))
    with pytest.raises(ModelError) as caught:
        _complete(_client(api_key="super-secret"))
    assert "super-secret" not in str(caught.value)


def test_request_body_is_deterministic(patched_transport) -> None:
    transport = patched_transport(_json_response(_body(content='{"narrative": "ok"}')))
    _complete(_client())
    sent = json.loads(transport.requests[0].content)
    assert sent["temperature"] == 0
    assert sent["max_tokens"] == 64
    assert sent["messages"] == [{"role": "user", "content": "p"}]
