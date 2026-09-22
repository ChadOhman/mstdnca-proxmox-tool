"""Tests for the Claude API client in clients/claude_client.py.

All tests mock the Anthropic SDK — no real API calls.
"""
import json
from unittest.mock import MagicMock, patch

import anthropic
import httpx2 as httpx

from clients.claude_client import (
    AVAILABLE_MODELS,
    DEFAULT_MAX_TOKENS,
    DEFAULT_MODEL,
    SERVER_FALLBACK_BETA,
    ClaudeClient,
    _replayable_content,
    get_claude_client,
    invalidate_cached_client,
    model_options,
)


def _sse(events):
    return "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in events).encode()


def _message_stream(blocks, stop_reason, model="claude-sonnet-5"):
    """Build a Messages API SSE body from (content_block_start, [deltas]) pairs."""
    events = [{"type": "message_start", "message": {
        "id": "msg_test", "type": "message", "role": "assistant", "model": model, "content": [],
        "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 10, "output_tokens": 0},
    }}]
    for index, (start, deltas) in enumerate(blocks):
        events.append({"type": "content_block_start", "index": index, "content_block": start})
        events.extend({"type": "content_block_delta", "index": index, "delta": d} for d in deltas)
        events.append({"type": "content_block_stop", "index": index})
    events.append({"type": "message_delta", "delta": {"stop_reason": stop_reason, "stop_sequence": None},
                   "usage": {"output_tokens": 7}})
    events.append({"type": "message_stop"})
    return _sse(events)


def _client_with_stream(model, body):
    """ClaudeClient backed by the real SDK over a mock transport; returns (client, captured request)."""
    captured = {}

    def handler(request):
        captured["headers"] = request.headers
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, content=body, headers={"content-type": "text/event-stream"})

    client = ClaudeClient("test-only-api-key", model=model)
    client._client = anthropic.Anthropic(
        api_key="test-only-api-key", http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    return client, captured


_THINKING_THEN_TOOL = [
    ({"type": "thinking", "thinking": "", "signature": ""}, [{"type": "signature_delta", "signature": "sig-1"}]),
    ({"type": "text", "text": ""}, [{"type": "text_delta", "text": "Checking."}]),
    ({"type": "tool_use", "id": "toolu_1", "name": "list_guests", "input": {}},
     [{"type": "input_json_delta", "partial_json": '{"status": null}'}]),
]


class TestClaudeClient:
    """ClaudeClient wrapper tests."""

    def test_init_stores_params(self):
        client = ClaudeClient("test-only-api-key", model="claude-haiku-4-5", max_tokens=1024)
        assert client.api_key == "test-only-api-key"
        assert client.model == "claude-haiku-4-5"
        assert client.max_tokens == 1024
        assert client._client is None

    def test_defaults(self):
        client = ClaudeClient("test-only-api-key")
        assert client.model == DEFAULT_MODEL == "claude-sonnet-5"
        assert client.max_tokens == DEFAULT_MAX_TOKENS == 16000

    @patch("clients.claude_client.ClaudeClient.client", new_callable=lambda: property(lambda self: MagicMock()))
    def test_test_connection_success(self, mock_client_prop):
        client = ClaudeClient("test-only-api-key")
        mock_response = MagicMock()
        mock_response.model = "claude-sonnet-5"
        client._client = MagicMock()
        client._client.messages.create.return_value = mock_response

        ok, msg = client.test_connection()
        assert ok is True
        assert "Connected" in msg

    def test_test_connection_failure(self):
        client = ClaudeClient("test-only-invalid-key")
        client._client = MagicMock()
        client._client.messages.create.side_effect = Exception("Invalid API key")

        ok, msg = client.test_connection()
        assert ok is False
        assert "failed" in msg.lower()

    def test_send_message_returns_none_on_error(self):
        client = ClaudeClient("test-only-api-key")
        client._client = MagicMock()
        client._client.messages.create.side_effect = Exception("Network error")

        result = client.send_message([{"role": "user", "content": "hello"}])
        assert result is None

    def test_send_message_returns_response(self):
        client = ClaudeClient("test-only-api-key")
        client._client = MagicMock()
        mock_response = MagicMock()
        client._client.messages.create.return_value = mock_response

        result = client.send_message([{"role": "user", "content": "hello"}])
        assert result is mock_response

    def test_send_message_passes_tools(self):
        client = ClaudeClient("test-only-api-key")
        client._client = MagicMock()
        mock_response = MagicMock()
        client._client.messages.create.return_value = mock_response

        tools = [{"name": "test_tool", "description": "test", "input_schema": {"type": "object"}}]
        client.send_message(
            [{"role": "user", "content": "hello"}],
            system_prompt="You are a test.",
            tools=tools,
        )

        call_kwargs = client._client.messages.create.call_args[1]
        assert call_kwargs["tools"] == tools
        assert call_kwargs["system"] == "You are a test."


class TestCachedClient:
    """get_claude_client caching behavior."""

    def test_returns_none_when_disabled(self, app):
        with app.app_context():
            from models import Setting
            Setting.set("ai_enabled", "false")
            invalidate_cached_client()
            assert get_claude_client() is None

    def test_returns_none_without_key(self, app):
        with app.app_context():
            from models import Setting
            Setting.set("ai_enabled", "true")
            Setting.set("ai_api_key", "")
            invalidate_cached_client()
            assert get_claude_client() is None

    def test_returns_client_when_configured(self, app):
        with app.app_context():
            from auth.credential_store import encrypt
            from models import Setting
            Setting.set("ai_enabled", "true")
            Setting.set("ai_api_key", encrypt("test-only-ai-api-key"))
            Setting.set("ai_model", "claude-opus-5")
            invalidate_cached_client()

            client = get_claude_client()
            assert client is not None
            assert isinstance(client, ClaudeClient)
            assert client.model == "claude-opus-5"
            Setting.set("ai_model", DEFAULT_MODEL)
            invalidate_cached_client()

    def test_legacy_stored_model_is_used_as_is(self, app):
        with app.app_context():
            from auth.credential_store import encrypt
            from models import Setting
            Setting.set("ai_enabled", "true")
            Setting.set("ai_api_key", encrypt("test-only-ai-api-key"))
            Setting.set("ai_model", "claude-sonnet-4-20250514")
            invalidate_cached_client()
            try:
                assert get_claude_client().model == "claude-sonnet-4-20250514"
            finally:
                Setting.set("ai_model", DEFAULT_MODEL)
                invalidate_cached_client()

    def test_caching_returns_same_instance(self, app):
        with app.app_context():
            from auth.credential_store import encrypt
            from models import Setting
            Setting.set("ai_enabled", "true")
            Setting.set("ai_api_key", encrypt("test-only-ai-api-key"))
            invalidate_cached_client()

            client1 = get_claude_client()
            client2 = get_claude_client()
            assert client1 is client2
            invalidate_cached_client()

    def test_invalidate_clears_cache(self, app):
        with app.app_context():
            from auth.credential_store import encrypt
            from models import Setting
            Setting.set("ai_enabled", "true")
            Setting.set("ai_api_key", encrypt("test-only-ai-api-key"))
            invalidate_cached_client()

            client1 = get_claude_client()
            invalidate_cached_client()
            client2 = get_claude_client()
            assert client1 is not client2
            invalidate_cached_client()


class TestModelOptions:
    """Dropdown options for Settings > AI Assistant."""

    def test_offers_current_undated_ids(self):
        ids = [model_id for model_id, _ in AVAILABLE_MODELS]
        assert ids == ["claude-sonnet-5", "claude-opus-5", "claude-haiku-4-5"]
        assert DEFAULT_MODEL in ids

    def test_known_model_adds_no_legacy_entry(self):
        assert model_options("claude-opus-5") == list(AVAILABLE_MODELS)
        assert model_options(None) == list(AVAILABLE_MODELS)

    def test_legacy_model_listed_first(self):
        options = model_options("claude-sonnet-4-20250514")
        assert options[0] == ("claude-sonnet-4-20250514", "claude-sonnet-4-20250514 (legacy)")
        assert options[1:] == list(AVAILABLE_MODELS)


class TestRequestShape:
    """Server-side refusal fallbacks are requested for Opus 5 only."""

    def test_opus_5_uses_beta_fallbacks(self):
        client = ClaudeClient("test-only-api-key", model="claude-opus-5")
        client._client = MagicMock()
        client.send_message([{"role": "user", "content": "hello"}])

        client._client.messages.create.assert_not_called()
        kwargs = client._client.beta.messages.create.call_args[1]
        assert kwargs["betas"] == [SERVER_FALLBACK_BETA] == ["server-side-fallback-2026-07-01"]
        assert kwargs["fallbacks"] == "default"

    def test_other_models_use_plain_endpoint(self):
        for model in ("claude-sonnet-5", "claude-haiku-4-5"):
            client = ClaudeClient("test-only-api-key", model=model)
            client._client = MagicMock()
            client.send_message([{"role": "user", "content": "hello"}])

            client._client.beta.messages.create.assert_not_called()
            kwargs = client._client.messages.create.call_args[1]
            assert kwargs["model"] == model
            assert "betas" not in kwargs
            assert "fallbacks" not in kwargs

    def test_no_sampling_thinking_or_tool_choice_params(self):
        """Sampling params / budget_tokens 400 on Sonnet 5 and Opus 5; forced tool_choice 400s on newer models."""
        client = ClaudeClient("test-only-api-key", model="claude-opus-5")
        client._client = MagicMock()
        client.send_message([{"role": "user", "content": "hello"}],
                            tools=[{"name": "t", "description": "t", "input_schema": {"type": "object"}}])
        kwargs = client._client.beta.messages.create.call_args[1]
        for param in ("temperature", "top_p", "top_k", "thinking", "tool_choice"):
            assert param not in kwargs

    def test_opus_5_stream_sends_fallbacks_on_the_wire(self):
        client, captured = _client_with_stream(
            "claude-opus-5", _message_stream([({"type": "text", "text": ""}, [])], "end_turn", "claude-opus-5"),
        )
        list(client.stream_chat([{"role": "user", "content": "hi"}]))
        assert captured["body"]["model"] == "claude-opus-5"
        assert captured["body"]["fallbacks"] == "default"
        assert SERVER_FALLBACK_BETA in captured["headers"]["anthropic-beta"]

    def test_sonnet_5_stream_sends_no_beta(self):
        client, captured = _client_with_stream(
            "claude-sonnet-5", _message_stream([({"type": "text", "text": ""}, [])], "end_turn"),
        )
        list(client.stream_chat([{"role": "user", "content": "hi"}]))
        assert captured["body"]["model"] == "claude-sonnet-5"
        assert "fallbacks" not in captured["body"]
        assert "anthropic-beta" not in captured["headers"]


class TestStreamChat:
    """stream_chat over a real SDK stream (mock HTTP transport)."""

    def test_thinking_blocks_returned_for_replay(self):
        client, _ = _client_with_stream("claude-sonnet-5", _message_stream(_THINKING_THEN_TOOL, "tool_use"))
        events = list(client.stream_chat([{"role": "user", "content": "hi"}]))

        assert {"type": "text", "content": "Checking."} in events
        tool_uses = [e for e in events if e["type"] == "tool_use"]
        assert tool_uses == [{"type": "tool_use", "id": "toolu_1", "name": "list_guests",
                              "input": {"status": None}}]
        done = events[-1]
        assert done["type"] == "done"
        assert done["stop_reason"] == "tool_use"
        # Unset SDK fields (citations, caller) are dropped; None inside tool input is kept.
        assert done["content"] == [
            {"type": "thinking", "thinking": "", "signature": "sig-1"},
            {"type": "text", "text": "Checking."},
            {"type": "tool_use", "id": "toolu_1", "name": "list_guests", "input": {"status": None}},
        ]

    def test_refusal_drops_tool_calls(self):
        blocks = _THINKING_THEN_TOOL[1:]
        client, _ = _client_with_stream("claude-opus-5", _message_stream(blocks, "refusal", "claude-opus-5"))
        events = list(client.stream_chat([{"role": "user", "content": "hi"}]))

        types = [e["type"] for e in events]
        assert "refusal" in types
        assert "tool_use" not in types
        assert events[-1]["type"] == "done"
        assert events[-1]["stop_reason"] == "refusal"

    def test_mid_output_fallback_drops_declined_tool_calls(self):
        blocks = [
            ({"type": "tool_use", "id": "toolu_declined", "name": "list_guests", "input": {}}, []),
            ({"type": "text", "text": ""}, [{"type": "text_delta", "text": "Partial. "}]),
            ({"type": "fallback", "from": {"model": "claude-opus-5"}, "to": {"model": "claude-opus-4-8"}}, []),
            ({"type": "tool_use", "id": "toolu_kept", "name": "list_guests", "input": {}}, []),
        ]
        client, _ = _client_with_stream("claude-opus-5", _message_stream(blocks, "tool_use", "claude-opus-4-8"))
        events = list(client.stream_chat([{"role": "user", "content": "hi"}]))

        assert [e["id"] for e in events if e["type"] == "tool_use"] == ["toolu_kept"]
        assert [b.get("id", b["type"]) for b in events[-1]["content"]] == ["text", "toolu_kept"]


class TestReplayableContent:
    def test_no_fallback_keeps_everything(self):
        blocks = [{"type": "thinking", "thinking": "", "signature": "s"}, {"type": "text", "text": "x"}]
        assert _replayable_content(blocks) == blocks

    def test_keeps_only_text_before_last_fallback(self):
        blocks = [
            {"type": "thinking", "thinking": "", "signature": "a"},
            {"type": "text", "text": "partial"},
            {"type": "tool_use", "id": "t1", "name": "n", "input": {}},
            {"type": "fallback", "from": {"model": "m1"}, "to": {"model": "m2"}},
            {"type": "thinking", "thinking": "", "signature": "b"},
            {"type": "tool_use", "id": "t2", "name": "n", "input": {}},
        ]
        assert _replayable_content(blocks) == [
            {"type": "text", "text": "partial"},
            {"type": "thinking", "thinking": "", "signature": "b"},
            {"type": "tool_use", "id": "t2", "name": "n", "input": {}},
        ]
