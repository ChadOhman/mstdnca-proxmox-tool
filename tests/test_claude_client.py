"""Tests for the Claude API client in clients/claude_client.py.

All tests mock the Anthropic SDK — no real API calls.
"""
from unittest.mock import MagicMock, patch

from clients.claude_client import ClaudeClient, get_claude_client, invalidate_cached_client


class TestClaudeClient:
    """ClaudeClient wrapper tests."""

    def test_init_stores_params(self):
        client = ClaudeClient("test-only-api-key", model="claude-haiku-4-5-20251001", max_tokens=1024)
        assert client.api_key == "test-only-api-key"
        assert client.model == "claude-haiku-4-5-20251001"
        assert client.max_tokens == 1024
        assert client._client is None

    @patch("clients.claude_client.ClaudeClient.client", new_callable=lambda: property(lambda self: MagicMock()))
    def test_test_connection_success(self, mock_client_prop):
        client = ClaudeClient("test-only-api-key")
        mock_response = MagicMock()
        mock_response.model = "claude-sonnet-4-20250514"
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
            Setting.set("ai_model", "claude-sonnet-4-20250514")
            invalidate_cached_client()

            client = get_claude_client()
            assert client is not None
            assert isinstance(client, ClaudeClient)
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
