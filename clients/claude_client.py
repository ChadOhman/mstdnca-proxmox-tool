import logging
import threading

logger = logging.getLogger(__name__)


class ClaudeClient:
    """Client for the Anthropic Claude Messages API with streaming and tool_use support."""

    def __init__(self, api_key, model="claude-sonnet-4-20250514", max_tokens=4096):
        self.api_key = api_key
        self.model = model
        self.max_tokens = max_tokens
        self._client = None

    @property
    def client(self):
        if self._client is None:
            import anthropic
            self._client = anthropic.Anthropic(api_key=self.api_key)
        return self._client

    def stream_chat(self, messages, system_prompt=None, tools=None):
        """Stream a chat completion, yielding events as dicts.

        Each yielded dict has a "type" key:
        - {"type": "text", "content": "..."} for text deltas
        - {"type": "tool_use", "id": "...", "name": "...", "input": {...}} for tool calls
        - {"type": "done", "usage": {"input_tokens": N, "output_tokens": N}} when complete
        """
        kwargs = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": messages,
        }
        if system_prompt:
            kwargs["system"] = system_prompt
        if tools:
            kwargs["tools"] = tools

        try:
            with self.client.messages.stream(**kwargs) as stream:
                for event in stream:
                    if event.type == "content_block_delta":
                        if hasattr(event.delta, "text"):
                            yield {"type": "text", "content": event.delta.text}
                    elif event.type == "content_block_start":
                        if event.content_block.type == "tool_use":
                            yield {
                                "type": "tool_use_start",
                                "id": event.content_block.id,
                                "name": event.content_block.name,
                            }
                    elif event.type == "message_stop":
                        pass

                # Get final message for usage and stop reason
                final = stream.get_final_message()
                usage = {"input_tokens": final.usage.input_tokens, "output_tokens": final.usage.output_tokens}

                # Extract any tool_use blocks from the final message
                tool_uses = []
                for block in final.content:
                    if block.type == "tool_use":
                        tool_uses.append({
                            "type": "tool_use",
                            "id": block.id,
                            "name": block.name,
                            "input": block.input,
                        })
                    elif block.type == "text":
                        pass  # Text already streamed via deltas

                # Yield tool uses (input is only available from final message)
                for tu in tool_uses:
                    yield tu

                yield {"type": "done", "usage": usage, "stop_reason": final.stop_reason}
        except Exception as e:
            logger.error("Claude API stream error: %s", e)
            yield {"type": "error", "message": str(e)}

    def send_message(self, messages, system_prompt=None, tools=None):
        """Send a non-streaming message. Returns the full response message object or None on error."""
        kwargs = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": messages,
        }
        if system_prompt:
            kwargs["system"] = system_prompt
        if tools:
            kwargs["tools"] = tools

        try:
            return self.client.messages.create(**kwargs)
        except Exception as e:
            logger.error("Claude API error: %s", e)
            return None

    def test_connection(self):
        """Test the API connection with a minimal request."""
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=16,
                messages=[{"role": "user", "content": "Hi"}],
            )
            return True, f"Connected. Model: {response.model}"
        except Exception as e:
            return False, f"Connection failed: {e}"


# ---------------------------------------------------------------------------
# Module-level cached client
# ---------------------------------------------------------------------------
_cached_client = None
_cached_settings_key = None
_client_lock = threading.Lock()


def get_claude_client():
    """Return a cached ClaudeClient built from application settings.

    Returns None if AI is not enabled or API key is not configured.
    """
    global _cached_client, _cached_settings_key

    from auth.credential_store import decrypt
    from models import Setting

    enabled = Setting.get("ai_enabled", "false")
    if enabled != "true":
        return None

    encrypted_key = Setting.get("ai_api_key", "")
    if not encrypted_key:
        return None

    model = Setting.get("ai_model", "claude-sonnet-4-20250514")
    max_tokens = int(Setting.get("ai_max_tokens", "4096"))
    api_key = decrypt(encrypted_key)
    if not api_key:
        return None

    key = (api_key, model, max_tokens)
    if _cached_client is not None and _cached_settings_key == key:
        return _cached_client

    with _client_lock:
        if _cached_client is not None and _cached_settings_key == key:
            return _cached_client
        _cached_client = ClaudeClient(api_key, model=model, max_tokens=max_tokens)
        _cached_settings_key = key
        return _cached_client


def invalidate_cached_client():
    """Discard the cached client (e.g. after settings change)."""
    global _cached_client, _cached_settings_key
    with _client_lock:
        _cached_client = None
        _cached_settings_key = None
