import logging
import threading

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "claude-sonnet-5"
DEFAULT_MAX_TOKENS = 16000

# (model id, label) offered in Settings > AI Assistant. Exact API ids, no date suffixes.
AVAILABLE_MODELS = (
    ("claude-sonnet-5", "Claude Sonnet 5"),
    ("claude-opus-5", "Claude Opus 5"),
    ("claude-haiku-4-5", "Claude Haiku 4.5"),
)

# Models whose safety classifiers can decline a request (stop_reason "refusal").
# For these we opt into server-side fallbacks: the API re-runs a declined request
# on Anthropic's recommended fallback model within the same call.
SERVER_FALLBACK_MODELS = frozenset({"claude-opus-5"})
SERVER_FALLBACK_BETA = "server-side-fallback-2026-07-01"


def model_options(current=None):
    """Return the (model id, label) pairs for the model dropdown.

    A saved model that is no longer offered (e.g. a retired or date-suffixed id)
    is listed first so the form keeps it selected instead of silently switching.
    """
    options = list(AVAILABLE_MODELS)
    if current and current not in {model_id for model_id, _ in options}:
        options.insert(0, (current, f"{current} (legacy)"))
    return options


def _block_to_dict(block):
    """Serialize an SDK content block for replay, tolerating block types the SDK doesn't model."""
    if isinstance(block, dict):
        return dict(block)
    return block.to_dict(exclude_none=True)


def _replayable_content(blocks):
    """Return the assistant content blocks to send back on the next request.

    Blocks are echoed unchanged (thinking blocks included) so the next tool round
    continues the same turn. After a mid-output server-side fallback, only text
    survives from before the last ``fallback`` marker: the declined model's
    thinking and tool calls are not part of the fallback model's turn.
    """
    boundary = max((i for i, b in enumerate(blocks) if b.get("type") == "fallback"), default=-1)
    return [
        b for i, b in enumerate(blocks)
        if b.get("type") != "fallback" and (i > boundary or b.get("type") == "text")
    ]


class ClaudeClient:
    """Client for the Anthropic Claude Messages API with streaming and tool_use support."""

    def __init__(self, api_key, model=DEFAULT_MODEL, max_tokens=DEFAULT_MAX_TOKENS):
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

    def _request(self, messages, system_prompt=None, tools=None):
        """Return (messages resource, request kwargs) for a chat request."""
        kwargs = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": messages,
        }
        if system_prompt:
            kwargs["system"] = system_prompt
        if tools:
            kwargs["tools"] = tools
        if self.model in SERVER_FALLBACK_MODELS:
            kwargs["betas"] = [SERVER_FALLBACK_BETA]
            kwargs["fallbacks"] = "default"
            return self.client.beta.messages, kwargs
        return self.client.messages, kwargs

    def stream_chat(self, messages, system_prompt=None, tools=None):
        """Stream a chat completion, yielding events as dicts.

        Each yielded dict has a "type" key:
        - {"type": "text", "content": "..."} for text deltas
        - {"type": "tool_use", "id": "...", "name": "...", "input": {...}} for tool calls
        - {"type": "refusal", "category": "..."} if the model declined (tool calls are dropped)
        - {"type": "done", "usage": {...}, "stop_reason": "...", "content": [...]} when complete;
          "content" is the assistant turn to send back verbatim if the loop continues
        """
        try:
            api, kwargs = self._request(messages, system_prompt, tools)
            with api.stream(**kwargs) as stream:
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
                content = _replayable_content([_block_to_dict(b) for b in final.content])

                if final.stop_reason == "refusal":
                    details = getattr(final, "stop_details", None)
                    yield {"type": "refusal", "category": getattr(details, "category", None)}
                else:
                    # Yield tool uses (input is only available from final message)
                    for block in content:
                        if block.get("type") == "tool_use":
                            yield {
                                "type": "tool_use",
                                "id": block["id"],
                                "name": block["name"],
                                "input": block["input"],
                            }

                yield {"type": "done", "usage": usage, "stop_reason": final.stop_reason, "content": content}
        except Exception as e:
            logger.error("Claude API stream error: %s", e)
            yield {"type": "error", "message": str(e)}

    def send_message(self, messages, system_prompt=None, tools=None):
        """Send a non-streaming message. Returns the full response message object or None on error.

        Callers must check ``stop_reason`` before reading ``content``: a "refusal" may carry
        no content, and thinking blocks can precede the text.
        """
        try:
            api, kwargs = self._request(messages, system_prompt, tools)
            return api.create(**kwargs)
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

    model = Setting.get("ai_model", DEFAULT_MODEL)
    max_tokens = int(Setting.get("ai_max_tokens", str(DEFAULT_MAX_TOKENS)))
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
