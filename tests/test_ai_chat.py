"""Tests for AI chat endpoints in routes/ai_chat.py.

Covers:
- Permission enforcement (can_use_ai)
- AI disabled state
- Rate limiting
- Session CRUD
- Chat endpoint basics (mocked Claude API)
"""
from unittest.mock import patch

from models import AIChatMessage, AIChatSession, Role, Setting, User, db

# Same-origin header the browser sends on same-origin fetch() POSTs. The AI
# blueprint requires this on state-changing requests (H2 CSRF hardening), so
# tests that POST/DELETE must supply it just like a real browser would.
_ORIGIN = {"Origin": "http://localhost"}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_viewer_user(app):
    """Create a viewer user (no AI permission) and return (user_id, password)."""
    password = "ViewerPass123!"
    with app.app_context():
        role = Role.query.filter_by(name="viewer").first()
        user = User.query.filter_by(username="testviewer").first()
        if not user:
            user = User(username="testviewer", display_name="Test Viewer", role_id=role.id)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
        return user.id, password


def _login_viewer(client, app):
    """Log in as the viewer user."""
    _, password = _create_viewer_user(app)
    client.post("/login", data={"username": "testviewer", "password": password},
                headers=_ORIGIN, follow_redirects=False)


def _enable_ai(app):
    """Enable AI in settings with a dummy key."""
    with app.app_context():
        from auth.credential_store import encrypt
        Setting.set("ai_enabled", "true")
        Setting.set("ai_api_key", encrypt("test-only-ai-api-key"))


def _disable_ai(app):
    """Disable AI in settings."""
    with app.app_context():
        Setting.set("ai_enabled", "false")


# ---------------------------------------------------------------------------
# Permission tests
# ---------------------------------------------------------------------------

class TestAIPermissions:
    """AI endpoints require can_use_ai permission."""

    def test_unauthenticated_redirects(self, client, app):
        _enable_ai(app)
        resp = client.get("/ai/sessions", follow_redirects=False)
        assert resp.status_code in (302, 401)

    def test_viewer_cannot_access_sessions(self, client, app):
        _enable_ai(app)
        _login_viewer(client, app)
        resp = client.get("/ai/sessions", follow_redirects=False)
        assert resp.status_code in (302, 403)

    def test_viewer_cannot_chat(self, client, app):
        _enable_ai(app)
        _login_viewer(client, app)
        resp = client.post("/ai/chat", json={"message": "hello"},
                           headers={"Accept": "text/event-stream", **_ORIGIN})
        assert resp.status_code == 403

    def test_admin_can_access_sessions(self, auth_client, app):
        _enable_ai(app)
        resp = auth_client.get("/ai/sessions")
        assert resp.status_code == 200

    def test_ai_disabled_returns_503(self, auth_client, app):
        _disable_ai(app)
        resp = auth_client.get("/ai/sessions",
                               headers={"Accept": "text/event-stream"})
        assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Session CRUD tests
# ---------------------------------------------------------------------------

class TestAISessions:
    """Session create / list / get / delete."""

    def test_create_session(self, auth_client, app):
        _enable_ai(app)
        resp = auth_client.post("/ai/sessions", json={"title": "Test Session"}, headers=_ORIGIN)
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["title"] == "Test Session"
        assert "id" in data

        # Cleanup
        with app.app_context():
            s = AIChatSession.query.get(data["id"])
            if s:
                db.session.delete(s)
                db.session.commit()

    def test_list_sessions(self, auth_client, app):
        _enable_ai(app)
        resp = auth_client.get("/ai/sessions")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)

    def test_get_nonexistent_session(self, auth_client, app):
        _enable_ai(app)
        resp = auth_client.get("/ai/sessions/99999")
        assert resp.status_code == 404

    def test_delete_session(self, auth_client, app):
        _enable_ai(app)
        # Create then delete
        create_resp = auth_client.post("/ai/sessions", json={"title": "To Delete"}, headers=_ORIGIN)
        session_id = create_resp.get_json()["id"]

        resp = auth_client.delete(f"/ai/sessions/{session_id}", headers=_ORIGIN)
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True

    def test_get_session_messages(self, auth_client, app):
        _enable_ai(app)
        # Create session with a message
        with app.app_context():
            admin = User.query.filter_by(username="admin").first()
            session = AIChatSession(user_id=admin.id, title="Msg Test")
            db.session.add(session)
            db.session.flush()
            msg = AIChatMessage(session_id=session.id, role="user", content="hello")
            db.session.add(msg)
            db.session.commit()
            sid = session.id

        resp = auth_client.get(f"/ai/sessions/{sid}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data["messages"]) == 1
        assert data["messages"][0]["content"] == "hello"

        # Cleanup
        with app.app_context():
            s = AIChatSession.query.get(sid)
            if s:
                db.session.delete(s)
                db.session.commit()


# ---------------------------------------------------------------------------
# Chat endpoint tests
# ---------------------------------------------------------------------------

class TestAIChat:
    """Chat endpoint with mocked Claude API."""

    def test_chat_requires_message(self, auth_client, app):
        _enable_ai(app)
        resp = auth_client.post("/ai/chat", json={}, headers=_ORIGIN)
        assert resp.status_code == 400

    def test_chat_empty_message(self, auth_client, app):
        _enable_ai(app)
        resp = auth_client.post("/ai/chat", json={"message": "  "}, headers=_ORIGIN)
        assert resp.status_code == 400

    def test_chat_no_client_returns_503(self, auth_client, app):
        _enable_ai(app)
        with patch("clients.claude_client.get_claude_client", return_value=None):
            resp = auth_client.post("/ai/chat", json={"message": "hello"}, headers=_ORIGIN)
            assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Rate limiting tests
# ---------------------------------------------------------------------------

class TestAIRateLimit:
    """Rate limiting prevents excessive API usage."""

    def test_rate_limit_check(self, auth_client, app):
        _enable_ai(app)
        with app.app_context():
            Setting.set("ai_daily_request_limit", "0")  # Zero limit = always exceeded

        resp = auth_client.post("/ai/chat", json={"message": "hello"}, headers=_ORIGIN)
        assert resp.status_code == 429

        # Reset
        with app.app_context():
            Setting.set("ai_daily_request_limit", "100")


# ---------------------------------------------------------------------------
# CSRF hardening (H2)
# ---------------------------------------------------------------------------

class TestAICsrf:
    """State-changing /ai/* routes require a same-origin Origin/Referer header."""

    def test_chat_without_origin_is_blocked(self, auth_client, app):
        _enable_ai(app)
        # No Origin/Referer header at all -> blocked (403), unlike the app-wide
        # check which would allow header-less requests.
        resp = auth_client.post("/ai/chat", json={"message": "hello"})
        assert resp.status_code == 403

    def test_chat_with_cross_site_origin_is_blocked(self, auth_client, app):
        _enable_ai(app)
        resp = auth_client.post("/ai/chat", json={"message": "hello"},
                                headers={"Origin": "http://evil.example.com"})
        assert resp.status_code == 403

    def test_create_session_without_origin_is_blocked(self, auth_client, app):
        _enable_ai(app)
        resp = auth_client.post("/ai/sessions", json={"title": "x"})
        assert resp.status_code == 403

    def test_get_sessions_without_origin_is_allowed(self, auth_client, app):
        """Safe GET requests are not subject to the origin requirement."""
        _enable_ai(app)
        resp = auth_client.get("/ai/sessions")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# B1: tools execute exactly once per request (critical regression test)
# ---------------------------------------------------------------------------

class _FakeStreamClient:
    """Fake Claude client: first round emits one tool_use, second round is plain text."""

    def __init__(self, tool_name, tool_input):
        self._tool_name = tool_name
        self._tool_input = tool_input
        self._calls = 0

    def stream_chat(self, messages, system_prompt=None, tools=None):
        self._calls += 1
        if self._calls == 1:
            # Round 1: model asks to call the tool exactly once.
            yield {"type": "tool_use", "id": "toolu_test_1",
                   "name": self._tool_name, "input": self._tool_input}
            yield {"type": "done", "usage": {"input_tokens": 5, "output_tokens": 5},
                   "stop_reason": "tool_use"}
        else:
            # Round 2: model responds with text and no further tools.
            yield {"type": "text", "content": "Done."}
            yield {"type": "done", "usage": {"input_tokens": 3, "output_tokens": 3},
                   "stop_reason": "end_turn"}


class TestToolExecutedOncePerRequest:
    """execute_tool must run exactly once per tool_use, not twice (B1 regression)."""

    def _make_guest_and_service(self, app):
        from models import Guest, GuestService
        with app.app_context():
            g = Guest(name="ai-b1-guest", guest_type="ct", enabled=True,
                      ip_address="10.9.9.9", status="up-to-date", power_state="running")
            db.session.add(g)
            db.session.flush()
            svc = GuestService(guest_id=g.id, service_name="ai-b1-svc",
                               unit_name="ai-b1-svc.service")
            db.session.add(svc)
            db.session.commit()
            return g.id, svc.id

    def _cleanup(self, app, guest_id, service_id):
        from models import Guest, GuestService
        with app.app_context():
            svc = GuestService.query.get(service_id)
            if svc:
                db.session.delete(svc)
            g = Guest.query.get(guest_id)
            if g:
                db.session.delete(g)
            db.session.commit()

    def test_control_service_action_fires_once(self, auth_client, app):
        """The underlying service_action must fire exactly ONCE across the stream."""
        _enable_ai(app)
        guest_id, service_id = self._make_guest_and_service(app)
        try:
            fake = _FakeStreamClient(
                "control_service",
                {"service_id": service_id, "action": "restart", "confirm": True},
            )
            with patch("clients.claude_client.get_claude_client", return_value=fake), \
                    patch("core.scanner.service_action", return_value=(True, "ok")) as mock_action:
                resp = auth_client.post("/ai/chat", json={"message": "restart it"},
                                        headers=_ORIGIN)
                # Drain the SSE stream so generate() fully runs.
                body = resp.get_data(as_text=True)
                assert resp.status_code == 200
                assert "tool_result" in body
                # The critical assertion: exactly one real execution, not two.
                assert mock_action.call_count == 1
        finally:
            self._cleanup(app, guest_id, service_id)

    def test_control_service_audit_logged_once(self, auth_client, app):
        """Exactly one ai_service_control audit entry per confirmed request."""
        from models import AuditLog
        _enable_ai(app)
        guest_id, service_id = self._make_guest_and_service(app)
        try:
            with app.app_context():
                before = AuditLog.query.filter_by(action="ai_service_control").count()
            fake = _FakeStreamClient(
                "control_service",
                {"service_id": service_id, "action": "restart", "confirm": True},
            )
            with patch("clients.claude_client.get_claude_client", return_value=fake), \
                    patch("core.scanner.service_action", return_value=(True, "ok")):
                resp = auth_client.post("/ai/chat", json={"message": "restart it"},
                                        headers=_ORIGIN)
                resp.get_data(as_text=True)  # drain stream
            with app.app_context():
                after = AuditLog.query.filter_by(action="ai_service_control").count()
            assert after - before == 1
        finally:
            self._cleanup(app, guest_id, service_id)
