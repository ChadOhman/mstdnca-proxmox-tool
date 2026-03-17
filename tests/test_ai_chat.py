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
    client.post("/login", data={"username": "testviewer", "password": password}, follow_redirects=False)


def _enable_ai(app):
    """Enable AI in settings with a dummy key."""
    with app.app_context():
        from auth.credential_store import encrypt
        Setting.set("ai_enabled", "true")
        Setting.set("ai_api_key", encrypt("sk-ant-test-key"))


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
                           headers={"Accept": "text/event-stream"})
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
        resp = auth_client.post("/ai/sessions", json={"title": "Test Session"})
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
        create_resp = auth_client.post("/ai/sessions", json={"title": "To Delete"})
        session_id = create_resp.get_json()["id"]

        resp = auth_client.delete(f"/ai/sessions/{session_id}")
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
        resp = auth_client.post("/ai/chat", json={})
        assert resp.status_code == 400

    def test_chat_empty_message(self, auth_client, app):
        _enable_ai(app)
        resp = auth_client.post("/ai/chat", json={"message": "  "})
        assert resp.status_code == 400

    def test_chat_no_client_returns_503(self, auth_client, app):
        _enable_ai(app)
        with patch("clients.claude_client.get_claude_client", return_value=None):
            resp = auth_client.post("/ai/chat", json={"message": "hello"})
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

        resp = auth_client.post("/ai/chat", json={"message": "hello"})
        assert resp.status_code == 429

        # Reset
        with app.app_context():
            Setting.set("ai_daily_request_limit", "100")
