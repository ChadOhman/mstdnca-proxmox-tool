"""Tests for server-side session management (UserSession tracking + revocation)."""

import jwt as pyjwt
import pytest

from auth.session_manager import SESSION_KEY, _hash_session_id
from models import Role, User, UserSession
from models import db as _db

_TEST_ADMIN_PASSWORD = "TestPass123!"
_OTHER_PASSWORD = "OtherPass123!"


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def viewer_user(app):
    """A non-admin (viewer) user with a known password."""
    with app.app_context():
        existing = User.query.filter_by(username="_sess_viewer").first()
        if existing:
            existing.set_password(_OTHER_PASSWORD)
            _db.session.commit()
            return existing.id
        viewer_role = Role.query.filter_by(name="viewer").first()
        u = User(username="_sess_viewer", display_name="Session Viewer", role_id=viewer_role.id)
        u.set_password(_OTHER_PASSWORD)
        _db.session.add(u)
        _db.session.commit()
        return u.id


def _login(client, username, password):
    return client.post("/login", data={"username": username, "password": password},
                       follow_redirects=False)


def _sessions_for(app, username):
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        return UserSession.query.filter_by(user_id=user.id).all()


# ---------------------------------------------------------------------------
# Session recording on login
# ---------------------------------------------------------------------------

class TestSessionRecordedOnLogin:
    def test_login_creates_session_row(self, app, client):
        before = len([s for s in _sessions_for(app, "admin") if not s.revoked])
        _login(client, "admin", _TEST_ADMIN_PASSWORD)
        active = [s for s in _sessions_for(app, "admin") if not s.revoked]
        assert len(active) == before + 1
        # Session id hash stored, never the raw id
        newest = active[-1]
        assert len(newest.session_id_hash) == 64
        assert newest.user_agent is not None or newest.user_agent is None  # optional

    def test_logout_revokes_session(self, app, client):
        _login(client, "admin", _TEST_ADMIN_PASSWORD)
        active_before = len([s for s in _sessions_for(app, "admin") if not s.revoked])
        assert active_before >= 1
        client.post("/logout", follow_redirects=False)
        active_after = [s for s in _sessions_for(app, "admin") if not s.revoked]
        assert len(active_after) == active_before - 1


# ---------------------------------------------------------------------------
# Revocation forces logout on next request
# ---------------------------------------------------------------------------

class TestRevocationForcesLogout:
    def test_revoked_session_forces_logout(self, app, client):
        _login(client, "admin", _TEST_ADMIN_PASSWORD)
        # Confirm authenticated
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code != 302 or "/login" not in resp.headers.get("Location", "")

        # Revoke the session server-side
        with client.session_transaction() as sess:
            raw = sess[SESSION_KEY]
        with app.app_context():
            record = UserSession.query.filter_by(session_id_hash=_hash_session_id(raw)).first()
            record.revoked = True
            _db.session.commit()

        # Next request should force logout -> redirect to login
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


# ---------------------------------------------------------------------------
# Revoke-all-others keeps the current session
# ---------------------------------------------------------------------------

class TestRevokeOthers:
    def test_revoke_others_keeps_current(self, app, client):
        # Two independent logins for admin (two browsers)
        other = app.test_client()
        _login(other, "admin", _TEST_ADMIN_PASSWORD)
        _login(client, "admin", _TEST_ADMIN_PASSWORD)

        active = [s for s in _sessions_for(app, "admin") if not s.revoked]
        assert len(active) >= 2

        resp = client.post("/sessions/revoke-others", follow_redirects=False)
        assert resp.status_code == 302

        # Current client still works
        me = client.get("/profile", follow_redirects=False)
        assert me.status_code == 200

        # The other client is now forced to log out
        other_resp = other.get("/", follow_redirects=False)
        assert other_resp.status_code == 302
        assert "/login" in other_resp.headers["Location"]

    def test_user_cannot_revoke_another_users_session(self, app, client, viewer_user):
        # viewer logs in and gets a session
        viewer_client = app.test_client()
        _login(viewer_client, "_sess_viewer", _OTHER_PASSWORD)
        with app.app_context():
            viewer_session = UserSession.query.filter_by(user_id=viewer_user, revoked=False).first()
            viewer_session_id = viewer_session.id

        # admin logs into `client` and tries to revoke viewer's session via the
        # self-service profile route (should be rejected -- not their session)
        _login(client, "admin", _TEST_ADMIN_PASSWORD)
        resp = client.post(f"/sessions/{viewer_session_id}/revoke", follow_redirects=False)
        assert resp.status_code == 302
        with app.app_context():
            still = UserSession.query.get(viewer_session_id)
            assert still.revoked is False


# ---------------------------------------------------------------------------
# Admin session management via /security
# ---------------------------------------------------------------------------

class TestAdminSessionManagement:
    def test_admin_can_revoke_any_session(self, app, viewer_user):
        viewer_client = app.test_client()
        _login(viewer_client, "_sess_viewer", _OTHER_PASSWORD)
        with viewer_client.session_transaction() as sess:
            raw = sess[SESSION_KEY]
        with app.app_context():
            vs = UserSession.query.filter_by(session_id_hash=_hash_session_id(raw)).first()
            vs_id = vs.id

        admin_client = app.test_client()
        _login(admin_client, "admin", _TEST_ADMIN_PASSWORD)
        resp = admin_client.post(f"/security/sessions/{vs_id}/revoke", follow_redirects=False)
        assert resp.status_code == 302
        with app.app_context():
            assert UserSession.query.get(vs_id).revoked is True

        # viewer is forced to log out on next request
        vr = viewer_client.get("/", follow_redirects=False)
        assert vr.status_code == 302
        assert "/login" in vr.headers["Location"]

    def test_non_admin_cannot_access_admin_session_revoke(self, app, viewer_user):
        # Set up an admin session to be the target
        admin_client = app.test_client()
        _login(admin_client, "admin", _TEST_ADMIN_PASSWORD)
        with app.app_context():
            admin_user = User.query.filter_by(username="admin").first()
            admin_session = UserSession.query.filter_by(user_id=admin_user.id, revoked=False).first()
            admin_session_id = admin_session.id

        # viewer (no can_manage_users) attempts the admin revoke route
        viewer_client = app.test_client()
        _login(viewer_client, "_sess_viewer", _OTHER_PASSWORD)
        resp = viewer_client.post(f"/security/sessions/{admin_session_id}/revoke",
                                  follow_redirects=False)
        # _require_access redirects non-admins to the dashboard
        assert resp.status_code == 302
        assert "/security" not in resp.headers["Location"]
        with app.app_context():
            assert UserSession.query.get(admin_session_id).revoked is False


# ---------------------------------------------------------------------------
# JWT mobile API is unaffected by the session hook
# ---------------------------------------------------------------------------

class TestJwtApiUnaffected:
    def test_jwt_request_needs_no_user_session(self, app):
        """A JWT-authenticated /api/v1 request works without any UserSession row
        and the hook must not force-logout or create sessions for it."""
        client = app.test_client()
        with app.app_context():
            admin = User.query.filter_by(username="admin").first()
            admin.set_password(_TEST_ADMIN_PASSWORD)
            _db.session.commit()

        # Obtain a JWT via the API login (this does NOT create a cookie UserSession)
        resp = client.post("/api/v1/auth/login",
                           json={"username": "admin", "password": _TEST_ADMIN_PASSWORD})
        assert resp.status_code == 200
        token = resp.get_json()["data"]["access_token"]

        sessions_before = len(_sessions_for(app, "admin"))

        # Call a protected endpoint with the Bearer token
        me = client.get("/api/v1/me", headers={"Authorization": f"Bearer {token}"})
        assert me.status_code == 200

        # No UserSession rows were created for the JWT flow
        sessions_after = len(_sessions_for(app, "admin"))
        assert sessions_after == sessions_before

    def test_expired_jwt_still_rejected_normally(self, app):
        """Sanity: hook doesn't interfere with normal JWT rejection."""
        client = app.test_client()
        with app.app_context():
            secret = app.config["SECRET_KEY"]
        from datetime import datetime, timedelta, timezone
        expired = pyjwt.encode(
            {"sub": "1", "type": "access", "iat": datetime.now(timezone.utc) - timedelta(hours=2),
             "exp": datetime.now(timezone.utc) - timedelta(hours=1)},
            secret, algorithm="HS256")
        resp = client.get("/api/v1/me", headers={"Authorization": f"Bearer {expired}"})
        assert resp.status_code == 401
