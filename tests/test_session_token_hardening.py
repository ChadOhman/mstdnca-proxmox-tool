"""Regression tests for the session / token / bootstrap-secret hardening.

Covers GHSA-23rf-x25p-6q66:

* the "remember me" cookie is transport-hardened, tracked and revocable, and is
  refused once the account's credentials have been rotated;
* a JWT-authenticated ``/api/v1`` request never mints a browser session cookie;
* refresh tokens rotate and a password change invalidates every earlier token;
* the terminal WebSocket refuses cross-origin handshakes and only honours the
  ``sudo`` message when the server itself saw a prompt;
* ad-hoc SSH credentials live in a single-use, expiring server-side store;
* the bootstrap admin password goes to a 0600 file and must be changed;
* ``credential_store`` refuses to mint a replacement key over live ciphertext.
"""

import os
import stat
import sys
import time

import pytest

from models import Credential, Guest, Role, User, UserSession
from models import db as _db

_TEST_ADMIN_PASSWORD = "TestPass123!"
_REMEMBER_PASSWORD = "test-only-RememberPass1!"
_TOKEN_PASSWORD = "test-only-TokenPass1!"


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _make_user(app, username, password, role_name="super_admin"):
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if user is None:
            role = Role.query.filter_by(name=role_name).first()
            user = User(username=username, display_name=username, role_id=role.id)
            _db.session.add(user)
        user.set_password(password)
        _db.session.commit()
        return user.id


@pytest.fixture()
def remember_user(app):
    uid = _make_user(app, "_sec_remember", _REMEMBER_PASSWORD)
    yield uid
    with app.app_context():
        UserSession.query.filter_by(user_id=uid).delete()
        User.query.filter_by(id=uid).delete()
        _db.session.commit()


@pytest.fixture()
def token_user(app):
    uid = _make_user(app, "_sec_token", _TOKEN_PASSWORD)
    yield uid
    with app.app_context():
        UserSession.query.filter_by(user_id=uid).delete()
        User.query.filter_by(id=uid).delete()
        _db.session.commit()


def _login(client, username, password, remember=False):
    data = {"username": username, "password": password}
    if remember:
        data["remember"] = "on"
    return client.post("/login", data=data, follow_redirects=False)


def _set_cookie_headers(response):
    return response.headers.getlist("Set-Cookie")


def _cookie_header(response, name):
    for raw in _set_cookie_headers(response):
        if raw.split("=", 1)[0].strip() == name:
            return raw
    return None


# ---------------------------------------------------------------------------
# 1. Remember-me cookie hardening
# ---------------------------------------------------------------------------

class TestRememberCookieAttributes:
    def test_config_defaults(self, app):
        assert app.config["REMEMBER_COOKIE_HTTPONLY"] is True
        assert app.config["REMEMBER_COOKIE_SAMESITE"] == "Lax"
        # Mirrors the session cookie rather than Flask-Login's insecure default.
        assert app.config["REMEMBER_COOKIE_SECURE"] == app.config["SESSION_COOKIE_SECURE"]
        # 14 days, not Flask-Login's 365.
        assert app.config["REMEMBER_COOKIE_DURATION"].days == 14

    def test_login_without_remember_sets_no_remember_cookie(self, app, client, remember_user):
        resp = _login(client, "_sec_remember", _REMEMBER_PASSWORD, remember=False)
        assert resp.status_code == 302
        assert _cookie_header(resp, "remember_token") is None
        assert _cookie_header(resp, "remember_ctx") is None

    def test_remember_cookies_are_hardened(self, app, client, remember_user):
        resp = _login(client, "_sec_remember", _REMEMBER_PASSWORD, remember=True)
        assert resp.status_code == 302

        for name in ("remember_token", "remember_ctx"):
            raw = _cookie_header(resp, name)
            assert raw is not None, f"{name} cookie was not set"
            assert "HttpOnly" in raw, raw
            assert "SameSite=Lax" in raw, raw
            if app.config["REMEMBER_COOKIE_SECURE"]:
                assert "Secure" in raw, raw
            # Bounded lifetime, not a year.
            assert "Max-Age=" in raw or "Expires=" in raw, raw
            if "Max-Age=" in raw:
                max_age = int(raw.split("Max-Age=", 1)[1].split(";", 1)[0])
                assert max_age <= 14 * 24 * 3600


class TestRememberCookieRestore:
    def test_restore_creates_a_tracked_session(self, app, client, remember_user):
        _login(client, "_sec_remember", _REMEMBER_PASSWORD, remember=True)
        with app.app_context():
            before = UserSession.query.filter_by(user_id=remember_user, revoked=False).count()

        # Drop the session cookie: only the remember cookies remain, as they
        # would after the browser session expired.
        client.delete_cookie("session")
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 200, "remember cookie should restore the login"

        with app.app_context():
            after = UserSession.query.filter_by(user_id=remember_user, revoked=False).count()
        assert after == before + 1, "the restored login must be tracked and revocable"

    def test_restore_refused_after_password_rotation(self, app, client, remember_user):
        _login(client, "_sec_remember", _REMEMBER_PASSWORD, remember=True)
        client.delete_cookie("session")

        # Rotate the credential (self-service change or admin reset both do this).
        with app.app_context():
            user = _db.session.get(User, remember_user)
            user.set_password("test-only-RotatedPass1!")
            _db.session.commit()
            sessions_before = UserSession.query.filter_by(user_id=remember_user, revoked=False).count()

        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

        with app.app_context():
            sessions_after = UserSession.query.filter_by(user_id=remember_user, revoked=False).count()
        assert sessions_after == sessions_before, "a refused restore must not be tracked as a login"

    def test_restore_refused_without_the_signed_marker(self, app, client, remember_user):
        """A stolen remember_token on its own is not enough."""
        _login(client, "_sec_remember", _REMEMBER_PASSWORD, remember=True)
        client.delete_cookie("session")
        client.delete_cookie("remember_ctx")

        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_session_revocation_clears_the_remember_cookie(self, app, client, remember_user):
        _login(client, "_sec_remember", _REMEMBER_PASSWORD, remember=True)
        with app.app_context():
            for record in UserSession.query.filter_by(user_id=remember_user, revoked=False).all():
                record.revoked = True
            _db.session.commit()

        # First request notices the revocation and clears the remember cookie...
        first = client.get("/", follow_redirects=False)
        assert first.status_code == 302
        assert client.get_cookie("remember_token") is None
        # ...so the next one cannot be restored either.
        second = client.get("/", follow_redirects=False)
        assert second.status_code == 302
        assert "/login" in second.headers["Location"]

    def test_inactive_user_is_not_restored(self, app, client, remember_user):
        _login(client, "_sec_remember", _REMEMBER_PASSWORD, remember=True)
        client.delete_cookie("session")
        with app.app_context():
            _db.session.get(User, remember_user).is_active_user = False
            _db.session.commit()
        try:
            resp = client.get("/", follow_redirects=False)
            assert resp.status_code == 302
            assert "/login" in resp.headers["Location"]
        finally:
            with app.app_context():
                _db.session.get(User, remember_user).is_active_user = True
                _db.session.commit()


# ---------------------------------------------------------------------------
# 2. JWT: no session cookie, rotation, password-change invalidation
# ---------------------------------------------------------------------------

def _api_login(client, username, password):
    resp = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    data = resp.get_json()["data"]
    return data["access_token"], data["refresh_token"]


class TestJwtSessionIsolation:
    def test_api_login_sets_no_cookie(self, app, client, token_user):
        resp = client.post("/api/v1/auth/login",
                           json={"username": "_sec_token", "password": _TOKEN_PASSWORD})
        assert resp.status_code == 200
        assert _cookie_header(resp, app.config.get("SESSION_COOKIE_NAME", "session")) is None

    def test_me_sets_no_session_cookie(self, app, client, token_user):
        access, _refresh = _api_login(client, "_sec_token", _TOKEN_PASSWORD)
        resp = client.get("/api/v1/me", headers={"Authorization": f"Bearer {access}"})
        assert resp.status_code == 200
        assert _cookie_header(resp, app.config.get("SESSION_COOKIE_NAME", "session")) is None
        assert resp.get_json()["data"]["username"] == "_sec_token"

    def test_guard_discards_a_session_touched_by_an_api_handler(self, app):
        from flask import make_response
        from flask import session as flask_session

        from routes.api_v1 import _strip_session_cookie

        cookie_name = app.config.get("SESSION_COOKIE_NAME", "session")
        with app.test_request_context("/api/v1/me"):
            flask_session["poke"] = 1
            resp = make_response("ok")
            resp.set_cookie(cookie_name, "forged")
            resp.set_cookie("unrelated", "kept")
            out = _strip_session_cookie(resp)
            # Flask writes the session cookie after after_request runs, so the
            # guard must also stop it being written in the first place.
            assert flask_session.modified is False
            headers = out.headers.getlist("Set-Cookie")
            assert not any(h.startswith(f"{cookie_name}=") for h in headers)
            assert any(h.startswith("unrelated=") for h in headers)

    def test_bearer_token_does_not_authenticate_the_web_ui(self, app, token_user):
        """The token must not leave behind anything a browser could reuse."""
        c = app.test_client()
        access, _refresh = _api_login(c, "_sec_token", _TOKEN_PASSWORD)
        assert c.get("/api/v1/me", headers={"Authorization": f"Bearer {access}"}).status_code == 200
        # No cookie was banked, so the HTML app still treats this client as anonymous.
        resp = c.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


class TestRefreshRotation:
    def test_refresh_rotates_and_burns_the_old_token(self, app, client, token_user):
        _access, refresh = _api_login(client, "_sec_token", _TOKEN_PASSWORD)

        first = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
        assert first.status_code == 200
        body = first.get_json()["data"]
        assert "access_token" in body
        assert "refresh_token" in body, "refresh must rotate, not just reissue an access token"
        assert body["refresh_token"] != refresh

        # Replaying the presented refresh token now fails.
        replay = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
        assert replay.status_code == 401
        assert replay.get_json()["error"]["code"] == "TOKEN_REVOKED"

        # The rotated one works.
        again = client.post("/api/v1/auth/refresh", json={"refresh_token": body["refresh_token"]})
        assert again.status_code == 200


class TestPasswordChangeInvalidatesTokens:
    def test_access_and_refresh_tokens_die_on_password_change(self, app, client, token_user):
        access, refresh = _api_login(client, "_sec_token", _TOKEN_PASSWORD)
        assert client.get("/api/v1/me", headers={"Authorization": f"Bearer {access}"}).status_code == 200

        with app.app_context():
            _db.session.get(User, token_user).set_password("test-only-NewTokenPass1!")
            _db.session.commit()

        stale = client.get("/api/v1/me", headers={"Authorization": f"Bearer {access}"})
        assert stale.status_code == 401
        assert stale.get_json()["error"]["code"] == "TOKEN_REVOKED"

        stale_refresh = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
        assert stale_refresh.status_code == 401
        assert stale_refresh.get_json()["error"]["code"] == "TOKEN_REVOKED"

        # A fresh login still works and its tokens are accepted.
        new_access, _ = _api_login(client, "_sec_token", "test-only-NewTokenPass1!")
        assert client.get("/api/v1/me", headers={"Authorization": f"Bearer {new_access}"}).status_code == 200

    def test_admin_reset_invalidates_tokens_and_sessions(self, app, token_user):
        c = app.test_client()
        access, _refresh = _api_login(c, "_sec_token", _TOKEN_PASSWORD)
        _login(c, "_sec_token", _TOKEN_PASSWORD)  # a browser session too

        with app.app_context():
            assert UserSession.query.filter_by(user_id=token_user, revoked=False).count() >= 1
            role_id = _db.session.get(User, token_user).role_id

        admin = app.test_client()
        _login(admin, "admin", _TEST_ADMIN_PASSWORD)
        resp = admin.post(f"/security/users/{token_user}/edit", data={
            "display_name": "_sec_token",
            "role_id": str(role_id),
            "is_active": "on",
            "new_password": "test-only-AdminReset1!",
        }, follow_redirects=False)
        assert resp.status_code == 302

        assert c.get("/api/v1/me", headers={"Authorization": f"Bearer {access}"}).status_code == 401
        with app.app_context():
            assert UserSession.query.filter_by(user_id=token_user, revoked=False).count() == 0


# ---------------------------------------------------------------------------
# 3./4. Terminal WebSocket: Origin check and sudo gating
# ---------------------------------------------------------------------------

class TestWebSocketOriginCheck:
    @pytest.mark.parametrize("origin,host", [
        ("https://panel.example.com", "panel.example.com"),
        ("http://panel.example.com", "panel.example.com"),      # scheme-insensitive
        ("https://PANEL.example.com", "panel.example.com"),     # case-insensitive
        ("http://localhost:5000", "localhost:5000"),
    ])
    def test_same_host_allowed(self, origin, host):
        from routes.terminal import ws_origin_allowed
        assert ws_origin_allowed(origin, host) is True

    @pytest.mark.parametrize("origin,host", [
        ("https://evil.example.net", "panel.example.com"),
        ("https://panel.example.com.evil.net", "panel.example.com"),
        ("http://localhost:5001", "localhost:5000"),
        ("null", "panel.example.com"),
        ("", "panel.example.com"),
        (None, "panel.example.com"),
    ])
    def test_foreign_or_missing_origin_refused(self, origin, host):
        from routes.terminal import ws_origin_allowed
        assert ws_origin_allowed(origin, host) is False


class TestSudoGate:
    def test_prompt_detection(self):
        from routes.terminal import looks_like_sudo_prompt
        assert looks_like_sudo_prompt("[sudo] password for deploy: ")
        assert looks_like_sudo_prompt("Password:")
        assert looks_like_sudo_prompt("sudo: Sorry, try again.\n")
        assert not looks_like_sudo_prompt("deploy@host:~$ ")
        assert not looks_like_sudo_prompt("")

    def test_refused_without_a_recent_prompt(self):
        from routes.terminal import SudoGate
        gate = SudoGate()
        allowed, reason = gate.allow()
        assert allowed is False
        assert reason == "no_recent_sudo_prompt"

    def test_allowed_once_per_prompt(self):
        from routes.terminal import SudoGate
        gate = SudoGate()
        gate.note_prompt()
        assert gate.allow() == (True, None)
        # One prompt authorises exactly one injection.
        allowed, reason = gate.allow()
        assert allowed is False
        assert reason == "no_recent_sudo_prompt"

    def test_stale_prompt_is_not_honoured(self):
        from routes.terminal import SudoGate
        clock = [1000.0]
        gate = SudoGate(prompt_window=5, clock=lambda: clock[0])
        gate.note_prompt()
        clock[0] += 6
        allowed, reason = gate.allow()
        assert allowed is False
        assert reason == "no_recent_sudo_prompt"

    def test_rate_limited(self):
        from routes.terminal import SudoGate
        clock = [1000.0]
        gate = SudoGate(rate_limit=2, clock=lambda: clock[0])
        for _ in range(2):
            gate.note_prompt()
            assert gate.allow()[0] is True
        gate.note_prompt()
        allowed, reason = gate.allow()
        assert allowed is False
        assert reason == "rate_limited"


# ---------------------------------------------------------------------------
# 5. Ad-hoc terminal credentials
# ---------------------------------------------------------------------------

class TestAdhocCredentialStore:
    def setup_method(self):
        from core.adhoc_credentials import clear
        clear()

    def test_single_use(self):
        from core.adhoc_credentials import store_credentials, take_credentials
        token = store_credentials(user_id=1, guest_id=2, username="root", password="test-only-pw")
        assert take_credentials(token, user_id=1, guest_id=2) == {
            "username": "root", "password": "test-only-pw",
        }
        assert take_credentials(token, user_id=1, guest_id=2) is None

    def test_expires(self):
        import core.adhoc_credentials as store
        token = store.store_credentials(user_id=1, guest_id=2, username="root", password="x")
        store._entries[token]["expires_at"] = time.monotonic() - 1
        assert store.take_credentials(token, user_id=1, guest_id=2) is None

    def test_scoped_to_issuer_and_guest(self):
        from core.adhoc_credentials import store_credentials, take_credentials
        token = store_credentials(user_id=1, guest_id=2, username="root", password="x")
        assert take_credentials(token, user_id=99, guest_id=2) is None
        token2 = store_credentials(user_id=1, guest_id=2, username="root", password="x")
        assert take_credentials(token2, user_id=1, guest_id=77) is None

    def test_unknown_token(self):
        from core.adhoc_credentials import take_credentials
        assert take_credentials("nope", user_id=1, guest_id=2) is None
        assert take_credentials(None, user_id=1, guest_id=2) is None

    def test_connect_adhoc_keeps_the_secret_out_of_the_cookie(self, app, auth_client):
        """The session may carry only an opaque token, never the password."""
        with app.app_context():
            guest = Guest(name="_sec-adhoc-target", guest_type="ct", ip_address="10.0.0.99")
            _db.session.add(guest)
            _db.session.commit()
            guest_id = guest.id
        try:
            resp = auth_client.post(
                f"/terminal/{guest_id}/connect-adhoc",
                data={"username": "root", "password": "test-only-adhoc-secret"},
                follow_redirects=False,
            )
            assert resp.status_code == 302
            with auth_client.session_transaction() as sess:
                token = sess.get(f"terminal_cred_token_{guest_id}")
                assert token, "an opaque token should be stored in the session"
                assert "test-only-adhoc-secret" not in str(dict(sess))
                assert f"terminal_cred_{guest_id}" not in sess

            from core.adhoc_credentials import take_credentials
            with app.app_context():
                admin_id = User.query.filter_by(username="admin").first().id
            creds = take_credentials(token, user_id=admin_id, guest_id=guest_id)
            assert creds == {"username": "root", "password": "test-only-adhoc-secret"}
        finally:
            with app.app_context():
                Guest.query.filter_by(id=guest_id).delete()
                _db.session.commit()


# ---------------------------------------------------------------------------
# 6. Bootstrap admin password
# ---------------------------------------------------------------------------

@pytest.fixture()
def bootstrap_app(tmp_path, monkeypatch, capsys):
    """A brand-new app on an empty database, so _ensure_default_admin runs."""
    import app as app_module

    monkeypatch.setattr(app_module, "DATA_DIR", str(tmp_path))
    application = app_module.create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SECRET_KEY": "test-only-bootstrap-secret-key-0123456789",
        "WTF_CSRF_ENABLED": False,
    })
    # Capture what the bootstrap printed so the test can assert on it.
    application.config["BOOTSTRAP_STDOUT"] = capsys.readouterr().out
    yield application
    with application.app_context():
        _db.session.remove()
        _db.engine.dispose()


class TestBootstrapAdminPassword:
    def _password_file(self, tmp_path):
        return os.path.join(str(tmp_path), "initial-admin-password")

    def test_password_goes_to_a_private_file_not_the_log(self, bootstrap_app, tmp_path):
        path = self._password_file(tmp_path)
        assert os.path.exists(path), "the bootstrap password must be written to DATA_DIR"

        with open(path, encoding="utf-8") as f:
            password = f.read().strip()
        assert password

        # The password itself must never be printed -- only its location.
        printed = bootstrap_app.config["BOOTSTRAP_STDOUT"]
        assert password not in printed
        assert "initial-admin-password" in printed

        if sys.platform != "win32":
            assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

        with bootstrap_app.app_context():
            admin = User.query.filter_by(username="admin").first()
            assert admin.must_change_password is True
            assert admin.check_password(password)

    def test_first_login_is_forced_through_change_password(self, bootstrap_app, tmp_path):
        path = self._password_file(tmp_path)
        with open(path, encoding="utf-8") as f:
            password = f.read().strip()

        client = bootstrap_app.test_client()
        resp = _login(client, "admin", password)
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/change-password")

        # Every other page bounces back to the change form.
        elsewhere = client.get("/", follow_redirects=False)
        assert elsewhere.status_code == 302
        assert elsewhere.headers["Location"].endswith("/change-password")

        # The change form itself is reachable.
        assert client.get("/change-password").status_code == 200

        done = client.post("/change-password", data={
            "current_password": password,
            "new_password": "test-only-BootstrapNew1!",
            "confirm_password": "test-only-BootstrapNew1!",
        }, follow_redirects=False)
        assert done.status_code == 302
        assert done.headers["Location"].endswith("/")

        with bootstrap_app.app_context():
            admin = User.query.filter_by(username="admin").first()
            assert admin.must_change_password is False
        assert not os.path.exists(path), "the bootstrap password file must be deleted after the change"

        assert client.get("/", follow_redirects=False).status_code == 200

    def test_api_login_refused_until_the_password_is_changed(self, bootstrap_app, tmp_path):
        with open(self._password_file(tmp_path), encoding="utf-8") as f:
            password = f.read().strip()
        client = bootstrap_app.test_client()
        resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": password})
        assert resp.status_code == 403
        assert resp.get_json()["error"]["code"] == "PASSWORD_CHANGE_REQUIRED"


# ---------------------------------------------------------------------------
# 7. credential_store key handling
# ---------------------------------------------------------------------------

class TestCredentialStoreKeyHandling:
    def test_refuses_to_generate_a_key_over_existing_ciphertext(self, app, tmp_path):
        import auth.credential_store as credential_store

        with app.app_context():
            cred = Credential(
                name="_sec-keyguard",
                username="root",
                auth_type="password",
                encrypted_value=credential_store.encrypt("test-only-secret"),
            )
            _db.session.add(cred)
            _db.session.commit()
            cred_id = cred.id

        original_path = credential_store.SECRET_KEY_PATH
        original_fernet = credential_store._fernet
        try:
            credential_store.SECRET_KEY_PATH = str(tmp_path / "gone" / "secret.key")
            credential_store._fernet = None
            with app.app_context(), pytest.raises(credential_store.CredentialKeyMissingError) as exc:
                credential_store.get_fernet()
            assert "missing" in str(exc.value).lower()
            assert not os.path.exists(credential_store.SECRET_KEY_PATH), \
                "a replacement key must not be written"
        finally:
            credential_store.SECRET_KEY_PATH = original_path
            credential_store._fernet = original_fernet
            with app.app_context():
                Credential.query.filter_by(id=cred_id).delete()
                _db.session.commit()

    def test_generates_a_private_key_on_a_fresh_install(self, tmp_path):
        import auth.credential_store as credential_store

        original_path = credential_store.SECRET_KEY_PATH
        original_fernet = credential_store._fernet
        try:
            key_path = str(tmp_path / "fresh" / "secret.key")
            credential_store.SECRET_KEY_PATH = key_path
            credential_store._fernet = None
            assert credential_store.get_fernet() is not None
            assert os.path.exists(key_path)
            if sys.platform != "win32":
                assert stat.S_IMODE(os.stat(key_path).st_mode) == 0o600
        finally:
            credential_store.SECRET_KEY_PATH = original_path
            credential_store._fernet = original_fernet

    def test_decrypt_failure_is_named_and_explained(self, app, tmp_path):
        import auth.credential_store as credential_store

        with app.app_context():
            blob = credential_store.encrypt("test-only-secret")

        original_path = credential_store.SECRET_KEY_PATH
        original_fernet = credential_store._fernet
        try:
            credential_store.SECRET_KEY_PATH = str(tmp_path / "other" / "secret.key")
            credential_store._fernet = None
            with pytest.raises(credential_store.CredentialDecryptError) as exc:
                credential_store.decrypt(blob)
            # Callers that only catch Exception keep working.
            assert isinstance(exc.value, Exception)
            assert "re-enter" in str(exc.value)
        finally:
            credential_store.SECRET_KEY_PATH = original_path
            credential_store._fernet = original_fernet
