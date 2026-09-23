"""GHSA-23rf-x25p-6q66 residuals: revocation re-checks that fail closed and run on
a wall clock, untracked sessions ended, self password change signs out other
browsers, the key-regeneration guard sees every ciphertext, the /metrics token
is header-only, unacknowledged alerts expire, and create-ct.sh keeps the root
password out of the console.
"""
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from sqlalchemy.exc import OperationalError

from auth.credential_store import encrypt
from auth.session_manager import SESSION_KEY
from models import Credential, ModerationAlert, Role, Setting, User, UserSession, db

_PASSWORD = "test-only-LeftoverPass1!"
_NEW_PASSWORD = "test-only-LeftoverPass2!"
SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts")


def _login(client, username, password):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=False)


@pytest.fixture()
def pw_user(app):
    with app.app_context():
        role = Role.query.filter_by(name="viewer").first()
        user = User.query.filter_by(username="_leftover_pw_user").first()
        if user is None:
            user = User(username="_leftover_pw_user", display_name="Leftover", role_id=role.id)
            db.session.add(user)
        user.set_password(_PASSWORD)
        user.must_change_password = False
        db.session.commit()
        user_id = user.id
    yield user_id
    with app.app_context():
        UserSession.query.filter_by(user_id=user_id).delete()
        user = db.session.get(User, user_id)
        if user is not None:
            db.session.delete(user)
        db.session.commit()


# ---------------------------------------------------------------------------
# Revocation re-checks
# ---------------------------------------------------------------------------


class TestRevocationRecheckFailsClosed:
    def test_terminal_recheck_returns_reason_on_db_error(self, app):
        from routes.terminal import _revocation_reason

        with patch("models.db.session.get", side_effect=RuntimeError("db down")):
            assert _revocation_reason(app, 1, None) == "recheck_failed"

    def test_stream_recheck_returns_false_on_db_error(self, app):
        from routes.api import _stream_authorized

        with app.app_context(), patch("models.db.session.get", side_effect=RuntimeError("db down")):
            assert _stream_authorized(1, None) is False

    def test_stream_recheck_false_for_revoked_session(self, app, pw_user, client):
        from auth.session_manager import _hash_session_id
        from routes.api import _stream_authorized

        _login(client, "_leftover_pw_user", _PASSWORD)
        with client.session_transaction() as sess:
            raw = sess[SESSION_KEY]
        with app.app_context():
            assert _stream_authorized(pw_user, _hash_session_id(raw)) is True
            record = UserSession.query.filter_by(session_id_hash=_hash_session_id(raw)).first()
            record.revoked = True
            db.session.commit()
            assert _stream_authorized(pw_user, _hash_session_id(raw)) is False

    def test_stream_rechecks_on_a_wall_clock(self):
        import routes.api as api_mod

        src = open(api_mod.__file__, encoding="utf-8").read()
        assert "_STREAM_RECHECK_SECONDS" in src
        # The re-check must not live only in the queue.Empty branch.
        loop = src.split("last_check = time.monotonic()", 1)[1]
        assert "if time.monotonic() - last_check >= _STREAM_RECHECK_SECONDS" in loop

    def test_follower_websocket_has_a_watchdog(self):
        import routes.terminal as term_mod

        src = open(term_mod.__file__, encoding="utf-8").read()
        follow = src.split("def _ws_follow(", 1)[1]
        assert "_follower_watchdog" in follow
        assert "_revocation_reason(_wd_app, _wd_user_id, _wd_session_hash)" in follow


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


class TestUntrackedSessionIsEnded:
    def test_cookie_without_tracking_key_is_logged_out(self, app, pw_user, client):
        _login(client, "_leftover_pw_user", _PASSWORD)
        assert client.get("/profile", follow_redirects=False).status_code == 200
        with client.session_transaction() as sess:
            sess.pop(SESSION_KEY, None)
        resp = client.get("/profile", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


class TestSelfPasswordChangeRevokesOtherSessions:
    def test_other_browser_signed_out_current_kept(self, app, pw_user, client):
        other = app.test_client()
        _login(other, "_leftover_pw_user", _PASSWORD)
        _login(client, "_leftover_pw_user", _PASSWORD)
        assert other.get("/profile", follow_redirects=False).status_code == 200

        resp = client.post("/change-password", data={
            "current_password": _PASSWORD, "new_password": _NEW_PASSWORD, "confirm_password": _NEW_PASSWORD,
        }, follow_redirects=False)
        assert resp.status_code == 302

        assert client.get("/profile", follow_redirects=False).status_code == 200
        other_resp = other.get("/profile", follow_redirects=False)
        assert other_resp.status_code == 302
        assert "/login" in other_resp.headers["Location"]
        with app.app_context():
            active = UserSession.query.filter_by(user_id=pw_user, revoked=False).count()
            assert active == 1


# ---------------------------------------------------------------------------
# Key-regeneration guard
# ---------------------------------------------------------------------------


class TestCiphertextExistsCoversEverything:
    def test_sudo_password_only_credential_counts(self, app):
        from auth.credential_store import _ciphertext_exists

        with app.app_context():
            cred = Credential(name="_leftover-sudo-only", username="ops", auth_type="key",
                              encrypted_value=encrypt("test-only-key"), encrypted_sudo_password=encrypt("test-only-sudo"))
            db.session.add(cred)
            db.session.commit()
            try:
                assert _ciphertext_exists() is True
            finally:
                db.session.delete(cred)
                db.session.commit()

    def test_encrypted_setting_counts(self, app):
        from auth.credential_store import _ciphertext_exists

        with app.app_context():
            Setting.set("_leftover_probe_token", encrypt("test-only-token"))
            try:
                assert _ciphertext_exists() is True
            finally:
                Setting.set("_leftover_probe_token", "")

    def test_query_failure_refuses_key_generation(self, app):
        from auth.credential_store import _ciphertext_exists

        with app.app_context(), patch("models.db.session.query", side_effect=RuntimeError("db down")):
            assert _ciphertext_exists() is True

    def test_missing_tables_still_allow_a_fresh_key(self, app):
        from auth.credential_store import _ciphertext_exists

        err = OperationalError("SELECT 1", {}, Exception("no such table"))
        with app.app_context(), patch("models.db.session.query", side_effect=err):
            assert _ciphertext_exists() is False


# ---------------------------------------------------------------------------
# /metrics token is header-only
# ---------------------------------------------------------------------------


class TestMetricsTokenHeaderOnly:
    @pytest.fixture(autouse=True)
    def _token(self, app):
        with app.app_context():
            Setting.set("prometheus_auth_token", encrypt("test-only-scrape-token"))
        yield
        with app.app_context():
            Setting.set("prometheus_auth_token", "")

    def test_query_param_no_longer_authenticates(self, client):
        assert client.get("/metrics?token=test-only-scrape-token").status_code == 401

    def test_bearer_header_still_works(self, client):
        assert client.get("/metrics", headers={"Authorization": "Bearer test-only-scrape-token"}).status_code == 200


# ---------------------------------------------------------------------------
# Unacknowledged alerts expire
# ---------------------------------------------------------------------------


class TestUnacknowledgedAlertsExpire:
    def test_old_unacknowledged_alert_is_pruned(self, app):
        from core.moderation_watch import _prune

        now = datetime.now(timezone.utc)
        with app.app_context():
            old = ModerationAlert(kind="watched_post", dedupe_key="_leftover-old", mastodon_account_id="1",
                                  acct="a@b", created_at=now - timedelta(days=400))
            fresh = ModerationAlert(kind="watched_post", dedupe_key="_leftover-fresh", mastodon_account_id="1",
                                    acct="a@b", created_at=now - timedelta(days=5))
            db.session.add_all([old, fresh])
            db.session.commit()
            try:
                _prune(now)
                assert ModerationAlert.query.filter_by(dedupe_key="_leftover-old").first() is None
                assert ModerationAlert.query.filter_by(dedupe_key="_leftover-fresh").first() is not None
            finally:
                ModerationAlert.query.filter(ModerationAlert.dedupe_key.like("_leftover-%")).delete(
                    synchronize_session=False)
                db.session.commit()


# ---------------------------------------------------------------------------
# create-ct.sh
# ---------------------------------------------------------------------------


class TestCreateCtScript:
    SCRIPT = os.path.join(SCRIPTS, "create-ct.sh")

    def _read(self):
        with open(self.SCRIPT, encoding="utf-8") as f:
            return f.read()

    def test_root_password_not_echoed(self):
        src = self._read()
        assert 'echo " Root Password: $CT_ROOT_PASS"' not in src
        assert "umask 077" in src
        assert 'printf \'%s\\n\' "$CT_ROOT_PASS" > "$CT_PASS_FILE"' in src

    def test_app_password_hint_points_at_the_file_not_journald(self):
        src = self._read()
        line = [ln for ln in src.splitlines() if "App Password:" in ln and "echo" in ln][0]
        assert "journalctl" not in line
        assert "initial-admin-password" in line

    @pytest.mark.skipif(sys.platform == "win32", reason="bash -n via WSL is covered by CI's shellcheck")
    def test_bash_syntax(self):
        result = subprocess.run(["bash", "-n", self.SCRIPT], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
