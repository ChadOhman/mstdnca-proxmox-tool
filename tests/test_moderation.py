"""Tests for Moderation routes and core logic."""

import base64
import json
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Route tests — authentication
# ---------------------------------------------------------------------------


class TestModerationRouteAuth:
    """Moderation routes require authentication."""

    def test_index_unauthenticated(self, client):
        resp = client.get("/moderation/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers.get("Location", "")

    def test_save_unauthenticated(self, client):
        resp = client.post("/moderation/save", follow_redirects=False)
        assert resp.status_code == 302

    def test_run_unauthenticated(self, client):
        resp = client.post("/moderation/run", follow_redirects=False)
        assert resp.status_code == 302

    def test_status_unauthenticated(self, client):
        resp = client.get("/moderation/status", follow_redirects=False)
        assert resp.status_code == 302


# ---------------------------------------------------------------------------
# Route tests — permission denied for viewer
# ---------------------------------------------------------------------------


class TestModerationRouteViewer:
    """Viewer users (can_moderate=False) should be denied access."""

    def test_viewer_denied_index(self, app, client):
        from models import Role, User, db

        with app.app_context():
            viewer_role = Role.query.filter_by(name="viewer").first()
            user = User(
                username="_mod_test_viewer",
                display_name="Mod Viewer",
                role_id=viewer_role.id,
            )
            user.set_password("ViewerPass123!")
            db.session.add(user)
            db.session.commit()

        try:
            client.post(
                "/login",
                data={"username": "_mod_test_viewer", "password": "ViewerPass123!"},
                follow_redirects=False,
            )
            resp = client.get("/moderation/", follow_redirects=False)
            assert resp.status_code == 302
            location = resp.headers.get("Location", "")
            assert "/moderation" not in location
        finally:
            with app.app_context():
                User.query.filter_by(username="_mod_test_viewer").delete()
                db.session.commit()


# ---------------------------------------------------------------------------
# Route tests — authenticated admin
# ---------------------------------------------------------------------------


class TestModerationRouteAuthed:
    """Admin users (can_moderate=True) can access moderation routes."""

    def test_index_loads(self, auth_client):
        resp = auth_client.get("/moderation/")
        assert resp.status_code == 200
        assert b"Moderation" in resp.data
        assert b"PeerTube" in resp.data

    def test_status_returns_json(self, auth_client):
        resp = auth_client.get("/moderation/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data
        assert "success" in data
        assert "log" in data

    def test_save_settings(self, app, auth_client):
        from models import Setting

        resp = auth_client.post("/moderation/save", data={
            "peertube_api_url": "https://pt.example.com",
            "peertube_api_token": "test-only-pt-token",
            "check_interval_hours": "12",
            "auto_ban_enabled": "on",
        }, follow_redirects=False)
        assert resp.status_code == 302

        with app.app_context():
            assert Setting.get("moderation_peertube_api_url") == "https://pt.example.com"
            assert Setting.get("moderation_check_interval_hours") == "12"
            assert Setting.get("moderation_auto_ban_enabled") == "true"
            # Token should be encrypted (not plaintext)
            stored_token = Setting.get("moderation_peertube_api_token")
            assert stored_token != "test-only-pt-token"
            assert stored_token  # not empty

    def test_save_settings_auto_ban_off(self, app, auth_client):
        from models import Setting

        auth_client.post("/moderation/save", data={
            "peertube_api_url": "https://pt.example.com",
            "check_interval_hours": "24",
            # auto_ban_enabled not present = checkbox unchecked
        }, follow_redirects=False)

        with app.app_context():
            assert Setting.get("moderation_auto_ban_enabled") == "false"


# ---------------------------------------------------------------------------
# Core logic tests
# ---------------------------------------------------------------------------


class TestFetchMastodonEmails:
    """Tests for core.moderation.fetch_mastodon_emails()."""

    def test_missing_db_guest_setting(self, app):
        from core.moderation import fetch_mastodon_emails
        from models import Setting

        with app.app_context():
            Setting.set("mastodon_db_guest_id", "")
            emails, err = fetch_mastodon_emails()
            assert emails is None
            assert "not configured" in err

    def test_guest_not_found(self, app):
        from core.moderation import fetch_mastodon_emails
        from models import Setting

        with app.app_context():
            Setting.set("mastodon_db_guest_id", "99999")
            emails, err = fetch_mastodon_emails()
            assert emails is None
            assert "not found" in err

    @patch("clients.ssh_client.SSHClient")
    def test_success(self, mock_ssh_class, app):
        from auth.credential_store import encrypt
        from core.moderation import fetch_mastodon_emails
        from models import Credential, Guest, Setting
        from models import db as _db

        with app.app_context():
            cred = Credential(
                name="_mod_test_cred",
                username="root",
                encrypted_value=encrypt("test-only-ssh-password"),
            )
            _db.session.add(cred)
            _db.session.flush()

            guest = Guest(
                name="_mod_test_db_guest",
                guest_type="ct",
                ip_address="10.0.0.50",
                credential_id=cred.id,
            )
            _db.session.add(guest)
            _db.session.commit()
            Setting.set("mastodon_db_guest_id", str(guest.id))

            mock_ssh = MagicMock()
            mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
            mock_ssh.__exit__ = MagicMock(return_value=False)
            mock_ssh_class.from_credential.return_value = mock_ssh
            mock_ssh.execute_sudo.return_value = (
                "alice@example.com\nBob@Example.COM\ncharlie@test.org\n",
                "",
                0,
            )

            emails, err = fetch_mastodon_emails()
            assert err is None
            assert emails == {"alice@example.com", "bob@example.com", "charlie@test.org"}

            # Cleanup
            _db.session.delete(guest)
            _db.session.delete(cred)
            _db.session.commit()

    @patch("clients.ssh_client.SSHClient")
    def test_psql_failure(self, mock_ssh_class, app):
        from auth.credential_store import encrypt
        from core.moderation import fetch_mastodon_emails
        from models import Credential, Guest, Setting
        from models import db as _db

        with app.app_context():
            cred = Credential(
                name="_mod_test_cred2",
                username="root",
                encrypted_value=encrypt("test-only-ssh-password"),
            )
            _db.session.add(cred)
            _db.session.flush()

            guest = Guest(
                name="_mod_test_db_guest2",
                guest_type="ct",
                ip_address="10.0.0.51",
                credential_id=cred.id,
            )
            _db.session.add(guest)
            _db.session.commit()
            Setting.set("mastodon_db_guest_id", str(guest.id))

            mock_ssh = MagicMock()
            mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
            mock_ssh.__exit__ = MagicMock(return_value=False)
            mock_ssh_class.from_credential.return_value = mock_ssh
            mock_ssh.execute_sudo.return_value = ("", "connection refused", 1)

            emails, err = fetch_mastodon_emails()
            assert emails is None
            assert "psql query failed" in err

            _db.session.delete(guest)
            _db.session.delete(cred)
            _db.session.commit()


class TestFetchPeertubeUsers:
    """Tests for core.moderation.fetch_peertube_users()."""

    @patch("core.moderation.urllib.request.urlopen")
    def test_success_single_page(self, mock_urlopen):
        from core.moderation import fetch_peertube_users

        response_data = json.dumps({
            "total": 2,
            "data": [
                {"id": 1, "username": "admin", "email": "admin@pt.com", "role": {"id": 0}},
                {"id": 2, "username": "user1", "email": "User1@PT.COM", "role": {"id": 2}},
            ],
        }).encode()

        mock_resp = MagicMock()
        mock_resp.read.return_value = response_data
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        users, err = fetch_peertube_users("https://pt.example.com", "test-only-pt-token")
        assert err is None
        assert len(users) == 2
        assert users[0]["role"] == 0
        assert users[1]["email"] == "user1@pt.com"  # lowercased

    @patch("core.moderation.urllib.request.urlopen")
    def test_pagination(self, mock_urlopen):
        from core.moderation import fetch_peertube_users

        page1 = json.dumps({
            "total": 150,
            "data": [{"id": i, "username": f"u{i}", "email": f"u{i}@pt.com", "role": {"id": 2}}
                      for i in range(100)],
        }).encode()
        page2 = json.dumps({
            "total": 150,
            "data": [{"id": i, "username": f"u{i}", "email": f"u{i}@pt.com", "role": {"id": 2}}
                      for i in range(100, 150)],
        }).encode()

        mock_resp1 = MagicMock()
        mock_resp1.read.return_value = page1
        mock_resp1.__enter__ = MagicMock(return_value=mock_resp1)
        mock_resp1.__exit__ = MagicMock(return_value=False)

        mock_resp2 = MagicMock()
        mock_resp2.read.return_value = page2
        mock_resp2.__enter__ = MagicMock(return_value=mock_resp2)
        mock_resp2.__exit__ = MagicMock(return_value=False)

        mock_urlopen.side_effect = [mock_resp1, mock_resp2]

        users, err = fetch_peertube_users("https://pt.example.com", "test-only-pt-token")
        assert err is None
        assert len(users) == 150

    @patch("core.moderation.urllib.request.urlopen")
    def test_api_error(self, mock_urlopen):
        import urllib.error

        from core.moderation import fetch_peertube_users

        mock_urlopen.side_effect = urllib.error.HTTPError(
            "https://pt.example.com/api/v1/users", 401, "Unauthorized", {}, None
        )
        users, err = fetch_peertube_users("https://pt.example.com", "bad-token")
        assert users is None
        assert "401" in err


class TestBanPeertubeUser:
    """Tests for core.moderation.ban_peertube_user()."""

    @patch("core.moderation.urllib.request.urlopen")
    def test_success(self, mock_urlopen):
        from core.moderation import ban_peertube_user

        mock_resp = MagicMock()
        mock_resp.status = 204
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        ok, err = ban_peertube_user("https://pt.example.com", "test-only-token", 5, "test ban")
        assert ok is True
        assert err is None

    @patch("core.moderation.urllib.request.urlopen")
    def test_failure(self, mock_urlopen):
        import urllib.error

        from core.moderation import ban_peertube_user

        mock_urlopen.side_effect = urllib.error.HTTPError(
            "https://pt.example.com/api/v1/users/5/block", 403, "Forbidden", {}, None
        )
        ok, err = ban_peertube_user("https://pt.example.com", "test-only-token", 5)
        assert ok is False
        assert "403" in err


class TestRunModerationCheck:
    """Tests for core.moderation.run_moderation_check()."""

    @patch("auth.audit.log_action")
    @patch("core.moderation.ban_peertube_user")
    @patch("core.moderation.fetch_peertube_users")
    @patch("core.moderation.fetch_mastodon_emails")
    def test_all_matched(self, mock_masto, mock_pt, mock_ban, _mock_audit, app):
        from auth.credential_store import encrypt
        from core.moderation import run_moderation_check
        from models import Setting

        with app.app_context():
            Setting.set("moderation_peertube_api_url", "https://pt.example.com")
            Setting.set("moderation_peertube_api_token", encrypt("test-only-token"))
            Setting.set("moderation_auto_ban_enabled", "true")

            mock_masto.return_value = ({"alice@example.com", "bob@example.com"}, None)
            mock_pt.return_value = ([
                {"id": 1, "username": "admin", "email": "admin@pt.com", "role": 0},
                {"id": 2, "username": "alice", "email": "alice@example.com", "role": 2},
                {"id": 3, "username": "bob", "email": "bob@example.com", "role": 2},
            ], None)

            ok, result = run_moderation_check()
            assert ok is True
            assert result["matched"] == 2
            assert len(result["unmatched"]) == 0
            assert result["skipped_admins"] == 1
            mock_ban.assert_not_called()

    @patch("auth.audit.log_action")
    @patch("core.moderation.ban_peertube_user")
    @patch("core.moderation.fetch_peertube_users")
    @patch("core.moderation.fetch_mastodon_emails")
    def test_unmatched_with_auto_ban(self, mock_masto, mock_pt, mock_ban, _mock_audit, app):
        from auth.credential_store import encrypt
        from core.moderation import run_moderation_check
        from models import Setting

        with app.app_context():
            Setting.set("moderation_peertube_api_url", "https://pt.example.com")
            Setting.set("moderation_peertube_api_token", encrypt("test-only-token"))
            Setting.set("moderation_auto_ban_enabled", "true")

            mock_masto.return_value = ({"alice@example.com"}, None)
            mock_pt.return_value = ([
                {"id": 2, "username": "alice", "email": "alice@example.com", "role": 2},
                {"id": 3, "username": "spammer", "email": "spam@evil.com", "role": 2},
            ], None)
            mock_ban.return_value = (True, None)

            ok, result = run_moderation_check()
            assert ok is True
            assert result["matched"] == 1
            assert len(result["unmatched"]) == 1
            assert result["unmatched"][0]["username"] == "spammer"
            assert result["unmatched"][0]["banned"] is True
            mock_ban.assert_called_once()

    @patch("auth.audit.log_action")
    @patch("core.moderation.ban_peertube_user")
    @patch("core.moderation.fetch_peertube_users")
    @patch("core.moderation.fetch_mastodon_emails")
    def test_unmatched_auto_ban_disabled(self, mock_masto, mock_pt, mock_ban, _mock_audit, app):
        from auth.credential_store import encrypt
        from core.moderation import run_moderation_check
        from models import Setting

        with app.app_context():
            Setting.set("moderation_peertube_api_url", "https://pt.example.com")
            Setting.set("moderation_peertube_api_token", encrypt("test-only-token"))
            Setting.set("moderation_auto_ban_enabled", "false")

            mock_masto.return_value = ({"alice@example.com"}, None)
            mock_pt.return_value = ([
                {"id": 2, "username": "alice", "email": "alice@example.com", "role": 2},
                {"id": 3, "username": "spammer", "email": "spam@evil.com", "role": 2},
            ], None)

            ok, result = run_moderation_check()
            assert ok is True
            assert len(result["unmatched"]) == 1
            assert result["unmatched"][0]["banned"] is False
            mock_ban.assert_not_called()

    @patch("auth.audit.log_action")
    @patch("core.moderation.fetch_peertube_users")
    @patch("core.moderation.fetch_mastodon_emails")
    def test_mastodon_fetch_error(self, mock_masto, mock_pt, _mock_audit, app):
        from auth.credential_store import encrypt
        from core.moderation import run_moderation_check
        from models import Setting

        with app.app_context():
            Setting.set("moderation_peertube_api_url", "https://pt.example.com")
            Setting.set("moderation_peertube_api_token", encrypt("test-only-token"))

            mock_masto.return_value = (None, "SSH connection failed")

            ok, result = run_moderation_check()
            assert ok is False
            assert "SSH connection failed" in result["errors"]
            mock_pt.assert_not_called()

    def test_missing_config(self, app):
        from core.moderation import run_moderation_check
        from models import Setting

        with app.app_context():
            Setting.set("moderation_peertube_api_url", "")
            Setting.set("moderation_peertube_api_token", "")

            ok, result = run_moderation_check()
            assert ok is False
            assert result["errors"]

    @patch("auth.audit.log_action")
    @patch("core.moderation.ban_peertube_user")
    @patch("core.moderation.fetch_peertube_users")
    @patch("core.moderation.fetch_mastodon_emails")
    def test_skips_admin_users(self, mock_masto, mock_pt, mock_ban, _mock_audit, app):
        """PeerTube admin users (role=0) should never be banned."""
        from auth.credential_store import encrypt
        from core.moderation import run_moderation_check
        from models import Setting

        with app.app_context():
            Setting.set("moderation_peertube_api_url", "https://pt.example.com")
            Setting.set("moderation_peertube_api_token", encrypt("test-only-token"))
            Setting.set("moderation_auto_ban_enabled", "true")

            # Admin email is NOT in mastodon, but should still be skipped
            mock_masto.return_value = ({"alice@example.com"}, None)
            mock_pt.return_value = ([
                {"id": 1, "username": "admin", "email": "admin@pt.com", "role": 0},
            ], None)

            ok, result = run_moderation_check()
            assert ok is True
            assert result["skipped_admins"] == 1
            assert len(result["unmatched"]) == 0
            mock_ban.assert_not_called()


# ---------------------------------------------------------------------------
# Scheduler integration test
# ---------------------------------------------------------------------------


class TestModerationScheduler:
    """Test the scheduler function for moderation checks."""

    @patch("core.moderation.run_moderation_check")
    def test_skipped_when_disabled(self, mock_run, app):
        from core.scheduler import _run_moderation_check
        from models import Setting

        with app.app_context():
            Setting.set("moderation_auto_ban_enabled", "false")

        _run_moderation_check(app)
        mock_run.assert_not_called()

    @patch("core.moderation.run_moderation_check")
    def test_skipped_when_no_url(self, mock_run, app):
        from core.scheduler import _run_moderation_check
        from models import Setting

        with app.app_context():
            Setting.set("moderation_auto_ban_enabled", "true")
            Setting.set("moderation_peertube_api_url", "")

        _run_moderation_check(app)
        mock_run.assert_not_called()

    @patch("core.moderation.run_moderation_check")
    def test_runs_when_enabled(self, mock_run, app):
        from core.scheduler import _run_moderation_check
        from models import Setting

        mock_run.return_value = (True, {"unmatched": []})

        with app.app_context():
            Setting.set("moderation_auto_ban_enabled", "true")
            Setting.set("moderation_peertube_api_url", "https://pt.example.com")

        _run_moderation_check(app)
        mock_run.assert_called_once()


# ---------------------------------------------------------------------------
# Security: SQL/command injection via mastodon_db_name (B1)
# ---------------------------------------------------------------------------


def _make_db_guest(app):
    """Create a Mastodon DB guest + credential and point the setting at it."""
    from auth.credential_store import encrypt
    from models import Credential, Guest, Setting
    from models import db as _db

    cred = Credential(
        name="_mod_inj_cred",
        username="root",
        encrypted_value=encrypt("test-only-ssh-password"),
    )
    _db.session.add(cred)
    _db.session.flush()
    guest = Guest(
        name="_mod_inj_db_guest",
        guest_type="ct",
        ip_address="10.0.0.60",
        credential_id=cred.id,
    )
    _db.session.add(guest)
    _db.session.commit()
    Setting.set("mastodon_db_guest_id", str(guest.id))
    return guest, cred


def _cleanup_db_guest(guest, cred):
    from models import db as _db
    _db.session.delete(guest)
    _db.session.delete(cred)
    _db.session.commit()


class TestMastodonEmailInjection:
    """The Mastodon email query must not be vulnerable to shell/SQL injection
    through the operator-controlled mastodon_db_name setting (B1)."""

    @patch("clients.ssh_client.SSHClient")
    def test_malicious_db_name_rejected(self, mock_ssh_class, app):
        """A db_name carrying shell metacharacters is rejected before any SSH
        command is constructed or executed."""
        from core.moderation import fetch_mastodon_emails
        from models import Setting

        with app.app_context():
            guest, cred = _make_db_guest(app)
            try:
                # Classic injection payload that would break out of the old
                # nested-quoted `-c "..."` string and run as root-via-postgres.
                Setting.set("mastodon_db_name", 'x"; rm -rf / #')

                emails, err = fetch_mastodon_emails()

                assert emails is None
                assert "unsafe characters" in err
                # No command should ever have been sent over SSH.
                mock_ssh_class.from_credential.assert_not_called()
            finally:
                _cleanup_db_guest(guest, cred)

    @patch("clients.ssh_client.SSHClient")
    def test_legit_db_name_uses_base64_stdin_transport(self, mock_ssh_class, app):
        """A legitimate db_name works, and the SELECT is transported as a base64
        blob piped to psql stdin — the SQL never appears verbatim in a shell
        metacharacter position, so metacharacters (if any) stay inert."""
        from core.moderation import fetch_mastodon_emails
        from models import Setting

        with app.app_context():
            guest, cred = _make_db_guest(app)
            try:
                Setting.set("mastodon_db_name", "mastodon_production")

                mock_ssh = MagicMock()
                mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
                mock_ssh.__exit__ = MagicMock(return_value=False)
                mock_ssh_class.from_credential.return_value = mock_ssh
                mock_ssh.execute_sudo.return_value = ("alice@example.com\n", "", 0)

                emails, err = fetch_mastodon_emails()

                assert err is None
                assert emails == {"alice@example.com"}

                # Inspect the exact command that would run on the guest.
                cmd = mock_ssh.execute_sudo.call_args[0][0]
                # Transported via base64 → psql stdin (mirrors apps/peertube.py).
                assert "base64 -d" in cmd
                assert "su - postgres -c 'psql" in cmd
                assert "-f -" in cmd
                # The raw SELECT text is NOT interpolated into the shell command.
                assert "SELECT email FROM users" not in cmd
                # The db name is present as the -d argument (validated as safe).
                assert "-d mastodon_production" in cmd
                # The base64 blob decodes back to the real SELECT statement.
                b64 = cmd.split("printf '%s' '", 1)[1].split("'", 1)[0]
                decoded = base64.b64decode(b64).decode()
                assert decoded.startswith("SELECT email FROM users")
            finally:
                _cleanup_db_guest(guest, cred)


# ---------------------------------------------------------------------------
# Security: no email PII persisted to the Setting store (H1)
# ---------------------------------------------------------------------------


class TestModerationResultNoPIIPersisted:
    """run_moderation_check must not write raw emails into the general Setting
    KV store (which has no field-level access control and feeds config export)."""

    @patch("auth.audit.log_action")
    @patch("core.moderation.ban_peertube_user")
    @patch("core.moderation.fetch_peertube_users")
    @patch("core.moderation.fetch_mastodon_emails")
    def test_persisted_result_has_no_emails(self, mock_masto, mock_pt, mock_ban, _mock_audit, app):
        from auth.credential_store import encrypt
        from core.moderation import run_moderation_check
        from models import Setting

        with app.app_context():
            Setting.set("moderation_peertube_api_url", "https://pt.example.com")
            Setting.set("moderation_peertube_api_token", encrypt("test-only-token"))
            Setting.set("moderation_auto_ban_enabled", "false")

            secret_email = "spammer@secret-domain.example"
            mock_masto.return_value = ({"alice@example.com"}, None)
            mock_pt.return_value = ([
                {"id": 2, "username": "alice", "email": "alice@example.com", "role": 2},
                {"id": 3, "username": "spammer", "email": secret_email, "role": 2},
            ], None)

            ok, result = run_moderation_check()
            assert ok is True

            # The live/transient result still carries emails for the admin view.
            assert any(e.get("email") == secret_email for e in result["unmatched"])

            # The persisted Setting must contain NO email addresses at all.
            persisted_raw = Setting.get("moderation_last_check_result", "")
            assert secret_email not in persisted_raw
            assert "alice@example.com" not in persisted_raw
            assert "@" not in persisted_raw

            persisted = json.loads(persisted_raw)
            for entry in persisted["unmatched"]:
                assert "email" not in entry
                # Non-PII fields are retained.
                assert "id" in entry
                assert "username" in entry
            mock_ban.assert_not_called()

    @patch("auth.audit.log_action")
    @patch("core.moderation.fetch_peertube_users")
    @patch("core.moderation.fetch_mastodon_emails")
    def test_status_log_has_no_emails(self, mock_masto, mock_pt, _mock_audit, app):
        """Log lines (surfaced via /status) must reference users by id/username,
        never by email."""
        from auth.credential_store import encrypt
        from core.moderation import run_moderation_check
        from models import Setting

        with app.app_context():
            Setting.set("moderation_peertube_api_url", "https://pt.example.com")
            Setting.set("moderation_peertube_api_token", encrypt("test-only-token"))
            Setting.set("moderation_auto_ban_enabled", "false")

            secret_email = "leak@secret-domain.example"
            mock_masto.return_value = ({"alice@example.com"}, None)
            mock_pt.return_value = ([
                {"id": 9, "username": "spammer", "email": secret_email, "role": 2},
            ], None)

            captured = []
            ok, _result = run_moderation_check(log_callback=captured.append)
            assert ok is True
            assert all(secret_email not in line for line in captured)


# ---------------------------------------------------------------------------
# Security: moderation routes require admin tier (H2)
# ---------------------------------------------------------------------------


class TestModerationAdminGate:
    """can_moderate alone must not unlock moderation for a non-admin user."""

    def _make_non_admin_moderator(self, app):
        """Create an operator-tier role with can_moderate=True and a user in it."""
        from models import Role, User, db

        with app.app_context():
            mod_role = Role(
                name="_mod_test_operator_mod",
                display_name="Operator+Moderate",
                level=2,  # below admin tier (3)
                is_builtin=False,
                can_moderate=True,
            )
            db.session.add(mod_role)
            db.session.flush()
            user = User(
                username="_mod_test_nonadmin",
                display_name="Non-admin Moderator",
                role_id=mod_role.id,
            )
            user.set_password("TestPass123!")
            db.session.add(user)
            db.session.commit()

    def _cleanup(self, app):
        from models import Role, User, db
        with app.app_context():
            User.query.filter_by(username="_mod_test_nonadmin").delete()
            Role.query.filter_by(name="_mod_test_operator_mod").delete()
            db.session.commit()

    def test_non_admin_with_can_moderate_denied_all_routes(self, app, client):
        self._make_non_admin_moderator(app)
        try:
            client.post(
                "/login",
                data={"username": "_mod_test_nonadmin", "password": "TestPass123!"},
                follow_redirects=False,
            )
            for method, path in [
                ("get", "/moderation/"),
                ("post", "/moderation/run"),
                ("get", "/moderation/status"),
                ("post", "/moderation/save"),
            ]:
                resp = getattr(client, method)(path, follow_redirects=False)
                # before_request redirects away from the moderation blueprint.
                assert resp.status_code == 302, f"{method} {path} not denied"
                assert "/moderation" not in resp.headers.get("Location", ""), \
                    f"{method} {path} was allowed for a non-admin moderator"
        finally:
            self._cleanup(app)
