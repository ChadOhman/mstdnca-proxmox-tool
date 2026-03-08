"""Tests for Moderation routes and core logic."""

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
        from models import db, User, Role

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
            "peertube_api_token": "test-token-123",
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
            assert stored_token != "test-token-123"
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
        from models import Setting
        from core.moderation import fetch_mastodon_emails

        with app.app_context():
            Setting.set("mastodon_db_guest_id", "")
            emails, err = fetch_mastodon_emails()
            assert emails is None
            assert "not configured" in err

    def test_guest_not_found(self, app):
        from models import Setting
        from core.moderation import fetch_mastodon_emails

        with app.app_context():
            Setting.set("mastodon_db_guest_id", "99999")
            emails, err = fetch_mastodon_emails()
            assert emails is None
            assert "not found" in err

    @patch("clients.ssh_client.SSHClient")
    def test_success(self, mock_ssh_class, app):
        from models import Setting, Guest, Credential, db as _db
        from core.moderation import fetch_mastodon_emails
        from auth.credential_store import encrypt

        with app.app_context():
            cred = Credential(
                name="_mod_test_cred",
                username="root",
                encrypted_value=encrypt("password123"),
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
        from models import Setting, Guest, Credential, db as _db
        from core.moderation import fetch_mastodon_emails
        from auth.credential_store import encrypt

        with app.app_context():
            cred = Credential(
                name="_mod_test_cred2",
                username="root",
                encrypted_value=encrypt("password123"),
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

        users, err = fetch_peertube_users("https://pt.example.com", "token123")
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

        users, err = fetch_peertube_users("https://pt.example.com", "token123")
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

        ok, err = ban_peertube_user("https://pt.example.com", "token", 5, "test ban")
        assert ok is True
        assert err is None

    @patch("core.moderation.urllib.request.urlopen")
    def test_failure(self, mock_urlopen):
        import urllib.error
        from core.moderation import ban_peertube_user

        mock_urlopen.side_effect = urllib.error.HTTPError(
            "https://pt.example.com/api/v1/users/5/block", 403, "Forbidden", {}, None
        )
        ok, err = ban_peertube_user("https://pt.example.com", "token", 5)
        assert ok is False
        assert "403" in err


class TestRunModerationCheck:
    """Tests for core.moderation.run_moderation_check()."""

    @patch("auth.audit.log_action")
    @patch("core.moderation.ban_peertube_user")
    @patch("core.moderation.fetch_peertube_users")
    @patch("core.moderation.fetch_mastodon_emails")
    def test_all_matched(self, mock_masto, mock_pt, mock_ban, _mock_audit, app):
        from models import Setting
        from auth.credential_store import encrypt
        from core.moderation import run_moderation_check

        with app.app_context():
            Setting.set("moderation_peertube_api_url", "https://pt.example.com")
            Setting.set("moderation_peertube_api_token", encrypt("token"))
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
        from models import Setting
        from auth.credential_store import encrypt
        from core.moderation import run_moderation_check

        with app.app_context():
            Setting.set("moderation_peertube_api_url", "https://pt.example.com")
            Setting.set("moderation_peertube_api_token", encrypt("token"))
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
        from models import Setting
        from auth.credential_store import encrypt
        from core.moderation import run_moderation_check

        with app.app_context():
            Setting.set("moderation_peertube_api_url", "https://pt.example.com")
            Setting.set("moderation_peertube_api_token", encrypt("token"))
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
        from models import Setting
        from auth.credential_store import encrypt
        from core.moderation import run_moderation_check

        with app.app_context():
            Setting.set("moderation_peertube_api_url", "https://pt.example.com")
            Setting.set("moderation_peertube_api_token", encrypt("token"))

            mock_masto.return_value = (None, "SSH connection failed")

            ok, result = run_moderation_check()
            assert ok is False
            assert "SSH connection failed" in result["errors"]
            mock_pt.assert_not_called()

    def test_missing_config(self, app):
        from models import Setting
        from core.moderation import run_moderation_check

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
        from models import Setting
        from auth.credential_store import encrypt
        from core.moderation import run_moderation_check

        with app.app_context():
            Setting.set("moderation_peertube_api_url", "https://pt.example.com")
            Setting.set("moderation_peertube_api_token", encrypt("token"))
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
        from models import Setting
        from core.scheduler import _run_moderation_check

        with app.app_context():
            Setting.set("moderation_auto_ban_enabled", "false")

        _run_moderation_check(app)
        mock_run.assert_not_called()

    @patch("core.moderation.run_moderation_check")
    def test_skipped_when_no_url(self, mock_run, app):
        from models import Setting
        from core.scheduler import _run_moderation_check

        with app.app_context():
            Setting.set("moderation_auto_ban_enabled", "true")
            Setting.set("moderation_peertube_api_url", "")

        _run_moderation_check(app)
        mock_run.assert_not_called()

    @patch("core.moderation.run_moderation_check")
    def test_runs_when_enabled(self, mock_run, app):
        from models import Setting
        from core.scheduler import _run_moderation_check

        mock_run.return_value = (True, {"unmatched": []})

        with app.app_context():
            Setting.set("moderation_auto_ban_enabled", "true")
            Setting.set("moderation_peertube_api_url", "https://pt.example.com")

        _run_moderation_check(app)
        mock_run.assert_called_once()
