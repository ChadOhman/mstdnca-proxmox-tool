"""Tests for PeerTube upgrade routes and scheduler integration."""
import sys
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Helpers (mirror test_scheduler.py patterns)
# ---------------------------------------------------------------------------

def _make_app(config=None):
    """Return a minimal Flask-like app mock with working app_context()."""
    app = MagicMock()
    app.config = config or {}
    ctx = MagicMock()
    ctx.__enter__ = MagicMock(return_value=ctx)
    ctx.__exit__ = MagicMock(return_value=False)
    app.app_context.return_value = ctx
    return app


class _SysModulesPatch:
    """Context-manager: temporarily inject mock modules into sys.modules."""

    def __init__(self, mocks: dict):
        self._mocks = mocks
        self._saved = {}

    def __enter__(self):
        for name, mock in self._mocks.items():
            self._saved[name] = sys.modules.get(name)
            sys.modules[name] = mock
        return self

    def __exit__(self, *_):
        for name, original in self._saved.items():
            if original is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original


# ---------------------------------------------------------------------------
# Route tests
# ---------------------------------------------------------------------------


class TestPeerTubeRouteAuth:
    """PeerTube routes require authentication and can_update permission."""

    def test_upgrade_page_unauthenticated(self, client):
        """Unauthenticated users are redirected to login."""
        resp = client.get("/peertube/upgrade", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers.get("Location", "")

    def test_save_unauthenticated(self, client):
        resp = client.post("/peertube/save", follow_redirects=False)
        assert resp.status_code == 302

    def test_check_unauthenticated(self, client):
        resp = client.post("/peertube/check", follow_redirects=False)
        assert resp.status_code == 302

    def test_detect_versions_unauthenticated(self, client):
        resp = client.post("/peertube/detect-versions", follow_redirects=False)
        assert resp.status_code == 302

    def test_preflight_unauthenticated(self, client):
        resp = client.post("/peertube/preflight", follow_redirects=False)
        assert resp.status_code == 302

    def test_upgrade_post_unauthenticated(self, client):
        resp = client.post("/peertube/upgrade", follow_redirects=False)
        assert resp.status_code == 302

    def test_upgrade_status_unauthenticated(self, client):
        resp = client.get("/peertube/upgrade/status", follow_redirects=False)
        assert resp.status_code == 302

    def test_preflight_status_unauthenticated(self, client):
        resp = client.get("/peertube/preflight/status", follow_redirects=False)
        assert resp.status_code == 302

    def test_install_post_unauthenticated(self, client):
        resp = client.post("/peertube/install", follow_redirects=False)
        assert resp.status_code == 302

    def test_install_status_unauthenticated(self, client):
        resp = client.get("/peertube/install/status", follow_redirects=False)
        assert resp.status_code == 302


class TestPeerTubeRouteViewer:
    """Viewer users (can_update=False) should be denied access."""

    def test_viewer_denied_upgrade_page(self, app, client):
        from models import Role, User, db

        with app.app_context():
            viewer_role = Role.query.filter_by(name="viewer").first()
            user = User(
                username="_pt_test_viewer",
                display_name="PT Viewer",
                role_id=viewer_role.id,
            )
            user.set_password("ViewerPass123!")
            db.session.add(user)
            db.session.commit()

        try:
            client.post(
                "/login",
                data={"username": "_pt_test_viewer", "password": "ViewerPass123!"},
                follow_redirects=False,
            )
            resp = client.get("/peertube/upgrade", follow_redirects=False)
            # Should redirect to dashboard with permission denied
            assert resp.status_code == 302
            location = resp.headers.get("Location", "")
            assert "/peertube" not in location
        finally:
            with app.app_context():
                User.query.filter_by(username="_pt_test_viewer").delete()
                db.session.commit()


class TestPeerTubeRouteAuthed:
    """Admin users (can_update=True) can access PeerTube routes."""

    def test_upgrade_page_loads(self, auth_client):
        """Authenticated admin can load the upgrade page."""
        resp = auth_client.get("/peertube/upgrade")
        assert resp.status_code == 200
        assert b"PeerTube" in resp.data

    def test_upgrade_status_returns_json(self, auth_client):
        resp = auth_client.get("/peertube/upgrade/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data
        assert "success" in data
        assert "log" in data

    def test_preflight_status_returns_json(self, auth_client):
        resp = auth_client.get("/peertube/preflight/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data
        assert "success" in data
        assert "log" in data

    def test_install_status_returns_json(self, auth_client):
        resp = auth_client.get("/peertube/install/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data
        assert "success" in data
        assert "log" in data

    def test_save_persists_settings(self, app, auth_client):
        """POST /peertube/save persists all form fields to settings."""
        from models import Setting

        resp = auth_client.post(
            "/peertube/save",
            data={
                "peertube_guest_id": "99",
                "peertube_db_guest_id": "100",
                "peertube_user": "peertube",
                "peertube_db_name": "peertube_prod",
                "peertube_dir": "/var/www/peertube",
                "peertube_url": "https://videos.example.com",
                "peertube_current_version": "6.3.0",
                "peertube_auto_upgrade": "on",
                "peertube_protection_type": "snapshot",
                "peertube_backup_storage": "",
                "peertube_backup_mode": "snapshot",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            assert Setting.get("peertube_guest_id") == "99"
            assert Setting.get("peertube_db_guest_id") == "100"
            assert Setting.get("peertube_user") == "peertube"
            assert Setting.get("peertube_db_name") == "peertube_prod"
            assert Setting.get("peertube_dir") == "/var/www/peertube"
            assert Setting.get("peertube_url") == "https://videos.example.com"
            assert Setting.get("peertube_current_version") == "6.3.0"
            assert Setting.get("peertube_auto_upgrade") == "true"

    def test_save_defaults_user_and_dir(self, app, auth_client):
        """Empty user/dir fields get defaults."""
        from models import Setting

        auth_client.post(
            "/peertube/save",
            data={
                "peertube_guest_id": "",
                "peertube_db_guest_id": "",
                "peertube_user": "",
                "peertube_db_name": "",
                "peertube_dir": "",
                "peertube_url": "",
                "peertube_current_version": "",
                "peertube_protection_type": "snapshot",
            },
            follow_redirects=False,
        )
        with app.app_context():
            assert Setting.get("peertube_user") == "peertube"
            assert Setting.get("peertube_db_name") == "peertube"
            assert Setting.get("peertube_dir") == "/var/www/peertube"

    def test_save_validates_protection_type(self, app, auth_client):
        """Invalid protection type defaults to snapshot."""
        from models import Setting

        auth_client.post(
            "/peertube/save",
            data={
                "peertube_protection_type": "invalid",
            },
            follow_redirects=False,
        )
        with app.app_context():
            assert Setting.get("peertube_protection_type") == "snapshot"

    def test_save_validates_backup_mode(self, app, auth_client):
        """Invalid backup mode defaults to snapshot."""
        from models import Setting

        auth_client.post(
            "/peertube/save",
            data={
                "peertube_backup_mode": "invalid",
                "peertube_protection_type": "backup",
            },
            follow_redirects=False,
        )
        with app.app_context():
            assert Setting.get("peertube_backup_mode") == "snapshot"

    def test_save_persists_db_host(self, app, auth_client):
        """POST /peertube/save persists db_host field."""
        from models import Setting

        auth_client.post(
            "/peertube/save",
            data={
                "peertube_db_host": "10.0.0.5",
                "peertube_protection_type": "snapshot",
            },
            follow_redirects=False,
        )
        with app.app_context():
            assert Setting.get("peertube_db_host") == "10.0.0.5"

    def test_save_encrypts_db_password(self, app, auth_client):
        """POST /peertube/save encrypts the DB password."""
        from models import Setting

        auth_client.post(
            "/peertube/save",
            data={
                "peertube_db_password": "test-only-db-pass",
                "peertube_protection_type": "snapshot",
            },
            follow_redirects=False,
        )
        with app.app_context():
            stored = Setting.get("peertube_db_password", "")
            assert stored != ""
            assert stored != "test-only-db-pass"
            # Verify it can be decrypted back
            from auth.credential_store import decrypt
            assert decrypt(stored) == "test-only-db-pass"

    def test_save_keeps_existing_password_when_blank(self, app, auth_client):
        """Submitting blank password preserves existing encrypted value."""
        from auth.credential_store import encrypt
        from models import Setting

        with app.app_context():
            Setting.set("peertube_db_password", encrypt("existing"))
            from models import db
            db.session.commit()

        auth_client.post(
            "/peertube/save",
            data={
                "peertube_db_password": "",
                "peertube_protection_type": "snapshot",
            },
            follow_redirects=False,
        )
        with app.app_context():
            stored = Setting.get("peertube_db_password", "")
            from auth.credential_store import decrypt
            assert decrypt(stored) == "existing"

    def test_check_no_guest_configured(self, app, auth_client):
        """Check redirects even without configuration."""
        resp = auth_client.post("/peertube/check", follow_redirects=False)
        assert resp.status_code == 302

    def test_detect_versions_no_guest(self, app, auth_client):
        """Detect versions redirects when no guest configured."""
        from models import Setting

        with app.app_context():
            Setting.set("peertube_guest_id", "")
        resp = auth_client.post("/peertube/detect-versions", follow_redirects=False)
        assert resp.status_code == 302


# ---------------------------------------------------------------------------
# Applications index
# ---------------------------------------------------------------------------


class TestApplicationsIndex:
    """PeerTube appears on the applications index page."""

    def test_peertube_card_present(self, auth_client):
        resp = auth_client.get("/applications/")
        assert resp.status_code == 200
        assert b"PeerTube" in resp.data
        assert b"/peertube/upgrade" in resp.data


# ---------------------------------------------------------------------------
# Scheduler: _check_peertube_release
# ---------------------------------------------------------------------------


class TestCheckPeerTubeRelease:
    def test_returns_early_when_no_peertube_guest_configured(self):
        from core.scheduler import _check_peertube_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.return_value = ""
        mock_peertube = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "apps.peertube": mock_peertube,
        }
        with _SysModulesPatch(mocks):
            _check_peertube_release(app)

        mock_peertube.check_peertube_release.assert_not_called()

    def test_sends_notification_when_update_available(self):
        from core.scheduler import _check_peertube_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "peertube_guest_id": "42",
            "peertube_current_version": "6.2.0",
            "peertube_auto_upgrade": "false",
            "peertube_last_notified_version": "",
        }.get(k, d)

        mock_peertube = MagicMock()
        mock_peertube.check_peertube_release.return_value = (True, "6.3.0", "https://example.com")
        mock_notifier = MagicMock()
        mock_notifier.send_peertube_update_notification.return_value = (True, "ok")

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "apps.peertube": mock_peertube,
            "core.notifier": mock_notifier,
        }
        with _SysModulesPatch(mocks):
            _check_peertube_release(app)

        mock_notifier.send_peertube_update_notification.assert_called_once_with(
            "6.2.0", "6.3.0", "https://example.com"
        )

    def test_skips_notification_when_already_notified_for_version(self):
        from core.scheduler import _check_peertube_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "peertube_guest_id": "42",
            "peertube_current_version": "6.2.0",
            "peertube_auto_upgrade": "false",
            "peertube_last_notified_version": "6.3.0",
        }.get(k, d)

        mock_peertube = MagicMock()
        mock_peertube.check_peertube_release.return_value = (True, "6.3.0", "https://example.com")
        mock_notifier = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "apps.peertube": mock_peertube,
            "core.notifier": mock_notifier,
        }
        with _SysModulesPatch(mocks):
            _check_peertube_release(app)

        mock_notifier.send_peertube_update_notification.assert_not_called()

    def test_no_notification_when_no_update_available(self):
        from core.scheduler import _check_peertube_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.return_value = "42"
        mock_peertube = MagicMock()
        mock_peertube.check_peertube_release.return_value = (False, "6.2.0", "")
        mock_notifier = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "apps.peertube": mock_peertube,
            "core.notifier": mock_notifier,
        }
        with _SysModulesPatch(mocks):
            _check_peertube_release(app)

        mock_notifier.send_peertube_update_notification.assert_not_called()

    def test_auto_upgrade_triggered_when_enabled(self):
        from core.scheduler import _check_peertube_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "peertube_guest_id": "42",
            "peertube_current_version": "6.2.0",
            "peertube_auto_upgrade": "true",
            "peertube_last_notified_version": "",
        }.get(k, d)

        mock_peertube = MagicMock()
        mock_peertube.check_peertube_release.return_value = (True, "6.3.0", "https://example.com")
        mock_peertube.run_peertube_upgrade.return_value = (True, "")
        mock_notifier = MagicMock()
        mock_notifier.send_peertube_update_notification.return_value = (True, "ok")
        mock_audit = MagicMock()
        mock_db = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting, db=mock_db),
            "apps.peertube": mock_peertube,
            "core.notifier": mock_notifier,
            "auth.audit": mock_audit,
        }
        with _SysModulesPatch(mocks):
            _check_peertube_release(app)

        mock_peertube.run_peertube_upgrade.assert_called_once()


# ---------------------------------------------------------------------------
# Notifier
# ---------------------------------------------------------------------------


class TestPeerTubeNotifier:
    """PeerTube notification functions exist and follow patterns."""

    def test_send_peertube_update_notification_exists(self):
        from core.notifier import send_peertube_update_notification
        assert callable(send_peertube_update_notification)

    def test_upgrade_started_supports_peertube(self, app):
        """send_upgrade_started_notification accepts 'peertube' service."""
        with app.app_context():
            from core.notifier import send_upgrade_started_notification
            # Should not raise — returns (False, ...) since Discord is disabled
            ok, msg = send_upgrade_started_notification("peertube", "6.3.0", "manual")
            assert isinstance(ok, bool)

    def test_upgrade_result_supports_peertube(self, app):
        """send_upgrade_result_notification accepts 'peertube' service."""
        with app.app_context():
            from core.notifier import send_upgrade_result_notification
            ok, msg = send_upgrade_result_notification("peertube", "6.3.0", True, "manual")
            assert isinstance(ok, bool)


# ---------------------------------------------------------------------------
# Version check (unit)
# ---------------------------------------------------------------------------


class TestCheckPeerTubeReleaseUnit:
    """Unit tests for peertube.check_peertube_release()."""

    def test_returns_false_on_network_error(self, app):
        with app.app_context():
            with patch("apps.peertube.urlopen", side_effect=Exception("timeout")):
                update, version, url = None, None, None
                from apps.peertube import check_peertube_release
                update, version, url = check_peertube_release()
                assert update is False
                assert version == ""

    def test_parses_github_release(self, app):
        import json
        fake_data = json.dumps({
            "tag_name": "v6.3.1",
            "html_url": "https://github.com/Chocobozzz/PeerTube/releases/tag/v6.3.1",
        }).encode()

        from unittest.mock import MagicMock as MM
        fake_resp = MM()
        fake_resp.read.return_value = fake_data
        fake_resp.__enter__ = lambda s: s
        fake_resp.__exit__ = MM(return_value=False)

        with app.app_context():
            from models import Setting
            Setting.set("peertube_current_version", "6.2.0")
            from models import db
            db.session.commit()

            with patch("apps.peertube.urlopen", return_value=fake_resp):
                from apps.peertube import check_peertube_release
                update, version, url = check_peertube_release()
                assert update is True
                assert version == "6.3.1"
                assert "v6.3.1" in url
