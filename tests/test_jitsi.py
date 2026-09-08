"""Tests for Jitsi Meet install/upgrade routes and scheduler integration."""
import sys
from unittest.mock import MagicMock

# ---------------------------------------------------------------------------
# Helpers (mirror test_elk.py patterns)
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


class TestJitsiRouteAuth:
    """Jitsi routes require authentication and can_update permission."""

    def test_upgrade_page_unauthenticated(self, client):
        resp = client.get("/jitsi/upgrade", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers.get("Location", "")

    def test_save_unauthenticated(self, client):
        resp = client.post("/jitsi/save", follow_redirects=False)
        assert resp.status_code == 302

    def test_check_unauthenticated(self, client):
        resp = client.post("/jitsi/check", follow_redirects=False)
        assert resp.status_code == 302

    def test_detect_versions_unauthenticated(self, client):
        resp = client.post("/jitsi/detect-versions", follow_redirects=False)
        assert resp.status_code == 302

    def test_preflight_unauthenticated(self, client):
        resp = client.post("/jitsi/preflight", follow_redirects=False)
        assert resp.status_code == 302

    def test_upgrade_post_unauthenticated(self, client):
        resp = client.post("/jitsi/upgrade", follow_redirects=False)
        assert resp.status_code == 302

    def test_install_unauthenticated(self, client):
        resp = client.post("/jitsi/install", follow_redirects=False)
        assert resp.status_code == 302

    def test_upgrade_status_unauthenticated(self, client):
        resp = client.get("/jitsi/upgrade/status", follow_redirects=False)
        assert resp.status_code == 302

    def test_preflight_status_unauthenticated(self, client):
        resp = client.get("/jitsi/preflight/status", follow_redirects=False)
        assert resp.status_code == 302

    def test_install_status_unauthenticated(self, client):
        resp = client.get("/jitsi/install/status", follow_redirects=False)
        assert resp.status_code == 302

    def test_sd_configure_unauthenticated(self, client):
        resp = client.post("/jitsi/configure-secure-domain", follow_redirects=False)
        assert resp.status_code == 302

    def test_sd_configure_status_unauthenticated(self, client):
        resp = client.get("/jitsi/configure-secure-domain/status", follow_redirects=False)
        assert resp.status_code == 302

    def test_sd_list_users_unauthenticated(self, client):
        resp = client.get("/jitsi/secure-domain/users", follow_redirects=False)
        assert resp.status_code == 302

    def test_sd_add_user_unauthenticated(self, client):
        resp = client.post("/jitsi/secure-domain/add-user", follow_redirects=False)
        assert resp.status_code == 302

    def test_sd_remove_user_unauthenticated(self, client):
        resp = client.post("/jitsi/secure-domain/remove-user", follow_redirects=False)
        assert resp.status_code == 302


class TestJitsiRouteViewer:
    """Viewer users (can_update=False) should be denied access."""

    def test_viewer_denied_upgrade_page(self, app, client):
        from models import Role, User, db

        with app.app_context():
            viewer_role = Role.query.filter_by(name="viewer").first()
            user = User(
                username="_jitsi_test_viewer",
                display_name="Jitsi Viewer",
                role_id=viewer_role.id,
            )
            user.set_password("ViewerPass123!")
            db.session.add(user)
            db.session.commit()

        try:
            client.post(
                "/login",
                data={"username": "_jitsi_test_viewer", "password": "ViewerPass123!"},
                follow_redirects=False,
            )
            resp = client.get("/jitsi/upgrade", follow_redirects=False)
            assert resp.status_code == 302
            location = resp.headers.get("Location", "")
            assert "/jitsi" not in location
        finally:
            with app.app_context():
                User.query.filter_by(username="_jitsi_test_viewer").delete()
                db.session.commit()


class TestJitsiRouteAuthed:
    """Admin users (can_update=True) can access Jitsi routes."""

    def test_upgrade_page_loads(self, auth_client):
        resp = auth_client.get("/jitsi/upgrade")
        assert resp.status_code == 200
        assert b"Jitsi" in resp.data

    def test_upgrade_status_returns_json(self, auth_client):
        resp = auth_client.get("/jitsi/upgrade/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data
        assert "success" in data
        assert "log" in data

    def test_preflight_status_returns_json(self, auth_client):
        resp = auth_client.get("/jitsi/preflight/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data
        assert "success" in data
        assert "log" in data

    def test_install_status_returns_json(self, auth_client):
        resp = auth_client.get("/jitsi/install/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data
        assert "success" in data
        assert "log" in data

    def test_save_persists_settings(self, app, auth_client):
        from models import Setting

        resp = auth_client.post(
            "/jitsi/save",
            data={
                "jitsi_guest_id": "99",
                "jitsi_hostname": "meet.example.com",
                "jitsi_cert_type": "letsencrypt",
                "jitsi_letsencrypt_email": "admin@example.com",
                "jitsi_url": "https://meet.example.com",
                "jitsi_current_version": "2.0.9457",
                "jitsi_auto_upgrade": "on",
                "jitsi_protection_type": "snapshot",
                "jitsi_backup_storage": "",
                "jitsi_backup_mode": "snapshot",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            assert Setting.get("jitsi_guest_id") == "99"
            assert Setting.get("jitsi_hostname") == "meet.example.com"
            assert Setting.get("jitsi_cert_type") == "letsencrypt"
            assert Setting.get("jitsi_letsencrypt_email") == "admin@example.com"
            assert Setting.get("jitsi_url") == "https://meet.example.com"
            assert Setting.get("jitsi_current_version") == "2.0.9457"
            assert Setting.get("jitsi_auto_upgrade") == "true"

    def test_save_validates_cert_type(self, app, auth_client):
        from models import Setting

        auth_client.post(
            "/jitsi/save",
            data={"jitsi_cert_type": "invalid"},
            follow_redirects=False,
        )
        with app.app_context():
            assert Setting.get("jitsi_cert_type") == "self-signed"

    def test_save_validates_protection_type(self, app, auth_client):
        from models import Setting

        auth_client.post(
            "/jitsi/save",
            data={"jitsi_protection_type": "invalid"},
            follow_redirects=False,
        )
        with app.app_context():
            assert Setting.get("jitsi_protection_type") == "snapshot"

    def test_save_validates_backup_mode(self, app, auth_client):
        from models import Setting

        auth_client.post(
            "/jitsi/save",
            data={
                "jitsi_backup_mode": "invalid",
                "jitsi_protection_type": "backup",
            },
            follow_redirects=False,
        )
        with app.app_context():
            assert Setting.get("jitsi_backup_mode") == "snapshot"

    def test_check_no_guest_configured(self, app, auth_client):
        from models import Setting

        with app.app_context():
            Setting.set("jitsi_guest_id", "")
        resp = auth_client.post("/jitsi/check", follow_redirects=False)
        assert resp.status_code == 302

    def test_detect_versions_no_guest(self, app, auth_client):
        from models import Setting

        with app.app_context():
            Setting.set("jitsi_guest_id", "")
        resp = auth_client.post("/jitsi/detect-versions", follow_redirects=False)
        assert resp.status_code == 302


# ---------------------------------------------------------------------------
# Applications index
# ---------------------------------------------------------------------------


class TestApplicationsIndexJitsi:
    """Jitsi appears on the applications index page."""

    def test_jitsi_card_present(self, auth_client):
        resp = auth_client.get("/applications/")
        assert resp.status_code == 200
        assert b"Jitsi" in resp.data
        assert b"/jitsi/upgrade" in resp.data


# ---------------------------------------------------------------------------
# Scheduler: _check_jitsi_release
# ---------------------------------------------------------------------------


class TestCheckJitsiRelease:
    def test_returns_early_when_no_jitsi_guest_configured(self):
        from core.scheduler import _check_jitsi_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.return_value = ""
        mock_jitsi = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "apps.jitsi": mock_jitsi,
        }
        with _SysModulesPatch(mocks):
            _check_jitsi_release(app)

        mock_jitsi.check_jitsi_release.assert_not_called()

    def test_returns_early_when_not_installed(self):
        from core.scheduler import _check_jitsi_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "jitsi_guest_id": "42",
            "jitsi_installed": "false",
        }.get(k, d)
        mock_jitsi = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "apps.jitsi": mock_jitsi,
        }
        with _SysModulesPatch(mocks):
            _check_jitsi_release(app)

        mock_jitsi.check_jitsi_release.assert_not_called()

    def test_sends_notification_when_update_available(self):
        from core.scheduler import _check_jitsi_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "jitsi_guest_id": "42",
            "jitsi_installed": "true",
            "jitsi_current_version": "2.0.9400",
            "jitsi_auto_upgrade": "false",
            "jitsi_last_notified_version": "",
        }.get(k, d)

        mock_jitsi = MagicMock()
        mock_jitsi.check_jitsi_release.return_value = (True, "2.0.9500", "")
        mock_notifier = MagicMock()
        mock_notifier.send_jitsi_update_notification.return_value = (True, "ok")

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "apps.jitsi": mock_jitsi,
            "core.notifier": mock_notifier,
        }
        with _SysModulesPatch(mocks):
            _check_jitsi_release(app)

        mock_notifier.send_jitsi_update_notification.assert_called_once_with(
            "2.0.9400", "2.0.9500", ""
        )

    def test_skips_notification_when_already_notified_for_version(self):
        from core.scheduler import _check_jitsi_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "jitsi_guest_id": "42",
            "jitsi_installed": "true",
            "jitsi_current_version": "2.0.9400",
            "jitsi_auto_upgrade": "false",
            "jitsi_last_notified_version": "2.0.9500",
        }.get(k, d)

        mock_jitsi = MagicMock()
        mock_jitsi.check_jitsi_release.return_value = (True, "2.0.9500", "")
        mock_notifier = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "apps.jitsi": mock_jitsi,
            "core.notifier": mock_notifier,
        }
        with _SysModulesPatch(mocks):
            _check_jitsi_release(app)

        mock_notifier.send_jitsi_update_notification.assert_not_called()

    def test_no_notification_when_no_update_available(self):
        from core.scheduler import _check_jitsi_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "jitsi_guest_id": "42",
            "jitsi_installed": "true",
        }.get(k, d)
        mock_jitsi = MagicMock()
        mock_jitsi.check_jitsi_release.return_value = (False, "2.0.9400", "")
        mock_notifier = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting),
            "apps.jitsi": mock_jitsi,
            "core.notifier": mock_notifier,
        }
        with _SysModulesPatch(mocks):
            _check_jitsi_release(app)

        mock_notifier.send_jitsi_update_notification.assert_not_called()

    def test_auto_upgrade_triggered_when_enabled(self):
        from core.scheduler import _check_jitsi_release

        app = _make_app()

        mock_setting = MagicMock()
        mock_setting.get.side_effect = lambda k, d="": {
            "jitsi_guest_id": "42",
            "jitsi_installed": "true",
            "jitsi_current_version": "2.0.9400",
            "jitsi_auto_upgrade": "true",
            "jitsi_last_notified_version": "",
        }.get(k, d)

        mock_jitsi = MagicMock()
        mock_jitsi.check_jitsi_release.return_value = (True, "2.0.9500", "")
        mock_jitsi.run_jitsi_upgrade.return_value = (True, "")
        mock_notifier = MagicMock()
        mock_notifier.send_jitsi_update_notification.return_value = (True, "ok")
        mock_audit = MagicMock()
        mock_db = MagicMock()

        mocks = {
            "models": MagicMock(Setting=mock_setting, db=mock_db),
            "apps.jitsi": mock_jitsi,
            "core.notifier": mock_notifier,
            "auth.audit": mock_audit,
        }
        with _SysModulesPatch(mocks):
            _check_jitsi_release(app)

        mock_jitsi.run_jitsi_upgrade.assert_called_once()


# ---------------------------------------------------------------------------
# Notifier
# ---------------------------------------------------------------------------


class TestJitsiNotifier:
    """Jitsi notification functions exist and follow patterns."""

    def test_send_jitsi_update_notification_exists(self):
        from core.notifier import send_jitsi_update_notification
        assert callable(send_jitsi_update_notification)

    def test_upgrade_started_supports_jitsi(self, app):
        with app.app_context():
            from core.notifier import send_upgrade_started_notification
            ok, msg = send_upgrade_started_notification("jitsi", "2.0.9500", "manual")
            assert isinstance(ok, bool)

    def test_upgrade_result_supports_jitsi(self, app):
        with app.app_context():
            from core.notifier import send_upgrade_result_notification
            ok, msg = send_upgrade_result_notification("jitsi", "2.0.9500", True, "manual")
            assert isinstance(ok, bool)


# ---------------------------------------------------------------------------
# Cloudflare Zero Trust configuration
# ---------------------------------------------------------------------------


class TestJitsiCfRouteAuth:
    """Cloudflare configure routes require authentication."""

    def test_cf_configure_unauthenticated(self, client):
        resp = client.post("/jitsi/configure-cloudflare", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers.get("Location", "")

    def test_cf_configure_status_unauthenticated(self, client):
        resp = client.get("/jitsi/configure-cloudflare/status", follow_redirects=False)
        assert resp.status_code == 302


class TestJitsiCfRouteAuthed:
    """Authenticated admin can use Cloudflare configure routes."""

    def test_cf_configure_status_returns_json(self, auth_client):
        resp = auth_client.get("/jitsi/configure-cloudflare/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data
        assert "success" in data
        assert "log" in data

    def test_cf_configure_blocked_when_not_installed(self, app, auth_client):
        from models import Setting
        with app.app_context():
            Setting.set("jitsi_installed", "false")
        resp = auth_client.post("/jitsi/configure-cloudflare", follow_redirects=False)
        assert resp.status_code == 302

    def test_save_persists_cf_mode(self, app, auth_client):
        from models import Setting
        auth_client.post(
            "/jitsi/save",
            data={"jitsi_cf_mode": "tcp_only", "jitsi_public_ip": ""},
            follow_redirects=False,
        )
        with app.app_context():
            assert Setting.get("jitsi_cf_mode") == "tcp_only"

    def test_save_validates_cf_mode(self, app, auth_client):
        from models import Setting
        auth_client.post(
            "/jitsi/save",
            data={"jitsi_cf_mode": "invalid"},
            follow_redirects=False,
        )
        with app.app_context():
            assert Setting.get("jitsi_cf_mode") == "none"

    def test_save_persists_public_ip(self, app, auth_client):
        from models import Setting
        auth_client.post(
            "/jitsi/save",
            data={"jitsi_cf_mode": "hybrid", "jitsi_public_ip": "203.0.113.1"},
            follow_redirects=False,
        )
        with app.app_context():
            assert Setting.get("jitsi_public_ip") == "203.0.113.1"


class TestJitsiCloudflareLogic:
    """Unit tests for run_cloudflare_configure validation paths."""

    def test_mode_none_returns_error(self, app):
        from models import Setting
        with app.app_context():
            Setting.set("jitsi_cf_mode", "none")
            from apps.jitsi import run_cloudflare_configure
            ok, log = run_cloudflare_configure()
            assert ok is False
            assert "nothing" in log.lower()

    def test_not_installed_returns_error(self, app):
        from models import Setting
        with app.app_context():
            Setting.set("jitsi_cf_mode", "tcp_only")
            Setting.set("jitsi_installed", "false")
            from apps.jitsi import run_cloudflare_configure
            ok, log = run_cloudflare_configure()
            assert ok is False
            assert "installed" in log.lower()

    def test_hybrid_mode_requires_public_ip(self, app):
        from models import Setting
        with app.app_context():
            Setting.set("jitsi_cf_mode", "hybrid")
            Setting.set("jitsi_installed", "true")
            Setting.set("jitsi_hostname", "meet.example.com")
            Setting.set("jitsi_public_ip", "")
            from apps.jitsi import run_cloudflare_configure
            ok, log = run_cloudflare_configure()
            assert ok is False
            assert "public ip" in log.lower() or "required" in log.lower()

    def test_hybrid_mode_validates_ip_format(self, app):
        from models import Setting
        with app.app_context():
            Setting.set("jitsi_cf_mode", "hybrid")
            Setting.set("jitsi_installed", "true")
            Setting.set("jitsi_hostname", "meet.example.com")
            Setting.set("jitsi_public_ip", "not-an-ip")
            from apps.jitsi import run_cloudflare_configure
            ok, log = run_cloudflare_configure()
            assert ok is False
            assert "valid" in log.lower()

    def test_no_hostname_returns_error(self, app):
        from models import Setting
        with app.app_context():
            Setting.set("jitsi_cf_mode", "tcp_only")
            Setting.set("jitsi_installed", "true")
            Setting.set("jitsi_hostname", "")
            from apps.jitsi import run_cloudflare_configure
            ok, log = run_cloudflare_configure()
            assert ok is False
            assert "hostname" in log.lower()


# ---------------------------------------------------------------------------
# Service monitoring tests
# ---------------------------------------------------------------------------


class TestJitsiServiceMonitoring:
    """Tests for Jitsi service monitoring integration."""

    def test_known_services_includes_jitsi(self):
        from models import GuestService
        assert "jitsi-videobridge2" in GuestService.KNOWN_SERVICES
        assert "jicofo" in GuestService.KNOWN_SERVICES
        assert "prosody" in GuestService.KNOWN_SERVICES
        # JVB should have port 8080
        assert GuestService.KNOWN_SERVICES["jitsi-videobridge2"][2] == 8080

    def test_jvb_metrics_history_unauthenticated(self, app, client):
        """Metrics history endpoint should redirect unauthenticated users."""
        from models import Guest, GuestService, db
        with app.app_context():
            guest = Guest.query.first()
            if not guest:
                guest = Guest(name="jvb-test", vmid=9999, guest_type="ct")
                db.session.add(guest)
                db.session.flush()
            svc = GuestService(
                guest_id=guest.id,
                service_name="jitsi-videobridge2",
                unit_name="jitsi-videobridge2.service",
                port=8080,
            )
            db.session.add(svc)
            db.session.commit()
            svc_id = svc.id

        resp = client.get(f"/services/{svc_id}/jvb/metrics-history")
        assert resp.status_code == 302

    def test_jvb_metrics_history_wrong_service_type(self, app, auth_client):
        """Metrics history returns 400 for non-JVB services."""
        from models import Guest, GuestService, db
        with app.app_context():
            guest = Guest.query.first()
            if not guest:
                guest = Guest(name="pg-test", vmid=9998, guest_type="ct")
                db.session.add(guest)
                db.session.flush()
            svc = GuestService(
                guest_id=guest.id,
                service_name="postgresql",
                unit_name="postgresql.service",
                port=5432,
            )
            db.session.add(svc)
            db.session.commit()
            svc_id = svc.id

        resp = auth_client.get(f"/services/{svc_id}/jvb/metrics-history")
        assert resp.status_code == 400

    def test_jvb_metrics_history_empty(self, app, auth_client):
        """Metrics history returns empty snapshots for a JVB service with no data."""
        from models import Guest, GuestService, db
        with app.app_context():
            guest = Guest.query.first()
            if not guest:
                guest = Guest(name="jvb-empty", vmid=9997, guest_type="ct")
                db.session.add(guest)
                db.session.flush()
            svc = GuestService(
                guest_id=guest.id,
                service_name="jitsi-videobridge2",
                unit_name="jitsi-videobridge2.service",
                port=8080,
            )
            db.session.add(svc)
            db.session.commit()
            svc_id = svc.id

        resp = auth_client.get(f"/services/{svc_id}/jvb/metrics-history")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["snapshots"] == []

    def test_stats_route_saves_jvb_snapshot(self, app, auth_client):
        """Stats route should persist a JVB metric snapshot."""
        from unittest.mock import patch

        from models import Guest, GuestService, ServiceMetricSnapshot, db
        with app.app_context():
            guest = Guest.query.first()
            if not guest:
                guest = Guest(name="jvb-snap", vmid=9996, guest_type="ct")
                db.session.add(guest)
                db.session.flush()
            svc = GuestService(
                guest_id=guest.id,
                service_name="jitsi-videobridge2",
                unit_name="jitsi-videobridge2.service",
                port=8080,
            )
            db.session.add(svc)
            db.session.commit()
            svc_id = svc.id

        mock_stats = {
            "type": "jitsi-videobridge2",
            "conferences": 3,
            "participants": 12,
            "stress_level": 0.25,
            "bit_rate_download": 5000,
        }
        with patch("routes.services.get_service_stats", return_value=mock_stats):
            resp = auth_client.get(f"/services/{svc_id}/stats")
            assert resp.status_code == 200

        with app.app_context():
            snap = ServiceMetricSnapshot.query.filter_by(service_id=svc_id).first()
            assert snap is not None
            import json
            d = json.loads(snap.data)
            assert d["conferences"] == 3
            assert d["participants"] == 12

    def test_configure_coturn_tls_adds_missing_directives(self):
        """_configure_coturn_tls adds tls-listening-port and cert paths."""
        from apps.jitsi import _configure_coturn_tls
        ssh = MagicMock()
        # Existing turnserver.conf without TLS
        existing = "listening-port=3478\nrealm=meet.example.com\n"
        ssh.execute_sudo.side_effect = [
            (existing, "", 0),       # cat /etc/turnserver.conf
            ("", "", 1),             # test LE certs (not found)
            ("", "", 0),             # sed enable coturn
            ("", "", 0),             # tee (write)
            ("", "", 0),             # restart coturn
        ]
        logs = []
        result = _configure_coturn_tls(ssh, "meet.example.com", logs.append)
        assert result == 0
        assert any("tls-listening-port" in msg for msg in logs)

    def test_configure_coturn_tls_skips_when_configured(self):
        """_configure_coturn_tls skips when all directives already present."""
        from apps.jitsi import _configure_coturn_tls
        ssh = MagicMock()
        existing = (
            "listening-port=3478\n"
            "tls-listening-port=5349\n"
            "cert=/etc/jitsi/meet/meet.example.com.crt\n"
            "pkey=/etc/jitsi/meet/meet.example.com.key\n"
            "no-multicast-peers\n"
            "no-cli\n"
            "no-loopback-peers\n"
        )
        ssh.execute_sudo.side_effect = [
            (existing, "", 0),  # cat
            ("", "", 1),        # test LE certs (not found)
            ("", "", 0),        # sed enable coturn
        ]
        logs = []
        result = _configure_coturn_tls(ssh, "meet.example.com", logs.append)
        assert result == 0
        assert any("SKIP" in msg for msg in logs)

    def test_configure_coturn_tls_uses_letsencrypt_certs(self):
        """_configure_coturn_tls prefers LE certs when they exist."""
        from apps.jitsi import _configure_coturn_tls
        ssh = MagicMock()
        existing = "listening-port=3478\n"
        ssh.execute_sudo.side_effect = [
            (existing, "", 0),    # cat
            ("yes", "", 0),       # test LE certs (found)
            ("", "", 0),          # sed enable coturn
            ("", "", 0),          # tee (write)
            ("", "", 0),          # restart coturn
        ]
        logs = []
        result = _configure_coturn_tls(ssh, "meet.example.com", logs.append)
        assert result == 0
        assert any("Let's Encrypt" in msg for msg in logs)

    def test_configure_coturn_tls_returns_warning_if_unreadable(self):
        """_configure_coturn_tls returns 1 if turnserver.conf cannot be read."""
        from apps.jitsi import _configure_coturn_tls
        ssh = MagicMock()
        ssh.execute_sudo.return_value = ("", "", 1)
        logs = []
        result = _configure_coturn_tls(ssh, "meet.example.com", logs.append)
        assert result == 1
        assert any("WARNING" in msg for msg in logs)

    def test_configure_prosody_turn_adds_external_services(self):
        """_configure_prosody_turn adds external_services block when missing."""
        from apps.jitsi import _configure_prosody_turn
        ssh = MagicMock()
        prosody_cfg = (
            'VirtualHost "meet.example.com"\n'
            '  modules_enabled = {\n    "bosh";\n  }\n'
            '\nComponent "conference.meet.example.com" "muc"\n'
        )
        ssh.execute_sudo.side_effect = [
            (prosody_cfg, "", 0),        # cat prosody cfg
            ("test-only-mysecret123", "", 0),      # cat TURN secret
            ("", "", 0),                 # tee (write)
            ("", "", 0),                 # restart prosody
        ]
        logs = []
        result = _configure_prosody_turn(ssh, "meet.example.com", logs.append)
        assert result == 0
        assert any("external_services" in msg for msg in logs)

    def test_configure_prosody_turn_skips_when_present(self):
        """_configure_prosody_turn skips when turns entry already exists."""
        from apps.jitsi import _configure_prosody_turn
        ssh = MagicMock()
        prosody_cfg = (
            'VirtualHost "meet.example.com"\n'
            'external_services = {\n'
            '  { type = "turns", port = 5349 },\n'
            '}\n'
        )
        ssh.execute_sudo.return_value = (prosody_cfg, "", 0)
        logs = []
        result = _configure_prosody_turn(ssh, "meet.example.com", logs.append)
        assert result == 0
        assert any("SKIP" in msg for msg in logs)

    def test_configure_prosody_turn_warns_on_missing_secret(self):
        """_configure_prosody_turn warns if TURN secret cannot be found."""
        from apps.jitsi import _configure_prosody_turn
        ssh = MagicMock()
        prosody_cfg = 'VirtualHost "meet.example.com"\n'
        ssh.execute_sudo.side_effect = [
            (prosody_cfg, "", 0),  # cat prosody cfg
            ("", "", 1),           # cat TURN secret (not found)
            ("", "", 1),           # grep turnserver.conf (not found)
        ]
        logs = []
        result = _configure_prosody_turn(ssh, "meet.example.com", logs.append)
        assert result == 1
        assert any("WARNING" in msg for msg in logs)

    def test_configure_jvb_nat_harvester_sets_ips(self):
        """_configure_jvb_nat_harvester sets NAT harvester addresses."""
        from apps.jitsi import _configure_jvb_nat_harvester
        ssh = MagicMock()
        existing = "org.jitsi.videobridge.SINGLE_PORT_HARVESTER_PORT=10000\n"
        ssh.execute_sudo.side_effect = [
            (existing, "", 0),  # cat sip-communicator.properties
            ("", "", 0),        # tee (write)
        ]
        logs = []
        result = _configure_jvb_nat_harvester(ssh, "10.0.0.5", "203.0.113.1", logs.append)
        assert result == 0
        assert any("NAT_HARVESTER" in msg for msg in logs)

    def test_configure_jvb_nat_harvester_skips_without_public_ip(self):
        """_configure_jvb_nat_harvester skips when no public IP given."""
        from apps.jitsi import _configure_jvb_nat_harvester
        ssh = MagicMock()
        logs = []
        result = _configure_jvb_nat_harvester(ssh, "10.0.0.5", "", logs.append)
        assert result == 0
        assert any("SKIP" in msg for msg in logs)
        ssh.execute_sudo.assert_not_called()

    def test_configure_jvb_nat_harvester_rejects_invalid_ip(self):
        """_configure_jvb_nat_harvester warns on invalid public IP."""
        from apps.jitsi import _configure_jvb_nat_harvester
        ssh = MagicMock()
        logs = []
        result = _configure_jvb_nat_harvester(ssh, "10.0.0.5", "not-an-ip", logs.append)
        assert result == 1
        assert any("WARNING" in msg for msg in logs)

    def test_enable_jvb_rest_api_idempotent(self):
        """_enable_jvb_rest_api should skip if REST API already enabled."""
        from apps.jitsi import _enable_jvb_rest_api
        ssh = MagicMock()
        ssh.execute_sudo.return_value = (
            'videobridge {\n  apis {\n    rest {\n      enabled = true\n    }\n  }\n}',
            "",
            0,
        )
        logs = []
        _enable_jvb_rest_api(ssh, logs.append)
        assert any("SKIP" in msg for msg in logs)
        # Should not have written the file back
        assert ssh.execute_sudo.call_count == 1

    def test_enable_jvb_rest_api_patches_conf(self):
        """_enable_jvb_rest_api should patch jvb.conf when REST not enabled."""
        from apps.jitsi import _enable_jvb_rest_api
        ssh = MagicMock()
        original_conf = 'videobridge {\n  ice {\n    udp {\n      port = 10000\n    }\n  }\n}'
        # First call reads the file, subsequent calls are write + restart
        ssh.execute_sudo.side_effect = [
            (original_conf, "", 0),  # cat
            ("", "", 0),  # tee (write)
            ("", "", 0),  # restart
        ]
        logs = []
        _enable_jvb_rest_api(ssh, logs.append)
        assert any("REST API enabled" in msg for msg in logs)
        # Should have called write (tee) and restart
        assert ssh.execute_sudo.call_count == 3


# ---------------------------------------------------------------------------
# Prometheus metrics parsing tests
# ---------------------------------------------------------------------------


class TestJvbPrometheusMetrics:
    """Tests for _parse_jvb_prometheus_metrics (JVB 2.3+ /metrics support)."""

    def test_parse_gauge_metrics(self):
        """Prometheus gauge metrics should map to expected stat keys."""
        from core.scanner import _parse_jvb_prometheus_metrics
        metrics = (
            "# HELP jitsi_jvb_conferences location\n"
            "# TYPE jitsi_jvb_conferences gauge\n"
            "jitsi_jvb_conferences 3.0\n"
            "jitsi_jvb_participants 7.0\n"
            "jitsi_jvb_largest_conference 4.0\n"
            "jitsi_jvb_endpoints_sending_audio 5.0\n"
            "jitsi_jvb_endpoints_sending_video 6.0\n"
            "jitsi_jvb_stress_level 0.123\n"
            "jitsi_jvb_threads 42.0\n"
        )
        stats = {}
        _parse_jvb_prometheus_metrics(stats, metrics)
        assert stats["conferences"] == 3
        assert stats["participants"] == 7
        assert stats["largest_conference"] == 4
        assert stats["endpoints_sending_audio"] == 5
        assert stats["endpoints_sending_video"] == 6
        assert stats["stress_level"] == 0.123
        assert stats["threads"] == 42

    def test_parse_counter_metrics(self):
        """Prometheus counter (total) metrics should map to cumulative stat keys."""
        from core.scanner import _parse_jvb_prometheus_metrics
        metrics = (
            "jitsi_jvb_conferences_created_total 100.0\n"
            "jitsi_jvb_conferences_completed_total 95.0\n"
            "jitsi_jvb_participants_total 500.0\n"
            "jitsi_jvb_conference_seconds_total 36000.0\n"
            "jitsi_jvb_bytes_received_total 1048576.0\n"
            "jitsi_jvb_bytes_sent_total 2097152.0\n"
            "jitsi_jvb_ice_succeeded_total 80.0\n"
            "jitsi_jvb_ice_failed_total 5.0\n"
            "jitsi_jvb_ice_succeeded_relayed_total 10.0\n"
        )
        stats = {}
        _parse_jvb_prometheus_metrics(stats, metrics)
        assert stats["total_conferences_created"] == 100
        assert stats["total_conferences_completed"] == 95
        assert stats["total_participants"] == 500
        assert stats["total_conference_seconds"] == 36000
        assert stats["total_bytes_received"] == 1048576
        assert stats["total_bytes_sent"] == 2097152
        assert stats["total_ice_succeeded"] == 80
        assert stats["total_ice_failed"] == 5
        assert stats["total_ice_succeeded_relayed"] == 10

    def test_parse_healthy_metric(self):
        """jitsi_jvb_healthy 1.0 should set jvb_healthy=True."""
        from core.scanner import _parse_jvb_prometheus_metrics
        stats = {}
        _parse_jvb_prometheus_metrics(stats, "jitsi_jvb_healthy 1.0\n")
        assert stats["jvb_healthy"] is True

    def test_parse_unhealthy_metric(self):
        """jitsi_jvb_healthy 0.0 should set jvb_healthy=False."""
        from core.scanner import _parse_jvb_prometheus_metrics
        stats = {}
        _parse_jvb_prometheus_metrics(stats, "jitsi_jvb_healthy 0.0\n")
        assert stats["jvb_healthy"] is False

    def test_parse_bitrate_metrics(self):
        """Bitrate and RTT should be kept as floats."""
        from core.scanner import _parse_jvb_prometheus_metrics
        metrics = (
            "jitsi_jvb_bit_rate_download 1234.5\n"
            "jitsi_jvb_bit_rate_upload 567.8\n"
            "jitsi_jvb_rtt_aggregate 12.3\n"
        )
        stats = {}
        _parse_jvb_prometheus_metrics(stats, metrics)
        assert stats["bit_rate_download"] == 1234.5
        assert stats["bit_rate_upload"] == 567.8
        assert stats["rtt_aggregate"] == 12.3

    def test_parse_skips_comments_and_empty_lines(self):
        """Comments and empty lines should be ignored."""
        from core.scanner import _parse_jvb_prometheus_metrics
        metrics = (
            "# HELP jitsi_jvb_conferences desc\n"
            "# TYPE jitsi_jvb_conferences gauge\n"
            "\n"
            "jitsi_jvb_conferences 2.0\n"
            "\n"
        )
        stats = {}
        _parse_jvb_prometheus_metrics(stats, metrics)
        assert stats["conferences"] == 2
        assert len(stats) == 1

    def test_parse_skips_unknown_metrics(self):
        """Unknown metric names should be silently ignored."""
        from core.scanner import _parse_jvb_prometheus_metrics
        metrics = (
            "some_other_metric 42.0\n"
            "jitsi_jvb_conferences 1.0\n"
        )
        stats = {}
        _parse_jvb_prometheus_metrics(stats, metrics)
        assert "some_other_metric" not in stats
        assert stats["conferences"] == 1

    def test_parse_metrics_with_labels(self):
        """Metrics with labels (e.g., {region=...}) should still parse."""
        from core.scanner import _parse_jvb_prometheus_metrics
        metrics = 'jitsi_jvb_conferences{region="us-east"} 5.0\n'
        stats = {}
        _parse_jvb_prometheus_metrics(stats, metrics)
        assert stats["conferences"] == 5


# ---------------------------------------------------------------------------
# Secure Domain config patching tests
# ---------------------------------------------------------------------------

# Minimal Prosody config for testing
_PROSODY_CFG = '''VirtualHost "meet.example.com"
    authentication = "jitsi-anonymous"
    modules_enabled = {
        "bosh";
        "pubsub";
    }
    c2s_require_encryption = false

Component "conference.meet.example.com" "muc"
    modules_enabled = { "muc_meeting_id"; }
'''

_PROSODY_CFG_ENABLED = '''VirtualHost "meet.example.com"
    authentication = "internal_hashed"
    modules_enabled = {
        "bosh";
        "pubsub";
    }
    c2s_require_encryption = false

-- Guest domain for unauthenticated participants (auto-configured)
VirtualHost "guest.meet.example.com"
    authentication = "jitsi-anonymous"
    modules_enabled = {
        "turncredentials";
    }
    c2s_require_encryption = false

Component "conference.meet.example.com" "muc"
    modules_enabled = { "muc_meeting_id"; }
'''

_MEET_CONFIG_JS = '''var config = {
    hosts: {
        domain: 'meet.example.com',
        muc: 'conference.meet.example.com'
    },
    bosh: '//meet.example.com/http-bind'
};
'''

_JICOFO_CONF = '''jicofo {
  xmpp {
    client {
      hostname = "meet.example.com"
    }
  }
}
'''

_JICOFO_CONF_ENABLED = '''jicofo {
  xmpp {
    client {
      hostname = "meet.example.com"
    }
  }
  authentication {
    enabled = true
    type = "XMPP"
    login-url = "meet.example.com"
  }
}
'''


class TestSecureDomainPatchProsody:
    """Tests for _sd_patch_prosody."""

    def test_enable_patches_auth_and_adds_guest(self):
        from apps.jitsi import _sd_patch_prosody
        ssh = MagicMock()
        ssh.execute_sudo.side_effect = [
            (_PROSODY_CFG, "", 0),  # cat
            ("", "", 0),  # tee (write)
        ]
        logs = []
        result = _sd_patch_prosody(ssh, "meet.example.com", True, logs.append)
        assert result == 0
        # Check the written content
        write_call = ssh.execute_sudo.call_args_list[1]
        written_cmd = write_call[0][0]
        assert "base64" in written_cmd
        assert any("internal_hashed" in msg for msg in logs)
        assert any("guest.meet.example.com" in msg for msg in logs)

    def test_enable_idempotent(self):
        from apps.jitsi import _sd_patch_prosody
        ssh = MagicMock()
        ssh.execute_sudo.return_value = (_PROSODY_CFG_ENABLED, "", 0)
        logs = []
        result = _sd_patch_prosody(ssh, "meet.example.com", True, logs.append)
        assert result == 0
        assert any("SKIP" in msg for msg in logs)
        # Should only have called cat, not write
        assert ssh.execute_sudo.call_count == 1

    def test_disable_reverts_auth_and_removes_guest(self):
        from apps.jitsi import _sd_patch_prosody
        ssh = MagicMock()
        ssh.execute_sudo.side_effect = [
            (_PROSODY_CFG_ENABLED, "", 0),  # cat
            ("", "", 0),  # tee (write)
        ]
        logs = []
        result = _sd_patch_prosody(ssh, "meet.example.com", False, logs.append)
        assert result == 0
        assert any("jitsi-anonymous" in msg for msg in logs)
        assert any("Removed" in msg for msg in logs)

    def test_disable_already_disabled(self):
        from apps.jitsi import _sd_patch_prosody
        ssh = MagicMock()
        ssh.execute_sudo.return_value = (_PROSODY_CFG, "", 0)
        logs = []
        result = _sd_patch_prosody(ssh, "meet.example.com", False, logs.append)
        assert result == 0
        assert any("SKIP" in msg for msg in logs)


class TestSecureDomainPatchMeetConfig:
    """Tests for _sd_patch_meet_config_js."""

    def test_enable_adds_anonymousdomain(self):
        from apps.jitsi import _sd_patch_meet_config_js
        ssh = MagicMock()
        ssh.execute_sudo.side_effect = [
            (_MEET_CONFIG_JS, "", 0),  # cat
            ("", "", 0),  # tee
        ]
        logs = []
        result = _sd_patch_meet_config_js(ssh, "meet.example.com", True, logs.append)
        assert result == 0
        assert any("anonymousdomain" in msg for msg in logs)

    def test_enable_idempotent(self):
        from apps.jitsi import _sd_patch_meet_config_js
        ssh = MagicMock()
        content = _MEET_CONFIG_JS + "\nconfig.hosts.anonymousdomain = 'guest.meet.example.com';\n"
        ssh.execute_sudo.return_value = (content, "", 0)
        logs = []
        result = _sd_patch_meet_config_js(ssh, "meet.example.com", True, logs.append)
        assert result == 0
        assert any("SKIP" in msg for msg in logs)

    def test_disable_removes_anonymousdomain(self):
        from apps.jitsi import _sd_patch_meet_config_js
        ssh = MagicMock()
        content = _MEET_CONFIG_JS + "\nconfig.hosts.anonymousdomain = 'guest.meet.example.com';\n"
        ssh.execute_sudo.side_effect = [
            (content, "", 0),  # cat
            ("", "", 0),  # tee
        ]
        logs = []
        result = _sd_patch_meet_config_js(ssh, "meet.example.com", False, logs.append)
        assert result == 0
        assert any("Removed" in msg for msg in logs)


class TestSecureDomainPatchJicofo:
    """Tests for _sd_patch_jicofo_conf."""

    def test_enable_adds_auth_block(self):
        from apps.jitsi import _sd_patch_jicofo_conf
        ssh = MagicMock()
        ssh.execute_sudo.side_effect = [
            (_JICOFO_CONF, "", 0),  # cat
            ("", "", 0),  # tee
        ]
        logs = []
        result = _sd_patch_jicofo_conf(ssh, "meet.example.com", True, logs.append)
        assert result == 0
        assert any("authentication block" in msg for msg in logs)

    def test_enable_idempotent(self):
        from apps.jitsi import _sd_patch_jicofo_conf
        ssh = MagicMock()
        ssh.execute_sudo.return_value = (_JICOFO_CONF_ENABLED, "", 0)
        logs = []
        result = _sd_patch_jicofo_conf(ssh, "meet.example.com", True, logs.append)
        assert result == 0
        assert any("SKIP" in msg for msg in logs)

    def test_disable_removes_auth_block(self):
        from apps.jitsi import _sd_patch_jicofo_conf
        ssh = MagicMock()
        ssh.execute_sudo.side_effect = [
            (_JICOFO_CONF_ENABLED, "", 0),  # cat
            ("", "", 0),  # tee
        ]
        logs = []
        result = _sd_patch_jicofo_conf(ssh, "meet.example.com", False, logs.append)
        assert result == 0
        assert any("Removed" in msg for msg in logs)

    def test_disable_already_disabled(self):
        from apps.jitsi import _sd_patch_jicofo_conf
        ssh = MagicMock()
        ssh.execute_sudo.return_value = (_JICOFO_CONF, "", 0)
        logs = []
        result = _sd_patch_jicofo_conf(ssh, "meet.example.com", False, logs.append)
        assert result == 0
        assert any("SKIP" in msg for msg in logs)


# ---------------------------------------------------------------------------
# Jitsi JVB Prometheus exporter integration
# ---------------------------------------------------------------------------


class TestJvbExporterRegistry:
    """Verify jitsi_jvb is registered as a builtin exporter."""

    def test_jitsi_jvb_in_known_exporters(self):
        from apps.exporters import KNOWN_EXPORTERS
        assert "jitsi_jvb" in KNOWN_EXPORTERS

    def test_jitsi_jvb_is_builtin(self):
        from apps.exporters import KNOWN_EXPORTERS
        info = KNOWN_EXPORTERS["jitsi_jvb"]
        assert info.get("builtin") is True
        assert info["binary_name"] is None
        assert info["default_port"] == 8080
        assert info["job_name"] == "jitsi_jvb"


class TestJvbPrometheusQueryClient:
    """Test get_jvb_metrics_exporter method."""

    def test_get_jvb_metrics_exporter_returns_snapshots(self, app):
        from unittest.mock import patch

        from clients.prometheus_query import PrometheusQueryClient

        with app.app_context():
            from models import Setting, db
            Setting.set("prometheus_url", "http://localhost:9090")
            db.session.commit()

            with patch.object(PrometheusQueryClient, '_run_snapshot_queries') as mock_rsq:
                mock_rsq.return_value = {"snapshots": [{"conferences": 5}], "source": "jitsi_jvb"}
                prom = PrometheusQueryClient()
                result = prom.get_jvb_metrics_exporter("10.0.0.5:8080", "day")
                assert result["source"] == "jitsi_jvb"
                assert len(result["snapshots"]) == 1
                # Verify the right queries were passed
                queries = mock_rsq.call_args[0][0]
                assert "conferences" in queries
                assert "stress_level" in queries
                assert "ice_succeeded_total" in queries
                assert "ice_failed_total" in queries
                assert "bit_rate_download" in queries
                assert "bit_rate_upload" in queries


class TestJvbTargetHelper:
    """Test _get_jvb_target helper."""

    def test_returns_none_when_scrape_disabled(self, app):
        from clients.prometheus_query import _get_jvb_target
        with app.app_context():
            from models import Setting, db
            Setting.set("jitsi_prometheus_scrape", "false")
            db.session.commit()
            assert _get_jvb_target() is None

    def test_returns_target_when_enabled(self, app):
        from clients.prometheus_query import _get_jvb_target
        with app.app_context():
            from models import Guest, Setting, db
            Setting.set("jitsi_prometheus_scrape", "true")
            guest = Guest(name="jitsi-vm", vmid=200, ip_address="10.0.0.5",
                          guest_type="qemu", enabled=True)
            db.session.add(guest)
            db.session.commit()
            Setting.set("jitsi_guest_id", str(guest.id))
            db.session.commit()
            target = _get_jvb_target()
            assert target == "10.0.0.5:8080"

    def test_returns_none_when_no_guest(self, app):
        from clients.prometheus_query import _get_jvb_target
        with app.app_context():
            from models import Setting, db
            Setting.set("jitsi_prometheus_scrape", "true")
            Setting.set("jitsi_guest_id", "")
            db.session.commit()
            assert _get_jvb_target() is None

    def test_returns_none_when_guest_has_dhcp(self, app):
        from clients.prometheus_query import _get_jvb_target
        with app.app_context():
            from models import Guest, Setting, db
            Setting.set("jitsi_prometheus_scrape", "true")
            guest = Guest(name="jitsi-vm", vmid=200, ip_address="dhcp",
                          guest_type="qemu", enabled=True)
            db.session.add(guest)
            db.session.commit()
            Setting.set("jitsi_guest_id", str(guest.id))
            db.session.commit()
            assert _get_jvb_target() is None


class TestJitsiSavePrometheusScrape:
    """Test that saving Jitsi settings persists prometheus_scrape."""

    def test_save_persists_prometheus_scrape(self, app, auth_client):
        from models import Setting

        auth_client.post(
            "/jitsi/save",
            data={"jitsi_prometheus_scrape": "on"},
            follow_redirects=False,
        )
        with app.app_context():
            assert Setting.get("jitsi_prometheus_scrape") == "true"

    def test_save_disables_prometheus_scrape(self, app, auth_client):
        from models import Setting

        # Enable first
        with app.app_context():
            Setting.set("jitsi_prometheus_scrape", "true")
        # Save without the checkbox
        auth_client.post(
            "/jitsi/save",
            data={},
            follow_redirects=False,
        )
        with app.app_context():
            assert Setting.get("jitsi_prometheus_scrape") == "false"


class TestConfigureJvbRestBinding:
    """Test configure_jvb_rest_binding for Prometheus network access."""

    def test_bind_all_inserts_http_servers_block(self, app):
        from unittest.mock import MagicMock, patch

        from apps.jitsi import configure_jvb_rest_binding

        jvb_conf = (
            "videobridge {\n"
            "  apis {\n"
            "    rest {\n"
            "      enabled = true\n"
            "    }\n"
            "  }\n"
            "}\n"
        )

        mock_ssh = MagicMock()
        mock_ssh.execute_sudo.side_effect = [
            (jvb_conf, "", 0),  # cat jvb.conf
            ("", "", 0),        # tee (write)
            ("", "", 0),        # systemctl restart
        ]
        mock_guest = MagicMock()

        with app.app_context():
            with patch("apps.jitsi._sd_get_ssh", return_value=(mock_ssh, mock_guest, None)):
                ok, msg = configure_jvb_rest_binding(bind_all=True)

        assert ok is True
        assert "0.0.0.0" in msg

    def test_bind_all_already_set(self, app):
        from unittest.mock import MagicMock, patch

        from apps.jitsi import configure_jvb_rest_binding

        jvb_conf = (
            "videobridge {\n"
            "  http-servers {\n"
            "    private {\n"
            "      host = 0.0.0.0\n"
            "    }\n"
            "  }\n"
            "}\n"
        )

        mock_ssh = MagicMock()
        mock_ssh.execute_sudo.return_value = (jvb_conf, "", 0)
        mock_guest = MagicMock()

        with app.app_context():
            with patch("apps.jitsi._sd_get_ssh", return_value=(mock_ssh, mock_guest, None)):
                ok, msg = configure_jvb_rest_binding(bind_all=True)

        assert ok is True
        assert "already" in msg

    def test_revert_to_localhost(self, app):
        from unittest.mock import MagicMock, patch

        from apps.jitsi import configure_jvb_rest_binding

        jvb_conf = (
            "videobridge {\n"
            "  http-servers {\n"
            "    private {\n"
            "      host = 0.0.0.0\n"
            "    }\n"
            "  }\n"
            "}\n"
        )

        mock_ssh = MagicMock()
        mock_ssh.execute_sudo.side_effect = [
            (jvb_conf, "", 0),  # cat jvb.conf
            ("", "", 0),        # tee (write)
            ("", "", 0),        # systemctl restart
        ]
        mock_guest = MagicMock()

        with app.app_context():
            with patch("apps.jitsi._sd_get_ssh", return_value=(mock_ssh, mock_guest, None)):
                ok, msg = configure_jvb_rest_binding(bind_all=False)

        assert ok is True
        assert "127.0.0.1" in msg

    def test_returns_error_when_no_ssh(self, app):
        from unittest.mock import patch

        from apps.jitsi import configure_jvb_rest_binding

        with app.app_context():
            with patch("apps.jitsi._sd_get_ssh", return_value=(None, None, "No SSH credential")):
                ok, msg = configure_jvb_rest_binding(bind_all=True)

        assert ok is False
        assert "No SSH credential" in msg
