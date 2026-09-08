"""Tests for unpoller automation (apps/unpoller.py and routes/unpoller.py)."""

import json
from unittest.mock import MagicMock, patch

from auth.credential_store import encrypt
from models import Setting, db

# ---------------------------------------------------------------------------
# apps/unpoller.py unit tests
# ---------------------------------------------------------------------------


class TestUnpollerConfig:
    """Test config generation helpers."""

    def test_generate_unpoller_config(self, app):
        from apps.unpoller import _generate_unpoller_config

        config = {
            "unifi_url": "https://10.0.0.1",
            "unifi_user": "admin",
            "unifi_pass": "test-only-secret",
            "unifi_site": "default",
            "metric_prefix": "unpoller",
            "listen_port": "9130",
        }
        result = _generate_unpoller_config(config)
        assert 'url = "https://10.0.0.1"' in result
        assert 'user = "admin"' in result
        assert 'pass = "test-only-secret"' in result
        assert 'sites = ["default"]' in result
        assert 'namespace = "unpoller"' in result
        assert 'http_listen = "0.0.0.0:9130"' in result

    def test_generate_config_adds_https(self, app):
        from apps.unpoller import _generate_unpoller_config

        config = {
            "unifi_url": "10.0.0.1",
            "unifi_user": "admin",
            "unifi_pass": "pw",
            "unifi_site": "default",
            "metric_prefix": "unpoller",
            "listen_port": "9130",
        }
        result = _generate_unpoller_config(config)
        assert 'url = "https://10.0.0.1"' in result

    def test_generate_systemd_unit(self, app):
        from apps.unpoller import _generate_systemd_unit

        result = _generate_systemd_unit()
        assert "ExecStart=/usr/local/bin/unpoller" in result
        assert "User=unpoller" in result
        assert "--config /etc/unpoller/up.conf" in result

    def test_get_unpoller_scrape_config(self, app):
        from apps.unpoller import get_unpoller_scrape_config

        with app.app_context():
            result = get_unpoller_scrape_config("10.0.0.50")
            assert 'job_name: "unpoller"' in result
            assert '"10.0.0.50:9130"' in result

    def test_get_unpoller_scrape_config_custom_port(self, app):
        from apps.unpoller import get_unpoller_scrape_config

        with app.app_context():
            result = get_unpoller_scrape_config("10.0.0.50", port="9999")
            assert '"10.0.0.50:9999"' in result


class TestUnpollerGetConfig:
    """Test _get_config reads settings correctly."""

    def test_get_config_defaults(self, app):
        from apps.unpoller import _get_config

        with app.app_context():
            config = _get_config()
            assert config["guest_id"] == ""
            assert config["unifi_site"] == "default"
            assert config["metric_prefix"] == "unpoller"
            assert config["listen_port"] == "9130"

    def test_get_config_reads_settings(self, app):
        from apps.unpoller import _get_config

        with app.app_context():
            Setting.set("prometheus_guest_id", "42")
            Setting.set("unifi_base_url", "https://udm.local")
            Setting.set("unifi_username", "testuser")
            # Stored encrypted, exactly as the settings UI persists it.
            Setting.set("unifi_password", encrypt("test-only-testpass"))
            Setting.set("unpoller_site_name", "mysite")
            db.session.commit()

            config = _get_config()
            assert config["guest_id"] == "42"
            assert config["unifi_url"] == "https://udm.local"
            assert config["unifi_user"] == "testuser"
            # Decrypted plaintext must reach up.conf, not the ciphertext.
            assert config["unifi_pass"] == "test-only-testpass"
            assert config["unifi_site"] == "mysite"

    def test_get_config_password_unset(self, app):
        from apps.unpoller import _get_config

        with app.app_context():
            # A blank/unset password yields an empty string, not a crash.
            # (Session-scoped DB is shared, so set it explicitly.)
            Setting.set("unifi_password", "")
            db.session.commit()
            config = _get_config()
            assert config["unifi_pass"] == ""

    def test_get_config_corrupt_password_falls_back(self, app):
        from apps.unpoller import _get_config

        with app.app_context():
            # A non-Fernet / corrupt value must not crash install/reconfigure.
            Setting.set("unifi_password", "not-a-valid-fernet-token")
            db.session.commit()

            config = _get_config()
            assert config["unifi_pass"] == ""


class TestCheckUnpollerRelease:
    """Test version check against GitHub API."""

    @patch("apps.unpoller.urllib.request.urlopen")
    def test_check_release_success(self, mock_urlopen, app):
        from apps.unpoller import check_unpoller_release

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "tag_name": "v2.11.2",
            "html_url": "https://github.com/unpoller/unpoller/releases/tag/v2.11.2",
        }).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        with app.app_context():
            update, latest, url = check_unpoller_release()
            assert latest == "2.11.2"
            assert not update  # no current version set
            assert Setting.get("unpoller_latest_version") == "2.11.2"

    @patch("apps.unpoller.urllib.request.urlopen")
    def test_check_release_update_available(self, mock_urlopen, app):
        from apps.unpoller import check_unpoller_release

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "tag_name": "v2.12.0",
            "html_url": "",
        }).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        with app.app_context():
            Setting.set("unpoller_current_version", "2.11.0")
            db.session.commit()

            update, latest, url = check_unpoller_release()
            assert update is True
            assert latest == "2.12.0"

    @patch("apps.unpoller.urllib.request.urlopen", side_effect=Exception("network error"))
    def test_check_release_failure(self, mock_urlopen, app):
        from apps.unpoller import check_unpoller_release

        with app.app_context():
            update, latest, url = check_unpoller_release()
            assert update is False
            assert latest == ""


class TestRunUnpollerInstall:
    """Test install logic validation (without actual SSH)."""

    def test_install_no_guest_configured(self, app):
        from apps.unpoller import run_unpoller_install

        with app.app_context():
            Setting.set("prometheus_guest_id", "")
            db.session.commit()
            ok, logs = run_unpoller_install()
            assert ok is False
            assert any("not configured" in line for line in logs)

    def test_install_guest_not_found(self, app):
        from apps.unpoller import run_unpoller_install

        with app.app_context():
            Setting.set("prometheus_guest_id", "99999")
            db.session.commit()
            ok, logs = run_unpoller_install()
            assert ok is False
            assert any("not found" in line.lower() for line in logs)


class TestRunUnpollerUpgrade:
    """Test upgrade logic validation (without actual SSH)."""

    def test_upgrade_no_guest(self, app):
        from apps.unpoller import run_unpoller_upgrade

        with app.app_context():
            Setting.set("prometheus_guest_id", "")
            db.session.commit()
            ok, logs = run_unpoller_upgrade()
            assert ok is False

    def test_upgrade_guest_not_found(self, app):
        from apps.unpoller import run_unpoller_upgrade

        with app.app_context():
            Setting.set("prometheus_guest_id", "99999")
            db.session.commit()
            ok, logs = run_unpoller_upgrade()
            assert ok is False
            assert any("not found" in line.lower() for line in logs)


# ---------------------------------------------------------------------------
# routes/unpoller.py blueprint tests
# ---------------------------------------------------------------------------


class TestUnpollerRoutes:
    """Test the unpoller management blueprint."""

    def test_manage_requires_login(self, client):
        resp = client.get("/unpoller/manage")
        assert resp.status_code in (302, 401)

    def test_manage_accessible_for_admin(self, auth_client):
        resp = auth_client.get("/unpoller/manage")
        assert resp.status_code == 200
        assert b"Unpoller" in resp.data

    def test_save_settings(self, auth_client, app):
        resp = auth_client.post("/unpoller/save", data={
            "unpoller_metric_prefix": "custom_prefix",
            "unpoller_site_name": "mysite",
            "unpoller_listen_port": "9999",
        }, follow_redirects=True)
        assert resp.status_code == 200

        with app.app_context():
            assert Setting.get("unpoller_metric_prefix") == "custom_prefix"
            assert Setting.get("unpoller_site_name") == "mysite"
            assert Setting.get("unpoller_listen_port") == "9999"

    def test_save_settings_defaults(self, auth_client, app):
        resp = auth_client.post("/unpoller/save", data={
            "unpoller_metric_prefix": "",
            "unpoller_site_name": "",
            "unpoller_listen_port": "",
        }, follow_redirects=True)
        assert resp.status_code == 200

        with app.app_context():
            assert Setting.get("unpoller_metric_prefix") == "unpoller"
            assert Setting.get("unpoller_site_name") == "default"
            assert Setting.get("unpoller_listen_port") == "9130"

    def test_save_auto_upgrade(self, auth_client, app):
        resp = auth_client.post("/unpoller/save", data={
            "unpoller_auto_upgrade": "on",
            "unpoller_metric_prefix": "unpoller",
            "unpoller_site_name": "default",
            "unpoller_listen_port": "9130",
        }, follow_redirects=True)
        assert resp.status_code == 200

        with app.app_context():
            assert Setting.get("unpoller_auto_upgrade") == "true"

    def test_install_status_returns_json(self, auth_client):
        resp = auth_client.get("/unpoller/install/status")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "running" in data
        assert "success" in data
        assert "log" in data

    def test_upgrade_status_returns_json(self, auth_client):
        resp = auth_client.get("/unpoller/upgrade/status")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "running" in data

    def test_preflight_status_returns_json(self, auth_client):
        resp = auth_client.get("/unpoller/preflight/status")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "running" in data
        assert "success" in data
        assert "log" in data

    def test_reconfig_status_returns_json(self, auth_client):
        resp = auth_client.get("/unpoller/reconfig/status")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "running" in data

    def test_detect_version_no_guest(self, auth_client, app):
        with app.app_context():
            Setting.set("prometheus_guest_id", "")
            db.session.commit()
        resp = auth_client.post("/unpoller/detect-version", follow_redirects=True)
        assert resp.status_code == 200

    def test_check_for_updates(self, auth_client, app):
        with patch("apps.unpoller.check_unpoller_release", return_value=(False, "2.11.0", "")):
            resp = auth_client.post("/unpoller/check", follow_redirects=True)
            assert resp.status_code == 200


class TestUnpollerPermissions:
    """Test permission requirements for unpoller routes."""

    def test_save_requires_login(self, client):
        resp = client.post("/unpoller/save")
        assert resp.status_code in (302, 401)

    def test_install_requires_login(self, client):
        resp = client.post("/unpoller/install")
        assert resp.status_code in (302, 401)

    def test_upgrade_requires_login(self, client):
        resp = client.post("/unpoller/upgrade")
        assert resp.status_code in (302, 401)

    def test_preflight_requires_login(self, client):
        resp = client.post("/unpoller/preflight")
        assert resp.status_code in (302, 401)

    def test_reconfig_requires_login(self, client):
        resp = client.post("/unpoller/reconfig")
        assert resp.status_code in (302, 401)


class TestUnpollerPreflight:
    """Test preflight check logic."""

    def test_preflight_no_guest(self, app):
        from apps.unpoller import run_unpoller_preflight

        with app.app_context():
            Setting.set("prometheus_guest_id", "")
            db.session.commit()
            ok, output = run_unpoller_preflight()
            assert ok is False
            assert "FAIL" in output

    def test_preflight_no_unifi_creds(self, app):
        from apps.unpoller import run_unpoller_preflight
        from models import Guest

        with app.app_context():
            guest = Guest(name="prom-pf", guest_type="ct", enabled=True)
            db.session.add(guest)
            db.session.flush()
            Setting.set("prometheus_guest_id", str(guest.id))
            Setting.set("unifi_base_url", "")
            Setting.set("unifi_username", "")
            Setting.set("unifi_password", "")
            db.session.commit()

            ok, output = run_unpoller_preflight()
            assert ok is False
            assert "UniFi" in output
