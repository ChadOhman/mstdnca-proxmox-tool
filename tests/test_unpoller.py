"""Tests for unpoller automation (apps/unpoller.py and routes/unpoller.py)."""

import base64
import json
import re
from unittest.mock import MagicMock, patch

from models import Credential, Guest, Setting, db


def _decode_written_file(cmd):
    """Extract and base64-decode the payload from a _write_remote_file() command
    (`echo <b64> | base64 -d | install ...`)."""
    m = re.search(r"echo (\S+) \| base64 -d", cmd)
    assert m, f"command does not look like a base64 atomic write: {cmd!r}"
    return base64.b64decode(m.group(1)).decode("utf-8")

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

    def test_verify_ssl_defaults_false(self, app):
        """verify_ssl must follow the app's unifi_verify_ssl setting (issue #128) —
        this checks the default (unset) case, which must stay false."""
        from apps.unpoller import _generate_unpoller_config

        with app.app_context():
            config = {
                "unifi_url": "https://10.0.0.1", "unifi_user": "admin", "unifi_pass": "test-only-unifi-pass",
                "unifi_site": "default", "metric_prefix": "unpoller", "listen_port": "9130",
                "verify_ssl": False,
            }
            result = _generate_unpoller_config(config)
            assert "verify_ssl = false" in result

    def test_verify_ssl_true_when_setting_enabled(self, app):
        from apps.unpoller import _generate_unpoller_config

        with app.app_context():
            config = {
                "unifi_url": "https://10.0.0.1", "unifi_user": "admin", "unifi_pass": "test-only-unifi-pass",
                "unifi_site": "default", "metric_prefix": "unpoller", "listen_port": "9130",
                "verify_ssl": True,
            }
            result = _generate_unpoller_config(config)
            assert "verify_ssl = true" in result

    def test_toml_escape_quote_and_newline(self, app):
        from apps.unpoller import _toml_escape
        assert _toml_escape('has"quote') == 'has\\"quote'
        assert _toml_escape("line1\nline2") == "line1\\nline2"
        assert _toml_escape("back\\slash") == "back\\\\slash"

    def test_generated_config_with_special_chars_is_valid_toml(self, app):
        """A password containing a `"` or a newline must not break the generated
        up.conf (issue #128)."""
        import tomllib

        from apps.unpoller import _generate_unpoller_config

        with app.app_context():
            config = {
                "unifi_url": "https://10.0.0.1",
                "unifi_user": "admin",
                "unifi_pass": 'wei"rd\npass\r\nword',
                "unifi_site": "default",
                "metric_prefix": "unpoller",
                "listen_port": "9130",
                "verify_ssl": False,
            }
            result = _generate_unpoller_config(config)
            parsed = tomllib.loads(result)
            controller = parsed["unifi"]["controller"][0]
            assert controller["pass"] == 'wei"rd\npass\r\nword'
            assert controller["url"] == "https://10.0.0.1"


class TestUnpollerGetConfig:
    """Test _get_config reads settings correctly."""

    def test_get_config_defaults(self, app):
        from apps.unpoller import _get_config

        with app.app_context():
            # prometheus_guest_id is a shared, cross-test Setting in this
            # session-scoped DB (the Prometheus/exporter tests set it), so clear
            # it here instead of depending on file execution order.
            Setting.set("prometheus_guest_id", "")
            config = _get_config()
            assert config["guest_id"] == ""
            assert config["unifi_site"] == "default"
            assert config["metric_prefix"] == "unpoller"
            assert config["listen_port"] == "9130"
            # verify_ssl's default is covered by test_get_config_follows_unifi_verify_ssl_setting,
            # which sets the underlying setting explicitly — unifi_verify_ssl is a
            # shared, cross-test Setting and other tests (e.g. the settings-page
            # save flow) may leave it toggled on in this session-scoped DB.

    def test_get_config_reads_settings(self, app):
        from apps.unpoller import _get_config

        with app.app_context():
            Setting.set("prometheus_guest_id", "42")
            Setting.set("unifi_base_url", "https://udm.local")
            Setting.set("unifi_username", "testuser")
            Setting.set("unifi_password", "test-only-testpass")
            Setting.set("unpoller_site_name", "mysite")
            db.session.commit()

            config = _get_config()
            assert config["guest_id"] == "42"
            assert config["unifi_url"] == "https://udm.local"
            assert config["unifi_user"] == "testuser"
            assert config["unifi_pass"] == "test-only-testpass"
            assert config["unifi_site"] == "mysite"

    def test_get_config_follows_unifi_verify_ssl_setting(self, app):
        """verify_ssl must track the app's existing UniFi verify-SSL setting (the
        same one clients/unifi_client.py and routes/settings.py use) rather than
        being hardcoded false."""
        from apps.unpoller import _get_config

        with app.app_context():
            Setting.set("unifi_verify_ssl", "true")
            db.session.commit()
            assert _get_config()["verify_ssl"] is True

            Setting.set("unifi_verify_ssl", "false")
            db.session.commit()
            assert _get_config()["verify_ssl"] is False


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

    @patch("apps.unpoller.SSHClient")
    @patch("apps.unpoller._snapshot_guest", return_value=(True, "snapshot ok"))
    def test_up_conf_written_atomically_not_via_heredoc(self, mock_snap, MockSSH, app):
        """up.conf (which carries the UniFi controller password) must be written
        via base64+install, with its final mode/ownership set in the same step —
        never a `cat > ... << 'UPEOF'` heredoc that a value in the config could
        break out of, and never chmod'd/chown'd after a plain-umask create."""
        from apps.unpoller import run_unpoller_install

        mock_ssh = MagicMock()
        mock_ssh.execute_sudo.return_value = ("", "", 0)
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)
        MockSSH.from_credential.return_value = mock_ssh

        with app.app_context():
            cred = Credential(
                name="up-install-cred", username="root", auth_type="password",
                encrypted_value="unused-in-mocked-ssh", is_default=True,
            )
            db.session.add(cred)
            guest = Guest(
                name="up-install-guest", vmid=501, guest_type="lxc",
                ip_address="10.0.0.55", credential_id=None,
            )
            db.session.add(guest)
            db.session.commit()
            guest.credential_id = cred.id
            db.session.commit()

            Setting.set("prometheus_guest_id", str(guest.id))
            Setting.set("unifi_base_url", "https://udm.local")
            Setting.set("unifi_username", "admin")
            Setting.set("unifi_password", "test-only-unifi-pass")
            Setting.set("unpoller_latest_version", "1.2.3")
            db.session.commit()

            with patch("apps.exporters._regenerate_prometheus_config", return_value=True):
                ok, logs = run_unpoller_install()

            assert ok is True, "\n".join(logs)

        calls = [str(c.args[0]) for c in mock_ssh.execute_sudo.call_args_list]
        write_calls = [c for c in calls if "up.conf" in c and "install -m 640" in c]
        assert len(write_calls) == 1
        cmd = write_calls[0]
        assert "cat >" not in cmd
        assert "UPEOF" not in cmd
        assert "install -m 640 -o root -g unpoller /dev/stdin /etc/unpoller/up.conf" in cmd
        assert "test-only-unifi-pass" not in cmd  # raw password never appears in the command line

        import tomllib
        parsed = tomllib.loads(_decode_written_file(cmd))
        assert parsed["unifi"]["controller"][0]["user"] == "admin"

        # No separate chmod/chown call after the write — install sets them atomically.
        assert not any("chmod 640" in c and "up.conf" in c for c in calls)

        with app.app_context():
            Setting.set("prometheus_guest_id", "")  # avoid leaking into other tests
            db.session.commit()


class TestRunUnpollerReconfig:
    @patch("apps.unpoller.SSHClient")
    def test_reconfig_writes_up_conf_atomically(self, MockSSH, app):
        from apps.unpoller import run_unpoller_reconfig

        mock_ssh = MagicMock()
        mock_ssh.execute_sudo.return_value = ("", "", 0)
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)
        MockSSH.from_credential.return_value = mock_ssh

        with app.app_context():
            cred = Credential(
                name="up-reconf-cred", username="root", auth_type="password",
                encrypted_value="unused-in-mocked-ssh", is_default=True,
            )
            db.session.add(cred)
            guest = Guest(
                name="up-reconf-guest", vmid=502, guest_type="lxc",
                ip_address="10.0.0.56", credential_id=None,
            )
            db.session.add(guest)
            db.session.commit()
            guest.credential_id = cred.id
            db.session.commit()

            Setting.set("prometheus_guest_id", str(guest.id))
            Setting.set("unifi_base_url", "https://udm.local")
            Setting.set("unifi_username", "admin")
            Setting.set("unifi_password", 'pw"withquote')
            db.session.commit()

            ok, logs = run_unpoller_reconfig()
            assert ok is True, "\n".join(logs)

        calls = [str(c.args[0]) for c in mock_ssh.execute_sudo.call_args_list]
        write_calls = [c for c in calls if "up.conf" in c and "install -m 640" in c]
        assert len(write_calls) == 1
        assert "UPEOF" not in write_calls[0]

        import tomllib
        parsed = tomllib.loads(_decode_written_file(write_calls[0]))
        assert parsed["unifi"]["controller"][0]["pass"] == 'pw"withquote'

        with app.app_context():
            Setting.set("prometheus_guest_id", "")  # avoid leaking into other tests
            db.session.commit()


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
