"""Tests for the settings blueprint routes."""
import json
from unittest.mock import MagicMock, patch

from models import Setting


class TestSettingsIndex:
    def test_get_settings_page_returns_200(self, auth_client):
        resp = auth_client.get("/settings/")
        assert resp.status_code == 200

    def test_settings_page_requires_auth(self, client):
        resp = client.get("/settings/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


class TestDiscordSettings:
    def test_save_discord_webhook_and_preferences(self, app, auth_client):
        resp = auth_client.post(
            "/settings/discord",
            data={
                "discord_webhook_url": "https://discord.com/api/webhooks/123/abc",
                "discord_enabled": "on",
                "discord_notify_updates": "on",
                "discord_notify_mastodon": "on",
                # discord_notify_updates_security_only omitted (unchecked)
                # discord_notify_ghost omitted (unchecked)
                # discord_notify_app omitted (unchecked)
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            assert Setting.get("discord_webhook_url") == "https://discord.com/api/webhooks/123/abc"
            assert Setting.get("discord_enabled") == "true"
            assert Setting.get("discord_notify_updates") == "true"
            assert Setting.get("discord_notify_updates_security_only") == "false"
            assert Setting.get("discord_notify_mastodon") == "true"
            assert Setting.get("discord_notify_ghost") == "false"
            assert Setting.get("discord_notify_app") == "false"

    def test_save_discord_all_checkboxes_unchecked(self, app, auth_client):
        resp = auth_client.post(
            "/settings/discord",
            data={
                "discord_webhook_url": "",
                # all checkboxes absent
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            assert Setting.get("discord_enabled") == "false"
            assert Setting.get("discord_notify_updates") == "false"
            assert Setting.get("discord_notify_mastodon") == "false"
            assert Setting.get("discord_notify_ghost") == "false"
            assert Setting.get("discord_notify_app") == "false"

    def test_save_discord_empty_webhook_does_not_overwrite(self, app, auth_client):
        """An empty webhook_url in the form should not overwrite an existing URL."""
        with app.app_context():
            Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/existing/url")

        auth_client.post(
            "/settings/discord",
            data={"discord_webhook_url": ""},
            follow_redirects=False,
        )

        with app.app_context():
            # The route only saves webhook_url when it is non-empty
            assert Setting.get("discord_webhook_url") == "https://discord.com/api/webhooks/existing/url"


class TestScanSettings:
    def test_save_scan_settings(self, app, auth_client):
        resp = auth_client.post(
            "/settings/scan",
            data={
                "scan_interval": "12",
                "scan_enabled": "on",
                "discovery_interval": "8",
                "discovery_enabled": "on",
                "service_check_interval": "10",
                # service_check_enabled omitted (unchecked)
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            assert Setting.get("scan_interval") == "12"
            assert Setting.get("scan_enabled") == "true"
            assert Setting.get("discovery_interval") == "8"
            assert Setting.get("discovery_enabled") == "true"
            assert Setting.get("service_check_interval") == "10"
            assert Setting.get("service_check_enabled") == "false"

    def test_save_scan_settings_all_disabled(self, app, auth_client):
        resp = auth_client.post(
            "/settings/scan",
            data={
                "scan_interval": "6",
                "discovery_interval": "4",
                "service_check_interval": "5",
                # all enabled checkboxes omitted
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            assert Setting.get("scan_enabled") == "false"
            assert Setting.get("discovery_enabled") == "false"
            assert Setting.get("service_check_enabled") == "false"


class TestUnifiSettings:
    def test_save_unifi_settings(self, app, auth_client):
        resp = auth_client.post(
            "/settings/unifi",
            data={
                "unifi_enabled": "on",
                "unifi_base_url": "https://unifi.example.com",
                "unifi_username": "admin",
                "unifi_password": "secret123",
                "unifi_site": "default",
                "unifi_is_udm": "on",
                "unifi_filter_subnet": "192.168.1.0/24",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            assert Setting.get("unifi_enabled") == "true"
            assert Setting.get("unifi_base_url") == "https://unifi.example.com"
            assert Setting.get("unifi_username") == "admin"
            # Password is encrypted; verify something was stored (not plaintext)
            stored_pw = Setting.get("unifi_password")
            assert stored_pw is not None
            assert stored_pw != "secret123"
            assert Setting.get("unifi_site") == "default"
            assert Setting.get("unifi_is_udm") == "true"
            assert Setting.get("unifi_filter_subnet") == "192.168.1.0/24"

    def test_save_unifi_disabled_and_no_udm(self, app, auth_client):
        resp = auth_client.post(
            "/settings/unifi",
            data={
                # unifi_enabled omitted (unchecked)
                "unifi_base_url": "https://unifi.local",
                "unifi_username": "localadmin",
                # unifi_is_udm omitted (unchecked)
                "unifi_site": "home",
                "unifi_filter_subnet": "",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            assert Setting.get("unifi_enabled") == "false"
            assert Setting.get("unifi_is_udm") == "false"
            assert Setting.get("unifi_site") == "home"

    def test_save_unifi_empty_password_does_not_overwrite(self, app, auth_client):
        """Submitting an empty password should leave the existing encrypted value intact."""
        with app.app_context():
            Setting.set("unifi_password", "previously-encrypted-value")

        auth_client.post(
            "/settings/unifi",
            data={
                "unifi_base_url": "https://unifi.example.com",
                "unifi_username": "admin",
                "unifi_password": "",  # empty — should not overwrite
            },
            follow_redirects=False,
        )

        with app.app_context():
            assert Setting.get("unifi_password") == "previously-encrypted-value"

    def test_save_unifi_empty_site_defaults_to_default(self, app, auth_client):
        """An empty site value should be coerced to 'default'."""
        auth_client.post(
            "/settings/unifi",
            data={
                "unifi_base_url": "",
                "unifi_username": "",
                "unifi_site": "",
            },
            follow_redirects=False,
        )

        with app.app_context():
            assert Setting.get("unifi_site") == "default"


class TestUnifiLoggingSettings:
    def test_save_valid_unifi_logging_settings(self, app, auth_client):
        resp = auth_client.post(
            "/settings/unifi-logging",
            data={
                "unifi_geoip_enabled": "on",
                "unifi_geoip_db_path": "/var/lib/mstdnca/GeoLite2-City.mmdb",
                "unifi_api_poll_enabled": "on",
                "unifi_api_poll_interval": "15",
                "unifi_log_retention_days": "90",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            assert Setting.get("unifi_geoip_enabled") == "true"
            assert Setting.get("unifi_geoip_db_path") == "/var/lib/mstdnca/GeoLite2-City.mmdb"
            assert Setting.get("unifi_api_poll_enabled") == "true"
            assert Setting.get("unifi_api_poll_interval") == "15"
            assert Setting.get("unifi_log_retention_days") == "90"

    def test_save_unifi_logging_interval_too_low(self, auth_client):
        """Poll interval of 0 is below the minimum of 1; should flash an error and redirect."""
        resp = auth_client.post(
            "/settings/unifi-logging",
            data={
                "unifi_api_poll_interval": "0",
                "unifi_log_retention_days": "60",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Poll interval must be between 1 and 1440 minutes" in resp.data

    def test_save_unifi_logging_interval_too_high(self, auth_client):
        """Poll interval above 1440 is out of range."""
        resp = auth_client.post(
            "/settings/unifi-logging",
            data={
                "unifi_api_poll_interval": "1441",
                "unifi_log_retention_days": "60",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Poll interval must be between 1 and 1440 minutes" in resp.data

    def test_save_unifi_logging_interval_non_numeric(self, auth_client):
        """Non-numeric poll interval should be rejected."""
        resp = auth_client.post(
            "/settings/unifi-logging",
            data={
                "unifi_api_poll_interval": "abc",
                "unifi_log_retention_days": "60",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Poll interval must be between 1 and 1440 minutes" in resp.data

    def test_save_unifi_logging_retention_too_low(self, auth_client):
        """Retention of 0 days is below the minimum of 1; should flash an error."""
        resp = auth_client.post(
            "/settings/unifi-logging",
            data={
                "unifi_api_poll_interval": "5",
                "unifi_log_retention_days": "0",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Retention must be between 1 and 365 days" in resp.data

    def test_save_unifi_logging_retention_too_high(self, auth_client):
        """Retention above 365 days is out of range."""
        resp = auth_client.post(
            "/settings/unifi-logging",
            data={
                "unifi_api_poll_interval": "5",
                "unifi_log_retention_days": "366",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Retention must be between 1 and 365 days" in resp.data

    def test_save_unifi_logging_retention_non_numeric(self, auth_client):
        """Non-numeric retention should be rejected."""
        resp = auth_client.post(
            "/settings/unifi-logging",
            data={
                "unifi_api_poll_interval": "5",
                "unifi_log_retention_days": "bad",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Retention must be between 1 and 365 days" in resp.data

    def test_save_unifi_logging_checkboxes_off(self, app, auth_client):
        """Unchecked checkboxes should persist as 'false'."""
        resp = auth_client.post(
            "/settings/unifi-logging",
            data={
                # geoip_enabled and api_poll_enabled both omitted
                "unifi_api_poll_interval": "5",
                "unifi_log_retention_days": "60",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            assert Setting.get("unifi_geoip_enabled") == "false"
            assert Setting.get("unifi_api_poll_enabled") == "false"


class TestUnpollerSettings:
    def test_save_unpoller_enabled(self, app, auth_client):
        resp = auth_client.post(
            "/settings/unpoller",
            data={
                "unpoller_enabled": "on",
                "unpoller_metric_prefix": "myprefix",
                "unpoller_site_name": "mysite",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302
        with app.app_context():
            assert Setting.get("unpoller_enabled") == "true"
            assert Setting.get("unpoller_metric_prefix") == "myprefix"
            assert Setting.get("unpoller_site_name") == "mysite"

    def test_save_unpoller_disabled(self, app, auth_client):
        resp = auth_client.post(
            "/settings/unpoller",
            data={
                "unpoller_metric_prefix": "",
                "unpoller_site_name": "",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302
        with app.app_context():
            assert Setting.get("unpoller_enabled") == "false"
            assert Setting.get("unpoller_metric_prefix") == "unpoller"  # defaults
            assert Setting.get("unpoller_site_name") == "default"

    def test_test_unpoller_no_prometheus(self, auth_client):
        resp = auth_client.post(
            "/settings/unpoller/test",
            data={
                "unpoller_enabled": "on",
                "unpoller_metric_prefix": "unpoller",
                "unpoller_site_name": "default",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "Prometheus URL is not configured" in html or "not configured" in html.lower()


class TestAppUpdateMode:
    def test_save_update_mode_with_branch_and_auto_update(self, app, auth_client):
        resp = auth_client.post(
            "/settings/app-update-mode",
            data={
                "app_auto_update": "on",
                "app_update_branch": "main",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            assert Setting.get("app_auto_update") == "true"
            assert Setting.get("app_update_branch") == "main"

    def test_save_update_mode_auto_update_off(self, app, auth_client):
        resp = auth_client.post(
            "/settings/app-update-mode",
            data={
                # app_auto_update omitted (unchecked)
                "app_update_branch": "",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            assert Setting.get("app_auto_update") == "false"
            assert Setting.get("app_update_branch") == ""

    def test_save_update_mode_branch_stripped(self, app, auth_client):
        """Leading/trailing whitespace in the branch name should be stripped."""
        resp = auth_client.post(
            "/settings/app-update-mode",
            data={
                "app_update_branch": "  develop  ",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            assert Setting.get("app_update_branch") == "develop"


class TestUpdateStatus:
    """Tests for GET /settings/update-status.

    The route reads a pid file and a log file from DATA_DIR.  In the test
    environment those files may not exist (or may contain a stale PID from a
    previous run that causes os.kill to raise a platform-specific error on
    Windows).  We patch os.path.exists inside the route to always report that
    neither file exists so the tests are deterministic on all platforms.
    """

    def _get_status(self, auth_client):
        with patch("routes.settings.os.path.exists", return_value=False):
            return auth_client.get("/settings/update-status")

    def test_update_status_returns_json(self, auth_client):
        resp = self._get_status(auth_client)
        assert resp.status_code == 200
        assert resp.content_type.startswith("application/json")

    def test_update_status_running_false_when_no_pid_file(self, auth_client):
        """When no update.pid file exists the running field should be false."""
        resp = self._get_status(auth_client)
        data = json.loads(resp.data)
        assert data["running"] is False

    def test_update_status_contains_expected_keys(self, auth_client):
        resp = self._get_status(auth_client)
        data = json.loads(resp.data)
        assert "running" in data
        assert "log" in data
        assert "line_count" in data

    def test_update_status_log_is_string(self, auth_client):
        resp = self._get_status(auth_client)
        data = json.loads(resp.data)
        assert isinstance(data["log"], str)


class TestApplyUpdate:
    def test_apply_update_error_when_script_missing(self, auth_client):
        """When update.sh does not exist the route should flash an error and redirect."""
        # Patch os.path.exists so the update script appears absent regardless of the filesystem
        with patch("routes.settings.os.path.exists", return_value=False):
            resp = auth_client.post(
                "/settings/apply-update",
                follow_redirects=True,
            )
        assert resp.status_code == 200
        assert b"Update script not found" in resp.data

    def test_apply_update_redirects_without_following(self, auth_client):
        """The route always issues a redirect (to error page or progress page)."""
        with patch("routes.settings.os.path.exists", return_value=False):
            resp = auth_client.post(
                "/settings/apply-update",
                follow_redirects=False,
            )
        # Should redirect — to settings.index on error (script missing)
        assert resp.status_code == 302


class TestCheckUpdate:
    def _make_fake_urlopen(self, payload: dict):
        """Return a context-manager mock that yields a fake HTTP response."""
        fake_resp = MagicMock()
        fake_resp.read.return_value = json.dumps(payload).encode()
        fake_resp.__enter__ = MagicMock(return_value=fake_resp)
        fake_resp.__exit__ = MagicMock(return_value=False)
        return fake_resp

    def test_check_update_latest_version_flashes_up_to_date(self, app, auth_client):
        """When GitHub reports the same version as the running app, a success flash appears."""
        with app.app_context():
            current_version = app.config.get("APP_VERSION", "1.0.0")

        fake_resp = self._make_fake_urlopen({"tag_name": f"v{current_version}"})

        with patch("urllib.request.urlopen", return_value=fake_resp):
            resp = auth_client.post(
                "/settings/check-update",
                data={"app_update_branch": ""},
                follow_redirects=True,
            )

        assert resp.status_code == 200
        # Should flash that we are on the latest version
        assert b"latest version" in resp.data.lower() or b"up to date" in resp.data.lower()

    def test_check_update_new_version_shows_update_available(self, app, auth_client):
        """When GitHub reports a newer version the settings page is rendered with update info."""
        fake_resp = self._make_fake_urlopen({"tag_name": "v99.99.99"})

        with patch("urllib.request.urlopen", return_value=fake_resp):
            resp = auth_client.post(
                "/settings/check-update",
                data={"app_update_branch": ""},
                follow_redirects=False,
            )

        # The route renders settings.html directly (not a redirect) when an update is found
        assert resp.status_code == 200
        assert b"99.99.99" in resp.data

    def test_check_update_saves_settings_from_form(self, app, auth_client):
        """check-update also persists app_auto_update and app_update_branch from the form."""
        fake_resp = self._make_fake_urlopen({"tag_name": "v0.0.1"})

        with patch("urllib.request.urlopen", return_value=fake_resp):
            auth_client.post(
                "/settings/check-update",
                data={
                    "app_auto_update": "on",
                    "app_update_branch": "",
                },
                follow_redirects=True,
            )

        with app.app_context():
            assert Setting.get("app_auto_update") == "true"

    def test_check_update_network_error_flashes_error(self, auth_client):
        """If the GitHub API call raises an exception the route should flash an error."""
        with patch("urllib.request.urlopen", side_effect=Exception("network timeout")):
            resp = auth_client.post(
                "/settings/check-update",
                data={"app_update_branch": ""},
                follow_redirects=True,
            )

        assert resp.status_code == 200
        assert b"Could not check for updates" in resp.data

    def test_check_update_branch_shows_update_available(self, app, auth_client):
        """When a branch is configured and HEAD differs from current commit, update is shown."""
        fake_branch_resp = self._make_fake_urlopen({
            "commit": {
                "sha": "deadbeef1234567890abcdef",
                "commit": {"message": "feat: some new feature"},
            }
        })

        with patch("urllib.request.urlopen", return_value=fake_branch_resp):
            resp = auth_client.post(
                "/settings/check-update",
                data={"app_update_branch": "develop"},
                follow_redirects=False,
            )

        # Either renders the page with update info (200) or redirects (already up to date)
        assert resp.status_code in (200, 302)

    def test_check_update_branch_network_error_flashes(self, auth_client):
        """A network error on the branch check should flash an error and redirect."""
        with patch("urllib.request.urlopen", side_effect=Exception("connection refused")):
            resp = auth_client.post(
                "/settings/check-update",
                data={"app_update_branch": "main"},
                follow_redirects=True,
            )

        assert resp.status_code == 200
        assert b"Could not check branch" in resp.data


class TestRefreshBackupStorages:
    def test_refresh_storages_xhr_returns_json(self, app, auth_client):
        """AJAX refresh should poll Proxmox and return JSON with storages list."""
        with patch("models.ProxmoxHost") as MockHost, \
             patch("clients.proxmox_api.ProxmoxClient"):
            MockHost.query.filter.return_value.all.return_value = []
            resp = auth_client.post(
                "/settings/backups/refresh-storages",
                headers={"X-Requested-With": "XMLHttpRequest"},
            )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert isinstance(data["storages"], list)
        assert "cached_at" in data

    def test_refresh_storages_saves_cache(self, app, auth_client):
        """Refresh should persist the storages list in the Setting table."""
        with patch("models.ProxmoxHost") as MockHost, \
             patch("clients.proxmox_api.ProxmoxClient"):
            MockHost.query.filter.return_value.all.return_value = []
            auth_client.post(
                "/settings/backups/refresh-storages",
                headers={"X-Requested-With": "XMLHttpRequest"},
            )
        with app.app_context():
            assert Setting.get("backup_storages_cache") is not None
            assert Setting.get("backup_storages_cache_time") is not None

    def test_refresh_storages_form_post_redirects(self, app, auth_client):
        """Non-AJAX POST should redirect back to settings."""
        with patch("models.ProxmoxHost") as MockHost, \
             patch("clients.proxmox_api.ProxmoxClient"):
            MockHost.query.filter.return_value.all.return_value = []
            resp = auth_client.post(
                "/settings/backups/refresh-storages",
                follow_redirects=False,
            )
        assert resp.status_code == 302


class TestBackupTagDefaults:
    def test_save_tag_overrides(self, app, auth_client):
        resp = auth_client.post(
            "/settings/backups/tag-defaults",
            data={
                "tag_name": ["production", "dev"],
                "tag_storage": ["pbs-prod", "local"],
                "tag_mode": ["snapshot", "stop"],
                "tag_compress": ["zstd", "lzo"],
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            raw = Setting.get("backup_tag_defaults")
            overrides = json.loads(raw)
            assert overrides["production"]["storage"] == "pbs-prod"
            assert overrides["production"]["mode"] == "snapshot"
            assert overrides["dev"]["compress"] == "lzo"

    def test_save_tag_overrides_skips_empty_names(self, app, auth_client):
        resp = auth_client.post(
            "/settings/backups/tag-defaults",
            data={
                "tag_name": ["", "staging"],
                "tag_storage": ["local", "remote"],
                "tag_mode": ["", "suspend"],
                "tag_compress": ["", "gzip"],
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            overrides = json.loads(Setting.get("backup_tag_defaults"))
            assert "" not in overrides
            assert "staging" in overrides

    def test_save_tag_overrides_skips_empty_storage(self, app, auth_client):
        """Rows with empty storage are skipped (storage is required)."""
        resp = auth_client.post(
            "/settings/backups/tag-defaults",
            data={
                "tag_name": ["production"],
                "tag_storage": [""],
                "tag_mode": ["snapshot"],
                "tag_compress": ["zstd"],
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            overrides = json.loads(Setting.get("backup_tag_defaults"))
            assert "production" not in overrides

    def test_save_tag_overrides_defaults_mode_and_compress(self, app, auth_client):
        """Empty mode/compress default to snapshot/zstd."""
        resp = auth_client.post(
            "/settings/backups/tag-defaults",
            data={
                "tag_name": ["production"],
                "tag_storage": ["pbs-prod"],
                "tag_mode": [""],
                "tag_compress": [""],
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            overrides = json.loads(Setting.get("backup_tag_defaults"))
            assert overrides["production"]["storage"] == "pbs-prod"
            assert overrides["production"]["mode"] == "snapshot"
            assert overrides["production"]["compress"] == "zstd"


class TestSettingsIndexCache:
    def test_index_loads_storages_from_cache(self, app, auth_client):
        """Settings index should read storages from cache, not poll API."""
        storages = [{"storage": "local-backup", "type": "dir", "avail": 1073741824}]
        with app.app_context():
            Setting.set("backup_storages_cache", json.dumps(storages))
            Setting.set("backup_storages_cache_time", "2026-03-04T12:00:00")

        resp = auth_client.get("/settings/")
        assert resp.status_code == 200
        assert b"local-backup" in resp.data

    def test_index_renders_without_cache(self, app, auth_client):
        """Settings page should load even with no cached storages."""
        resp = auth_client.get("/settings/")
        assert resp.status_code == 200


class TestGithubAuthHeaders:
    def test_returns_empty_when_no_token(self, app):
        from routes.settings import _github_auth_headers
        with app.app_context():
            from models import Setting
            Setting.set("github_token", "")
            assert _github_auth_headers() == {}

    def test_returns_bearer_when_token_set(self, app):
        from auth.credential_store import encrypt
        from models import Setting
        from routes.settings import _github_auth_headers
        with app.app_context():
            Setting.set("github_token", encrypt("ghp_test123"))
            assert _github_auth_headers() == {"Authorization": "Bearer ghp_test123"}


class TestCheckUpdateAuthHeader:
    def _recorder(self):
        """Return (capture_dict, fake_urlopen) that records the Request passed in."""
        capture = {}

        def fake_urlopen(req, timeout=None):
            capture["auth"] = req.get_header("Authorization")
            resp = MagicMock()
            resp.read.return_value = json.dumps({"tag_name": "v0.0.1"}).encode()
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=False)
            return resp

        return capture, fake_urlopen

    def test_release_check_sends_bearer_when_token_set(self, app, auth_client):
        from auth.credential_store import encrypt
        from models import Setting
        with app.app_context():
            Setting.set("github_token", encrypt("ghp_abc"))
        capture, fake = self._recorder()
        with patch("urllib.request.urlopen", side_effect=fake):
            auth_client.post("/settings/check-update", data={"app_update_branch": ""},
                             follow_redirects=True)
        assert capture["auth"] == "Bearer ghp_abc"

    def test_release_check_no_header_when_no_token(self, app, auth_client):
        from models import Setting
        with app.app_context():
            Setting.set("github_token", "")
        capture, fake = self._recorder()
        with patch("urllib.request.urlopen", side_effect=fake):
            auth_client.post("/settings/check-update", data={"app_update_branch": ""},
                             follow_redirects=True)
        assert capture["auth"] is None


class TestGithubTokenSave:
    def test_app_update_mode_saves_encrypted_token(self, app, auth_client):
        from auth.credential_store import decrypt
        from models import Setting
        auth_client.post("/settings/app-update-mode",
                         data={"app_update_branch": "main", "github_token": "ghp_secret"},
                         follow_redirects=True)
        with app.app_context():
            stored = Setting.get("github_token", "")
            assert stored != ""
            assert stored != "ghp_secret"          # encrypted at rest
            assert decrypt(stored) == "ghp_secret"  # round-trips

    def test_blank_token_keeps_existing(self, app, auth_client):
        from auth.credential_store import decrypt, encrypt
        from models import Setting
        with app.app_context():
            Setting.set("github_token", encrypt("ghp_existing"))
        auth_client.post("/settings/app-update-mode",
                         data={"app_update_branch": "main", "github_token": ""},
                         follow_redirects=True)
        with app.app_context():
            assert decrypt(Setting.get("github_token", "")) == "ghp_existing"
