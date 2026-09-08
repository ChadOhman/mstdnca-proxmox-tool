"""Tests for config export/import and app-database backup (routes/settings.py)."""
import json

import pytest

from auth.credential_store import encrypt
from models import Guest, ProxmoxHost, Role, Setting, Tag, User, db

_LOWPRIV_PASSWORD = "LowPrivPass123!"


@pytest.fixture()
def viewer_client(app):
    """A test client logged in as a low-privilege (viewer) user."""
    with app.app_context():
        viewer_role = Role.query.filter_by(name="viewer").first()
        existing = User.query.filter_by(username="viewer-test").first()
        if existing is None:
            u = User(username="viewer-test", display_name="Viewer Test", role_id=viewer_role.id)
            u.set_password(_LOWPRIV_PASSWORD)
            db.session.add(u)
            db.session.commit()
    with app.test_client() as c:
        c.post("/login", data={"username": "viewer-test", "password": _LOWPRIV_PASSWORD},
               follow_redirects=False)
        yield c


@pytest.fixture()
def seeded_config(app):
    """Seed hosts, guests, tags, and secret-bearing settings for export tests."""
    secrets = {
        "host_pw": "test-only-host-pw",
        "token_secret": "test-only-api-token",
        "ipmi_pw": "test-only-ipmi-pw",
        "unifi_pw_plain": "test-only-unifi-pw",
        "github_token_plain": "test-only-github-token",
        "discord_url": "https://example.invalid/webhooks/123/test-only-webhook",
    }
    with app.app_context():
        # Clean slate for deterministic assertions. Delete via ORM objects so the
        # guest_tags association rows are cleared through the relationship cascade.
        for g in Guest.query.all():
            db.session.delete(g)
        db.session.flush()
        for h in ProxmoxHost.query.all():
            db.session.delete(h)
        for t in Tag.query.all():
            db.session.delete(t)
        db.session.commit()

        tag = Tag(name="production", color="#ff0000")
        db.session.add(tag)
        db.session.flush()

        host = ProxmoxHost(
            name="pve1", hostname="pve1.example.com", port=8006, auth_type="token",
            username="root@pam", api_token_id="root@pam!mytoken",
            encrypted_password=encrypt(secrets["host_pw"]),
            api_token_secret=encrypt(secrets["token_secret"]),
            ipmi_enabled=True, ipmi_address="10.0.0.5", ipmi_username="ADMIN",
            ipmi_password=encrypt(secrets["ipmi_pw"]),
            host_type="pve",
        )
        db.session.add(host)
        db.session.flush()

        guest = Guest(
            proxmox_host_id=host.id, vmid=101, name="web01", guest_type="ct",
            ip_address="10.0.0.101", connection_method="ssh", enabled=True,
        )
        guest.tags = [tag]
        db.session.add(guest)

        Setting.set("scan_interval", "9")
        Setting.set("unifi_password", encrypt(secrets["unifi_pw_plain"]))
        Setting.set("github_token", encrypt(secrets["github_token_plain"]))
        Setting.set("discord_webhook_url", secrets["discord_url"])
        db.session.commit()

    yield secrets

    # Teardown: remove everything we created so the session-scoped DB is not
    # polluted for other tests (e.g. those that also create a "production" tag).
    with app.app_context():
        for g in Guest.query.all():
            db.session.delete(g)
        db.session.flush()
        for h in ProxmoxHost.query.all():
            db.session.delete(h)
        for t in Tag.query.all():
            db.session.delete(t)
        db.session.commit()


class TestExport:
    def test_export_returns_json_attachment(self, auth_client, seeded_config):
        resp = auth_client.get("/settings/config/export")
        assert resp.status_code == 200
        assert resp.mimetype == "application/json"
        assert "attachment" in resp.headers["Content-Disposition"]
        doc = json.loads(resp.data)
        assert doc["version"] == 1
        assert {"hosts", "guests", "tags", "roles", "settings"} <= set(doc)

    def test_export_includes_config_fields(self, auth_client, seeded_config):
        doc = json.loads(auth_client.get("/settings/config/export").data)
        host = next(h for h in doc["hosts"] if h["name"] == "pve1")
        assert host["hostname"] == "pve1.example.com"
        assert host["ipmi_username"] == "ADMIN"
        guest = next(g for g in doc["guests"] if g["name"] == "web01")
        assert guest["vmid"] == 101
        assert guest["host_name"] == "pve1"
        assert "production" in guest["tags"]

    def test_export_excludes_all_secrets(self, auth_client, seeded_config):
        """No decrypted OR encrypted secret value may appear anywhere in the export."""
        raw = auth_client.get("/settings/config/export").data.decode("utf-8")
        # Decrypted plaintext secrets
        for plain in ("test-only-host-pw", "test-only-api-token", "test-only-ipmi-pw",
                      "test-only-unifi-pw", "test-only-github-token", "test-only-webhook"):
            assert plain not in raw, f"secret {plain!r} leaked into export"

        doc = json.loads(raw)
        host = next(h for h in doc["hosts"] if h["name"] == "pve1")
        # Encrypted secret columns must be entirely absent from the host object
        for secret_field in ("encrypted_password", "api_token_secret", "ipmi_password"):
            assert secret_field not in host

        # Secret settings are redacted, not real values
        assert doc["settings"].get("unifi_password") == "***REDACTED***"
        assert doc["settings"].get("github_token") == "***REDACTED***"
        assert doc["settings"].get("discord_webhook_url") == "***REDACTED***"
        # Non-secret setting round-trips
        assert doc["settings"].get("scan_interval") == "9"

    def test_export_denied_for_viewer(self, viewer_client):
        resp = viewer_client.get("/settings/config/export")
        # Lower-privilege users are bounced by the settings before_request
        # (redirect to dashboard) or by the super-admin gate (403).
        assert resp.status_code in (302, 403)


class TestImport:
    def _export(self, auth_client):
        return json.loads(auth_client.get("/settings/config/export").data)

    def _upload(self, client, doc, **extra_form):
        import io
        payload = json.dumps(doc).encode("utf-8")
        return client.post(
            "/settings/config/import",
            data={"config_file": (io.BytesIO(payload), "config.json"), **extra_form},
            content_type="multipart/form-data",
            follow_redirects=True,
        )

    def test_import_round_trip(self, app, auth_client, seeded_config):
        doc = self._export(auth_client)
        # Wipe the DB config, then re-import
        with app.app_context():
            for g in Guest.query.all():
                db.session.delete(g)
            db.session.flush()
            for h in ProxmoxHost.query.all():
                db.session.delete(h)
            for t in Tag.query.all():
                db.session.delete(t)
            Setting.set("scan_interval", "1")
            db.session.commit()

        resp = self._upload(auth_client, doc)
        assert resp.status_code == 200
        assert b"Config imported" in resp.data

        with app.app_context():
            host = ProxmoxHost.query.filter_by(name="pve1").first()
            assert host is not None
            assert host.hostname == "pve1.example.com"
            # Secret columns were NOT restored
            assert host.encrypted_password is None
            assert host.api_token_secret is None
            assert host.ipmi_password is None

            guest = Guest.query.filter_by(name="web01").first()
            assert guest is not None
            assert guest.vmid == 101
            assert guest.proxmox_host_id == host.id
            assert "production" in {t.name for t in guest.tags}

            assert Setting.get("scan_interval") == "9"
            # Secret settings were not imported/overwritten with the placeholder
            assert Setting.get("unifi_password") != "***REDACTED***"

    def test_import_upsert_updates_existing(self, app, auth_client, seeded_config):
        doc = self._export(auth_client)
        # Mutate a config value in the export and re-import
        for h in doc["hosts"]:
            if h["name"] == "pve1":
                h["hostname"] = "pve1-new.example.com"
        # Overwriting an existing host's connection fields is opt-in
        # (GHSA-8mgh-j8r7-7rf2 finding 3) -- exercise that opt-in here.
        self._upload(auth_client, doc, import_hosts="on")
        with app.app_context():
            host = ProxmoxHost.query.filter_by(name="pve1").first()
            assert host.hostname == "pve1-new.example.com"
            # No duplicate host created
            assert ProxmoxHost.query.filter_by(name="pve1").count() == 1
            # Opting into host import clears the stored credential so a
            # repointed host can't send the old secret to a new endpoint.
            assert host.encrypted_password is None

    def test_import_rejects_non_json(self, auth_client):
        import io
        resp = auth_client.post(
            "/settings/config/import",
            data={"config_file": (io.BytesIO(b"not json at all {{"), "bad.json")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Invalid JSON" in resp.data

    def test_import_rejects_wrong_version(self, auth_client):
        import io
        doc = {"version": 999, "hosts": [], "tags": [], "guests": [], "roles": [], "settings": {}}
        resp = auth_client.post(
            "/settings/config/import",
            data={"config_file": (io.BytesIO(json.dumps(doc).encode()), "c.json")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Import rejected" in resp.data

    def test_import_rejects_missing_section(self, auth_client):
        import io
        doc = {"version": 1, "hosts": []}  # missing tags/guests/roles/settings
        resp = auth_client.post(
            "/settings/config/import",
            data={"config_file": (io.BytesIO(json.dumps(doc).encode()), "c.json")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Import rejected" in resp.data

    def test_import_rejects_wrong_types(self, auth_client):
        import io
        doc = {"version": 1, "hosts": "notalist", "tags": [], "guests": [],
               "roles": [], "settings": {}}
        resp = auth_client.post(
            "/settings/config/import",
            data={"config_file": (io.BytesIO(json.dumps(doc).encode()), "c.json")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Import rejected" in resp.data

    def test_import_no_file_flashes_error(self, auth_client):
        resp = auth_client.post("/settings/config/import", data={},
                                content_type="multipart/form-data", follow_redirects=True)
        assert resp.status_code == 200
        assert b"No file selected" in resp.data

    def test_import_denied_for_viewer(self, viewer_client):
        import io
        doc = {"version": 1, "hosts": [], "tags": [], "guests": [], "roles": [], "settings": {}}
        resp = viewer_client.post(
            "/settings/config/import",
            data={"config_file": (io.BytesIO(json.dumps(doc).encode()), "c.json")},
            content_type="multipart/form-data",
            follow_redirects=False,
        )
        assert resp.status_code in (302, 403)


class TestExportRuleBasedRedaction:
    """GHSA-8mgh-j8r7-7rf2 finding 4: the old denylist missed jibri/prometheus/
    peertube/moderation secrets. Redaction is now rule-based (key pattern or
    Fernet-looking value), so these are caught without needing a code change.
    """

    # key -> is_encrypted; the placeholder value is derived from the key so no
    # line pairs a secret-shaped key with a literal (keeps secret scanners quiet).
    _EXTRA_SECRET_KEYS = {
        "jibri_smb_password": False,
        "jibri_xmpp_password": False,
        "jibri_recorder_password": False,
        "prometheus_auth_token": False,
        "moderation_peertube_api_token": True,
        "peertube_db_password": True,
    }
    _EXTRA_SECRET_SETTINGS = {
        key: ("test-only-" + key.replace("_", "-"), enc) for key, enc in _EXTRA_SECRET_KEYS.items()
    }

    def test_export_redacts_jibri_prometheus_peertube_moderation_secrets(self, app, auth_client, seeded_config):
        with app.app_context():
            for key, (plain, is_encrypted) in self._EXTRA_SECRET_SETTINGS.items():
                Setting.set(key, encrypt(plain) if is_encrypted else plain)
            db.session.commit()
        try:
            raw = auth_client.get("/settings/config/export").data.decode("utf-8")
            for plain, _is_encrypted in self._EXTRA_SECRET_SETTINGS.values():
                assert plain not in raw, f"secret {plain!r} leaked into export"
            doc = json.loads(raw)
            for key in self._EXTRA_SECRET_SETTINGS:
                assert doc["settings"].get(key) == "***REDACTED***", f"{key} was not redacted"
        finally:
            with app.app_context():
                for key in self._EXTRA_SECRET_SETTINGS:
                    Setting.query.filter_by(key=key).delete()
                db.session.commit()

    def test_export_redacts_any_fernet_looking_value_regardless_of_key_name(self, app, auth_client, seeded_config):
        """A key with no secret-shaped name is still redacted if its value is
        Fernet ciphertext -- the value-based signal is a backstop for keys the
        pattern doesn't catch."""
        with app.app_context():
            Setting.set("totally_innocuous_setting", encrypt("test-only-hidden-value"))
            db.session.commit()
        try:
            raw = auth_client.get("/settings/config/export").data.decode("utf-8")
            assert "test-only-hidden-value" not in raw
            doc = json.loads(raw)
            assert doc["settings"].get("totally_innocuous_setting") == "***REDACTED***"
        finally:
            with app.app_context():
                Setting.query.filter_by(key="totally_innocuous_setting").delete()
                db.session.commit()


class TestImportAuthCriticalBlocklist:
    """GHSA-8mgh-j8r7-7rf2 finding 1: auth-critical settings must never be
    importable, and skipped keys must be reported to the user."""

    def _upload(self, client, doc, **extra_form):
        import io
        data = {"config_file": (io.BytesIO(json.dumps(doc).encode()), "config.json"), **extra_form}
        return client.post(
            "/settings/config/import",
            data=data,
            content_type="multipart/form-data",
            follow_redirects=True,
        )

    def test_auth_critical_settings_are_skipped_and_reported(self, app, auth_client):
        with app.app_context():
            before_trusted = Setting.get("trusted_subnets")
            before_bypass = Setting.get("local_bypass_enabled")
            before_cf = Setting.get("cf_access_enabled")

        doc = {
            "version": 1, "hosts": [], "tags": [], "guests": [], "roles": [],
            "settings": {
                "trusted_subnets": "0.0.0.0/0",
                "local_bypass_enabled": "true",
                "cf_access_enabled": "true",
                "cf_access_bypass_local_auth": "true",
                "app_update_branch": "attacker/evil-fork:main",
                "scan_interval": "7",  # a legitimate, non-auth-critical setting
            },
        }
        resp = self._upload(auth_client, doc)
        assert resp.status_code == 200
        assert b"Config imported" in resp.data
        from core import config_backup as _cb
        blocked = [k for k in doc["settings"] if k in _cb._AUTH_CRITICAL_SETTING_KEYS]
        assert len(blocked) >= 3
        for key in (k.encode() for k in blocked):
            assert key in resp.data, f"{key!r} not reported as skipped in flash message"

        with app.app_context():
            assert Setting.get("trusted_subnets") == before_trusted
            assert Setting.get("local_bypass_enabled") == before_bypass
            assert Setting.get("cf_access_enabled") == before_cf
            assert Setting.get("app_update_branch") != "attacker/evil-fork:main"
            # The non-auth-critical setting in the same document still applies.
            assert Setting.get("scan_interval") == "7"

    def test_out_of_range_interval_setting_is_skipped_not_trusted_verbatim(self, app, auth_client):
        with app.app_context():
            before = Setting.get("service_check_interval")
        doc = {
            "version": 1, "hosts": [], "tags": [], "guests": [], "roles": [],
            "settings": {"service_check_interval": "999999"},  # bounds: 1-1440 minutes
        }
        resp = self._upload(auth_client, doc)
        assert resp.status_code == 200
        with app.app_context():
            assert Setting.get("service_check_interval") == before


class TestImportRolesOptIn:
    """GHSA-8mgh-j8r7-7rf2 finding 2: role permissions must not change unless
    the admin explicitly opts in."""

    ROLE_NAME = "test-only-custom-role"

    @pytest.fixture()
    def custom_role(self, app):
        with app.app_context():
            role = Role.query.filter_by(name=self.ROLE_NAME).first()
            if role is None:
                role = Role(name=self.ROLE_NAME, display_name="Test Only Custom Role", level=1,
                            is_builtin=False, base_tier="viewer")
                db.session.add(role)
                db.session.commit()
            role_id = role.id
        yield role_id
        with app.app_context():
            role = db.session.get(Role, role_id)
            if role is not None:
                db.session.delete(role)
                db.session.commit()

    def _upload(self, client, doc, **extra_form):
        import io
        data = {"config_file": (io.BytesIO(json.dumps(doc).encode()), "config.json"), **extra_form}
        return client.post(
            "/settings/config/import",
            data=data,
            content_type="multipart/form-data",
            follow_redirects=True,
        )

    def _doc(self):
        return {
            "version": 1, "hosts": [], "tags": [], "guests": [],
            "roles": [{
                "name": self.ROLE_NAME, "display_name": "Test Only Custom Role",
                "level": 1, "is_builtin": False, "base_tier": "viewer",
                "can_manage_users": True,
            }],
            "settings": {},
        }

    def test_role_permissions_not_applied_without_opt_in(self, app, auth_client, custom_role):
        resp = self._upload(auth_client, self._doc())
        assert resp.status_code == 200
        with app.app_context():
            role = db.session.get(Role, custom_role)
            assert role.can_manage_users is False

    def test_role_permissions_applied_with_opt_in(self, app, auth_client, custom_role):
        resp = self._upload(auth_client, self._doc(), import_roles="on")
        assert resp.status_code == 200
        with app.app_context():
            role = db.session.get(Role, custom_role)
            assert role.can_manage_users is True


class TestImportHostsOptIn:
    """GHSA-8mgh-j8r7-7rf2 finding 3: an import must not repoint an existing
    host's connection fields while leaving its stored credential intact."""

    def _upload(self, client, doc, **extra_form):
        import io
        data = {"config_file": (io.BytesIO(json.dumps(doc).encode()), "config.json"), **extra_form}
        return client.post(
            "/settings/config/import",
            data=data,
            content_type="multipart/form-data",
            follow_redirects=True,
        )

    def _doc(self):
        return {
            "version": 1, "tags": [], "guests": [], "roles": [],
            "hosts": [{
                "name": "pve1", "hostname": "collector.attacker.invalid", "port": 8006,
                "auth_type": "token", "username": "root@pam", "api_token_id": "root@pam!mytoken",
                "verify_ssl": False, "host_type": "pve",
                "ipmi_enabled": True, "ipmi_address": "10.0.0.5", "ipmi_username": "ADMIN",
                "ipmi_verify_ssl": True,
            }],
            "settings": {},
        }

    def test_existing_host_hostname_unchanged_without_opt_in(self, app, auth_client, seeded_config):
        resp = self._upload(auth_client, self._doc())
        assert resp.status_code == 200
        with app.app_context():
            host = ProxmoxHost.query.filter_by(name="pve1").first()
            # The doc tries to repoint this host to an attacker-controlled
            # hostname; without import_hosts it must be silently ignored.
            assert host.hostname == "pve1.example.com"
            # Credential is untouched (still present) because nothing changed.
            assert host.encrypted_password is not None
            assert host.api_token_secret is not None

    def test_existing_host_hostname_changed_with_opt_in_clears_credential(self, app, auth_client, seeded_config):
        resp = self._upload(auth_client, self._doc(), import_hosts="on")
        assert resp.status_code == 200
        with app.app_context():
            host = ProxmoxHost.query.filter_by(name="pve1").first()
            assert host.hostname == "collector.attacker.invalid"
            # Stored credentials were cleared in the same transaction so the
            # repointed host cannot send the old secret to the new endpoint.
            assert host.encrypted_password is None
            assert host.api_token_secret is None
            assert host.ipmi_password is None


class TestImportAtomicity:
    """GHSA-8mgh-j8r7-7rf2 finding 5: Setting.set() used to commit per call,
    so a mid-import failure left a partial write while the flash message
    claimed nothing was applied. apply_import() now writes through the
    session without per-row commits so a failure rolls back everything."""

    def test_mid_import_failure_leaves_zero_changes(self, app, auth_client, monkeypatch):
        from core import config_backup

        original_set_no_commit = config_backup.Setting.set_no_commit
        calls = {"n": 0}

        def flaky_set_no_commit(key, value):
            calls["n"] += 1
            if calls["n"] == 2:
                raise RuntimeError("simulated failure mid-import")
            return original_set_no_commit(key, value)

        monkeypatch.setattr(config_backup.Setting, "set_no_commit", flaky_set_no_commit)

        with app.app_context():
            before_scan_interval = Setting.get("scan_interval")
            before_discovery_interval = Setting.get("discovery_interval")

        doc = {
            "version": 1,
            "hosts": [{
                "name": "test-only-atomic-host", "hostname": "atomic.example.invalid", "port": 8006,
                "auth_type": "token", "username": "root@pam", "verify_ssl": True, "host_type": "pve",
            }],
            "tags": [{"name": "test-only-atomic-tag", "color": "#123456", "unifi_networks": []}],
            "guests": [],
            "roles": [],
            "settings": {"scan_interval": "5", "discovery_interval": "3"},
        }
        import io
        resp = auth_client.post(
            "/settings/config/import",
            data={"config_file": (io.BytesIO(json.dumps(doc).encode()), "c.json")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"No changes were applied" in resp.data

        with app.app_context():
            assert ProxmoxHost.query.filter_by(name="test-only-atomic-host").first() is None
            assert Tag.query.filter_by(name="test-only-atomic-tag").first() is None
            assert Setting.get("scan_interval") == before_scan_interval
            assert Setting.get("discovery_interval") == before_discovery_interval


class TestDatabaseBackup:
    def test_backup_denied_for_viewer(self, viewer_client):
        resp = viewer_client.get("/settings/config/backup-db")
        assert resp.status_code in (302, 403)

    def test_backup_without_file_backed_db_reports_unavailable(self, auth_client, monkeypatch):
        """With no file-backed database (e.g. :memory:) there is nothing to back up."""
        from core import config_backup

        monkeypatch.setattr(config_backup, "_database_file_path", lambda: None)
        resp = auth_client.get("/settings/config/backup-db", follow_redirects=True)
        assert resp.status_code == 200
        assert b"Database backup is unavailable" in resp.data

    def test_backup_database_to_produces_valid_sqlite(self, tmp_path, monkeypatch):
        """Exercise the real backup_database_to against an on-disk SQLite source."""
        import sqlite3

        from core import config_backup

        db_file = tmp_path / "live.sqlite3"
        con = sqlite3.connect(str(db_file))
        con.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
        con.execute("INSERT INTO t (v) VALUES ('hello')")
        con.commit()
        con.close()

        # Make the production helper believe this file is the app DB.
        monkeypatch.setattr(config_backup, "_database_file_path", lambda: str(db_file))

        dest = tmp_path / "backup.sqlite3"
        assert config_backup.backup_database_to(str(dest)) is True

        with open(dest, "rb") as fh:
            assert fh.read(16).startswith(b"SQLite format 3")
        chk = sqlite3.connect(str(dest))
        rows = chk.execute("SELECT v FROM t").fetchall()
        chk.close()
        assert rows == [("hello",)]

    def test_backup_endpoint_streams_valid_sqlite(self, auth_client, tmp_path, monkeypatch):
        """The HTTP endpoint returns a valid SQLite file when a file-backed DB exists."""
        import sqlite3

        from core import config_backup

        db_file = tmp_path / "app.sqlite3"
        con = sqlite3.connect(str(db_file))
        con.execute("CREATE TABLE meta (k TEXT, v TEXT)")
        con.execute("INSERT INTO meta VALUES ('ver', '1')")
        con.commit()
        con.close()

        monkeypatch.setattr(config_backup, "_database_file_path", lambda: str(db_file))

        resp = auth_client.get("/settings/config/backup-db")
        assert resp.status_code == 200
        assert resp.headers["Content-Disposition"].startswith("attachment")
        assert resp.data.startswith(b"SQLite format 3")
