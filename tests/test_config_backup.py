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

    def _upload(self, client, doc):
        import io
        payload = json.dumps(doc).encode("utf-8")
        return client.post(
            "/settings/config/import",
            data={"config_file": (io.BytesIO(payload), "config.json")},
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
        self._upload(auth_client, doc)
        with app.app_context():
            host = ProxmoxHost.query.filter_by(name="pve1").first()
            assert host.hostname == "pve1-new.example.com"
            # No duplicate host created
            assert ProxmoxHost.query.filter_by(name="pve1").count() == 1

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


class TestDatabaseBackup:
    def test_backup_denied_for_viewer(self, viewer_client):
        resp = viewer_client.get("/settings/config/backup-db")
        assert resp.status_code in (302, 403)

    def test_backup_in_memory_db_reports_unavailable(self, auth_client):
        """The test suite uses an in-memory DB, so there is no file to back up."""
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
