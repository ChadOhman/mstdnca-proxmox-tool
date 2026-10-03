"""Tests for the admin-only Mastodon active-user list / CSV export."""

import base64
import json
from unittest.mock import MagicMock, patch

import pytest

from core.mastodon_active_users import (
    DEFAULT_DAYS,
    MAX_DAYS,
    build_active_users_query,
    clamp_days,
    parse_active_users_output,
    rows_to_csv,
)

_ROWS = [
    {"username": "alice", "email": "alice@example.com", "locale": "en", "last_active": "2026-10-01T12:00:00Z"},
    {"username": "bob", "email": "=bob@example.com", "locale": "", "last_active": "2026-09-20T08:30:00Z"},
]


class TestQueryBuilding:
    def test_clamp_days(self):
        assert clamp_days("30") == 30
        assert clamp_days("0") == 1
        assert clamp_days("9999") == MAX_DAYS
        assert clamp_days("30; DROP TABLE users") == DEFAULT_DAYS
        assert clamp_days(None) == DEFAULT_DAYS

    def test_query_filters(self):
        sql = build_active_users_query(30)
        assert "interval '30 days'" in sql
        for clause in ("a.domain IS NULL", "u.confirmed_at IS NOT NULL", "u.approved = true",
                       "u.disabled = false", "a.suspended_at IS NULL", "a.memorial = false"):
            assert clause in sql

    def test_query_never_interpolates_raw_input(self):
        sql = build_active_users_query("1 days'; DROP TABLE users; --")
        assert "DROP" not in sql
        assert f"interval '{DEFAULT_DAYS} days'" in sql


class TestParsing:
    def test_parse_rows(self):
        rows = parse_active_users_output(json.dumps(_ROWS) + "\n")
        assert [r["username"] for r in rows] == ["alice", "bob"]

    def test_parse_empty(self):
        assert parse_active_users_output("[]") == []
        assert parse_active_users_output("") == []

    def test_parse_skips_rows_without_email(self):
        rows = parse_active_users_output(json.dumps([{"username": "x", "email": None}, _ROWS[0]]))
        assert [r["username"] for r in rows] == ["alice"]

    def test_parse_rejects_garbage(self):
        with pytest.raises(ValueError):
            parse_active_users_output("ERROR: nope")
        with pytest.raises(ValueError):
            parse_active_users_output('{"a": 1}')

    def test_csv_neutralises_formula_cells(self):
        text = rows_to_csv(_ROWS)
        lines = text.splitlines()
        assert lines[0] == "username,email,locale,last_active"
        assert lines[1] == "alice,alice@example.com,en,2026-10-01T12:00:00Z"
        assert lines[2].startswith("bob,'=bob@example.com,")


@pytest.fixture()
def db_guest(app):
    from auth.credential_store import encrypt
    from models import Credential, Guest, Setting
    from models import db as _db

    with app.app_context():
        cred = Credential(name="_mau_test_cred", username="root", encrypted_value=encrypt("test-only-ssh-password"))
        _db.session.add(cred)
        _db.session.flush()
        guest = Guest(name="_mau_test_db_guest", guest_type="ct", ip_address="10.0.0.51", credential_id=cred.id)
        _db.session.add(guest)
        _db.session.commit()
        previous = Setting.get("mastodon_db_guest_id", "")
        Setting.set("mastodon_db_guest_id", str(guest.id))
        guest_id, cred_id = guest.id, cred.id

    yield guest_id

    with app.app_context():
        Setting.set("mastodon_db_guest_id", previous)
        _db.session.delete(_db.session.get(Guest, guest_id))
        _db.session.delete(_db.session.get(Credential, cred_id))
        _db.session.commit()


def _mock_ssh(mock_ssh_class, result):
    ssh = MagicMock()
    ssh.__enter__ = MagicMock(return_value=ssh)
    ssh.__exit__ = MagicMock(return_value=False)
    ssh.execute_sudo.return_value = result
    mock_ssh_class.from_credential.return_value = ssh
    return ssh


class TestFetch:
    def test_unconfigured(self, app):
        from core.mastodon_active_users import fetch_active_users
        from models import Setting

        with app.app_context():
            previous = Setting.get("mastodon_db_guest_id", "")
            Setting.set("mastodon_db_guest_id", "")
            try:
                rows, err = fetch_active_users()
            finally:
                Setting.set("mastodon_db_guest_id", previous)
        assert rows is None
        assert "not configured" in err

    @patch("clients.ssh_client.SSHClient")
    def test_success_pipes_sql_on_stdin(self, mock_ssh_class, app, db_guest):
        from core.mastodon_active_users import fetch_active_users

        ssh = _mock_ssh(mock_ssh_class, (json.dumps(_ROWS), "", 0))
        with app.app_context():
            rows, err = fetch_active_users(7)
        assert err is None
        assert len(rows) == 2
        cmd = ssh.execute_sudo.call_args[0][0]
        assert "psql -d mastodon_production" in cmd
        b64 = cmd.split("printf '%s' '")[1].split("'")[0]
        assert "interval '7 days'" in base64.b64decode(b64).decode()

    @patch("clients.ssh_client.SSHClient")
    def test_psql_failure_hides_stderr(self, mock_ssh_class, app, db_guest):
        from core.mastodon_active_users import fetch_active_users

        _mock_ssh(mock_ssh_class, ("", "ERROR: secret detail", 1))
        with app.app_context():
            rows, err = fetch_active_users()
        assert rows is None
        assert "exit 1" in err
        assert "secret detail" not in err


class TestRoutes:
    def test_unauthenticated_redirects_to_login(self, client):
        resp = client.get("/active-users/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_moderator_denied(self, moderator_client):
        for method, path in (("get", "/active-users/"), ("post", "/active-users/preview"),
                             ("post", "/active-users/export.csv")):
            resp = getattr(moderator_client, method)(path, data={"days": "30"}, follow_redirects=False)
            assert resp.status_code == 302, path
            assert "/active-users" not in resp.headers["Location"]

    def test_admin_index(self, auth_client):
        resp = auth_client.get("/active-users/")
        assert resp.status_code == 200
        assert b"Mastodon Active Users" in resp.data
        assert resp.headers["Cache-Control"] == "no-store"

    @patch("routes.active_users.fetch_active_users")
    def test_preview_renders_and_audits(self, mock_fetch, app, auth_client):
        from models import AuditLog

        mock_fetch.return_value = (_ROWS, None)
        resp = auth_client.post("/active-users/preview", data={"days": "30"})
        assert resp.status_code == 200
        assert b"2 active users in the last 30 days" in resp.data
        assert b"alice@example.com" in resp.data
        mock_fetch.assert_called_once_with(30)
        with app.app_context():
            entry = AuditLog.query.filter_by(action="mastodon_active_users_view").order_by(AuditLog.id.desc()).first()
            assert entry is not None

    @patch("routes.active_users.fetch_active_users")
    def test_export_csv(self, mock_fetch, app, auth_client):
        from models import AuditLog

        mock_fetch.return_value = (_ROWS, None)
        resp = auth_client.post("/active-users/export.csv", data={"days": "45"})
        assert resp.status_code == 200
        assert resp.mimetype == "text/csv"
        assert "mastodon-active-users-45d-" in resp.headers["Content-Disposition"]
        assert resp.headers["Cache-Control"] == "no-store"
        assert resp.data.decode().startswith("username,email,locale,last_active")
        with app.app_context():
            entry = AuditLog.query.filter_by(action="mastodon_active_users_export").order_by(AuditLog.id.desc()).first()
            assert entry is not None
            # Emails stay out of the audit trail.
            assert "@" not in (entry.details or "")

    @patch("routes.active_users.fetch_active_users")
    def test_error_flashes_and_redirects(self, mock_fetch, auth_client):
        mock_fetch.return_value = (None, "Mastodon database guest is not configured")
        resp = auth_client.post("/active-users/export.csv", data={"days": "30"}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"not configured" in resp.data
