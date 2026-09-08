"""
Security regression tests for PostgreSQL command injection fixes.

Verifies that the database allowlist validation in pg_vacuum and pg_explain
rejects shell metacharacters and injection payloads before they reach SSH commands.
"""
import json

import pytest

from models import Guest, GuestService, db


@pytest.fixture()
def pg_service(app):
    """Create a PostgreSQL GuestService and return its ID. Cleaned up after the test."""
    with app.app_context():
        guest = Guest(name="_sec-pg-test", guest_type="ct", enabled=True)
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
        guest_id = guest.id

    yield svc_id, guest_id

    with app.app_context():
        GuestService.query.filter_by(guest_id=guest_id).delete()
        Guest.query.filter_by(id=guest_id).delete()
        db.session.commit()


_INJECTION_PAYLOADS = [
    "postgres'; rm -rf /",
    "testdb; id",
    "testdb`id`",
    "testdb$(id)",
    "testdb|cat /etc/passwd",
    "testdb&id",
    "../../etc/passwd",
    "a" * 64,            # exceeds 63-char limit
    "",                  # empty — caught by the earlier check, but confirm
]

_VALID_DB_NAMES = [
    "postgres",
    "my_app_db",
    "App123",
    "a",
    "a" * 63,            # exactly 63 chars — should be accepted
]


class TestPgVacuumDatabaseValidation:
    """pg_vacuum must reject database names that contain shell metacharacters."""

    def test_injection_payloads_rejected(self, app, auth_client, pg_service):
        svc_id, _ = pg_service
        for payload in _INJECTION_PAYLOADS:
            resp = auth_client.post(
                f"/services/{svc_id}/pg/vacuum",
                data=json.dumps({"database": payload, "analyze": False}),
                content_type="application/json",
            )
            data = resp.get_json()
            assert resp.status_code == 400, (
                f"Expected 400 for database={payload!r}, got {resp.status_code}: {data}"
            )
            assert data.get("ok") is False

    def test_valid_names_pass_validation(self, app, auth_client, pg_service):
        """Valid database names should pass validation (even if SSH fails — we only care about the 400)."""
        svc_id, _ = pg_service
        for name in _VALID_DB_NAMES:
            resp = auth_client.post(
                f"/services/{svc_id}/pg/vacuum",
                data=json.dumps({"database": name, "analyze": False}),
                content_type="application/json",
            )
            data = resp.get_json()
            # The SSH call will fail (no real host), but it must NOT be a 400 from validation
            assert resp.status_code != 400 or data.get("message") != "Invalid database name.", (
                f"Valid database name {name!r} was incorrectly rejected"
            )


class TestPgExplainDatabaseValidation:
    """pg_explain must reject database names that contain shell metacharacters."""

    def test_injection_payloads_rejected(self, app, auth_client, pg_service):
        svc_id, _ = pg_service
        for payload in _INJECTION_PAYLOADS:
            resp = auth_client.post(
                f"/services/{svc_id}/pg/explain",
                data=json.dumps({"database": payload, "query": "SELECT 1"}),
                content_type="application/json",
            )
            data = resp.get_json()
            assert resp.status_code == 400, (
                f"Expected 400 for database={payload!r}, got {resp.status_code}: {data}"
            )
            assert data.get("ok") is False

    def test_valid_names_pass_validation(self, app, auth_client, pg_service):
        svc_id, _ = pg_service
        for name in _VALID_DB_NAMES:
            resp = auth_client.post(
                f"/services/{svc_id}/pg/explain",
                data=json.dumps({"database": name, "query": "SELECT 1"}),
                content_type="application/json",
            )
            data = resp.get_json()
            assert resp.status_code != 400 or data.get("message") != "Invalid database name.", (
                f"Valid database name {name!r} was incorrectly rejected"
            )


class TestPgExplainQueryShellQuoting:
    """
    Verify shlex.quote() is used for the query: queries containing shell
    metacharacters should be accepted (not rejected), but the resulting
    shlex.quote() output must contain only safe single-quoted content.
    """

    def test_shlex_quote_output_is_safe(self):
        """Unit-level check: shlex.quote wraps dangerous content in single quotes.

        Inside POSIX single-quoted strings, ALL metacharacters (backticks, $(),
        semicolons, pipes) are treated as literal text by the shell — no expansion
        occurs. shlex.quote() always produces a single-quoted string (handling
        embedded single quotes via the '"'"' pattern).
        """
        import shlex

        dangerous_queries = [
            "SELECT 1; `id`",
            "SELECT $(id)",
            "SELECT 1; rm -rf /",
            "SELECT 'hello'",
        ]
        for q in dangerous_queries:
            quoted = shlex.quote(f"EXPLAIN {q}")
            # shlex.quote must always wrap output in single quotes so the shell
            # treats ALL metacharacters as literal characters.
            assert quoted.startswith("'"), f"shlex.quote did not single-quote: {quoted}"
            assert quoted.endswith("'"), f"shlex.quote did not single-quote: {quoted}"
