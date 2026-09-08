"""Route tests for routes/services.py (GitHub issue #131 — previously had zero route tests).

Covers:
  * Unauthenticated access is redirected to login.
  * A user without `can_view_services` is denied the services index.
  * A user with `can_view_services=True` but `can_edit_services=False` (a role
    combination no built-in role has, so we construct one) is denied on every
    mutating endpoint, and the underlying SSH/command execution is never invoked.
  * `pg_explain`'s shell-quoting of the `query` field is verified at the route
    level (tests/test_pg_injection.py only checks `shlex.quote()` in isolation).
"""
import json
import shlex
from unittest.mock import patch

import pytest

from models import Guest, GuestService, Role, User, db


def _login(client, username, password):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )


# Copied from tests/test_pg_injection.py's _INJECTION_PAYLOADS (database-name injection
# payloads) — kept local per the task's isolation preference rather than importing.
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

# Copied from tests/test_pg_injection.py::TestPgExplainQueryShellQuoting's
# `dangerous_queries` — payloads for the `query` field (not `database`).
_DANGEROUS_QUERIES = [
    "SELECT 1; `id`",
    "SELECT $(id)",
    "SELECT 1; rm -rf /",
    "SELECT 'hello'",
]


def _assert_query_is_shell_quoted(command: str) -> None:
    """Walk `command` as a POSIX shell would and confirm every ';', '`', or '$('
    occurrence falls inside a quoted segment (single- or double-quoted), i.e. it
    is a literal character rather than a live shell metacharacter.

    shlex.quote() wraps its output in single quotes and represents each embedded
    literal single quote as the four-character switch '"'"' (close single, open
    double containing one literal quote, close double, reopen single). A naive
    "toggle on every single-quote character" walk misparses that idiom — it has
    an odd count of single-quote characters, which flips quote-state parity even
    though the surrounding text never actually becomes shell-live. Tracking
    single- and double-quote state separately (like a real shell) avoids that.
    """
    state = None  # None (shell-live), "'" (single-quoted), or '"' (double-quoted)
    i = 0
    n = len(command)
    while i < n:
        ch = command[i]
        if state == "'":
            if ch == "'":
                state = None
            i += 1
            continue
        if state == '"':
            if ch == '"':
                state = None
            i += 1
            continue
        # state is None: this character is live to the shell.
        if ch == "'":
            state = "'"
        elif ch == '"':
            state = '"'
        else:
            assert ch not in (";", "`"), f"Unquoted {ch!r} at index {i} in command: {command!r}"
            assert not (ch == "$" and command[i:i + 2] == "$("), (
                f"Unquoted '$(' at index {i} in command: {command!r}"
            )
        i += 1
    assert state is None, f"Unbalanced quotes in command: {command!r}"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def pg_service(app):
    """A PostgreSQL GuestService. Mirrors tests/test_pg_injection.py's fixture."""
    with app.app_context():
        guest = Guest(name="_svc-route-pg-test", guest_type="ct", enabled=True)
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


@pytest.fixture()
def sidekiq_service(app):
    """A Sidekiq GuestService."""
    with app.app_context():
        guest = Guest(name="_svc-route-sidekiq-test", guest_type="ct", enabled=True)
        db.session.add(guest)
        db.session.flush()
        svc = GuestService(
            guest_id=guest.id,
            service_name="sidekiq",
            unit_name="mastodon-sidekiq*.service",
            port=None,
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


@pytest.fixture()
def generic_service(app):
    """A non-postgres/non-sidekiq GuestService, for the generic `control` route."""
    with app.app_context():
        guest = Guest(name="_svc-route-generic-test", guest_type="ct", enabled=True)
        db.session.add(guest)
        db.session.flush()
        svc = GuestService(
            guest_id=guest.id,
            service_name="prosody",
            unit_name="prosody.service",
            port=None,
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


@pytest.fixture()
def viewer_user(app):
    """A user with the built-in `viewer` role: can_view_services=False."""
    with app.app_context():
        viewer_role = Role.query.filter_by(name="viewer").first()
        assert viewer_role.can_view_services is False  # guard
        user = User(username="_svc_route_viewer", display_name="Svc Route Viewer", role_id=viewer_role.id)
        user.set_password("ViewerPass123!")
        db.session.add(user)
        db.session.commit()
        uid = user.id

    yield "_svc_route_viewer", "ViewerPass123!"

    with app.app_context():
        User.query.filter_by(id=uid).delete()
        db.session.commit()


@pytest.fixture()
def view_only_user(app):
    """A user with a custom role: can_view_services=True, can_edit_services=False.

    No built-in role has this combination (admin/super_admin have both True;
    operator/viewer have both False), so a role row is constructed directly,
    copying every other permission flag from the built-in `viewer` role.
    """
    with app.app_context():
        viewer_role = Role.query.filter_by(name="viewer").first()
        role = Role(
            name="_svc_route_view_only",
            display_name="Service View Only",
            level=2,
            is_builtin=False,
            base_tier=None,
            can_ssh=viewer_role.can_ssh,
            can_update=viewer_role.can_update,
            can_manage_users=viewer_role.can_manage_users,
            can_manage_settings=viewer_role.can_manage_settings,
            can_manage_credentials=viewer_role.can_manage_credentials,
            can_view_hosts=viewer_role.can_view_hosts,
            can_manage_hosts=viewer_role.can_manage_hosts,
            can_manage_guests=viewer_role.can_manage_guests,
            can_restart_unifi=viewer_role.can_restart_unifi,
            can_view_audit_log=viewer_role.can_view_audit_log,
            can_view_services=True,
            can_edit_services=False,
            can_view_unifi=viewer_role.can_view_unifi,
            can_view_ipmi=viewer_role.can_view_ipmi,
            can_manage_ipmi=viewer_role.can_manage_ipmi,
            can_moderate=viewer_role.can_moderate,
        )
        db.session.add(role)
        db.session.commit()
        role_id = role.id

        user = User(username="_svc_route_view_only", display_name="Svc Route View Only", role_id=role_id)
        user.set_password("ViewOnlyPass123!")
        db.session.add(user)
        db.session.commit()
        uid = user.id

    yield "_svc_route_view_only", "ViewOnlyPass123!"

    with app.app_context():
        User.query.filter_by(id=uid).delete()
        Role.query.filter_by(id=role_id).delete()
        db.session.commit()


# ---------------------------------------------------------------------------
# Unauthenticated access
# ---------------------------------------------------------------------------

class TestUnauthenticatedAccess:
    """`@login_required` on the blueprint's before_request gates every route."""

    def test_index_redirects_to_login(self, client):
        resp = client.get("/services/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


# ---------------------------------------------------------------------------
# can_view_services gate
# ---------------------------------------------------------------------------

class TestViewPermission:
    """A logged-in user without `can_view_services` is bounced from every route."""

    def test_viewer_denied_index(self, client, viewer_user):
        username, password = viewer_user
        _login(client, username, password)
        resp = client.get("/services/", follow_redirects=False)
        assert resp.status_code == 302
        # before_request handler redirects to dashboard.index ("/")
        assert resp.headers["Location"].rstrip("/") == "" or resp.headers["Location"].endswith("/")


# ---------------------------------------------------------------------------
# can_view_services=True but can_edit_services=False: mutating endpoints denied
# ---------------------------------------------------------------------------

class TestViewOnlyCannotEdit:
    """can_view_services=True, can_edit_services=False must be denied on every
    mutating endpoint, and the underlying command execution must never run.
    """

    @patch("routes.services.service_action")
    def test_control_start_denied(self, mock_action, client, view_only_user, generic_service):
        svc_id, _ = generic_service
        username, password = view_only_user
        _login(client, username, password)

        resp = client.post(f"/services/{svc_id}/start", follow_redirects=False)

        # control() flashes + redirects (not a JSON 403) on permission denial.
        assert resp.status_code == 302
        assert "/services/" in resp.headers["Location"]
        mock_action.assert_not_called()

    @patch("core.scanner._execute_command")
    def test_pg_vacuum_denied(self, mock_exec, client, view_only_user, pg_service):
        svc_id, _ = pg_service
        username, password = view_only_user
        _login(client, username, password)

        resp = client.post(
            f"/services/{svc_id}/pg/vacuum",
            data=json.dumps({"database": "mydb", "analyze": False}),
            content_type="application/json",
        )

        assert resp.status_code == 403
        assert resp.get_json() == {"ok": False, "message": "Permission denied."}
        mock_exec.assert_not_called()

    @patch("core.scanner._execute_command")
    def test_pg_explain_denied(self, mock_exec, client, view_only_user, pg_service):
        svc_id, _ = pg_service
        username, password = view_only_user
        _login(client, username, password)

        resp = client.post(
            f"/services/{svc_id}/pg/explain",
            data=json.dumps({"database": "mydb", "query": "SELECT 1"}),
            content_type="application/json",
        )

        assert resp.status_code == 403
        assert resp.get_json() == {"ok": False, "message": "Permission denied."}
        mock_exec.assert_not_called()

    @patch("routes.services.sidekiq_clear_dead")
    def test_sidekiq_clear_dead_denied(self, mock_fn, client, view_only_user, sidekiq_service):
        svc_id, _ = sidekiq_service
        username, password = view_only_user
        _login(client, username, password)

        resp = client.post(f"/services/{svc_id}/sidekiq/clear-dead")

        assert resp.status_code == 403
        assert resp.get_json() == {"ok": False, "message": "Permission denied."}
        mock_fn.assert_not_called()

    @patch("routes.services.sidekiq_retry_dead")
    def test_sidekiq_retry_dead_denied(self, mock_fn, client, view_only_user, sidekiq_service):
        svc_id, _ = sidekiq_service
        username, password = view_only_user
        _login(client, username, password)

        resp = client.post(f"/services/{svc_id}/sidekiq/retry-dead")

        assert resp.status_code == 403
        assert resp.get_json() == {"ok": False, "message": "Permission denied."}
        mock_fn.assert_not_called()

    @patch("routes.services.sidekiq_clear_retry")
    def test_sidekiq_clear_retry_denied(self, mock_fn, client, view_only_user, sidekiq_service):
        svc_id, _ = sidekiq_service
        username, password = view_only_user
        _login(client, username, password)

        resp = client.post(f"/services/{svc_id}/sidekiq/clear-retry")

        assert resp.status_code == 403
        assert resp.get_json() == {"ok": False, "message": "Permission denied."}
        mock_fn.assert_not_called()

    @patch("routes.services.sidekiq_retry_retry")
    def test_sidekiq_retry_retry_denied(self, mock_fn, client, view_only_user, sidekiq_service):
        svc_id, _ = sidekiq_service
        username, password = view_only_user
        _login(client, username, password)

        resp = client.post(f"/services/{svc_id}/sidekiq/retry-retry")

        assert resp.status_code == 403
        assert resp.get_json() == {"ok": False, "message": "Permission denied."}
        mock_fn.assert_not_called()


# ---------------------------------------------------------------------------
# pg_explain: shell-quoting of the `query` field, verified at the route level
# ---------------------------------------------------------------------------

class TestPgExplainShellQuotingAtEndpoint:
    """tests/test_pg_injection.py::TestPgExplainQueryShellQuoting only verifies
    shlex.quote() in isolation — it never checks that the /pg/explain route
    actually applies it to the command handed to core.scanner._execute_command.
    This exercises the real route and inspects the captured command string.

    This is expected to pass on current main: it pins the already-correct
    shell-quoting behavior of the endpoint.
    """

    @patch("core.scanner._execute_command")
    def test_dangerous_queries_are_shell_quoted_in_printf_command(self, mock_exec, auth_client, pg_service):
        svc_id, _ = pg_service
        mock_exec.return_value = ("", None)

        for query in _DANGEROUS_QUERIES:
            mock_exec.reset_mock()
            resp = auth_client.post(
                f"/services/{svc_id}/pg/explain",
                data=json.dumps({"database": "mydb", "query": query}),
                content_type="application/json",
            )

            assert resp.status_code == 200, resp.get_json()
            data = resp.get_json()
            assert data.get("ok") is True

            # First call writes the (quoted) query to a temp file via `printf %s`.
            assert mock_exec.call_count == 2
            write_call = mock_exec.call_args_list[0]
            command = write_call.args[1]
            assert command.startswith("printf %s ")

            expected_quoted = shlex.quote(f"EXPLAIN {query}")
            assert expected_quoted.startswith("'")
            assert expected_quoted.endswith("'")
            assert expected_quoted in command, f"Expected shlex.quote() output in command: {command!r}"

            _assert_query_is_shell_quoted(command)

    @patch("core.scanner._execute_command")
    def test_injection_payloads_as_query_are_still_shell_quoted(self, mock_exec, auth_client, pg_service):
        """The database-name injection payloads, if smuggled into `query` instead,
        must also come out shell-quoted (query has no allowlist — quoting is the
        only defense).
        """
        svc_id, _ = pg_service
        mock_exec.return_value = ("", None)

        for payload in _INJECTION_PAYLOADS:
            if not payload:
                continue  # empty query is rejected with 400 before any command runs
            mock_exec.reset_mock()
            resp = auth_client.post(
                f"/services/{svc_id}/pg/explain",
                data=json.dumps({"database": "mydb", "query": payload}),
                content_type="application/json",
            )

            assert resp.status_code == 200, resp.get_json()
            assert mock_exec.call_count == 2
            command = mock_exec.call_args_list[0].args[1]
            _assert_query_is_shell_quoted(command)
