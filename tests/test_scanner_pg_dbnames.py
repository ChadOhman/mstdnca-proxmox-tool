"""
Security regression tests for GHSA-3cjx-7w8r-jwxv.

`core.scanner._stats_postgresql` reads PostgreSQL database names back from a
monitored guest (`SELECT datname FROM pg_stat_database ...`) and previously
interpolated them, unquoted, into `sudo -u postgres psql -d <name> ...`
commands run as root over SSH. The guest is a trust boundary: anyone who can
CREATE DATABASE on it (or who has compromised the postgres service account)
can make `datname` an arbitrary string containing shell metacharacters.

These tests verify that a hostile database name read back from the guest is
validated against the shared allowlist (`core.pg_identifiers`) before it
ever reaches a command string, that a valid name still works, and that the
code falls back to the next valid candidate database instead of failing
closed.
"""
import logging
from types import SimpleNamespace
from unittest.mock import patch

from core.scanner import _stats_postgresql

_HOSTILE_DB_NAMES = [
    "postgres'; rm -rf /",
    "testdb; id",
    "testdb`id`",
    "testdb$(id)",
    "testdb&id",
    "../../etc/passwd",
    "a" * 64,  # exceeds the 63-char allowlist limit
]

_VALID_DB_NAME = "my_app_db"


def _guest():
    """A guest stand-in with just the attribute `_stats_postgresql` touches
    directly (`.name`, for the warning log) -- every actual command execution
    goes through the mocked `_execute_command`, so no real SSH/agent fields
    are needed.
    """
    return SimpleNamespace(name="_sec-pg-scan-test")


def _database_list_output(names):
    """Pipe-delimited output matching the `pg_stat_database JOIN pg_database` query:
    datname|size_bytes|xact_commit|xact_rollback|temp_files|temp_bytes
    """
    return "\n".join(f"{name}|{1000 + i}|10|0|0|0" for i, name in enumerate(names))


def _make_exec_mock(db_names, captured):
    """Fake `_execute_command` that records every command string and answers
    only the two queries these tests care about: the database-list query
    (source of the taint) and the two sink queries under test.
    """

    def _exec(guest, command, timeout=60, sudo=False):
        captured.append(command)
        if "pg_database_size" in command:
            return _database_list_output(db_names), None
        if "SHOW server_version" in command:
            return "16.4", None
        return None, None

    return _exec


class TestTableStatsTargetDbValidation:
    """`_table_target_db` feeds the pg_stat_user_tables sink."""

    def test_hostile_datname_never_reaches_a_command(self):
        for payload in _HOSTILE_DB_NAMES:
            captured = []
            with patch("core.scanner._execute_command", side_effect=_make_exec_mock([payload], captured)):
                stats = _stats_postgresql(_guest())
            assert "tables" not in stats
            assert "tables_database" not in stats
            for cmd in captured:
                assert payload not in cmd, f"hostile datname leaked into command: {cmd!r}"
            table_cmds = [c for c in captured if "pg_stat_user_tables" in c]
            assert not table_cmds, "table-stats query must not run when no valid target db exists"

    def test_valid_datname_is_used(self):
        captured = []
        with patch("core.scanner._execute_command", side_effect=_make_exec_mock([_VALID_DB_NAME], captured)):
            _stats_postgresql(_guest())
        table_cmds = [c for c in captured if "pg_stat_user_tables" in c]
        assert table_cmds, "table-stats query should have been issued"
        assert f"-d {_VALID_DB_NAME} " in table_cmds[0]

    def test_fallback_picks_next_valid_non_system_db(self):
        hostile = "evil; id"
        captured = []
        names = [hostile, _VALID_DB_NAME]
        with patch("core.scanner._execute_command", side_effect=_make_exec_mock(names, captured)):
            _stats_postgresql(_guest())
        table_cmds = [c for c in captured if "pg_stat_user_tables" in c]
        assert table_cmds
        assert f"-d {_VALID_DB_NAME} " in table_cmds[0]
        for cmd in captured:
            assert hostile not in cmd


class TestSlowQueryStatsDbValidation:
    """`_ss_db` feeds the pg_stat_statements sink; unlike `_table_target_db` it
    always falls back to the literal "postgres" rather than skipping the query.
    """

    def test_hostile_datname_never_reaches_a_command(self):
        for payload in _HOSTILE_DB_NAMES:
            captured = []
            with patch("core.scanner._execute_command", side_effect=_make_exec_mock([payload], captured)):
                _stats_postgresql(_guest())
            for cmd in captured:
                assert payload not in cmd, f"hostile datname leaked into command: {cmd!r}"

    def test_falls_back_to_postgres_when_only_hostile_names_exist(self):
        captured = []
        with patch("core.scanner._execute_command", side_effect=_make_exec_mock(["evil; id"], captured)):
            _stats_postgresql(_guest())
        ss_cmds = [c for c in captured if "pg_stat_statements" in c]
        assert ss_cmds
        assert "-d postgres " in ss_cmds[0]

    def test_fallback_picks_next_valid_non_system_db(self):
        hostile = "evil`id`"
        captured = []
        names = [hostile, _VALID_DB_NAME]
        with patch("core.scanner._execute_command", side_effect=_make_exec_mock(names, captured)):
            _stats_postgresql(_guest())
        ss_cmds = [c for c in captured if "pg_stat_statements" in c]
        assert ss_cmds
        assert f"-d {_VALID_DB_NAME} " in ss_cmds[0]
        for cmd in captured:
            assert hostile not in cmd


class TestInvalidDatnameIsLogged:
    def test_invalid_datname_logs_a_warning_with_repr(self, caplog):
        payload = "evil; id"
        captured = []
        with caplog.at_level(logging.WARNING, logger="core.scanner"):
            with patch("core.scanner._execute_command", side_effect=_make_exec_mock([payload], captured)):
                _stats_postgresql(_guest())
        assert any(repr(payload) in record.getMessage() for record in caplog.records)
