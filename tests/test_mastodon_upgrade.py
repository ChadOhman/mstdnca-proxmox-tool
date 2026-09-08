"""Unit tests for the Mastodon upgrade primitives (issue #125).

``_swap_env_db`` used to be mocked everywhere and never exercised directly, so
a ``sed`` that matched nothing still reported a successful swap.  These tests
pin the read-back verification, the stash helpers, and the version.rb parser
shared with routes/mastodon.py.
"""
from apps.mastodon import _git_stash, _git_stash_pop, _swap_env_db, parse_version_rb


class FakeSSH:
    """Mock SSHClient: matches command substrings to canned (stdout, stderr, code)."""

    def __init__(self, responses=None):
        self.responses = responses or []
        self.calls = []

    def execute_sudo(self, cmd, timeout=None):
        self.calls.append(cmd)
        for substr, resp in self.responses:
            if substr in cmd:
                return resp
        return ("", "", 0)

    def ran(self, substr):
        return any(substr in c for c in self.calls)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _collect_log():
    lines = []
    return lines, lines.append


class TestSwapEnvDb:
    def test_verified_swap_succeeds(self):
        ssh = FakeSSH([("grep -E", ("DB_HOST=10.0.0.5\nDB_PORT=5432\n", "", 0))])
        ok, msg = _swap_env_db(ssh, "/home/mastodon/live", "10.0.0.5", "5432")
        assert ok is True
        assert "10.0.0.5:5432" in msg
        assert ssh.ran("sed -i 's|^DB_HOST=.*|DB_HOST=10.0.0.5|'")
        assert ssh.ran("sed -i 's|^DB_PORT=.*|DB_PORT=5432|'")

    def test_sed_matching_nothing_is_not_success(self):
        # 'sed -i' exits 0 even when the pattern matched nothing.
        ssh = FakeSSH([("grep -E", ("", "", 1))])
        ok, msg = _swap_env_db(ssh, "/home/mastodon/live", "10.0.0.5", "5432")
        assert ok is False
        assert "verify" in msg.lower()

    def test_wrong_host_readback_fails(self):
        ssh = FakeSSH([("grep -E", ("DB_HOST=pgbouncer\nDB_PORT=5432\n", "", 0))])
        ok, msg = _swap_env_db(ssh, "/home/mastodon/live", "10.0.0.5", "5432")
        assert ok is False
        assert "DB_HOST=10.0.0.5" in msg

    def test_wrong_port_readback_fails(self):
        ssh = FakeSSH([("grep -E", ("DB_HOST=10.0.0.5\nDB_PORT=6432\n", "", 0))])
        ok, msg = _swap_env_db(ssh, "/home/mastodon/live", "10.0.0.5", "5432")
        assert ok is False
        assert "DB_PORT=5432" in msg

    def test_sed_failure_short_circuits(self):
        ssh = FakeSSH([("sed -i", ("", "permission denied", 1))])
        ok, msg = _swap_env_db(ssh, "/home/mastodon/live", "10.0.0.5", "5432")
        assert ok is False
        assert "permission denied" in msg
        assert not ssh.ran("grep -E")

    def test_non_numeric_port_rejected(self):
        ssh = FakeSSH()
        ok, msg = _swap_env_db(ssh, "/home/mastodon/live", "10.0.0.5", "54a32")
        assert ok is False
        assert "Invalid DB port" in msg
        assert ssh.calls == []


class TestGitStashHelpers:
    def test_clean_tree_reports_nothing_stashed(self):
        logs, log = _collect_log()
        ssh = FakeSSH([("git stash", ("No local changes to save", "", 0))])
        ok, stashed = _git_stash(ssh, "mastodon", "/home/mastodon/live", log)
        assert ok is True
        assert stashed is False

    def test_dirty_tree_reports_stashed(self):
        logs, log = _collect_log()
        ssh = FakeSSH([("git stash", ("Saved working directory ...", "", 0))])
        ok, stashed = _git_stash(ssh, "mastodon", "/home/mastodon/live", log)
        assert ok is True
        assert stashed is True

    def test_stash_failure_is_reported(self):
        logs, log = _collect_log()
        ssh = FakeSSH([("git stash", ("", "fatal: not a git repository", 128))])
        ok, stashed = _git_stash(ssh, "mastodon", "/home/mastodon/live", log)
        assert ok is False
        assert stashed is False
        assert any("git stash failed" in line for line in logs)

    def test_pop_failure_warns_and_returns_false(self):
        logs, log = _collect_log()
        ssh = FakeSSH([("git stash pop", ("", "CONFLICT", 1))])
        assert _git_stash_pop(ssh, "mastodon", "/home/mastodon/live", log) is False
        assert any("still on the stash" in line for line in logs)

    def test_pop_success(self):
        logs, log = _collect_log()
        ssh = FakeSSH()
        assert _git_stash_pop(ssh, "mastodon", "/home/mastodon/live", log) is True


class TestParseVersionRb:
    def test_method_style(self):
        content = (
            "module Mastodon\n"
            "  module Version\n"
            "    def major\n      4\n    end\n"
            "    def minor\n      6\n    end\n"
            "    def patch\n      0\n    end\n"
            "    def default_prerelease\n      'alpha.5'\n    end\n"
            "  end\nend\n"
        )
        assert parse_version_rb(content) == "4.6.0-alpha.5"

    def test_constant_style_with_build_metadata(self):
        content = (
            "MAJOR = 4\nMINOR = 3\nPATCH = 2\n"
            "PRE = 'rc1'\nBUILD_METADATA = 'glitch'\n"
        )
        assert parse_version_rb(content) == "4.3.2-rc1+glitch"

    def test_unparseable_returns_none(self):
        assert parse_version_rb("nothing useful here") is None
        assert parse_version_rb("") is None
        assert parse_version_rb(None) is None
