"""Tests for Mastodon runtime version remediation (Ruby / Node.js / Bundler)."""
from apps.mastodon import _bundler_from_lock, _node_major_from_range, _remediate_node


class FakeSSH:
    """Mock SSHClient: matches command substrings to canned (stdout, stderr, code).

    `responses` is a list of (substring, (stdout, stderr, code)). The first
    substring contained in the command wins. Unmatched commands return ("","",0).
    """

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


def _collect_log():
    lines = []
    return lines, lines.append


class TestNodeMajorFromRange:
    def test_gte(self):
        assert _node_major_from_range(">=22") == 22

    def test_caret_with_patch(self):
        assert _node_major_from_range("^22.1.0") == 22

    def test_dot_x(self):
        assert _node_major_from_range("22.x") == 22

    def test_bounded_range_takes_floor(self):
        assert _node_major_from_range(">=20 <23") == 20

    def test_empty(self):
        assert _node_major_from_range("") is None

    def test_none(self):
        assert _node_major_from_range(None) is None


class TestBundlerFromLock:
    def test_extracts_version(self):
        lock = "GEM\n  remote: https://rubygems.org/\n\nBUNDLED WITH\n   2.5.11\n"
        assert _bundler_from_lock(lock) == "2.5.11"

    def test_missing_section(self):
        assert _bundler_from_lock("GEM\n  specs:\n") is None

    def test_empty(self):
        assert _bundler_from_lock("") is None

    def test_none(self):
        assert _bundler_from_lock(None) is None


class TestRemediateNode:
    def test_noop_when_major_matches(self):
        logs, log = _collect_log()
        ssh = FakeSSH()
        assert _remediate_node(ssh, 22, "22.4.1", log) is True
        assert not ssh.ran("nodesource")  # no install attempted

    def test_installs_when_major_differs(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("nodesource", ("done", "", 0)),
            ("node --version", ("v22.4.1\n", "", 0)),
        ])
        assert _remediate_node(ssh, 22, "20.20.2", log) is True
        assert ssh.ran("node_22.x")

    def test_fails_when_install_nonzero(self):
        logs, log = _collect_log()
        ssh = FakeSSH([("nodesource", ("", "apt error", 1))])
        assert _remediate_node(ssh, 22, "20.20.2", log) is False

    def test_fails_when_verify_wrong_major(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("nodesource", ("done", "", 0)),
            ("node --version", ("v20.20.2\n", "", 0)),
        ])
        assert _remediate_node(ssh, 22, "20.20.2", log) is False

    def test_warns_and_passes_when_no_requirement(self):
        logs, log = _collect_log()
        assert _remediate_node(FakeSSH(), None, "20.20.2", log) is True
