"""Tests for Mastodon runtime version remediation (Ruby / Node.js / Bundler)."""
import sys
from unittest.mock import MagicMock, patch

from apps.mastodon import (
    _bundler_from_lock,
    _check_env_compliance,
    _node_major_from_range,
    _remediate_bundler,
    _remediate_environment,
    _remediate_node,
    _remediate_ruby,
)


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


class TestRemediateRuby:
    def test_noop_when_version_matches(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("cat /srv/live/.ruby-version", ("4.0.5\n", "", 0)),
            ("ruby --version", ("ruby 4.0.5 (2026-01-01)\n", "", 0)),
        ])
        assert _remediate_ruby(ssh, "mastodon", "/srv/live", log) is True
        assert not ssh.ran("rbenv install")

    def test_installs_when_version_differs(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("cat /srv/live/.ruby-version", ("4.0.5\n", "", 0)),
            ("ruby --version", ("ruby 3.4.1 (2025-01-01)\n", "", 0)),
            ("rbenv install", ("installed", "", 0)),
        ])
        # After install, the verify read of `ruby --version` must report 4.0.5.
        # FakeSSH returns the first matching substring, so override the verify
        # by ordering a more specific match isn't possible here; use a counter.
        calls = {"ruby": 0}

        def exec_sudo(cmd, timeout=None):
            ssh.calls.append(cmd)
            if "cat /srv/live/.ruby-version" in cmd:
                return ("4.0.5\n", "", 0)
            if "rbenv install" in cmd:
                return ("installed", "", 0)
            if "ruby --version" in cmd:
                calls["ruby"] += 1
                return ("ruby 3.4.1 (2025)\n", "", 0) if calls["ruby"] == 1 else ("ruby 4.0.5 (2026)\n", "", 0)
            return ("", "", 0)

        ssh.execute_sudo = exec_sudo
        assert _remediate_ruby(ssh, "mastodon", "/srv/live", log) is True
        assert ssh.ran("rbenv global 4.0.5")

    def test_fails_when_ruby_version_unreadable(self):
        logs, log = _collect_log()
        ssh = FakeSSH([("cat /srv/live/.ruby-version", ("", "", 1))])
        assert _remediate_ruby(ssh, "mastodon", "/srv/live", log) is False

    def test_fails_when_install_nonzero(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("cat /srv/live/.ruby-version", ("4.0.5\n", "", 0)),
            ("ruby --version", ("ruby 3.4.1 (2025)\n", "", 0)),
            ("rbenv install", ("", "rbenv: command not found", 127)),
        ])
        assert _remediate_ruby(ssh, "mastodon", "/srv/live", log) is False


class TestRemediateBundler:
    def test_noop_when_version_matches(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("cat /srv/live/Gemfile.lock", ("BUNDLED WITH\n   2.5.11\n", "", 0)),
            ("bundle --version", ("Bundler version 2.5.11\n", "", 0)),
        ])
        assert _remediate_bundler(ssh, "mastodon", "/srv/live", log) is True
        assert not ssh.ran("gem install bundler")

    def test_installs_pinned_version(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("cat /srv/live/Gemfile.lock", ("BUNDLED WITH\n   2.5.11\n", "", 0)),
            ("bundle --version", ("Bundler version 2.4.1\n", "", 0)),
            ("gem install bundler", ("done", "", 0)),
        ])
        assert _remediate_bundler(ssh, "mastodon", "/srv/live", log) is True
        assert ssh.ran("gem install bundler -v 2.5.11")

    def test_installs_latest_when_no_pin(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("cat /srv/live/Gemfile.lock", ("GEM\n  specs:\n", "", 0)),
            ("gem install bundler --no-document", ("done", "", 0)),
        ])
        assert _remediate_bundler(ssh, "mastodon", "/srv/live", log) is True
        assert ssh.ran("gem install bundler --no-document")

    def test_fails_when_install_nonzero(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("cat /srv/live/Gemfile.lock", ("BUNDLED WITH\n   2.5.11\n", "", 0)),
            ("bundle --version", ("Bundler version 2.4.1\n", "", 0)),
            ("gem install bundler", ("", "boom", 1)),
        ])
        assert _remediate_bundler(ssh, "mastodon", "/srv/live", log) is False


class TestRemediateEnvironment:
    def _ssh_all_current(self):
        """Everything already compliant: Ruby 4.0.5, Bundler 2.5.11, Node 22."""
        return FakeSSH([
            ("cat /srv/live/.ruby-version", ("4.0.5\n", "", 0)),
            ("ruby --version", ("ruby 4.0.5 (2026)\n", "", 0)),
            ("cat /srv/live/Gemfile.lock", ("BUNDLED WITH\n   2.5.11\n", "", 0)),
            ("bundle --version", ("Bundler version 2.5.11\n", "", 0)),
            ("cat /srv/live/package.json", ('{"engines":{"node":">=22"}}', "", 0)),
            ("node --version", ("v22.4.1\n", "", 0)),
        ])

    def test_all_compliant_no_actions(self):
        logs, log = _collect_log()
        ssh = self._ssh_all_current()
        assert _remediate_environment(ssh, "mastodon", "/srv/live", log) is True
        assert not ssh.ran("rbenv install")
        assert not ssh.ran("gem install bundler")
        assert not ssh.ran("nodesource")

    def test_aborts_when_ruby_fails(self):
        logs, log = _collect_log()
        ssh = FakeSSH([("cat /srv/live/.ruby-version", ("", "", 1))])
        assert _remediate_environment(ssh, "mastodon", "/srv/live", log) is False
        # Bundler/Node must not be attempted after Ruby aborts
        assert not ssh.ran("gem install bundler")
        assert not ssh.ran("nodesource")


class TestComplianceNonBlocking:
    def _ssh(self, ruby_installed, node_installed):
        # Provides: git fetch (ok), remote .ruby-version, remote package.json,
        # installed ruby, installed node, installed bundler.
        return FakeSSH([
            ("git fetch", ("", "", 0)),
            (".ruby-version", ("4.0.5\n", "", 0)),
            ("package.json", ('{"engines":{"node":">=22"}}', "", 0)),
            ("ruby --version", (f"ruby {ruby_installed} (2026)\n", "", 0)),
            ("node --version", (f"v{node_installed}\n", "", 0)),
            ("bundle --version", ("Bundler version 2.5.11\n", "", 0)),
        ])

    def test_node_mismatch_is_not_blocking(self):
        logs, log = _collect_log()
        ssh = self._ssh(ruby_installed="4.0.5", node_installed="20.20.2")
        result = _check_env_compliance(ssh, "mastodon", "/srv/live", "main", log)
        assert result is True  # no longer blocks
        joined = "\n".join(logs)
        assert "will be upgraded" in joined
        assert "[FAIL] Node" not in joined

    def test_ruby_major_minor_mismatch_is_not_blocking(self):
        logs, log = _collect_log()
        ssh = self._ssh(ruby_installed="3.4.1", node_installed="22.4.1")
        result = _check_env_compliance(ssh, "mastodon", "/srv/live", "main", log)
        assert result is True
        joined = "\n".join(logs)
        assert "[FAIL] Ruby" not in joined
        assert "will be upgraded" in joined


class TestUpgradeWiring:
    """run_mastodon_upgrade calls _remediate_environment and aborts on failure."""

    def test_remediation_failure_aborts_upgrade(self):
        import apps.mastodon as m

        cfg = {
            "guest_id": "1", "db_guest_id": "2", "db_name": "mastodon_production",
            "user": "mastodon", "app_dir": "/srv/live", "branch": "main",
            "pgbouncer_host": "10.0.0.9", "pgbouncer_port": "6432",
            "direct_db_host": "10.0.0.2", "direct_db_port": "5432",
            "protection_type": "snapshot", "backup_storage": "", "backup_mode": "snapshot",
            "guest_id_2": "", "current_version": "4.0.0", "latest_version": "4.1.0",
            "auto_upgrade": False,
        }

        # mastodon_guest: has ip, has credential; db_guest: no ip (skip pg_dump)
        mastodon_guest = MagicMock()
        mastodon_guest.ip_address = "10.0.0.5"
        mastodon_guest.credential = MagicMock()
        mastodon_guest.name = "mastodon-app"

        db_guest = MagicMock()
        db_guest.ip_address = None  # skip pg_dump step
        db_guest.name = "mastodon-db"

        # FakeSSH: make git operations succeed so we reach step 2e
        fake_ssh = FakeSSH([
            ("git ls-files --unmerged", ("", "", 0)),
            # "git stash pop" must precede "git stash" — FakeSSH matches the first
            # substring contained in the command, and "git stash" is a prefix of it.
            ("git stash pop", ("No stash entries", "", 1)),  # non-zero but no unmerged = continue
            ("git stash", ("No local changes", "", 0)),
            ("git pull", ("Already up to date.", "", 0)),
        ])
        ssh_ctx = MagicMock()
        ssh_ctx.__enter__ = MagicMock(return_value=fake_ssh)
        ssh_ctx.__exit__ = MagicMock(return_value=False)

        # Stub out models.Credential and models.db for the local import inside run_mastodon_upgrade
        mock_credential_cls = MagicMock()
        mock_db = MagicMock()
        models_stub = MagicMock()
        models_stub.Credential = mock_credential_cls
        models_stub.db = mock_db

        with patch.object(m, "_get_mastodon_config", return_value=cfg), \
             patch.object(m, "Guest") as mock_guest_cls, \
             patch.object(m, "snapshot_guest", return_value=(True, "ok")), \
             patch.object(m, "SSHClient") as mock_ssh_cls, \
             patch.object(m, "_swap_env_db", return_value=(True, "swapped")), \
             patch.object(m, "_remediate_environment", return_value=False) as rem, \
             patch.dict(sys.modules, {"models": models_stub}):

            mock_guest_cls.query.get.side_effect = lambda gid: mastodon_guest if gid == 1 else db_guest
            mock_ssh_cls.from_credential.return_value = ssh_ctx

            ok, log_out = m.run_mastodon_upgrade()

        assert ok is False
        assert rem.called
        assert "Runtime version remediation failed" in log_out


class TestSecondGuestWiring:
    def test_vm2_remediation_failure_returns_false(self):
        import apps.mastodon as m

        guest2 = MagicMock()
        guest2.ip_address = "10.0.0.6"
        guest2.credential = MagicMock()

        fake_ssh = FakeSSH()
        ssh_ctx = MagicMock()
        ssh_ctx.__enter__ = MagicMock(return_value=fake_ssh)
        ssh_ctx.__exit__ = MagicMock(return_value=False)

        logs, log = _collect_log()
        models_stub = MagicMock()
        with patch.object(m.SSHClient, "from_credential", return_value=ssh_ctx), \
             patch.object(m, "_remediate_environment", return_value=False) as rem, \
             patch.dict(sys.modules, {"models": models_stub}):
            ok = m._run_second_guest_sync(guest2, "mastodon", "/srv/live", log, branch="main")

        assert ok is False
        assert rem.called
        assert any("[VM2] Runtime version remediation failed" in line for line in logs)


class TestSkipProtectionSkipsPgDump:
    """skip_protection=True skips BOTH the snapshot/backup step and the pg_dump step."""

    def _run(self, skip_protection):
        import apps.mastodon as m

        cfg = {
            "guest_id": "1", "db_guest_id": "2", "db_name": "mastodon_production",
            "user": "mastodon", "app_dir": "/srv/live", "branch": "main",
            "pgbouncer_host": "10.0.0.9", "pgbouncer_port": "6432",
            "direct_db_host": "10.0.0.2", "direct_db_port": "5432",
            "protection_type": "snapshot", "backup_storage": "", "backup_mode": "snapshot",
            "guest_id_2": "", "current_version": "4.0.0", "latest_version": "4.1.0",
            "auto_upgrade": False,
        }

        mastodon_guest = MagicMock()
        mastodon_guest.ip_address = "10.0.0.5"
        mastodon_guest.credential = MagicMock()
        mastodon_guest.name = "mastodon-app"

        # db_guest HAS an ip + credential, so pg_dump WOULD run unless skipped.
        db_guest = MagicMock()
        db_guest.ip_address = "10.0.0.2"
        db_guest.credential = MagicMock()
        db_guest.name = "mastodon-db"

        fake_ssh = FakeSSH([
            ("git ls-files --unmerged", ("", "", 0)),
            ("git stash pop", ("No stash entries", "", 1)),
            ("git stash", ("No local changes", "", 0)),
            ("git pull", ("Already up to date.", "", 0)),
        ])
        ssh_ctx = MagicMock()
        ssh_ctx.__enter__ = MagicMock(return_value=fake_ssh)
        ssh_ctx.__exit__ = MagicMock(return_value=False)

        models_stub = MagicMock()

        with patch.object(m, "_get_mastodon_config", return_value=cfg), \
             patch.object(m, "Guest") as mock_guest_cls, \
             patch.object(m, "snapshot_guest", return_value=(True, "ok")) as snap, \
             patch.object(m, "SSHClient") as mock_ssh_cls, \
             patch.object(m, "_swap_env_db", return_value=(True, "swapped")), \
             patch.object(m, "_remediate_environment", return_value=False), \
             patch.dict(sys.modules, {"models": models_stub}):
            mock_guest_cls.query.get.side_effect = lambda gid: mastodon_guest if gid == 1 else db_guest
            mock_ssh_cls.from_credential.return_value = ssh_ctx
            # remediation returns False so the upgrade aborts after Steps 1-2 (keeps the test short)
            ok, log_out = m.run_mastodon_upgrade(skip_protection=skip_protection)

        return log_out, fake_ssh, snap

    def test_skip_protection_skips_pg_dump(self):
        log_out, fake_ssh, snap = self._run(skip_protection=True)
        assert "Skipping pg_dump (requested by super-admin)" in log_out
        assert "Step 2: PostgreSQL backup (pg_dump)" not in log_out
        assert not fake_ssh.ran("pg_dump")   # no dump command issued
        assert not snap.called               # snapshot/backup also skipped

    def test_pg_dump_runs_when_not_skipped(self):
        log_out, fake_ssh, _snap = self._run(skip_protection=False)
        assert "Step 2: PostgreSQL backup (pg_dump)" in log_out
        assert fake_ssh.ran("pg_dump")       # dump command issued
