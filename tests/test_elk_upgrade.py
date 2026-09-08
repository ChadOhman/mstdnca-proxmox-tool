"""Elk upgrade failure semantics and git stash handling (issue #125).

The old pull command (``git stash; git pull && git stash pop || true``) made the
exit-code check dead, and a dead service after the rebuild was only a warning.
"""
from unittest.mock import MagicMock, patch


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

    def index_of(self, substr):
        for i, c in enumerate(self.calls):
            if substr in c:
                return i
        return -1

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _elk_settings(overrides=None):
    base = {
        "elk_guest_id": "1",
        "elk_user": "elk",
        "elk_dir": "/opt/elk",
        "elk_url": "https://elk.example.com",
        "elk_instance_url": "https://mastodon.example.com",
        "elk_deploy_method": "bare-metal",
        "elk_current_version": "0.14.0",
        "elk_latest_version": "0.15.0",
        "elk_protection_type": "snapshot",
        "elk_backup_storage": "",
        "elk_backup_mode": "snapshot",
        "elk_auto_upgrade": "false",
        "elk_installed": "true",
    }
    if overrides:
        base.update(overrides)
    return base


def _run_elk_upgrade(ssh, settings_overrides=None, settings_sink=None):
    from apps.elk import run_elk_upgrade

    settings = _elk_settings(settings_overrides)
    fake_setting = MagicMock()
    fake_setting.get.side_effect = lambda k, d="": settings.get(k, d)
    if settings_sink is not None:
        fake_setting.set.side_effect = lambda k, v: settings_sink.update({k: v})

    app_guest = MagicMock()
    app_guest.credential = MagicMock()
    app_guest.ip_address = "10.0.0.6"
    app_guest.name = "elk-vm"
    fake_guest_cls = MagicMock()
    fake_guest_cls.query.get.return_value = app_guest

    with (
        patch("apps.elk.Setting", fake_setting),
        patch("apps.elk.Guest", fake_guest_cls),
        patch("apps.elk.SSHClient") as fake_sshclient,
        patch("apps.elk.time.sleep"),
    ):
        fake_sshclient.from_credential.return_value = ssh
        return run_elk_upgrade(skip_protection=True)


class TestElkUpgradeServiceFailure:
    def test_returns_false_when_service_down(self):
        ssh = FakeSSH([("systemctl is-active elk", ("failed", "", 3))])
        ok, log = _run_elk_upgrade(ssh)
        assert ok is False
        assert "Build completed" in log

    def test_does_not_persist_version_when_service_down(self):
        written = {}
        ssh = FakeSSH([("systemctl is-active elk", ("failed", "", 3))])
        ok, _ = _run_elk_upgrade(ssh, settings_sink=written)
        assert ok is False
        assert "elk_current_version" not in written

    def test_active_service_reports_success(self):
        written = {}
        ssh = FakeSSH([
            ("systemctl is-active elk", ("active", "", 0)),
            ("package.json", ("0.15.0\n", "", 0)),
        ])
        ok, _ = _run_elk_upgrade(ssh, settings_sink=written)
        assert ok is True
        assert written["elk_current_version"] == "0.15.0"

    def test_docker_container_not_running_fails(self):
        ssh = FakeSSH([("docker compose", ("exited", "", 0))])
        ok, _ = _run_elk_upgrade(ssh, {"elk_deploy_method": "docker"})
        assert ok is False


class TestElkGitStash:
    def test_stash_pull_pop_are_separate_commands(self):
        ssh = FakeSSH([
            ("git stash", ("Saved working directory", "", 0)),
            ("systemctl is-active elk", ("active", "", 0)),
        ])
        ok, _ = _run_elk_upgrade(ssh)
        assert ok is True
        # No '|| true' masking, and each step is its own command.
        assert not any("|| true" in c for c in ssh.calls)
        assert ssh.index_of("git stash") < ssh.index_of("git pull")
        assert ssh.index_of("git pull") < ssh.index_of("git stash pop")

    def test_clean_tree_skips_the_pop(self):
        ssh = FakeSSH([
            ("git stash", ("No local changes to save", "", 0)),
            ("systemctl is-active elk", ("active", "", 0)),
        ])
        ok, _ = _run_elk_upgrade(ssh)
        assert ok is True
        assert not ssh.ran("git stash pop")

    def test_pull_failure_pops_the_stash(self):
        ssh = FakeSSH([
            ("git stash pop", ("Restored", "", 0)),
            ("git stash", ("Saved working directory", "", 0)),
            ("git pull", ("", "fatal: could not read from remote", 128)),
        ])
        ok, log = _run_elk_upgrade(ssh)
        assert ok is False
        assert "git pull failed" in log
        # Local changes must not be stranded on the stash.
        assert ssh.ran("git stash pop")

    def test_stash_failure_aborts_before_pull(self):
        ssh = FakeSSH([("git stash", ("", "fatal: not a git repository", 128))])
        ok, log = _run_elk_upgrade(ssh)
        assert ok is False
        assert "git stash failed" in log
        assert not ssh.ran("git pull")

    def test_pop_failure_after_successful_pull_is_fatal(self):
        ssh = FakeSSH([
            ("git stash pop", ("", "CONFLICT (content)", 1)),
            ("git stash", ("Saved working directory", "", 0)),
        ])
        ok, log = _run_elk_upgrade(ssh)
        assert ok is False
        assert "could not restore local changes" in log
