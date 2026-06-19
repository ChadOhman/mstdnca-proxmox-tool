"""Tests for Ghost upgrade permission remediation.

The Ghost updater fixes file permissions both *before* and *after* ``ghost
update``: the update unpacks a new ``versions/<v>`` tree and runs migrations,
which can leave ``content/`` owned by root and make Ghost hit ``EACCES`` at
runtime (FM1 in the remediation runbook).  These tests pin that behaviour so a
future refactor can't silently drop the post-update pass.
"""
from unittest.mock import MagicMock, patch

from apps.ghost import (
    _ensure_ghost_db_privileges,
    _fix_ghost_permissions,
    run_ghost_upgrade,
)


class FakeSSH:
    """Mock SSHClient: matches command substrings to canned (stdout, stderr, code).

    Mirrors the harness in test_mastodon_remediation.py.  The first substring
    contained in the command wins; unmatched commands return ("", "", 0).
    Doubles as its own context manager so it can stand in for the object
    returned by SSHClient.from_credential(...).
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

    def index_of(self, substr):
        for i, c in enumerate(self.calls):
            if substr in c:
                return i
        return -1

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _collect_log():
    lines = []
    return lines, lines.append


class TestFixGhostPermissions:
    def test_chowns_to_user_and_normalises_modes(self):
        logs, log = _collect_log()
        ssh = FakeSSH()
        assert _fix_ghost_permissions(ssh, "/opt/ghost", "ghost_user", log) is True
        cmd = ssh.calls[0]
        assert "chown -R ghost_user: /opt/ghost" in cmd
        assert "-type f -exec chmod 664" in cmd
        assert "-type d -exec chmod 775" in cmd

    def test_excludes_versions_tree_from_chmod(self):
        logs, log = _collect_log()
        ssh = FakeSSH()
        _fix_ghost_permissions(ssh, "/opt/ghost", "ghost_user", log)
        assert "! -path '*/versions/*'" in ssh.calls[0]

    def test_returns_false_and_warns_on_nonzero(self):
        logs, log = _collect_log()
        ssh = FakeSSH([("chown -R", ("", "Operation not permitted", 1))])
        assert _fix_ghost_permissions(ssh, "/opt/ghost", "ghost_user", log) is False
        assert any("WARNING" in line for line in logs)


class TestEnsureGhostDbPrivileges:
    """FM4: pre-update assertion that the Ghost MySQL user can run migration DDL."""

    def test_grants_all_when_user_lacks_db_privileges(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("config.production.json", ('["ghost", "ghost"]', "", 0)),
            ("SHOW GRANTS", (
                "GRANT USAGE ON *.* TO `ghost`@`localhost`\n"
                "GRANT SELECT, INSERT, UPDATE, DELETE ON `ghost`.* TO `ghost`@`localhost`",
                "", 0)),
            ("GRANT ALL PRIVILEGES ON", ("", "", 0)),
        ])
        assert _ensure_ghost_db_privileges(ssh, "/opt/ghost", log) is True
        assert ssh.ran("GRANT ALL PRIVILEGES ON ghost.* TO 'ghost'@'localhost'")

    def test_skips_grant_when_db_privileges_present(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("config.production.json", ('["ghost", "ghost"]', "", 0)),
            ("SHOW GRANTS", ("GRANT ALL PRIVILEGES ON `ghost`.* TO `ghost`@`localhost`", "", 0)),
        ])
        assert _ensure_ghost_db_privileges(ssh, "/opt/ghost", log) is True
        assert not ssh.ran("GRANT ALL PRIVILEGES ON ghost.*")

    def test_skips_grant_when_user_has_global_all(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("config.production.json", ('["ghost", "ghost"]', "", 0)),
            ("SHOW GRANTS", (
                "GRANT ALL PRIVILEGES ON *.* TO `ghost`@`localhost` WITH GRANT OPTION", "", 0)),
        ])
        assert _ensure_ghost_db_privileges(ssh, "/opt/ghost", log) is True
        assert not ssh.ran("GRANT ALL PRIVILEGES ON ghost.*")

    def test_resolves_db_and_user_from_config_not_hardcoded(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("config.production.json", ('["news_db", "news_user"]', "", 0)),
            ("SHOW GRANTS", ("GRANT USAGE ON *.* TO `news_user`@`localhost`", "", 0)),
            ("GRANT ALL PRIVILEGES ON", ("", "", 0)),
        ])
        assert _ensure_ghost_db_privileges(ssh, "/opt/ghost", log) is True
        assert ssh.ran("SHOW GRANTS FOR 'news_user'@'localhost'")
        assert ssh.ran("GRANT ALL PRIVILEGES ON news_db.* TO 'news_user'@'localhost'")

    def test_skips_when_account_missing(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("config.production.json", ('["ghost", "ghost"]', "", 0)),
            ("SHOW GRANTS", ("", "ERROR 1141 (42000): There is no such grant defined", 1)),
        ])
        # Never issues a bare GRANT (which would auto-create a passwordless account).
        assert _ensure_ghost_db_privileges(ssh, "/opt/ghost", log) is False
        assert not ssh.ran("GRANT ALL PRIVILEGES ON")

    def test_skips_when_config_unreadable(self):
        logs, log = _collect_log()
        ssh = FakeSSH([("config.production.json", ("", "No such file", 1))])
        assert _ensure_ghost_db_privileges(ssh, "/opt/ghost", log) is False
        assert not ssh.ran("SHOW GRANTS")
        assert not ssh.ran("mysql")

    def test_rejects_unsafe_identifier_without_touching_mysql(self):
        logs, log = _collect_log()
        # A DB name with shell/SQL metacharacters must never reach mysql.
        ssh = FakeSSH([
            ("config.production.json", ('["ghost; DROP DATABASE x", "ghost"]', "", 0)),
        ])
        assert _ensure_ghost_db_privileges(ssh, "/opt/ghost", log) is False
        assert not ssh.ran("mysql")
        assert any("unexpected characters" in line for line in logs)


def _make_settings(overrides=None):
    base = {
        "ghost_guest_id": "1",
        "ghost_user": "ghost_user",
        "ghost_dir": "/opt/ghost",
        "ghost_current_version": "6.21.0",
        "ghost_latest_version": "6.22.0",
        "ghost_protection_type": "snapshot",
        "ghost_backup_storage": "",
        "ghost_backup_mode": "snapshot",
        "ghost_auto_upgrade": "false",
    }
    if overrides:
        base.update(overrides)
    return base


class TestGhostUpgradePostUpdatePermissions:
    """End-to-end (mocked SSH) check that the permission fix runs after the update."""

    def _run(self, ssh):
        fake_setting = MagicMock()
        settings = _make_settings()
        fake_setting.get.side_effect = lambda k, d="": settings.get(k, d)

        fake_guest = MagicMock()
        fake_guest.credential = MagicMock()
        fake_guest.ip_address = "10.0.0.5"
        fake_guest.name = "ghost-vm"
        fake_guest_cls = MagicMock()
        fake_guest_cls.query.get.return_value = fake_guest

        with (
            patch("apps.ghost.Setting", fake_setting),
            patch("apps.ghost.Guest", fake_guest_cls),
            patch("apps.ghost.SSHClient") as fake_sshclient,
        ):
            fake_sshclient.from_credential.return_value = ssh
            return run_ghost_upgrade(skip_protection=True)

    def _healthy_ssh(self):
        ghost_cli_json = '{"name": "news-mstdn-ca", "active-version": "6.22.0"}'
        return FakeSSH([
            (".ghost-cli", (ghost_cli_json, "", 0)),
            ("config.production.json", ('["ghost", "ghost"]', "", 0)),
            ("SHOW GRANTS", ("GRANT ALL PRIVILEGES ON `ghost`.* TO `ghost`@`localhost`", "", 0)),
            ("command -v systemctl", ("/usr/bin/systemctl", "", 0)),
            ("npm install -g ghost-cli", ("ok", "", 0)),
            ("ghost update", ("Finished", "", 0)),
            ("is-active", ("active", "", 0)),
        ])

    def test_permissions_fixed_before_and_after_update(self):
        ssh = self._healthy_ssh()
        ok, _ = self._run(ssh)

        assert ok is True

        # The permission fix runs twice: once before, once after the update.
        perms_idxs = [i for i, c in enumerate(ssh.calls) if "chown -R ghost_user:" in c]
        assert len(perms_idxs) == 2, ssh.calls
        update_idx = ssh.index_of("ghost update")
        assert perms_idxs[0] < update_idx < perms_idxs[1]

    def test_db_privileges_checked_before_update(self):
        ssh = self._healthy_ssh()
        ok, _ = self._run(ssh)

        assert ok is True
        show_idx = ssh.index_of("SHOW GRANTS")
        update_idx = ssh.index_of("ghost update")
        assert 0 <= show_idx < update_idx, ssh.calls

    def test_service_restarted_after_post_update_fix(self):
        ssh = self._healthy_ssh()
        ok, _ = self._run(ssh)

        assert ok is True
        perms_idxs = [i for i, c in enumerate(ssh.calls) if "chown -R ghost_user:" in c]
        # Match the actual restart command, not the "systemctl restart ..."
        # substring that also appears inside the sudoers NOPASSWD grant lines.
        restart_idx = ssh.index_of("systemctl restart ghost_news-mstdn-ca 2>&1")
        assert restart_idx > perms_idxs[1], ssh.calls
