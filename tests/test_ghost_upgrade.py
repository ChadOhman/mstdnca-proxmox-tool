"""Tests for Ghost upgrade permission remediation.

The Ghost updater fixes file permissions both *before* and *after* ``ghost
update``: the update unpacks a new ``versions/<v>`` tree and runs migrations,
which can leave ``content/`` owned by root and make Ghost hit ``EACCES`` at
runtime (FM1 in the remediation runbook).  These tests pin that behaviour so a
future refactor can't silently drop the post-update pass.
"""
from unittest.mock import MagicMock, patch

from apps.ghost import (
    _PERMS_FIX_TIMEOUT,
    _check_ghost_http,
    _ensure_ghost_db_privileges,
    _fix_ghost_permissions,
    _preflight_nginx_reload,
    _resolve_ghost_http_target,
    _resolve_guest_binary,
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

    def test_sweep_gets_a_long_timeout(self):
        # The tree walk (versions/*/node_modules + content/images) took longer
        # than the old 120 s budget on production, which silently skipped the
        # remediation with "[timeout after 120 s]".
        logs, log = _collect_log()
        ssh = FakeSSH()
        seen = {}

        def _execute_sudo(cmd, timeout=None):
            seen["timeout"] = timeout
            return ("", "", 0)

        ssh.execute_sudo = _execute_sudo
        _fix_ghost_permissions(ssh, "/opt/ghost", "ghost_user", log)
        assert seen["timeout"] == _PERMS_FIX_TIMEOUT
        assert _PERMS_FIX_TIMEOUT >= 600


class TestResolveGuestBinary:
    def test_uses_path_reported_by_guest(self):
        ssh = FakeSSH([("command -v nginx", ("/usr/sbin/nginx\n", "", 0))])
        assert _resolve_guest_binary(ssh, "nginx", "/opt/nginx") == "/usr/sbin/nginx"

    def test_falls_back_to_default_when_guest_prints_nothing(self):
        ssh = FakeSSH([("command -v nginx", ("", "", 1))])
        assert _resolve_guest_binary(ssh, "nginx", "/usr/sbin/nginx") == "/usr/sbin/nginx"


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
        ghost_cli_json = '{"name": "example-site", "active-version": "6.22.0"}'
        return FakeSSH([
            (".ghost-cli", (ghost_cli_json, "", 0)),
            ("config.production.json", ('["ghost", "ghost"]', "", 0)),
            ("SHOW GRANTS", ("GRANT ALL PRIVILEGES ON `ghost`.* TO `ghost`@`localhost`", "", 0)),
            ("command -v systemctl", ("/usr/bin/systemctl", "", 0)),
            ("npm install -g ghost-cli", ("ok", "", 0)),
            ("ghost update", ("Finished", "", 0)),
            ("is-active", ("active", "", 0)),
            ("curl", ("HTTP:200", "", 0)),
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
        restart_idx = ssh.index_of("systemctl restart ghost_example-site 2>&1")
        assert restart_idx > perms_idxs[1], ssh.calls


class TestGhostUpgradeReportsServiceFailure:
    """A dead service after 'ghost update' must not be reported as success (#125)."""

    def _run(self, ssh, settings_sink=None):
        fake_setting = MagicMock()
        settings = _make_settings()
        fake_setting.get.side_effect = lambda k, d="": settings.get(k, d)
        if settings_sink is not None:
            fake_setting.set.side_effect = lambda k, v: settings_sink.update({k: v})

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

    def _down_ssh(self):
        ghost_cli_json = '{"name": "news-mstdn-ca", "active-version": "6.22.0"}'
        return FakeSSH([
            (".ghost-cli", (ghost_cli_json, "", 0)),
            ("config.production.json", ('["ghost", "ghost"]', "", 0)),
            ("SHOW GRANTS", ("GRANT ALL PRIVILEGES ON `ghost`.* TO `ghost`@`localhost`", "", 0)),
            ("command -v systemctl", ("/usr/bin/systemctl", "", 0)),
            ("npm install -g ghost-cli", ("ok", "", 0)),
            ("ghost update", ("Finished", "", 0)),
            ("is-active", ("failed", "", 3)),
        ])

    def test_returns_false_when_service_is_down(self):
        ok, log = self._run(self._down_ssh())
        assert ok is False
        # The full log is preserved so the route records it against the failure.
        assert "ghost update completed successfully" in log
        assert "still failed after start attempt" in log

    def test_does_not_persist_version_when_service_is_down(self):
        written = {}
        ok, _ = self._run(self._down_ssh(), settings_sink=written)
        assert ok is False
        assert "ghost_current_version" not in written
        assert "ghost_update_available" not in written

    def test_start_attempt_recovers_and_reports_success(self):
        ghost_cli_json = '{"name": "news-mstdn-ca", "active-version": "6.22.0"}'
        states = iter(["inactive", "active"])
        ssh = FakeSSH([
            (".ghost-cli", (ghost_cli_json, "", 0)),
            ("config.production.json", ('["ghost", "ghost"]', "", 0)),
            ("SHOW GRANTS", ("GRANT ALL PRIVILEGES ON `ghost`.* TO `ghost`@`localhost`", "", 0)),
            ("command -v systemctl", ("/usr/bin/systemctl", "", 0)),
            ("npm install -g ghost-cli", ("ok", "", 0)),
            ("ghost update", ("Finished", "", 0)),
            ("is-active", None),  # placeholder, replaced below
        ])

        def _execute_sudo(cmd, timeout=None):
            ssh.calls.append(cmd)
            if "is-active" in cmd:
                return (next(states), "", 0)
            if ".ghost-cli" in cmd:
                return (ghost_cli_json, "", 0)
            if "config.production.json" in cmd:
                return ('["ghost", "ghost"]', "", 0)
            if "SHOW GRANTS" in cmd:
                return ("GRANT ALL PRIVILEGES ON `ghost`.* TO `ghost`@`localhost`", "", 0)
            if "command -v systemctl" in cmd:
                return ("/usr/bin/systemctl", "", 0)
            if "curl" in cmd:
                return ("HTTP:200", "", 0)
            return ("", "", 0)

        ssh.execute_sudo = _execute_sudo

        written = {}
        ok, _ = self._run(ssh, settings_sink=written)
        assert ok is True
        assert written["ghost_current_version"] == "6.22.0"


class TestGhostSudoersGrants:
    """The NOPASSWD grants must cover every 'sudo' ghost-cli issues during update.

    ghost-cli 1.31.0 added pre-update nginx migrations (ActivityPub resolver,
    X-Forwarded-For rewrite) that run 'sudo mv', 'sudo sed -i', 'sudo nginx -t'
    and 'sudo nginx -s reload'.  With only systemctl whitelisted, sudo asked for
    a password and ghost-cli aborted with "Prompts have been disabled".
    """

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

    def _ssh(self):
        ghost_cli_json = '{"name": "news-mstdn-ca", "active-version": "6.22.0"}'
        return FakeSSH([
            (".ghost-cli", (ghost_cli_json, "", 0)),
            ("config.production.json", ('["ghost", "ghost"]', "", 0)),
            ("SHOW GRANTS", ("GRANT ALL PRIVILEGES ON `ghost`.* TO `ghost`@`localhost`", "", 0)),
            ("command -v systemctl", ("/usr/bin/systemctl", "", 0)),
            ("command -v mv", ("/usr/bin/mv", "", 0)),
            ("command -v sed", ("/usr/bin/sed", "", 0)),
            ("command -v nginx", ("/usr/sbin/nginx", "", 0)),
            ("npm install -g ghost-cli", ("ok", "", 0)),
            ("ghost update", ("Finished", "", 0)),
            ("is-active", ("active", "", 0)),
            ("curl", ("HTTP:200", "", 0)),
        ])

    def _sudoers_cmd(self, ssh):
        cmds = [c for c in ssh.calls if "/etc/sudoers.d/ghost-ghost_news-mstdn-ca" in c]
        assert len(cmds) == 1, ssh.calls
        return cmds[0]

    def test_grants_nginx_migration_commands(self):
        ssh = self._ssh()
        ok, _ = self._run(ssh)
        assert ok is True

        cmd = self._sudoers_cmd(ssh)
        assert "ghost_user ALL=(root) NOPASSWD: /usr/bin/mv /tmp/* /etc/nginx/sites-available/*" in cmd
        assert "ghost_user ALL=(root) NOPASSWD: /usr/bin/sed -i * /etc/nginx/sites-available/*" in cmd
        assert "ghost_user ALL=(root) NOPASSWD: /usr/sbin/nginx -t" in cmd
        assert "ghost_user ALL=(root) NOPASSWD: /usr/sbin/nginx -s reload" in cmd

    def test_keeps_systemctl_grants(self):
        ssh = self._ssh()
        self._run(ssh)
        cmd = self._sudoers_cmd(ssh)
        for action in ("start", "stop", "restart", "reset-failed",
                       "is-active", "is-enabled", "enable", "disable"):
            assert f"NOPASSWD: /usr/bin/systemctl {action} ghost_news-mstdn-ca" in cmd
        assert "NOPASSWD: /usr/bin/systemctl daemon-reload" in cmd

    def test_sudoers_written_before_update_and_locked_down(self):
        ssh = self._ssh()
        self._run(ssh)
        assert ssh.index_of("/etc/sudoers.d/") < ssh.index_of("ghost update")
        assert "chmod 440 /etc/sudoers.d/ghost-ghost_news-mstdn-ca" in self._sudoers_cmd(ssh)

    def test_binary_paths_fall_back_when_guest_lookup_fails(self):
        ssh = self._ssh()
        ssh.responses = [r for r in ssh.responses if not r[0].startswith("command -v")]
        self._run(ssh)
        cmd = self._sudoers_cmd(ssh)
        assert "/usr/bin/mv /tmp/*" in cmd
        assert "/usr/bin/sed -i *" in cmd
        assert "/usr/sbin/nginx -t" in cmd
        assert "/usr/bin/systemctl daemon-reload" in cmd


class TestPreflightNginxReload:
    """ghost-cli's nginx migrations end in 'nginx -s reload' and hide its stderr
    behind "Failed to restart Nginx."; the pre-flight reproduces it up front."""

    NGINX = "/usr/sbin/nginx"

    def test_passes_when_reload_works(self):
        logs, log = _collect_log()
        ssh = FakeSSH()
        assert _preflight_nginx_reload(ssh, self.NGINX, log) is True
        assert ssh.ran(f"{self.NGINX} -t 2>&1 && {self.NGINX} -s reload 2>&1")
        assert not ssh.ran("systemctl restart nginx")

    def test_skips_when_nginx_absent(self):
        logs, log = _collect_log()
        ssh = FakeSSH([("test -x", ("", "", 1))])
        assert _preflight_nginx_reload(ssh, self.NGINX, log) is True
        assert not ssh.ran("-s reload")
        assert any("skipping" in line for line in logs)

    def test_restarts_nginx_when_active_but_unsignallable(self):
        # Debian race: nginx up under systemd, /run/nginx.pid empty ->
        # 'nginx -s reload' fails with "invalid PID number".
        logs, log = _collect_log()
        ssh = FakeSSH()
        reload_results = iter([
            ("nginx: [error] invalid PID number \"\" in \"/run/nginx.pid\"", "", 1),
            ("", "", 0),
        ])

        def _execute_sudo(cmd, timeout=None):
            ssh.calls.append(cmd)
            if "-s reload" in cmd:
                return next(reload_results)
            if "is-active nginx" in cmd:
                return ("active", "", 0)
            return ("", "", 0)

        ssh.execute_sudo = _execute_sudo
        assert _preflight_nginx_reload(ssh, self.NGINX, log) is True
        assert ssh.ran("systemctl restart nginx")
        assert ssh.index_of("systemctl restart nginx") < len(ssh.calls) - 1
        assert any("invalid PID number" in line for line in logs)

    def test_fails_without_restart_when_nginx_inactive(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("-s reload", ("nginx: [error] open() \"/run/nginx.pid\" failed", "", 1)),
            ("is-active nginx", ("inactive", "", 3)),
        ])
        assert _preflight_nginx_reload(ssh, self.NGINX, log) is False
        assert not ssh.ran("systemctl restart nginx")
        assert any("not active" in line for line in logs)

    def test_fails_when_reload_still_broken_after_restart(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("-s reload", ("nginx: [error] invalid PID number", "", 1)),
            ("is-active nginx", ("active", "", 0)),
        ])
        assert _preflight_nginx_reload(ssh, self.NGINX, log) is False
        assert ssh.ran("systemctl restart nginx")
        assert any("still fails after restart" in line for line in logs)


class TestGhostUpgradeNginxPreflightAndDebugLog:
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

    def _base_responses(self):
        ghost_cli_json = '{"name": "example-site", "active-version": "6.22.0"}'
        return [
            (".ghost-cli", (ghost_cli_json, "", 0)),
            ("config.production.json", ('["ghost", "ghost"]', "", 0)),
            ("SHOW GRANTS", ("GRANT ALL PRIVILEGES ON `ghost`.* TO `ghost`@`localhost`", "", 0)),
            ("command -v systemctl", ("/usr/bin/systemctl", "", 0)),
            ("command -v nginx", ("/usr/sbin/nginx", "", 0)),
            ("npm install -g ghost-cli", ("ok", "", 0)),
        ]

    def test_preflight_runs_before_update_and_aborts_when_nginx_down(self):
        ssh = FakeSSH(self._base_responses() + [
            ("-s reload", ("nginx: [error] open() \"/run/nginx.pid\" failed", "", 1)),
            ("is-active nginx", ("inactive", "", 3)),
            ("ghost update", ("Finished", "", 0)),
        ])
        ok, msg = self._run(ssh)
        assert ok is False
        assert not ssh.ran("ghost update"), ssh.calls
        assert "aborting before ghost update" in msg

    def test_debug_log_tailed_when_update_fails(self):
        ssh = FakeSSH(self._base_responses() + [
            ("ghost update", ("[FAILED] Failed to restart Nginx.", "", 1)),
            ("ghost-cli-debug-", ("--- /opt/ghost/.ghost/logs/ghost-cli-debug-x.log ---\n"
                                  "nginx: [error] invalid PID number", "", 0)),
        ])
        ok, msg = self._run(ssh)
        assert ok is False
        assert ssh.index_of("ghost-cli-debug-") > ssh.index_of("ghost update")
        assert "ghost-cli debug log (tail)" in msg
        assert "invalid PID number" in msg

    def test_debug_log_not_fetched_on_success(self):
        ssh = FakeSSH(self._base_responses() + [
            ("ghost update", ("Finished", "", 0)),
            ("is-active", ("active", "", 0)),
            ("curl", ("HTTP:200", "", 0)),
        ])
        ok, _ = self._run(ssh)
        assert ok is True
        assert not ssh.ran("ghost-cli-debug-")


class TestCheckGhostHttp:
    """After the update the site must answer over HTTP — an active Ghost unit
    is not enough (news.mstdn.ca was 'upgraded successfully' with nginx dead)."""

    NGINX = "/usr/sbin/nginx"
    TARGET = ('{"url": "https://news.example.com", "host": "127.0.0.1", "port": 2370}', "", 0)

    def test_resolves_target_from_config(self):
        ssh = FakeSSH([("ghost-http-target", self.TARGET)])
        assert _resolve_ghost_http_target(ssh, "/opt/ghost") == ("news.example.com", "127.0.0.1", 2370)

    def test_falls_back_to_defaults_when_config_unreadable(self):
        ssh = FakeSSH([("ghost-http-target", ("", "", 1))])
        assert _resolve_ghost_http_target(ssh, "/opt/ghost") == (None, "127.0.0.1", 2368)

    def test_rejects_unsafe_values(self):
        bad = ('{"url": "https://x;rm -rf /", "host": "127.0.0.1;id", "port": "abc"}', "", 0)
        ssh = FakeSSH([("ghost-http-target", bad)])
        assert _resolve_ghost_http_target(ssh, "/opt/ghost") == (None, "127.0.0.1", 2368)

    def test_passes_when_ghost_and_nginx_answer(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("ghost-http-target", self.TARGET),
            ("http://127.0.0.1:2370/", ("HTTP:200", "", 0)),
            ("https://127.0.0.1/", ("HTTP:200", "", 0)),
        ])
        assert _check_ghost_http(ssh, "/opt/ghost", self.NGINX, log) is True
        assert ssh.ran("-H 'Host: news.example.com' https://127.0.0.1/")

    def test_accepts_redirects(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("ghost-http-target", self.TARGET),
            ("http://127.0.0.1:2370/", ("HTTP:301", "", 0)),
            ("https://127.0.0.1/", ("HTTP:302", "", 0)),
        ])
        assert _check_ghost_http(ssh, "/opt/ghost", self.NGINX, log) is True

    def test_fails_when_ghost_does_not_answer(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("ghost-http-target", self.TARGET),
            ("http://127.0.0.1:2370/", ("HTTP:000", "", 0)),
        ])
        assert _check_ghost_http(ssh, "/opt/ghost", self.NGINX, log) is False
        assert not ssh.ran("https://127.0.0.1/")
        assert any("Ghost is not answering" in line for line in logs)

    def test_fails_when_nginx_is_dead(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("ghost-http-target", self.TARGET),
            ("http://127.0.0.1:2370/", ("HTTP:200", "", 0)),
            ("https://127.0.0.1/", ("HTTP:000", "", 0)),
            ("is-active nginx", ("failed", "", 3)),
        ])
        assert _check_ghost_http(ssh, "/opt/ghost", self.NGINX, log) is False
        assert any("not reachable through nginx" in line and "nginx is failed" in line for line in logs)

    def test_skips_nginx_check_when_nginx_absent(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("ghost-http-target", self.TARGET),
            ("http://127.0.0.1:2370/", ("HTTP:200", "", 0)),
            ("test -x", ("", "", 1)),
        ])
        assert _check_ghost_http(ssh, "/opt/ghost", self.NGINX, log) is True
        assert not ssh.ran("https://127.0.0.1/")


class TestGhostUpgradeHttpVerification:
    def _run(self, ssh, settings_sink=None):
        fake_setting = MagicMock()
        settings = _make_settings()
        fake_setting.get.side_effect = lambda k, d="": settings.get(k, d)
        if settings_sink is not None:
            fake_setting.set.side_effect = lambda k, v: settings_sink.update({k: v})

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

    def _responses(self, nginx_status):
        ghost_cli_json = '{"name": "news-mstdn-ca", "active-version": "6.46.0"}'
        return [
            (".ghost-cli", (ghost_cli_json, "", 0)),
            ("ghost-http-target", TestCheckGhostHttp.TARGET),
            ("config.production.json", ('["ghost", "ghost"]', "", 0)),
            ("SHOW GRANTS", ("GRANT ALL PRIVILEGES ON `ghost`.* TO `ghost`@`localhost`", "", 0)),
            ("command -v systemctl", ("/usr/bin/systemctl", "", 0)),
            ("command -v nginx", ("/usr/sbin/nginx", "", 0)),
            ("npm install -g ghost-cli", ("ok", "", 0)),
            ("ghost update", ("Finished", "", 0)),
            ("is-active nginx", ("failed" if nginx_status != "HTTP:200" else "active", "", 0)),
            ("is-active", ("active", "", 0)),
            ("http://127.0.0.1:2370/", ("HTTP:200", "", 0)),
            ("https://127.0.0.1/", (nginx_status, "", 0)),
        ]

    def test_reports_failure_when_site_unreachable_despite_active_unit(self):
        written = {}
        ssh = FakeSSH(self._responses("HTTP:000"))
        ok, msg = self._run(ssh, settings_sink=written)
        assert ok is False
        assert "not reachable through nginx" in msg
        assert "nginx is failed" in msg
        assert "ghost_current_version" not in written

    def test_succeeds_when_site_answers(self):
        written = {}
        ssh = FakeSSH(self._responses("HTTP:200"))
        ok, _ = self._run(ssh, settings_sink=written)
        assert ok is True
        assert written["ghost_current_version"] == "6.46.0"
        assert ssh.index_of("https://127.0.0.1/") > ssh.index_of("ghost update")
