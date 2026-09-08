"""PeerTube upgrade/install failure semantics (issue #125).

A dead service after upgrade.sh, a failed pre-upgrade pg_dump, and a missing DB
password all used to be logged as warnings while the run still reported
success.  These tests pin the failing behaviour.
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

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _peertube_settings(overrides=None):
    base = {
        "peertube_guest_id": "1",
        "peertube_db_guest_id": "2",
        "peertube_user": "peertube",
        "peertube_db_name": "peertube",
        "peertube_dir": "/var/www/peertube",
        "peertube_url": "https://tube.example.com",
        "peertube_db_host": "",
        "peertube_db_password": "",
        "peertube_current_version": "6.0.0",
        "peertube_latest_version": "6.1.0",
        "peertube_protection_type": "snapshot",
        "peertube_backup_storage": "",
        "peertube_backup_mode": "snapshot",
        "peertube_auto_upgrade": "false",
    }
    if overrides:
        base.update(overrides)
    return base


def _run_peertube_upgrade(ssh, settings_overrides=None, settings_sink=None,
                          skip_protection=True):
    from apps.peertube import run_peertube_upgrade

    settings = _peertube_settings(settings_overrides)
    fake_setting = MagicMock()
    fake_setting.get.side_effect = lambda k, d="": settings.get(k, d)
    if settings_sink is not None:
        fake_setting.set.side_effect = lambda k, v: settings_sink.update({k: v})

    app_guest = MagicMock()
    app_guest.credential = MagicMock()
    app_guest.ip_address = "10.0.0.7"
    app_guest.name = "peertube-vm"

    db_guest = MagicMock()
    db_guest.credential = MagicMock()
    db_guest.ip_address = "10.0.0.8"
    db_guest.name = "pg-vm"

    fake_guest_cls = MagicMock()
    fake_guest_cls.query.get.side_effect = lambda gid: app_guest if gid == 1 else db_guest

    with (
        patch("apps.peertube.Setting", fake_setting),
        patch("apps.peertube.Guest", fake_guest_cls),
        patch("apps.peertube.SSHClient") as fake_sshclient,
        patch("apps.peertube.time.sleep"),
        patch("apps.peertube.snapshot_guest", return_value=(True, "ok")),
    ):
        fake_sshclient.from_credential.return_value = ssh
        return run_peertube_upgrade(skip_protection=skip_protection)


class TestPeerTubeUpgradeServiceFailure:
    def test_returns_false_when_service_down(self):
        ssh = FakeSSH([("systemctl is-active peertube", ("failed", "", 3))])
        ok, log = _run_peertube_upgrade(ssh)
        assert ok is False
        # The whole log is preserved so the route records it against the failure.
        assert "upgrade.sh completed successfully" in log

    def test_does_not_persist_version_when_service_down(self):
        written = {}
        ssh = FakeSSH([("systemctl is-active peertube", ("failed", "", 3))])
        ok, _ = _run_peertube_upgrade(ssh, settings_sink=written)
        assert ok is False
        assert "peertube_current_version" not in written

    def test_active_service_reports_success(self):
        written = {}
        ssh = FakeSSH([
            ("systemctl is-active peertube", ("active", "", 0)),
            # Symlink target carries the 'peertube-' prefix, so version detection
            # falls back to reading package.json.
            ("readlink -f", ("/var/www/peertube/versions/peertube-6.1.0", "", 0)),
            ("package.json", ("6.1.0\n", "", 0)),
        ])
        ok, _ = _run_peertube_upgrade(ssh, settings_sink=written)
        assert ok is True
        assert written["peertube_current_version"] == "6.1.0"


class TestPeerTubePgDump:
    def test_pg_dump_targets_prod_database(self):
        ssh = FakeSSH([("systemctl is-active peertube", ("active", "", 0))])
        ok, _ = _run_peertube_upgrade(ssh, skip_protection=False)
        assert ok is True
        # PeerTube's production.yaml sets database.suffix '_prod'.
        assert ssh.ran("pg_dump peertube_prod >")
        assert not any("pg_dump peertube >" in c for c in ssh.calls)

    def test_pg_dump_failure_is_fatal(self):
        ssh = FakeSSH([
            ("pg_dump", ("", "could not connect", 1)),
            ("systemctl is-active peertube", ("active", "", 0)),
        ])
        ok, log = _run_peertube_upgrade(ssh, skip_protection=False)
        assert ok is False
        assert "Aborting" in log
        assert not ssh.ran("upgrade.sh")

    def test_pg_dump_failure_tolerated_when_protection_skipped(self):
        ssh = FakeSSH([
            ("pg_dump", ("", "could not connect", 1)),
            ("systemctl is-active peertube", ("active", "", 0)),
        ])
        ok, log = _run_peertube_upgrade(ssh, skip_protection=True)
        assert ok is True
        assert "protection explicitly skipped" in log


class TestPeerTubePnpmPrune:
    def test_prune_is_not_masked_by_true(self):
        ssh = FakeSSH([
            ("systemctl is-active peertube", ("active", "", 0)),
            ("pnpm store prune", ("", "ENOENT", 1)),
        ])
        ok, log = _run_peertube_upgrade(ssh)
        assert ok is True
        prune_calls = [c for c in ssh.calls if "pnpm store prune" in c]
        assert prune_calls and all("|| true" not in c for c in prune_calls)
        assert "pnpm store prune skipped or failed (exit 1" in log


class TestPeerTubeInstallValidation:
    def _run_install(self, settings_overrides=None):
        from apps.peertube import run_peertube_install

        settings = _peertube_settings(settings_overrides)
        fake_setting = MagicMock()
        fake_setting.get.side_effect = lambda k, d="": settings.get(k, d)

        app_guest = MagicMock()
        app_guest.credential = MagicMock()
        app_guest.ip_address = "10.0.0.7"
        fake_guest_cls = MagicMock()
        fake_guest_cls.query.get.return_value = app_guest

        with (
            patch("apps.peertube.Setting", fake_setting),
            patch("apps.peertube.Guest", fake_guest_cls),
        ):
            return run_peertube_install()

    def test_refuses_install_without_db_password(self):
        ok, msg = self._run_install()
        assert ok is False
        assert "database password" in msg.lower()

    def test_rejects_invalid_hostname(self):
        ok, msg = self._run_install({"peertube_url": "https://-bad-.example.com"})
        assert ok is False
        assert "hostname" in msg.lower()


class TestPeerTubeYamlEscaping:
    def test_every_value_is_yaml_escaped(self):
        from apps.peertube import _PEERTUBE_PRODUCTION_YAML, _yaml_sq

        content = _PEERTUBE_PRODUCTION_YAML.format(
            hostname=_yaml_sq("tube.example.com"),
            db_host=_yaml_sq("db'host"),
            db_user=_yaml_sq("pt'user"),
            db_password=_yaml_sq("pa'ss"),
            peertube_dir=_yaml_sq("/var/www/pe'ertube"),
        )
        # Each embedded quote is doubled, so no scalar is terminated early.
        assert "'db''host'" in content
        assert "'pt''user'" in content
        assert "'pa''ss'" in content
        assert "'/var/www/pe''ertube/storage/tmp/'" in content

    def test_yaml_sq_handles_none(self):
        from apps.peertube import _yaml_sq

        assert _yaml_sq(None) == ""


class TestPeerTubeHostnameRegex:
    def test_accepts_normal_hostnames(self):
        from apps.peertube import _HOSTNAME_RE

        for good in ("tube.example.com", "localhost", "a-b.c-d.example"):
            assert _HOSTNAME_RE.match(good), good

    def test_rejects_injection_shapes(self):
        from apps.peertube import _HOSTNAME_RE

        for bad in ("tube.example.com'", "-bad.example.com", "bad-.example.com",
                    "tube example.com", "tube.example.com/../x", ""):
            assert not _HOSTNAME_RE.match(bad), bad
