"""Jitsi configure/upgrade failure semantics (issue #125).

``run_cloudflare_configure`` and ``run_secure_domain_configure`` returned True
even when every config patch and service restart failed, and the "targeted"
upgrade ran a full ``apt-get upgrade``.
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


def _jitsi_settings(overrides=None):
    base = {
        "jitsi_guest_id": "1",
        "jitsi_hostname": "meet.example.com",
        "jitsi_cert_type": "self-signed",
        "jitsi_letsencrypt_email": "",
        "jitsi_url": "https://meet.example.com",
        "jitsi_current_version": "2.0.9000",
        "jitsi_latest_version": "2.0.9500",
        "jitsi_protection_type": "snapshot",
        "jitsi_backup_storage": "",
        "jitsi_backup_mode": "snapshot",
        "jitsi_auto_upgrade": "false",
        "jitsi_installed": "true",
        "jitsi_cf_mode": "tcp_only",
        "jitsi_public_ip": "203.0.113.10",
        "jitsi_secure_domain": "true",
    }
    if overrides:
        base.update(overrides)
    return base


def _run(func_name, ssh, settings_overrides=None, **kwargs):
    import apps.jitsi as jitsi_mod

    settings = _jitsi_settings(settings_overrides)
    fake_setting = MagicMock()
    fake_setting.get.side_effect = lambda k, d="": settings.get(k, d)

    app_guest = MagicMock()
    app_guest.credential = MagicMock()
    app_guest.ip_address = "10.0.0.4"
    app_guest.name = "jitsi-vm"
    fake_guest_cls = MagicMock()
    fake_guest_cls.query.get.return_value = app_guest

    with (
        patch("apps.jitsi.Setting", fake_setting),
        patch("apps.jitsi.Guest", fake_guest_cls),
        patch("apps.jitsi.SSHClient") as fake_sshclient,
        patch("apps.jitsi.time.sleep"),
    ):
        fake_sshclient.from_credential.return_value = ssh
        return getattr(jitsi_mod, func_name)(**kwargs)


class TestCloudflareConfigureReportsWarnings:
    def test_returns_false_when_services_are_down(self):
        ssh = FakeSSH([("systemctl is-active", ("failed", "", 3))])
        ok, log = _run("run_cloudflare_configure", ssh)
        assert ok is False
        assert "FAILED" in log

    def test_returns_true_when_everything_is_clean(self):
        ssh = FakeSSH([("systemctl is-active", ("active", "", 0))])
        # Config patching is covered by its own tests; here we pin the
        # warning-count → return-value aggregation.
        with (
            patch("apps.jitsi._cf_patch_jvb_conf_tcp", return_value=0),
            patch("apps.jitsi._cf_patch_meet_config_js", return_value=0),
            patch("apps.jitsi._configure_coturn_tls", return_value=0),
            patch("apps.jitsi._configure_prosody_turn", return_value=0),
            patch("apps.jitsi._cf_verify_coturn"),
        ):
            ok, log = _run("run_cloudflare_configure", ssh)
        assert ok is True
        assert "Cloudflare configuration complete" in log

    def test_restart_failure_counts_as_a_warning(self):
        ssh = FakeSSH([
            ("systemctl restart", ("", "job failed", 1)),
            ("systemctl is-active", ("active", "", 0)),
        ])
        with (
            patch("apps.jitsi._cf_patch_jvb_conf_tcp", return_value=0),
            patch("apps.jitsi._cf_patch_meet_config_js", return_value=0),
            patch("apps.jitsi._configure_coturn_tls", return_value=0),
            patch("apps.jitsi._configure_prosody_turn", return_value=0),
            patch("apps.jitsi._cf_verify_coturn"),
        ):
            ok, log = _run("run_cloudflare_configure", ssh)
        assert ok is False
        assert "restart returned exit code 1" in log


class TestSecureDomainConfigureReportsWarnings:
    def test_returns_false_when_services_are_down(self):
        ssh = FakeSSH([("systemctl is-active", ("failed", "", 3))])
        ok, log = _run("run_secure_domain_configure", ssh)
        assert ok is False
        assert "FAILED" in log

    def test_returns_true_when_everything_is_clean(self):
        ssh = FakeSSH([("systemctl is-active", ("active", "", 0))])
        with (
            patch("apps.jitsi._sd_patch_prosody", return_value=0),
            patch("apps.jitsi._sd_patch_meet_config_js", return_value=0),
            patch("apps.jitsi._sd_patch_jicofo_conf", return_value=0),
        ):
            ok, log = _run("run_secure_domain_configure", ssh)
        assert ok is True
        assert "successfully" in log


class TestJitsiTargetedUpgrade:
    def test_uses_install_only_upgrade(self):
        ssh = FakeSSH([("systemctl is-active", ("active", "", 0))])
        ok, _ = _run("run_jitsi_upgrade", ssh, skip_protection=True)
        assert ok is True
        # Naming packages after 'apt-get upgrade' does not restrict the
        # operation — '--only-upgrade' does.
        assert ssh.ran("apt-get install -y --only-upgrade jitsi-meet")
        assert not any("apt-get upgrade -y jitsi" in c for c in ssh.calls)
