"""Jibri install/configure failure semantics (issue #125).

``run_jibri_install`` returned True when the jibri service never started, and
``run_jibri_jitsi_configure`` ignored ``prosodyctl register`` exit codes.
"""
from unittest.mock import patch

from apps.jibri import _prosodyctl_register


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


class TestProsodyctlRegister:
    def test_success(self):
        logs, log = _collect_log()
        ssh = FakeSSH()
        assert _prosodyctl_register(ssh, "jibri", "auth.meet.example.com",
                                    "test-only-pw", log) is True
        assert ssh.ran("prosodyctl register jibri auth.meet.example.com")

    def test_password_is_not_in_the_command_line(self):
        logs, log = _collect_log()
        ssh = FakeSSH()
        _prosodyctl_register(ssh, "jibri", "auth.meet.example.com",
                             "test-only-s3cret", log)
        assert all("test-only-s3cret" not in c for c in ssh.calls)
        assert ssh.ran("base64 -d")

    def test_already_exists_is_tolerated(self):
        logs, log = _collect_log()
        ssh = FakeSSH([("prosodyctl register", ("That user already exists", "", 1))])
        assert _prosodyctl_register(ssh, "jibri", "auth.meet.example.com",
                                    "test-only-pw", log) is True
        assert any("already exists" in line for line in logs)

    def test_real_failure_is_reported(self):
        logs, log = _collect_log()
        ssh = FakeSSH([("prosodyctl register", ("", "Unable to connect to prosody", 1))])
        assert _prosodyctl_register(ssh, "jibri", "auth.meet.example.com",
                                    "test-only-pw", log) is False
        assert any("ERROR: prosodyctl register" in line for line in logs)


class TestJibriInstallServiceVerification:
    """The install must fail when the jibri unit never comes up."""

    def _run(self, ssh, app):
        from apps.jibri import run_jibri_install
        from auth import credential_store
        from models import Credential, Guest, Setting, db

        with app.app_context():
            cred = Credential.query.filter_by(name="_jibri-svc-cred").first()
            if not cred:
                cred = Credential(
                    name="_jibri-svc-cred", username="root", auth_type="password",
                    encrypted_value=credential_store.encrypt("test-only-passphrase"),
                )
                db.session.add(cred)
                db.session.commit()
            guest = Guest(name="_jibri-svc-vm", vmid=9310, guest_type="vm",
                          enabled=True, ip_address="10.0.0.3",
                          credential_id=cred.id)
            jitsi_guest = Guest(name="_jibri-svc-jitsi", vmid=9311, guest_type="vm",
                                enabled=True, ip_address="10.0.0.4")
            db.session.add_all([guest, jitsi_guest])
            db.session.commit()
            guest_id, jitsi_id = guest.id, jitsi_guest.id
            Setting.set("jibri_guest_id", str(guest_id))
            Setting.set("jitsi_guest_id", str(jitsi_id))
            Setting.set("jitsi_installed", "true")
            Setting.set("jitsi_hostname", "meet.example.com")
            Setting.set("jibri_xmpp_password", "test-only-xmpp")
            Setting.set("jibri_recorder_password", "test-only-recorder")
            Setting.set("jibri_protection_type", "snapshot")
            try:
                with (
                    patch("apps.jibri.SSHClient") as fake_sshclient,
                    patch("apps.jibri.time.sleep"),
                    patch("apps.jibri.snapshot_guest", return_value=(True, "ok")),
                ):
                    fake_sshclient.from_credential.return_value = ssh
                    return run_jibri_install()
            finally:
                for gid in (guest_id, jitsi_id):
                    g = Guest.query.get(gid)
                    if g:
                        db.session.delete(g)
                db.session.commit()

    @staticmethod
    def _ssh(is_active):
        """A remote host where everything works except the final service check."""
        return FakeSSH([
            ("lsb_release -rs", ("22.04", "", 0)),
            ("lsb_release -si", ("Ubuntu", "", 0)),
            ("systemctl is-active jibri", (is_active, "", 0 if is_active == "active" else 3)),
        ])

    def test_returns_false_when_service_never_starts(self, app):
        ok, log = self._run(self._ssh("failed"), app)
        assert ok is False
        assert "jibri service status: failed" in log

    def test_does_not_mark_installed_when_service_is_down(self, app):
        from models import Setting

        with app.app_context():
            Setting.set("jibri_installed", "false")
        ok, _ = self._run(self._ssh("failed"), app)
        assert ok is False
        with app.app_context():
            assert Setting.get("jibri_installed", "false") != "true"

    def test_active_service_reports_success(self, app):
        ok, log = self._run(self._ssh("active"), app)
        assert ok is True
        assert "Jibri installation complete" in log
