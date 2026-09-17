"""The interactive apply path (routes.api._run_update_background) explains sudo refusals.

When the SSH credential is a non-root user and the guest still demands a sudo
password, every wrapped command fails with ``sudo: a password is required``.
The job should say what to fix rather than leaving a bare exit code, and
should not bother running the upgrade once apt-get update has already been
refused for that reason.
"""
import routes.api as api_mod
from models import Credential, Guest, db

SUDO_REFUSAL = (
    "sudo: a terminal is required to read the password; either use the -S option "
    "to read from standard input or configure an askpass helper\n"
    "sudo: a password is required\n"
)


def _make_guest(app, name, username="ubuntu"):
    with app.app_context():
        cred = Credential(name=f"_sh-cred-{name}", username=username, auth_type="password",
                          encrypted_value="unused", is_default=False)
        db.session.add(cred)
        db.session.flush()
        g = Guest(name=name, guest_type="vm", enabled=True, ip_address="10.0.0.130",
                  connection_method="ssh", credential_id=cred.id)
        db.session.add(g)
        db.session.commit()
        return g.id, cred.id


def _cleanup(app, guest_id, cred_id):
    with app.app_context():
        for model, obj_id in ((Guest, guest_id), (Credential, cred_id)):
            obj = model.query.get(obj_id)
            if obj:
                db.session.delete(obj)
        db.session.commit()


def _run(app, monkeypatch, guest_id, name, fake_cls):
    monkeypatch.setattr(
        "clients.ssh_client.SSHClient.from_credential",
        classmethod(lambda cls, host, cred, port=22: fake_cls()),
    )
    with app.app_context():
        job = api_mod.UpdateJob(guest_id, name)
        api_mod._update_jobs[guest_id] = job
    api_mod._run_update_background(app, guest_id, dist_upgrade=False)
    return api_mod._update_jobs.pop(guest_id)


class _FakeSSHBase:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute_sudo(self, cmd, timeout=None):
        return ("no", "", 0)


def test_sudo_refusal_on_update_is_explained_and_upgrade_skipped(app, monkeypatch):
    guest_id, cred_id = _make_guest(app, "_sh-guest-refused")
    commands = []

    class FakeSSH(_FakeSSHBase):
        def execute_sudo_streaming(self, cmd, callback, timeout=None, stop_fn=None):
            commands.append(cmd)
            callback(SUDO_REFUSAL)
            return 1

    try:
        job = _run(app, monkeypatch, guest_id, "_sh-guest-refused", FakeSSH)
        assert job.success is False
        assert commands == ["apt-get update"], "upgrade should not run after a sudo refusal"
        assert "[Hint]" in job.log
        assert "'ubuntu'" in job.log
        assert "sudo password" in job.log
    finally:
        _cleanup(app, guest_id, cred_id)


def test_sudo_refusal_on_upgrade_is_explained(app, monkeypatch):
    guest_id, cred_id = _make_guest(app, "_sh-guest-upgrade")

    class FakeSSH(_FakeSSHBase):
        def execute_sudo_streaming(self, cmd, callback, timeout=None, stop_fn=None):
            if cmd == "apt-get update":
                callback("Reading package lists... Done\n")
                return 0
            callback("sudo: a password is required\n")
            return 1

    try:
        job = _run(app, monkeypatch, guest_id, "_sh-guest-upgrade", FakeSSH)
        assert job.success is False
        assert "apt exited with code 1" in job.log
        assert "[Hint]" in job.log
    finally:
        _cleanup(app, guest_id, cred_id)


def test_ordinary_apt_failure_has_no_hint(app, monkeypatch):
    guest_id, cred_id = _make_guest(app, "_sh-guest-plain")
    commands = []

    class FakeSSH(_FakeSSHBase):
        def execute_sudo_streaming(self, cmd, callback, timeout=None, stop_fn=None):
            commands.append(cmd)
            callback("E: Could not get lock /var/lib/apt/lists/lock\n")
            return 100

    try:
        job = _run(app, monkeypatch, guest_id, "_sh-guest-plain", FakeSSH)
        assert job.success is False
        # A non-sudo failure of apt-get update still lets the upgrade run, as before.
        assert commands == ["apt-get update", "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"]
        assert "[Hint]" not in job.log
    finally:
        _cleanup(app, guest_id, cred_id)


def test_hint_not_shown_when_the_update_output_was_clean(app, monkeypatch):
    """A refusal captured for apt-get update must not leak into the upgrade check."""
    guest_id, cred_id = _make_guest(app, "_sh-guest-clear")

    class FakeSSH(_FakeSSHBase):
        def execute_sudo_streaming(self, cmd, callback, timeout=None, stop_fn=None):
            if cmd == "apt-get update":
                callback("W: some repo warning\n")
                return 0
            callback("E: Unable to correct problems, you have held broken packages.\n")
            return 100

    try:
        job = _run(app, monkeypatch, guest_id, "_sh-guest-clear", FakeSSH)
        assert job.success is False
        assert "[Hint]" not in job.log
    finally:
        _cleanup(app, guest_id, cred_id)
