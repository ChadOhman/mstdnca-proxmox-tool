"""Tests for the per-host SSH apply worker routes.hosts._run_apply (PVE and PBS).

_run_apply normally runs in a background thread; here it is called directly
(same thread, same DB connection) with SSHClient.from_credential patched to a
fake, so no real SSH happens.
"""
from unittest.mock import patch

import pytest

from models import Credential, HostUpdatePackage, ProxmoxHost, db
from routes.hosts import _apply_jobs, _apply_lock, _run_apply

UPGRADABLE_KEPT_BACK = (
    "Listing...\n"
    "proxmox-backup-server/stable 3.4.2 amd64 [upgradable from: 3.4.1]\n"
)


class FakeSSH:
    def __init__(self, stream_output="", exit_code=0, upgradable="Listing...\n", upgradable_code=0,
                 cancel_host_id=None):
        self.stream_output = stream_output
        self.exit_code = exit_code
        self.upgradable = upgradable
        self.upgradable_code = upgradable_code
        self.cancel_host_id = cancel_host_id
        self.sudo_streamed = []
        self.executed = []
        self.closed = False

    def execute_sudo_streaming(self, command, callback, timeout=600, stop_fn=None):
        self.sudo_streamed.append(command)
        if self.cancel_host_id is not None:
            with _apply_lock:
                _apply_jobs[self.cancel_host_id]["cancelled"] = True
        callback(self.stream_output)
        return self.exit_code

    def execute(self, command, timeout=120, _sudo=False):
        self.executed.append(command)
        return self.upgradable, "", self.upgradable_code

    def close(self):
        self.closed = True


@pytest.fixture
def pbs_host(app):
    with app.app_context():
        cred = Credential(name="_run-apply-cred", username="backupadmin", auth_type="password",
                          encrypted_value="test-only-encrypted")
        db.session.add(cred)
        db.session.flush()
        host = ProxmoxHost(name="_run-apply-pbs", hostname="10.0.0.50", host_type="pbs",
                           ssh_credential_id=cred.id)
        db.session.add(host)
        db.session.flush()
        db.session.add_all([
            HostUpdatePackage(host_id=host.id, package_name="proxmox-backup-server",
                              status="pending", severity="normal"),
            HostUpdatePackage(host_id=host.id, package_name="openssl",
                              status="pending", severity="critical"),
            HostUpdatePackage(host_id=host.id, package_name="curl",
                              status="pending", severity="normal"),
        ])
        db.session.commit()
        host_id, cred_id = host.id, cred.id
    with _apply_lock:
        _apply_jobs[host_id] = {"log": [], "running": True, "success": None, "cancelled": False}
    yield host_id
    with _apply_lock:
        _apply_jobs.pop(host_id, None)
    with app.app_context():
        HostUpdatePackage.query.filter_by(host_id=host_id).delete()
        db.session.delete(ProxmoxHost.query.get(host_id))
        db.session.delete(Credential.query.get(cred_id))
        db.session.commit()


def _run(app, host_id, fake):
    with patch("clients.ssh_client.SSHClient.from_credential", return_value=fake), \
         patch("core.notifier.send_updates_applied_notification") as notify:
        _run_apply(host_id, app)
    with _apply_lock:
        job = dict(_apply_jobs[host_id])
    return job, "".join(job["log"]), notify


def _statuses(app, host_id):
    with app.app_context():
        return {p.package_name: p.status for p in HostUpdatePackage.query.filter_by(host_id=host_id)}


class TestRunApply:
    def test_refreshes_lists_and_upgrades_through_sudo(self, app, pbs_host):
        fake = FakeSSH()
        job, _, _ = _run(app, pbs_host, fake)
        assert job["success"] is True and job["running"] is False
        assert len(fake.sudo_streamed) == 1
        cmd = fake.sudo_streamed[0]
        assert cmd.startswith("apt-get update && ")
        assert "dist-upgrade -y" in cmd
        assert fake.closed

    def test_only_installed_packages_marked_applied(self, app, pbs_host):
        fake = FakeSSH(upgradable=UPGRADABLE_KEPT_BACK)
        job, log, notify = _run(app, pbs_host, fake)
        assert job["success"] is True
        assert _statuses(app, pbs_host) == {
            "proxmox-backup-server": "pending",
            "openssl": "applied",
            "curl": "applied",
        }
        assert "kept back" in log and "proxmox-backup-server" in log
        notify.assert_called_once()
        (summary,), _ = notify.call_args
        assert summary == [{"name": "_run-apply-pbs", "type": "PBS", "applied": 2, "security": 1}]

    def test_failed_recheck_leaves_pending_untouched(self, app, pbs_host):
        fake = FakeSSH(upgradable="", upgradable_code=1)
        job, log, _ = _run(app, pbs_host, fake)
        assert job["success"] is True
        assert set(_statuses(app, pbs_host).values()) == {"pending"}
        assert "Could not re-check" in log

    def test_sudo_failure_adds_hint_and_marks_nothing(self, app, pbs_host):
        fake = FakeSSH(stream_output="sudo: a password is required\n", exit_code=1)
        job, log, notify = _run(app, pbs_host, fake)
        assert job["success"] is False
        assert "apt exited with code 1" in log
        assert "[Hint]" in log and "'backupadmin'" in log
        assert fake.executed == []  # no re-check after a failed upgrade
        assert set(_statuses(app, pbs_host).values()) == {"pending"}
        notify.assert_not_called()

    def test_cancel_reports_failure(self, app, pbs_host):
        fake = FakeSSH(exit_code=-1, cancel_host_id=pbs_host)
        job, log, notify = _run(app, pbs_host, fake)
        assert job["success"] is False
        assert "[Cancelled by user]" in log
        assert set(_statuses(app, pbs_host).values()) == {"pending"}
        notify.assert_not_called()

    def test_missing_credential(self, app, pbs_host):
        with app.app_context():
            ProxmoxHost.query.get(pbs_host).ssh_credential_id = None
            db.session.commit()
        job, log, _ = _run(app, pbs_host, FakeSSH())
        assert job["success"] is False
        assert "no longer available" in log
