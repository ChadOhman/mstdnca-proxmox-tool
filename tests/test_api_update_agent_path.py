"""The interactive apply path over the QEMU guest agent streams its output.

A guest with no usable IP is updated through the guest agent.  Plain
guest-exec only returns output when the process exits, so the update page sat
blank for a whole apt run; the job now uses the streaming exec, honours
cancel, and reports a run that did not complete instead of treating a
timeout as success.
"""
import routes.api as api_mod
from core.scanner import apt_upgrade_command
from models import Guest, ProxmoxHost, UpdatePackage, db


def _make_guest(app, name):
    with app.app_context():
        host = ProxmoxHost(name=f"_ag-host-{name}", hostname="pve.test", host_type="pve",
                           auth_type="token", username="root@pam", api_token_id="t",
                           api_token_secret="x")
        db.session.add(host)
        db.session.flush()
        g = Guest(name=name, guest_type="vm", vmid=901, enabled=True, ip_address="dhcp",
                  connection_method="agent", proxmox_host_id=host.id, status="updates-available")
        db.session.add(g)
        db.session.flush()
        db.session.add(UpdatePackage(guest_id=g.id, package_name="pkg0", status="pending", severity="normal"))
        db.session.commit()
        return g.id, host.id


def _cleanup(app, guest_id, host_id):
    with app.app_context():
        g = Guest.query.get(guest_id)
        if g:
            db.session.delete(g)
        h = ProxmoxHost.query.get(host_id)
        if h:
            db.session.delete(h)
        db.session.commit()


class FakeClient:
    """Stands in for ProxmoxClient: records the streamed command and plays a script."""

    instances = []

    def __init__(self, host_model, script=None):
        self.calls = []
        FakeClient.instances.append(self)

    def get_all_guests(self):
        return [{"vmid": 901, "node": "pve1"}]

    # set per test
    exit_code = 0
    chunks = ("Reading package lists...\n", "done\n")
    cancel_after_first_chunk = False

    def exec_guest_agent_streaming(self, node, vmid, command, callback, timeout=None, stop_fn=None):
        self.calls.append((node, vmid, command, timeout))
        for i, c in enumerate(self.chunks):
            callback(c)
            if self.cancel_after_first_chunk and i == 0:
                self._job.cancel_requested = True
            if stop_fn and stop_fn():
                callback("\n[Cancelled: sent SIGTERM to the process group in the guest]\n")
                return None
        return self.exit_code


def _run(app, monkeypatch, guest_id, name, client_cls):
    monkeypatch.setattr("clients.proxmox_api.ProxmoxClient", client_cls)
    monkeypatch.setattr("core.scanner.check_reboot_required", lambda guest: None)
    with app.app_context():
        job = api_mod.UpdateJob(guest_id, name)
        api_mod._update_jobs[guest_id] = job
    client_cls._job = job
    api_mod._run_update_background(app, guest_id, dist_upgrade=False)
    return api_mod._update_jobs.pop(guest_id)


def test_agent_path_streams_and_marks_success(app, monkeypatch):
    guest_id, host_id = _make_guest(app, "_ag-guest-ok")
    FakeClient.instances.clear()

    class Ok(FakeClient):
        exit_code = 0

    try:
        job = _run(app, monkeypatch, guest_id, "_ag-guest-ok", Ok)
        assert job.success is True
        node, vmid, command, timeout = FakeClient.instances[0].calls[0]
        assert (node, vmid) == ("pve1", 901)
        # the streamed command is the raw shell snippet: the client wraps it itself
        assert command == f"apt-get update && {apt_upgrade_command()}"
        assert timeout == 1800
        assert "Reading package lists...\ndone\n" in job.log
        assert "Updates applied successfully." in job.log
        with app.app_context():
            g = Guest.query.get(guest_id)
            assert g.status == "up-to-date"
            assert all(p.status == "applied" for p in UpdatePackage.query.filter_by(guest_id=guest_id))
    finally:
        _cleanup(app, guest_id, host_id)


def test_agent_path_nonzero_exit_is_a_failure_with_the_code(app, monkeypatch):
    guest_id, host_id = _make_guest(app, "_ag-guest-fail")
    FakeClient.instances.clear()

    class Fail(FakeClient):
        exit_code = 100
        chunks = ("E: dpkg was interrupted\n",)

    try:
        job = _run(app, monkeypatch, guest_id, "_ag-guest-fail", Fail)
        assert job.success is False
        assert "apt exited with code 100." in job.log
        with app.app_context():
            assert Guest.query.get(guest_id).status == "updates-available"
    finally:
        _cleanup(app, guest_id, host_id)


def test_agent_path_incomplete_run_is_not_success(app, monkeypatch):
    """A timeout or lost agent returns None: never mark packages applied."""
    guest_id, host_id = _make_guest(app, "_ag-guest-none")
    FakeClient.instances.clear()

    class Incomplete(FakeClient):
        exit_code = None
        chunks = ("Get:1 ...\n", "\n[Timeout] Still running after 1800s; left running in the guest.\n")

    try:
        job = _run(app, monkeypatch, guest_id, "_ag-guest-none", Incomplete)
        assert job.success is False
        assert "did not complete" in job.log
        with app.app_context():
            g = Guest.query.get(guest_id)
            assert g.status == "updates-available"
            assert all(p.status == "pending" for p in UpdatePackage.query.filter_by(guest_id=guest_id))
    finally:
        _cleanup(app, guest_id, host_id)


def test_agent_path_cancel_is_honoured(app, monkeypatch):
    guest_id, host_id = _make_guest(app, "_ag-guest-cancel")
    FakeClient.instances.clear()

    class Cancel(FakeClient):
        cancel_after_first_chunk = True
        chunks = ("Get:1 ...\n", "never shown\n")

    try:
        job = _run(app, monkeypatch, guest_id, "_ag-guest-cancel", Cancel)
        assert job.success is False
        assert "[Cancelled by user]" in job.log
        assert "never shown" not in job.log
    finally:
        _cleanup(app, guest_id, host_id)
