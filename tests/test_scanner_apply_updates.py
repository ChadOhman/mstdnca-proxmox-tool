"""Tests for core.scanner.apply_updates post-upgrade reconciliation (issue #125).

``apt-get upgrade -y`` exits 0 even when packages are held back, so a zero exit
is not proof that every pending package was installed.  apply_updates re-reads
``apt list --upgradable`` and only retires rows that no longer appear there.
"""
from unittest.mock import MagicMock, patch

from core.scanner import apply_updates
from models import Credential, Guest, ProxmoxHost, UpdatePackage, db


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


def _make_guest(app, name, packages, connection_method="ssh", guest_type="ct"):
    from auth import credential_store

    with app.app_context():
        host = ProxmoxHost(name=f"pve-{name}", hostname=f"{name}.local", host_type="pve")
        cred = Credential(
            name=f"cred-{name}", username="root", auth_type="password",
            encrypted_value=credential_store.encrypt("test-only-passphrase"),
        )
        db.session.add_all([host, cred])
        db.session.commit()
        guest = Guest(
            name=name, vmid=9000 + len(name), guest_type=guest_type,
            proxmox_host_id=host.id, credential_id=cred.id,
            ip_address="10.0.0.9", connection_method=connection_method,
            status="updates-available",
        )
        db.session.add(guest)
        db.session.commit()
        for pkg in packages:
            db.session.add(UpdatePackage(
                guest_id=guest.id, package_name=pkg,
                current_version="1.0", available_version="2.0", status="pending",
            ))
        db.session.commit()
        return guest.id


class TestApplyUpdatesKeptBack:
    def test_kept_back_packages_stay_pending(self, app):
        guest_id = _make_guest(app, "keptback", ["curl", "linux-image-amd64"])
        # apt-get upgrade succeeds, but linux-image-amd64 is still upgradable.
        ssh = FakeSSH([
            ("apt list --upgradable", (
                "Listing...\n"
                "linux-image-amd64/stable 6.1.2 amd64 [upgradable from: 6.1.1]\n",
                "", 0)),
        ])
        with app.app_context():
            guest = Guest.query.get(guest_id)
            with patch("core.scanner.SSHClient") as fake_cls, \
                 patch("core.scanner.check_reboot_required"):
                fake_cls.from_credential.return_value = ssh
                ok, _ = apply_updates(guest)

            assert ok is True
            by_name = {p.package_name: p for p in guest.updates}
            assert by_name["curl"].status == "applied"
            assert by_name["curl"].applied_at is not None
            assert by_name["linux-image-amd64"].status == "pending"
            assert by_name["linux-image-amd64"].applied_at is None
            assert guest.status == "updates-available"

    def test_all_applied_sets_up_to_date(self, app):
        guest_id = _make_guest(app, "allapplied", ["curl", "vim"])
        ssh = FakeSSH([("apt list --upgradable", ("Listing...\n", "", 0))])
        with app.app_context():
            guest = Guest.query.get(guest_id)
            with patch("core.scanner.SSHClient") as fake_cls, \
                 patch("core.scanner.check_reboot_required"):
                fake_cls.from_credential.return_value = ssh
                ok, _ = apply_updates(guest)

            assert ok is True
            assert all(p.status == "applied" for p in guest.updates)
            assert guest.status == "up-to-date"

    def test_recheck_failure_leaves_everything_pending(self, app):
        guest_id = _make_guest(app, "recheckfail", ["curl"])
        ssh = FakeSSH([("apt list --upgradable", ("", "boom", 1))])
        with app.app_context():
            guest = Guest.query.get(guest_id)
            with patch("core.scanner.SSHClient") as fake_cls, \
                 patch("core.scanner.check_reboot_required"):
                fake_cls.from_credential.return_value = ssh
                ok, _ = apply_updates(guest)

            assert ok is True
            assert guest.updates[0].status == "pending"
            assert guest.status == "updates-available"

    def test_failed_upgrade_does_not_touch_packages(self, app):
        guest_id = _make_guest(app, "upgradefail", ["curl"])
        ssh = FakeSSH([("apt-get upgrade", ("", "dpkg error", 100))])
        with app.app_context():
            guest = Guest.query.get(guest_id)
            with patch("core.scanner.SSHClient") as fake_cls:
                fake_cls.from_credential.return_value = ssh
                ok, err = apply_updates(guest)

            assert ok is False
            assert "dpkg error" in err
            assert guest.updates[0].status == "pending"
            assert not ssh.ran("apt list --upgradable")


class TestApplyUpdatesAgentPath:
    def test_agent_command_is_wrapped_in_sh_c(self, app):
        guest_id = _make_guest(app, "agentpath", ["curl", "vim"],
                               connection_method="agent", guest_type="vm")
        client = MagicMock()
        client.get_all_guests.return_value = [{"vmid": 9009, "node": "pve1"}]
        client.exec_guest_agent.return_value = ("Listing...\n", None)

        with app.app_context():
            guest = Guest.query.get(guest_id)
            client.get_all_guests.return_value = [{"vmid": guest.vmid, "node": "pve1"}]
            with patch("core.scanner.ProxmoxClient", return_value=client), \
                 patch("core.scanner.check_reboot_required"):
                ok, _ = apply_updates(guest)

            assert ok is True
            upgrade_calls = [
                c.args[2] for c in client.exec_guest_agent.call_args_list
                if "apt-get upgrade" in c.args[2]
            ]
            assert len(upgrade_calls) == 1
            # The env-var prefix is not a program name — it must go through a shell.
            assert upgrade_calls[0].startswith("sh -c ")
            assert "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y" in upgrade_calls[0]

    def test_agent_kept_back_packages_stay_pending(self, app):
        guest_id = _make_guest(app, "agentkeptback", ["curl", "vim"],
                               connection_method="agent", guest_type="vm")
        client = MagicMock()

        def _exec(node, vmid, cmd):
            if "apt list --upgradable" in cmd:
                return ("Listing...\nvim/stable 2.0 amd64 [upgradable from: 1.0]\n", None)
            return ("", None)

        client.exec_guest_agent.side_effect = _exec

        with app.app_context():
            guest = Guest.query.get(guest_id)
            client.get_all_guests.return_value = [{"vmid": guest.vmid, "node": "pve1"}]
            with patch("core.scanner.ProxmoxClient", return_value=client), \
                 patch("core.scanner.check_reboot_required"):
                ok, _ = apply_updates(guest)

            assert ok is True
            by_name = {p.package_name: p for p in guest.updates}
            assert by_name["curl"].status == "applied"
            assert by_name["vim"].status == "pending"
            assert guest.status == "updates-available"
