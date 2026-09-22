"""Tests for core.mastodon_maintenance.run_maintenance() and the single-flight lock.

build_modify_command()'s own validation (hostile username/email/settings never
reach SSHClient) is covered alongside the rest of the shell-injection hardening
suite in tests/test_shell_injection_hardening.py; this file exercises the SSH
round trip: success/failure parsing, password redaction, and the guest/
credential lookup failure modes.
"""

from unittest.mock import MagicMock, patch

import pytest

from models import Credential, Guest, ProxmoxHost, Role, Setting, User, db
from routes.moderation import STAFF_TARGET_ERROR


def _settings(**overrides):
    values = {
        "mastodon_guest_id": None,  # filled in by the caller once the guest exists
        "mastodon_user": "mastodon",
        "mastodon_app_dir": "/home/mastodon/live",
    }
    values.update(overrides)
    for key, value in values.items():
        if value is not None:
            Setting.set(key, value)


def _credential(name="test-only-maintenance-cred"):
    cred = Credential.query.filter_by(name=name).first()
    if cred:
        return cred
    from auth import credential_store
    cred = Credential(
        name=name,
        username="root",
        auth_type="password",
        encrypted_value=credential_store.encrypt("test-only-password"),
    )
    db.session.add(cred)
    db.session.commit()
    return cred


def _guest(vmid_hint=9900, name="mastodon-maint", ip="10.0.0.95", with_credential=True):
    host = ProxmoxHost.query.filter_by(name="pve-maintenance").first()
    if not host:
        host = ProxmoxHost(name="pve-maintenance", hostname="10.0.0.2", host_type="pve")
        db.session.add(host)
        db.session.commit()
    highest = (
        db.session.query(db.func.max(Guest.vmid))
        .filter(Guest.proxmox_host_id == host.id)
        .scalar()
    )
    guest = Guest(
        proxmox_host_id=host.id,
        vmid=max(highest or 0, vmid_hint) + 1,
        name=name,
        guest_type="lxc",
        ip_address=ip,
        credential_id=_credential().id if with_credential else None,
    )
    db.session.add(guest)
    db.session.commit()
    return guest


class _FakeSSH:
    """Context-manager SSH stub returning a canned (stdout, stderr, code)."""

    def __init__(self, stdout="", stderr="", code=0):
        self._result = (stdout, stderr, code)
        self.calls = []

    def execute_sudo(self, cmd, timeout=None):
        self.calls.append(cmd)
        return self._result

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class TestRunMaintenanceSuccess:
    def test_disable_2fa_success(self, app):
        from core.mastodon_maintenance import run_maintenance
        with app.app_context():
            guest = _guest(9900, "mastodon-2fa")
            _settings(mastodon_guest_id=str(guest.id))
            fake = _FakeSSH(stdout="OK\n", code=0)
            with patch("core.mastodon_maintenance.SSHClient") as mock_ssh:
                mock_ssh.from_credential.return_value = fake
                result = run_maintenance("disable_2fa", "alice")

        assert result["ok"] is True
        assert result["message"] == "Disable two-factor authentication applied to @alice"
        assert result["password"] is None
        assert "OK" in result["output"]
        mock_ssh.from_credential.assert_called_once()
        assert "--disable-2fa" in fake.calls[0]

    def test_reset_password_returns_password_and_redacts_output(self, app):
        from core.mastodon_maintenance import run_maintenance
        with app.app_context():
            guest = _guest(9910, "mastodon-pw")
            _settings(mastodon_guest_id=str(guest.id))
            fake = _FakeSSH(stdout="OK\nNew password: test-only-generated-pw\n", code=0)
            with patch("core.mastodon_maintenance.SSHClient") as mock_ssh:
                mock_ssh.from_credential.return_value = fake
                result = run_maintenance("reset_password", "alice")

        assert result["ok"] is True
        assert result["password"] == "test-only-generated-pw"
        assert "[redacted]" in result["output"]
        assert "test-only-generated-pw" not in result["output"]
        assert "test-only-generated-pw" not in result["message"]

    def test_change_email_with_confirm(self, app):
        from core.mastodon_maintenance import run_maintenance
        with app.app_context():
            guest = _guest(9920, "mastodon-email")
            _settings(mastodon_guest_id=str(guest.id))
            fake = _FakeSSH(stdout="OK\n", code=0)
            with patch("core.mastodon_maintenance.SSHClient") as mock_ssh:
                mock_ssh.from_credential.return_value = fake
                result = run_maintenance("change_email", "alice", email="a@b.example", confirm=True)

        assert result["ok"] is True
        assert "--email a@b.example --confirm" in fake.calls[0]


class TestRunMaintenanceFailure:
    def test_non_zero_exit_reports_stderr_without_password(self, app):
        from core.mastodon_maintenance import run_maintenance
        with app.app_context():
            guest = _guest(9930, "mastodon-fail")
            _settings(mastodon_guest_id=str(guest.id))
            fake = _FakeSSH(stdout="", stderr="No such account\n", code=1)
            with patch("core.mastodon_maintenance.SSHClient") as mock_ssh:
                mock_ssh.from_credential.return_value = fake
                result = run_maintenance("disable_2fa", "alice")

        assert result["ok"] is False
        assert result["message"] == "No such account"
        assert result["password"] is None

    def test_non_zero_exit_falls_back_to_exit_code_message(self, app):
        from core.mastodon_maintenance import run_maintenance
        with app.app_context():
            guest = _guest(9940, "mastodon-fail2")
            _settings(mastodon_guest_id=str(guest.id))
            fake = _FakeSSH(stdout="", stderr="", code=1)
            with patch("core.mastodon_maintenance.SSHClient") as mock_ssh:
                mock_ssh.from_credential.return_value = fake
                result = run_maintenance("disable_2fa", "alice")

        assert result["ok"] is False
        assert result["message"] == "tootctl exited with code 1"

    def test_missing_guest_configuration(self, app):
        from core.mastodon_maintenance import run_maintenance
        with app.app_context():
            _settings(mastodon_guest_id="")
            with patch("core.mastodon_maintenance.SSHClient") as mock_ssh:
                result = run_maintenance("disable_2fa", "alice")

        assert result["ok"] is False
        assert result["message"] == "Mastodon app guest is not configured"
        mock_ssh.from_credential.assert_not_called()

    def test_guest_id_pointing_at_nothing(self, app):
        from core.mastodon_maintenance import run_maintenance
        with app.app_context():
            _settings(mastodon_guest_id="999999")
            with patch("core.mastodon_maintenance.SSHClient") as mock_ssh:
                result = run_maintenance("disable_2fa", "alice")

        assert result["ok"] is False
        assert result["message"] == "Mastodon app guest is not configured"
        mock_ssh.from_credential.assert_not_called()

    def test_guest_without_ip_address(self, app):
        from core.mastodon_maintenance import run_maintenance
        with app.app_context():
            guest = _guest(9950, "mastodon-noip", ip=None)
            _settings(mastodon_guest_id=str(guest.id))
            with patch("core.mastodon_maintenance.SSHClient") as mock_ssh:
                result = run_maintenance("disable_2fa", "alice")

        assert result["ok"] is False
        assert result["message"] == "Guest has no IP address"
        mock_ssh.from_credential.assert_not_called()

    def test_guest_without_credential_and_no_default(self, app):
        from core.mastodon_maintenance import run_maintenance
        with app.app_context():
            # Ensure no default credential exists (mirrors test_mastodon_exporter.py).
            Credential.query.filter_by(is_default=True).update({"is_default": False})
            db.session.commit()
            guest = _guest(9960, "mastodon-nocred", with_credential=False)
            _settings(mastodon_guest_id=str(guest.id))
            with patch("core.mastodon_maintenance.SSHClient") as mock_ssh:
                result = run_maintenance("disable_2fa", "alice")

        assert result["ok"] is False
        assert result["message"] == "No SSH credential for the Mastodon guest"
        mock_ssh.from_credential.assert_not_called()

    def test_ssh_exception_never_leaks_raw_text(self, app):
        from core.mastodon_maintenance import run_maintenance
        with app.app_context():
            guest = _guest(9970, "mastodon-sshfail")
            _settings(mastodon_guest_id=str(guest.id))
            with patch("core.mastodon_maintenance.SSHClient") as mock_ssh:
                mock_ssh.from_credential.side_effect = OSError("connection reset by internal-host-10.2.3.4")
                result = run_maintenance("disable_2fa", "alice")

        assert result["ok"] is False
        assert "internal-host" not in result["message"]
        assert result["message"] == "network or I/O error"


class TestMaintenanceSlot:
    def test_slot_is_reentrant_free_after_release(self):
        from core.mastodon_maintenance import maintenance_slot

        with maintenance_slot():
            pass
        # A second, independent use must succeed once the first is released.
        with maintenance_slot():
            pass

    def test_slot_busy_raises(self):
        from core.mastodon_maintenance import MaintenanceBusy, maintenance_slot

        with maintenance_slot():
            with pytest.raises(MaintenanceBusy):
                with maintenance_slot():
                    pass

    def test_try_acquire_and_release(self):
        from core.mastodon_maintenance import release, try_acquire

        assert try_acquire() is True
        try:
            assert try_acquire() is False
        finally:
            release()
        assert try_acquire() is True
        release()


# ---------------------------------------------------------------------------
# Route: POST /moderation/mastodon/accounts/<id>/maintenance
# ---------------------------------------------------------------------------


def _last_audit(app, action):
    from models import AuditLog

    with app.app_context():
        return AuditLog.query.filter_by(action=action).order_by(AuditLog.id.desc()).first()


@pytest.fixture()
def masto_client():
    """Patch the route-level Mastodon Admin API client factory with a MagicMock."""
    client = MagicMock()
    with patch("routes.moderation._get_mastodon_client", return_value=(client, None)):
        yield client


@pytest.fixture()
def moderator_with_maintenance(app):
    """A level-2, non-admin user granted can_moderate + can_maintain_mastodon_accounts
    but NOT can_moderate_staff -- exercises the staff guard independently of the
    can_maintain_mastodon_accounts gate.
    """
    with app.app_context():
        role = Role.query.filter_by(name="_test_mod_with_maintenance").first()
        if role is None:
            role = Role(
                name="_test_mod_with_maintenance",
                display_name="Moderator+Maintenance",
                level=2,
                is_builtin=False,
                can_moderate=True,
                can_maintain_mastodon_accounts=True,
                can_moderate_staff=False,
            )
            db.session.add(role)
            db.session.flush()
        user = User.query.filter_by(username="_test_mod_with_maintenance_user").first()
        if user is None:
            user = User(
                username="_test_mod_with_maintenance_user",
                display_name="Moderator+Maintenance",
                role_id=role.id,
            )
            user.set_password("test-only-ModPlusMaint123!")
            db.session.add(user)
        db.session.commit()
    with app.test_client() as c:
        c.post(
            "/login",
            data={"username": "_test_mod_with_maintenance_user", "password": "test-only-ModPlusMaint123!"},
            follow_redirects=False,
        )
        yield c


class TestMaintenanceRoute:
    def test_moderator_without_flag_is_refused(self, app, moderator_client, masto_client):
        resp = moderator_client.post(
            "/moderation/mastodon/accounts/5/maintenance",
            data={"action": "disable_2fa", "acct": "alice"},
        )
        assert resp.status_code == 403
        assert resp.get_json() == {"ok": False, "error": "Your role may not run account maintenance"}
        masto_client.get_admin_account.assert_not_called()

        entry = _last_audit(app, "mastodon_maintenance_refused")
        assert entry is not None
        assert entry.details == {"account_id": "5", "action": "disable_2fa", "reason": "permission"}

    def test_unknown_action_is_400(self, auth_client, masto_client):
        resp = auth_client.post(
            "/moderation/mastodon/accounts/5/maintenance",
            data={"action": "nuke_from_orbit", "acct": "alice"},
        )
        assert resp.status_code == 400
        masto_client.get_admin_account.assert_not_called()

    def test_remote_target_is_400(self, auth_client, masto_client):
        masto_client.get_admin_account.return_value = {
            "id": "5", "acct": "alice@remote.example", "username": "alice", "domain": "remote.example",
        }
        with patch("routes.moderation.run_maintenance") as mock_run:
            resp = auth_client.post(
                "/moderation/mastodon/accounts/5/maintenance",
                data={"action": "disable_2fa", "acct": "alice@remote.example"},
            )
        assert resp.status_code == 400
        assert "local accounts only" in resp.get_json()["error"]
        mock_run.assert_not_called()

    def test_staff_target_refused_for_moderator_with_maintenance_flag(
        self, app, moderator_with_maintenance, masto_client
    ):
        masto_client.get_admin_account.return_value = {
            "id": "5", "acct": "staffer", "username": "staffer", "domain": None,
            "is_staff": True, "role_name": "Moderator",
        }
        with patch("routes.moderation.run_maintenance") as mock_run:
            resp = moderator_with_maintenance.post(
                "/moderation/mastodon/accounts/5/maintenance",
                data={"action": "disable_2fa", "acct": "staffer"},
            )
        assert resp.status_code == 403
        assert resp.get_json() == {"ok": False, "error": STAFF_TARGET_ERROR}
        mock_run.assert_not_called()

        entry = _last_audit(app, "mastodon_account_action_refused")
        assert entry is not None
        assert entry.resource_name == "staffer"
        assert entry.details["type"] == "maintenance:disable_2fa"

    def test_admin_disable_2fa_success_uses_target_username(self, app, auth_client, masto_client):
        masto_client.get_admin_account.return_value = {
            "id": "5", "acct": "alice", "username": "aliceuser", "domain": None, "is_staff": False,
        }
        with patch("routes.moderation.run_maintenance") as mock_run:
            mock_run.return_value = {
                "ok": True, "message": "Disable two-factor authentication applied to @aliceuser",
                "password": None, "output": "OK",
            }
            resp = auth_client.post(
                "/moderation/mastodon/accounts/5/maintenance",
                data={"action": "disable_2fa", "acct": "alice"},
            )

        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True
        assert body["password"] is None
        mock_run.assert_called_once_with("disable_2fa", "aliceuser", email=None, confirm=False)

        entry = _last_audit(app, "mastodon_maintenance_disable_2fa")
        assert entry is not None
        assert entry.resource_name == "alice"
        assert entry.details == {"account_id": "5", "ok": True, "email_changed": False}
        assert "password" not in entry.details
        assert "email" not in entry.details

    def test_reset_password_success_returns_password_without_leaking_to_audit(self, app, auth_client, masto_client):
        masto_client.get_admin_account.return_value = {
            "id": "5", "acct": "alice", "username": "aliceuser", "domain": None, "is_staff": False,
        }
        with patch("routes.moderation.run_maintenance") as mock_run:
            mock_run.return_value = {
                "ok": True, "message": "Reset password applied to @aliceuser",
                "password": "test-only-newpass99", "output": "OK",
            }
            resp = auth_client.post(
                "/moderation/mastodon/accounts/5/maintenance",
                data={"action": "reset_password", "acct": "alice"},
            )

        assert resp.status_code == 200
        body = resp.get_json()
        assert body["password"] == "test-only-newpass99"

        entry = _last_audit(app, "mastodon_maintenance_reset_password")
        assert "password" not in entry.details
        assert "test-only-newpass99" not in str(entry.details)

    def test_change_email_bad_email_is_400_and_run_maintenance_not_called(self, auth_client, masto_client):
        masto_client.get_admin_account.return_value = {
            "id": "5", "acct": "alice", "username": "aliceuser", "domain": None, "is_staff": False,
        }
        with patch("routes.moderation.run_maintenance") as mock_run:
            resp = auth_client.post(
                "/moderation/mastodon/accounts/5/maintenance",
                data={"action": "change_email", "acct": "alice", "email": "not-an-email"},
            )
        assert resp.status_code == 400
        mock_run.assert_not_called()

    def test_change_email_success_audits_without_email_value(self, app, auth_client, masto_client):
        masto_client.get_admin_account.return_value = {
            "id": "5", "acct": "alice", "username": "aliceuser", "domain": None, "is_staff": False,
        }
        with patch("routes.moderation.run_maintenance") as mock_run:
            mock_run.return_value = {
                "ok": True, "message": "Change email applied to @aliceuser",
                "password": None, "output": "OK",
            }
            resp = auth_client.post(
                "/moderation/mastodon/accounts/5/maintenance",
                data={"action": "change_email", "acct": "alice", "email": "new@example.com", "confirm": "1"},
            )
        assert resp.status_code == 200
        mock_run.assert_called_once_with("change_email", "aliceuser", email="new@example.com", confirm=True)

        entry = _last_audit(app, "mastodon_maintenance_change_email")
        assert entry.details == {"account_id": "5", "ok": True, "email_changed": True}
        assert "new@example.com" not in str(entry.details)

    def test_run_maintenance_failure_is_502(self, app, auth_client, masto_client):
        masto_client.get_admin_account.return_value = {
            "id": "5", "acct": "alice", "username": "aliceuser", "domain": None, "is_staff": False,
        }
        with patch("routes.moderation.run_maintenance") as mock_run:
            mock_run.return_value = {
                "ok": False, "message": "No such account", "password": None, "output": "",
            }
            resp = auth_client.post(
                "/moderation/mastodon/accounts/5/maintenance",
                data={"action": "disable_2fa", "acct": "alice"},
            )
        assert resp.status_code == 502
        assert resp.get_json() == {"ok": False, "error": "No such account"}

        entry = _last_audit(app, "mastodon_maintenance_disable_2fa")
        assert entry.details == {"account_id": "5", "ok": False, "email_changed": False}

    def test_busy_is_409(self, auth_client, masto_client):
        from core.mastodon_maintenance import MaintenanceBusy

        masto_client.get_admin_account.return_value = {
            "id": "5", "acct": "alice", "username": "aliceuser", "domain": None, "is_staff": False,
        }
        with patch("routes.moderation.maintenance_slot") as mock_slot:
            mock_slot.side_effect = MaintenanceBusy("busy")
            resp = auth_client.post(
                "/moderation/mastodon/accounts/5/maintenance",
                data={"action": "disable_2fa", "acct": "alice"},
            )
        assert resp.status_code == 409
        assert resp.get_json() == {"ok": False, "error": "Another maintenance action is running"}
