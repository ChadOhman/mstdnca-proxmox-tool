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


def _token_account_settings(account_id="3", acct="admin"):
    import json
    Setting.set("moderation_mastodon_token_account", json.dumps({"id": account_id, "acct": acct}))


class TestRunStatusAction:
    def test_delete_success_parses_count_and_mentions_report(self, app):
        from core.mastodon_maintenance import run_status_action
        with app.app_context():
            guest = _guest(9980, "mastodon-status-del")
            _settings(mastodon_guest_id=str(guest.id))
            _token_account_settings()
            fake = _FakeSSH(stdout="OK 2\n", code=0)
            with patch("core.mastodon_maintenance.SSHClient") as mock_ssh:
                mock_ssh.from_credential.return_value = fake
                result = run_status_action("delete", ["10", "20"], "9")

        assert result["ok"] is True
        assert result["count"] == 2
        assert "report #9" in result["message"]
        assert "Delete" in result["message"]
        mock_ssh.from_credential.assert_called_once()
        assert "Account.find" not in fake.calls[0]  # the *shell* command, not the script
        assert "bin/rails runner -" in fake.calls[0]

    def test_mark_as_sensitive_success(self, app):
        from core.mastodon_maintenance import run_status_action
        with app.app_context():
            guest = _guest(9981, "mastodon-status-sens")
            _settings(mastodon_guest_id=str(guest.id))
            _token_account_settings()
            fake = _FakeSSH(stdout="OK 1\n", code=0)
            with patch("core.mastodon_maintenance.SSHClient") as mock_ssh:
                mock_ssh.from_credential.return_value = fake
                result = run_status_action("mark_as_sensitive", ["10"], "9")

        assert result["ok"] is True
        assert result["count"] == 1
        assert "Mark as sensitive" in result["message"]

    def test_ruby_exception_on_stderr_is_surfaced(self, app):
        from core.mastodon_maintenance import run_status_action
        with app.app_context():
            guest = _guest(9982, "mastodon-status-err")
            _settings(mastodon_guest_id=str(guest.id))
            _token_account_settings()
            fake = _FakeSSH(stdout="", stderr="RuntimeError: none of the selected statuses belong to this report\n",
                            code=1)
            with patch("core.mastodon_maintenance.SSHClient") as mock_ssh:
                mock_ssh.from_credential.return_value = fake
                result = run_status_action("delete", ["10"], "9")

        assert result["ok"] is False
        assert result["count"] == 0
        assert result["message"] == "RuntimeError: none of the selected statuses belong to this report"

    def test_non_zero_exit_without_output_falls_back_to_exit_code_message(self, app):
        from core.mastodon_maintenance import run_status_action
        with app.app_context():
            guest = _guest(9983, "mastodon-status-noout")
            _settings(mastodon_guest_id=str(guest.id))
            _token_account_settings()
            fake = _FakeSSH(stdout="", stderr="", code=1)
            with patch("core.mastodon_maintenance.SSHClient") as mock_ssh:
                mock_ssh.from_credential.return_value = fake
                result = run_status_action("delete", ["10"], "9")

        assert result["ok"] is False
        assert result["message"] == "rails runner exited with code 1"

    def test_zero_exit_without_ok_marker_is_failure(self, app):
        """A rails runner deprecation warning on stdout without the OK marker must not be
        misread as success.
        """
        from core.mastodon_maintenance import run_status_action
        with app.app_context():
            guest = _guest(9984, "mastodon-status-noOK")
            _settings(mastodon_guest_id=str(guest.id))
            _token_account_settings()
            fake = _FakeSSH(stdout="some warning\n", stderr="", code=0)
            with patch("core.mastodon_maintenance.SSHClient") as mock_ssh:
                mock_ssh.from_credential.return_value = fake
                result = run_status_action("delete", ["10"], "9")

        assert result["ok"] is False
        assert result["count"] == 0

    def test_missing_guest_configuration(self, app):
        from core.mastodon_maintenance import run_status_action
        with app.app_context():
            _settings(mastodon_guest_id="")
            _token_account_settings()
            with patch("core.mastodon_maintenance.SSHClient") as mock_ssh:
                result = run_status_action("delete", ["10"], "9")

        assert result["ok"] is False
        assert result["message"] == "Mastodon app guest is not configured"
        mock_ssh.from_credential.assert_not_called()

    def test_ssh_exception_never_leaks_raw_text(self, app):
        from core.mastodon_maintenance import run_status_action
        with app.app_context():
            guest = _guest(9985, "mastodon-status-sshfail")
            _settings(mastodon_guest_id=str(guest.id))
            _token_account_settings()
            with patch("core.mastodon_maintenance.SSHClient") as mock_ssh:
                mock_ssh.from_credential.side_effect = OSError("connection reset by internal-host-10.2.3.4")
                result = run_status_action("delete", ["10"], "9")

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


# ---------------------------------------------------------------------------
# Route: POST /moderation/mastodon/reports/<id>/statuses/action
# ---------------------------------------------------------------------------

_REPORT_ACTION_VIEWER_PASSWORD = "test-only-ReportActionsViewerPass123!"


@pytest.fixture()
def viewer_client(app):
    """A test client logged in as a low-privilege (viewer, no can_moderate) user."""
    with app.app_context():
        role = Role.query.filter_by(name="viewer").first()
        user = User.query.filter_by(username="_report_action_viewer").first()
        if user is None:
            user = User(username="_report_action_viewer", display_name="Report Action Viewer", role_id=role.id)
            user.set_password(_REPORT_ACTION_VIEWER_PASSWORD)
            db.session.add(user)
            db.session.commit()
    with app.test_client() as c:
        c.post(
            "/login",
            data={"username": "_report_action_viewer", "password": _REPORT_ACTION_VIEWER_PASSWORD},
            follow_redirects=False,
        )
        yield c


def _report(report_id=9, status_ids=("10", "20"), action_taken=False, target=None):
    return {
        "id": report_id,
        "action_taken": action_taken,
        "statuses": [{"id": sid} for sid in status_ids],
        "target_account": target if target is not None else {
            "id": "5", "acct": "alice", "username": "aliceuser", "domain": None, "is_staff": False,
        },
    }


@pytest.fixture()
def report_maintenance_settings(app):
    """Configure the token-account identity and app guest that run_status_action()
    needs before it will even reach the maintenance lock, cleaning both settings
    up afterward so they don't leak into other tests sharing the session-scoped app.
    """
    with app.app_context():
        _token_account_settings()
        Setting.set("mastodon_guest_id", "1")
    yield
    with app.app_context():
        Setting.set("moderation_mastodon_token_account", "")
        Setting.set("mastodon_guest_id", "")


class TestReportStatusesActionRoute:
    def test_unauthenticated_is_redirected_to_login(self, client, masto_client):
        resp = client.post(
            "/moderation/mastodon/reports/9/statuses/action",
            data={"type": "delete", "status_ids": ["10"]},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "/login" in resp.headers.get("Location", "")

    def test_viewer_is_redirected(self, viewer_client, masto_client):
        resp = viewer_client.post(
            "/moderation/mastodon/reports/9/statuses/action",
            data={"type": "delete", "status_ids": ["10"]},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        masto_client.get_report.assert_not_called()

    def test_moderator_allowed_without_maintenance_flag(self, moderator_client, masto_client,
                                                          report_maintenance_settings):
        masto_client.get_report.return_value = _report()
        with patch("routes.moderation.run_status_action") as mock_run:
            mock_run.return_value = {
                "ok": True, "message": "Delete applied to 2 post(s)", "count": 2, "output": "OK 2",
            }
            resp = moderator_client.post(
                "/moderation/mastodon/reports/9/statuses/action",
                data={"type": "delete", "status_ids": ["10", "20"]},
            )
        assert resp.status_code == 200
        assert resp.get_json() == {"ok": True, "message": "Delete applied to 2 post(s)", "count": 2}

    def test_unknown_type_is_400(self, auth_client, masto_client):
        resp = auth_client.post(
            "/moderation/mastodon/reports/9/statuses/action",
            data={"type": "nuke_from_orbit", "status_ids": ["10"]},
        )
        assert resp.status_code == 400
        masto_client.get_report.assert_not_called()

    def test_no_ids_is_400(self, auth_client, masto_client):
        resp = auth_client.post(
            "/moderation/mastodon/reports/9/statuses/action",
            data={"type": "delete"},
        )
        assert resp.status_code == 400
        masto_client.get_report.assert_not_called()

    def test_ids_not_on_report_is_400_and_run_not_called(self, auth_client, masto_client):
        masto_client.get_report.return_value = _report(status_ids=("10", "20"))
        with patch("routes.moderation.run_status_action") as mock_run:
            resp = auth_client.post(
                "/moderation/mastodon/reports/9/statuses/action",
                data={"type": "delete", "status_ids": ["999"]},
            )
        assert resp.status_code == 400
        assert "None of the selected posts" in resp.get_json()["error"]
        mock_run.assert_not_called()

    def test_resolved_report_is_400(self, auth_client, masto_client):
        masto_client.get_report.return_value = _report(action_taken=True)
        with patch("routes.moderation.run_status_action") as mock_run:
            resp = auth_client.post(
                "/moderation/mastodon/reports/9/statuses/action",
                data={"type": "delete", "status_ids": ["10"]},
            )
        assert resp.status_code == 400
        assert "already resolved" in resp.get_json()["error"]
        mock_run.assert_not_called()

    def test_staff_target_refused_for_moderator(self, app, moderator_client, masto_client):
        masto_client.get_report.return_value = _report(target={
            "id": "5", "acct": "staffer", "username": "staffer", "domain": None,
            "is_staff": True, "role_name": "Moderator",
        })
        with patch("routes.moderation.run_status_action") as mock_run:
            resp = moderator_client.post(
                "/moderation/mastodon/reports/9/statuses/action",
                data={"type": "delete", "status_ids": ["10"]},
            )
        assert resp.status_code == 403
        assert resp.get_json() == {"ok": False, "error": STAFF_TARGET_ERROR}
        mock_run.assert_not_called()

        entry = _last_audit(app, "mastodon_account_action_refused")
        assert entry is not None
        assert entry.resource_name == "staffer"
        assert entry.details["type"] == "posts:delete"

    def test_staff_target_ok_for_admin(self, auth_client, masto_client, report_maintenance_settings):
        masto_client.get_report.return_value = _report(target={
            "id": "5", "acct": "staffer", "username": "staffer", "domain": None,
            "is_staff": True, "role_name": "Moderator",
        })
        with patch("routes.moderation.run_status_action") as mock_run:
            mock_run.return_value = {
                "ok": True, "message": "Delete applied to 1 post(s)", "count": 1, "output": "OK 1",
            }
            resp = auth_client.post(
                "/moderation/mastodon/reports/9/statuses/action",
                data={"type": "delete", "status_ids": ["10"]},
            )
        assert resp.status_code == 200
        mock_run.assert_called_once()

    def test_remote_target_forces_send_email_false(self, auth_client, masto_client, report_maintenance_settings):
        masto_client.get_report.return_value = _report(target={
            "id": "5", "acct": "alice@remote.example", "username": "alice", "domain": "remote.example",
            "is_staff": False,
        })
        with patch("routes.moderation.run_status_action") as mock_run:
            mock_run.return_value = {"ok": True, "message": "ok", "count": 2, "output": "OK 2"}
            resp = auth_client.post(
                "/moderation/mastodon/reports/9/statuses/action",
                data={"type": "delete", "status_ids": ["10", "20"], "send_email_notification": "1"},
            )
        assert resp.status_code == 200
        mock_run.assert_called_once_with("delete", ["10", "20"], "9", text="", send_email=False)

    def test_missing_token_account_is_400(self, app, auth_client, masto_client):
        masto_client.get_report.return_value = _report()
        with app.app_context():
            Setting.set("moderation_mastodon_token_account", "")
            Setting.set("mastodon_guest_id", "1")
        with patch("routes.moderation.run_status_action") as mock_run:
            resp = auth_client.post(
                "/moderation/mastodon/reports/9/statuses/action",
                data={"type": "delete", "status_ids": ["10"]},
            )
        assert resp.status_code == 400
        assert "Test Connection" in resp.get_json()["error"]
        mock_run.assert_not_called()

    def test_missing_guest_is_400(self, app, auth_client, masto_client):
        masto_client.get_report.return_value = _report()
        with app.app_context():
            _token_account_settings()
            Setting.set("mastodon_guest_id", "")
        with patch("routes.moderation.run_status_action") as mock_run:
            resp = auth_client.post(
                "/moderation/mastodon/reports/9/statuses/action",
                data={"type": "delete", "status_ids": ["10"]},
            )
        assert resp.status_code == 400
        assert "Configure the Mastodon app guest" in resp.get_json()["error"]
        mock_run.assert_not_called()
        with app.app_context():
            Setting.set("moderation_mastodon_token_account", "")

    def test_busy_is_409(self, auth_client, masto_client, report_maintenance_settings):
        from core.mastodon_maintenance import MaintenanceBusy

        masto_client.get_report.return_value = _report()
        with patch("routes.moderation.maintenance_slot") as mock_slot:
            mock_slot.side_effect = MaintenanceBusy("busy")
            resp = auth_client.post(
                "/moderation/mastodon/reports/9/statuses/action",
                data={"type": "delete", "status_ids": ["10"]},
            )
        assert resp.status_code == 409
        assert resp.get_json() == {"ok": False, "error": "Another server-side action is running"}

    def test_ok_result_audits_without_text_content(self, app, auth_client, masto_client,
                                                     report_maintenance_settings):
        masto_client.get_report.return_value = _report()
        with patch("routes.moderation.run_status_action") as mock_run:
            mock_run.return_value = {
                "ok": True, "message": "Delete applied to 2 post(s)", "count": 2, "output": "OK 2",
            }
            resp = auth_client.post(
                "/moderation/mastodon/reports/9/statuses/action",
                data={"type": "delete", "status_ids": ["10", "20"], "text": "spam content here"},
            )
        assert resp.status_code == 200
        assert resp.get_json() == {"ok": True, "message": "Delete applied to 2 post(s)", "count": 2}

        entry = _last_audit(app, "mastodon_report_posts_delete")
        assert entry is not None
        assert entry.resource_name == "report 9"
        assert entry.details == {
            "report_id": "9", "status_count": 2, "acted": 2, "ok": True,
            "target": "alice", "text_len": len("spam content here"), "email": False,
        }
        assert "spam content here" not in str(entry.details)

    def test_ok_false_result_is_502(self, auth_client, masto_client, report_maintenance_settings):
        masto_client.get_report.return_value = _report()
        with patch("routes.moderation.run_status_action") as mock_run:
            mock_run.return_value = {"ok": False, "message": "RuntimeError: boom", "count": 0, "output": ""}
            resp = auth_client.post(
                "/moderation/mastodon/reports/9/statuses/action",
                data={"type": "delete", "status_ids": ["10"]},
            )
        assert resp.status_code == 502
        assert resp.get_json() == {"ok": False, "error": "RuntimeError: boom"}

    def test_mark_as_sensitive_audits_correct_action(self, app, auth_client, masto_client,
                                                       report_maintenance_settings):
        masto_client.get_report.return_value = _report()
        with patch("routes.moderation.run_status_action") as mock_run:
            mock_run.return_value = {
                "ok": True, "message": "Mark as sensitive applied to 2 post(s)", "count": 2, "output": "OK 2",
            }
            resp = auth_client.post(
                "/moderation/mastodon/reports/9/statuses/action",
                data={"type": "mark_as_sensitive", "status_ids": ["10", "20"]},
            )
        assert resp.status_code == 200
        entry = _last_audit(app, "mastodon_report_posts_mark_as_sensitive")
        assert entry is not None
        assert entry.details["ok"] is True
