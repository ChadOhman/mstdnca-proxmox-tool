"""Power control and snapshot tools for the AI assistant (core/ai_tools.py).

- control_guest_power / manage_snapshot require can_manage_guests and are two-phase
  (preview without confirm, execute with confirm), mirroring routes/guests.py.
- list_snapshots needs only guest access.
"""
import json
import re
from unittest.mock import patch

from models import AuditLog, Guest, Role, User, db
from tests.test_ai_live_tools import _admin, _cleanup, _fake_client, _make_host_and_guest


def _no_manage_user():
    """A can_use_ai user without can_manage_guests (execute_tool must refuse before the handler)."""
    role = Role.query.filter_by(name="_ai_no_manage").first()
    if not role:
        role = Role(name="_ai_no_manage", display_name="AI no-manage", level=3, is_builtin=False,
                    can_use_ai=True, can_view_guests=True, can_manage_guests=False)
        db.session.add(role)
        db.session.commit()
    user = User.query.filter_by(username="_ai_no_manage").first()
    if not user:
        user = User(username="_ai_no_manage", display_name="AI no-manage", role_id=role.id)
        user.set_password("test-only-dummy")
        db.session.add(user)
        db.session.commit()
    return User.query.options(db.joinedload(User.role_obj)).get(user.id)


def _last_audit(action):
    return AuditLog.query.filter_by(action=action).order_by(AuditLog.id.desc()).first()


class TestToolOffering:

    def test_admin_offered_all_three(self, app):
        from core.ai_tools import get_tools_for_user
        with app.app_context():
            names = {t["name"] for t in get_tools_for_user(_admin())}
        assert {"control_guest_power", "list_snapshots", "manage_snapshot"} <= names

    def test_user_without_manage_guests_only_lists(self, app):
        from core.ai_tools import execute_tool, get_tools_for_user
        with app.app_context():
            user = _no_manage_user()
            names = {t["name"] for t in get_tools_for_user(user)}
            assert "list_snapshots" in names
            assert "control_guest_power" not in names
            assert "manage_snapshot" not in names
            with patch("clients.proxmox_api.ProxmoxClient") as client_cls:
                power = json.loads(execute_tool(
                    "control_guest_power", {"guest_id": 1, "action": "start", "confirm": True}, user))
                snap = json.loads(execute_tool(
                    "manage_snapshot", {"guest_id": 1, "action": "delete", "snapname": "x", "confirm": True}, user))
            assert "can_manage_guests" in power["error"]
            assert "can_manage_guests" in snap["error"]
            client_cls.assert_not_called()


class TestControlGuestPower:

    def test_invalid_action(self, app):
        from core.ai_tools import execute_tool
        with app.app_context():
            result = json.loads(execute_tool("control_guest_power", {"guest_id": 1, "action": "explode"}, _admin()))
        assert "Invalid action" in result["error"]

    def test_preview_does_not_touch_proxmox(self, app):
        from core.ai_tools import execute_tool
        host_id, guest_id = _make_host_and_guest(app)
        try:
            with app.app_context():
                Guest.query.get(guest_id).lock_reason = "backup"
                db.session.commit()
                with patch("clients.proxmox_api.ProxmoxClient") as client_cls:
                    result = json.loads(execute_tool(
                        "control_guest_power", {"guest_id": guest_id, "action": "stop"}, _admin()))
                client_cls.assert_not_called()
                assert Guest.query.get(guest_id).power_state == "running"
            assert result["status"] == "confirmation_required"
            assert "currently running" in result["message"]
            assert "locked (backup)" in result["message"]
            assert "hard power-off" in result["message"]
            assert result["pending_action"] == {
                "tool": "control_guest_power", "guest_id": guest_id, "guest": "swizzin",
                "action": "stop", "current_power_state": "running",
            }
        finally:
            _cleanup(app, host_id, guest_id)

    def test_confirmed_shutdown_runs_once_and_is_audited(self, app):
        from core.ai_tools import execute_tool
        host_id, guest_id = _make_host_and_guest(app)
        fake = _fake_client(find_guest_node="lola", shutdown_guest=(True, "Shutdown command sent"))
        try:
            with app.app_context(), patch("clients.proxmox_api.ProxmoxClient", return_value=fake):
                result = json.loads(execute_tool(
                    "control_guest_power", {"guest_id": guest_id, "action": "shutdown", "confirm": True}, _admin()))
                assert Guest.query.get(guest_id).power_state == "stopped"
                audit = _last_audit("guest_power")
                assert audit.resource_id == guest_id
                assert audit.details["action"] == "shutdown"
                assert audit.details["via"] == "ai_assistant"
            assert result == {"success": True, "message": "Shutdown command sent to swizzin."}
            fake.shutdown_guest.assert_called_once_with("lola", 103, "ct")
            fake.start_guest.assert_not_called()
        finally:
            _cleanup(app, host_id, guest_id)

    def test_reboot_clears_reboot_required_and_falls_back_to_host_node(self, app):
        from core.ai_tools import execute_tool
        host_id, guest_id = _make_host_and_guest(app)
        fake = _fake_client(find_guest_node=None, reboot_guest=(True, "ok"))
        try:
            with app.app_context(), patch("clients.proxmox_api.ProxmoxClient", return_value=fake):
                Guest.query.get(guest_id).reboot_required = True
                db.session.commit()
                result = json.loads(execute_tool(
                    "control_guest_power", {"guest_id": guest_id, "action": "reboot", "confirm": True}, _admin()))
                assert Guest.query.get(guest_id).reboot_required is False
            assert result["success"] is True
            fake.reboot_guest.assert_called_once_with("ai-live-host", 103, "ct")
        finally:
            _cleanup(app, host_id, guest_id)

    def test_proxmox_failure_is_generic_and_not_audited(self, app):
        from core.ai_tools import execute_tool
        host_id, guest_id = _make_host_and_guest(app)
        fake = _fake_client(find_guest_node="lola", start_guest=(False, "500 Internal Server Error: token xyz"))
        try:
            with app.app_context(), patch("clients.proxmox_api.ProxmoxClient", return_value=fake):
                before = AuditLog.query.filter_by(action="guest_power").count()
                result = json.loads(execute_tool(
                    "control_guest_power", {"guest_id": guest_id, "action": "start", "confirm": True}, _admin()))
                assert AuditLog.query.filter_by(action="guest_power").count() == before
            assert result["success"] is False
            assert "token xyz" not in result["message"]
            assert "rejected the start command" in result["message"]
        finally:
            _cleanup(app, host_id, guest_id)


class TestListSnapshots:

    def test_lists_snapshots_with_timestamps(self, app):
        from core.ai_tools import execute_tool
        host_id, guest_id = _make_host_and_guest(app)
        fake = _fake_client(find_guest_node="lola", guest_supports_snapshot=True, list_snapshots=[
            {"name": "pre-upgrade", "description": "before 4.3", "snaptime": 1_700_000_000, "vmstate": 1},
            {"name": "manual-20260901-120000", "parent": "pre-upgrade"},
        ])
        try:
            with app.app_context(), patch("clients.proxmox_api.ProxmoxClient", return_value=fake):
                result = json.loads(execute_tool("list_snapshots", {"guest_id": guest_id}, _admin()))
            assert result["count"] == 2
            assert result["snapshots_supported"] is True
            assert result["snapshots"][0] == {
                "name": "pre-upgrade", "description": "before 4.3",
                "created_at": "2023-11-14T22:13:20+00:00", "parent": None, "includes_ram": True,
            }
            assert result["snapshots"][1]["created_at"] is None
            assert result["snapshots"][1]["parent"] == "pre-upgrade"
            fake.list_snapshots.assert_called_once_with("lola", 103, "ct")
        finally:
            _cleanup(app, host_id, guest_id)


class TestManageSnapshot:

    def test_name_validation(self, app):
        from core.ai_tools import execute_tool
        host_id, guest_id = _make_host_and_guest(app)
        try:
            with app.app_context():
                bad = json.loads(execute_tool(
                    "manage_snapshot", {"guest_id": guest_id, "action": "create", "snapname": "../etc"}, _admin()))
                missing = json.loads(execute_tool(
                    "manage_snapshot", {"guest_id": guest_id, "action": "delete"}, _admin()))
            assert "Invalid snapshot name" in bad["error"]
            assert missing["error"] == "snapname is required"
        finally:
            _cleanup(app, host_id, guest_id)

    def test_rollback_preview_warns_and_does_nothing(self, app):
        from core.ai_tools import execute_tool
        host_id, guest_id = _make_host_and_guest(app)
        try:
            with app.app_context(), patch("clients.proxmox_api.ProxmoxClient") as client_cls:
                result = json.loads(execute_tool(
                    "manage_snapshot", {"guest_id": guest_id, "action": "rollback", "snapname": "pre-upgrade"},
                    _admin()))
            client_cls.assert_not_called()
            assert result["status"] == "confirmation_required"
            assert "cannot be undone" in result["message"]
            assert result["pending_action"] == {
                "tool": "manage_snapshot", "guest_id": guest_id, "guest": "swizzin",
                "action": "rollback", "snapname": "pre-upgrade",
            }
        finally:
            _cleanup(app, host_id, guest_id)

    def test_confirmed_create_defaults_name_and_tracks_task(self, app):
        from core.ai_tools import execute_tool
        host_id, guest_id = _make_host_and_guest(app)
        fake = _fake_client(find_guest_node="lola", guest_supports_snapshot=True,
                            create_snapshot=(True, "UPID:lola:0001:snapshot"))
        try:
            with app.app_context(), patch("clients.proxmox_api.ProxmoxClient", return_value=fake), \
                    patch("routes.api.start_proxmox_job") as start_job:
                result = json.loads(execute_tool(
                    "manage_snapshot",
                    {"guest_id": guest_id, "action": "create", "description": "via chat", "confirm": True},
                    _admin()))
                audit = _last_audit("guest_snapshot_create")
                assert audit.resource_id == guest_id and audit.details["via"] == "ai_assistant"
                snapname = audit.details["snapname"]
                start_job.assert_called_once()
                job_guest, job_type, upid, node = start_job.call_args.args
                assert (job_guest.id, job_type, upid, node) == (guest_id, "snapshot", "UPID:lola:0001:snapshot", "lola")
            assert re.fullmatch(r"manual-\d{8}-\d{6}", snapname)
            assert result["success"] is True and result["task"] == "UPID:lola:0001:snapshot"
            fake.create_snapshot.assert_called_once_with("lola", 103, "ct", snapname, "via chat")
        finally:
            _cleanup(app, host_id, guest_id)

    def test_confirmed_delete_uses_delete_job_type(self, app):
        from core.ai_tools import execute_tool
        host_id, guest_id = _make_host_and_guest(app)
        fake = _fake_client(find_guest_node="lola", delete_snapshot=(True, "UPID:lola:0002:delete"))
        try:
            with app.app_context(), patch("clients.proxmox_api.ProxmoxClient", return_value=fake), \
                    patch("routes.api.start_proxmox_job") as start_job:
                result = json.loads(execute_tool(
                    "manage_snapshot",
                    {"guest_id": guest_id, "action": "delete", "snapname": "pre-upgrade", "confirm": True},
                    _admin()))
                assert _last_audit("guest_snapshot_delete").details["snapname"] == "pre-upgrade"
                assert start_job.call_args.args[1] == "snapshot_delete"
            assert result["success"] is True
            fake.delete_snapshot.assert_called_once_with("lola", 103, "ct", "pre-upgrade")
            fake.create_snapshot.assert_not_called()
        finally:
            _cleanup(app, host_id, guest_id)

    def test_unsupported_storage_and_proxmox_failure(self, app):
        from core.ai_tools import execute_tool
        host_id, guest_id = _make_host_and_guest(app)
        unsupported = _fake_client(find_guest_node="lola", guest_supports_snapshot=False)
        failing = _fake_client(find_guest_node="lola", rollback_snapshot=(False, "snapshot 'x' does not exist"))
        try:
            with app.app_context():
                with patch("clients.proxmox_api.ProxmoxClient", return_value=unsupported), \
                        patch("routes.api.start_proxmox_job") as start_job:
                    no_snap = json.loads(execute_tool(
                        "manage_snapshot", {"guest_id": guest_id, "action": "create", "confirm": True}, _admin()))
                with patch("clients.proxmox_api.ProxmoxClient", return_value=failing):
                    failed = json.loads(execute_tool(
                        "manage_snapshot",
                        {"guest_id": guest_id, "action": "rollback", "snapname": "x", "confirm": True}, _admin()))
            assert "does not support snapshots" in no_snap["error"]
            unsupported.create_snapshot.assert_not_called()
            start_job.assert_not_called()
            assert failed["success"] is False
            assert "does not exist" not in failed["message"]
        finally:
            _cleanup(app, host_id, guest_id)
