"""Node apt update tools for the AI assistant (core/ai_tools.py), mirroring routes/hosts.py.

- get_host_updates: live apt list (can_view_hosts), last-scan fallback, apply-job state.
- manage_host_updates: refresh (no confirm), apply (two-phase, SSH job), cancel (can_manage_hosts).
"""
import json
from unittest.mock import MagicMock, patch

from models import AuditLog, Credential, HostUpdatePackage, ProxmoxHost, Role, User, db
from tests.test_ai_live_tools import _admin

APT = [
    {"Package": "pve-kernel-6.8", "Title": "Proxmox kernel", "OldVersion": "6.8.4-2", "Version": "6.8.8-1",
     "Priority": "important"},
    {"Package": "curl", "Title": "command line tool", "OldVersion": "7.88.1-10", "Version": "7.88.1-11",
     "Priority": "optional"},
]


def _make_host(app, host_type="pve", with_ssh=False):
    with app.app_context():
        host = ProxmoxHost(name="ai-apt-host", hostname="10.0.0.26", host_type=host_type)
        if with_ssh:
            cred = Credential(name="ai-apt-cred", username="root", auth_type="password",
                              encrypted_value="test-only-encrypted")
            db.session.add(cred)
            db.session.flush()
            host.ssh_credential_id = cred.id
        db.session.add(host)
        db.session.commit()
        return host.id


def _cleanup(app, host_id):
    from routes.hosts import _apply_jobs, _apply_lock
    with _apply_lock:
        _apply_jobs.pop(host_id, None)
    with app.app_context():
        host = ProxmoxHost.query.get(host_id)
        cred_id = host.ssh_credential_id if host else None
        if host:
            db.session.delete(host)
        if cred_id:
            cred = Credential.query.get(cred_id)
            if cred:
                db.session.delete(cred)
        db.session.commit()


def _view_only_user():
    role = Role.query.filter_by(name="_ai_host_viewer").first()
    if not role:
        role = Role(name="_ai_host_viewer", display_name="AI host viewer", level=3, is_builtin=False,
                    can_use_ai=True, can_view_hosts=True, can_manage_hosts=False)
        db.session.add(role)
        db.session.commit()
    user = User.query.filter_by(username="_ai_host_viewer").first()
    if not user:
        user = User(username="_ai_host_viewer", display_name="AI host viewer", role_id=role.id)
        user.set_password("test-only-dummy")
        db.session.add(user)
        db.session.commit()
    return User.query.options(db.joinedload(User.role_obj)).get(user.id)


def _last_audit(action):
    return AuditLog.query.filter_by(action=action).order_by(AuditLog.id.desc()).first()


class TestOffering:

    def test_view_only_user_gets_read_tool_only(self, app):
        from core.ai_tools import execute_tool, get_tools_for_user
        with app.app_context():
            assert {"get_host_updates", "manage_host_updates"} <= {t["name"] for t in get_tools_for_user(_admin())}
            user = _view_only_user()
            names = {t["name"] for t in get_tools_for_user(user)}
            assert "get_host_updates" in names and "manage_host_updates" not in names
            denied = json.loads(execute_tool("manage_host_updates", {"host_id": 1, "action": "refresh"}, user))
            assert "can_manage_hosts" in denied["error"]


class TestGetHostUpdates:

    def test_unknown_host(self, app):
        from core.ai_tools import execute_tool
        with app.app_context():
            result = json.loads(execute_tool("get_host_updates", {"host_id": 999999}, _admin()))
        assert result == {"error": "Host not found"}

    def test_live_list_with_severity(self, app):
        from core.ai_tools import execute_tool
        host_id = _make_host(app)
        fake = MagicMock()
        fake.get_apt_updates.return_value = [dict(u) for u in APT]
        try:
            with app.app_context(), patch("routes.hosts._get_client_and_node", return_value=(fake, "lola")):
                result = json.loads(execute_tool("get_host_updates", {"host_id": host_id}, _admin()))
            assert result["source"] == "live" and result["node"] == "lola"
            assert result["count"] == 2 and result["security_count"] == 1
            assert result["packages"][0] == {"package": "pve-kernel-6.8", "title": "Proxmox kernel",
                                             "current": "6.8.4-2", "available": "6.8.8-1", "severity": "critical"}
            assert result["packages"][1]["severity"] == "normal"
            assert "apply_job" not in result
            fake.get_apt_updates.assert_called_once_with("lola")
        finally:
            _cleanup(app, host_id)

    def test_pbs_host_queries_without_node(self, app):
        from core.ai_tools import execute_tool
        host_id = _make_host(app, host_type="pbs")
        fake = MagicMock()
        fake.get_apt_updates.return_value = []
        try:
            with app.app_context(), patch("routes.hosts._get_client_and_node", return_value=(fake, "pbs1")):
                result = json.loads(execute_tool("get_host_updates", {"host_id": host_id}, _admin()))
            assert result["count"] == 0 and result["type"] == "pbs"
            fake.get_apt_updates.assert_called_once_with()
        finally:
            _cleanup(app, host_id)

    def test_falls_back_to_last_scan_and_reports_job(self, app):
        from core.ai_tools import execute_tool
        from routes.hosts import _apply_jobs, _apply_lock
        host_id = _make_host(app)
        try:
            with app.app_context():
                db.session.add(HostUpdatePackage(host_id=host_id, package_name="openssl", current_version="3.0.11",
                                                 available_version="3.0.15", severity="critical", status="pending"))
                db.session.add(HostUpdatePackage(host_id=host_id, package_name="old", current_version="1",
                                                 available_version="2", severity="normal", status="applied"))
                db.session.commit()
                with _apply_lock:
                    _apply_jobs[host_id] = {"log": ["Reading package lists...\n", "Done\n"], "running": False,
                                            "success": True, "cancelled": False}
                with patch("routes.hosts._get_client_and_node", side_effect=RuntimeError("timeout")):
                    result = json.loads(execute_tool("get_host_updates", {"host_id": host_id}, _admin()))
            assert result["source"] == "last_scan" and "last scheduled scan" in result["note"]
            assert result["count"] == 1 and result["security_count"] == 1
            assert result["packages"][0]["package"] == "openssl"
            assert result["apply_job"] == {"running": False, "success": True, "cancelled": False,
                                           "log_tail": "Reading package lists...\nDone\n"}
        finally:
            _cleanup(app, host_id)


class TestManageHostUpdates:

    def test_refresh_runs_immediately_and_is_audited(self, app):
        from core.ai_tools import execute_tool
        host_id = _make_host(app)
        fake = MagicMock()
        fake.refresh_apt_cache.return_value = "UPID:lola:0005:aptupdate"
        try:
            with app.app_context(), patch("routes.hosts._get_client_and_node", return_value=(fake, "lola")):
                result = json.loads(execute_tool("manage_host_updates", {"host_id": host_id, "action": "refresh"}, _admin()))
                assert _last_audit("host_refresh_updates").details == {"via": "ai_assistant"}
            assert result["success"] is True and result["task"] == "UPID:lola:0005:aptupdate"
            fake.refresh_apt_cache.assert_called_once_with("lola")
        finally:
            _cleanup(app, host_id)

    def test_apply_needs_ssh_credential(self, app):
        from core.ai_tools import execute_tool
        host_id = _make_host(app, with_ssh=False)
        try:
            with app.app_context():
                result = json.loads(execute_tool(
                    "manage_host_updates", {"host_id": host_id, "action": "apply", "confirm": True}, _admin()))
            assert "No SSH credential" in result["error"]
        finally:
            _cleanup(app, host_id)

    def test_apply_preview_then_confirmed_start(self, app):
        from core.ai_tools import execute_tool
        from routes.hosts import _apply_jobs
        host_id = _make_host(app, with_ssh=True)
        try:
            with app.app_context():
                db.session.add(HostUpdatePackage(host_id=host_id, package_name="pve-kernel", current_version="a",
                                                 available_version="b", severity="critical", status="pending"))
                db.session.commit()
                with patch("routes.hosts._threading.Thread") as thread_cls:
                    preview = json.loads(execute_tool(
                        "manage_host_updates", {"host_id": host_id, "action": "apply"}, _admin()))
                    thread_cls.assert_not_called()
                    assert host_id not in _apply_jobs
                    started = json.loads(execute_tool(
                        "manage_host_updates", {"host_id": host_id, "action": "apply", "confirm": True}, _admin()))
                    thread_cls.assert_called_once()
                    thread_cls.return_value.start.assert_called_once()
                    again = json.loads(execute_tool(
                        "manage_host_updates", {"host_id": host_id, "action": "apply", "confirm": True}, _admin()))
                assert _apply_jobs[host_id]["running"] is True
                assert _last_audit("host_apply_updates").details == {"via": "ai_assistant"}
            assert preview["status"] == "confirmation_required"
            assert "1 package(s) pending" in preview["message"] and "1 security" in preview["message"]
            assert "dist-upgrade" in preview["message"]
            assert preview["pending_action"] == {"tool": "manage_host_updates", "host_id": host_id,
                                                 "host": "ai-apt-host", "action": "apply"}
            assert started["success"] is True
            assert "already running" in again["error"]
        finally:
            _cleanup(app, host_id)

    def test_cancel_flags_running_job(self, app):
        from core.ai_tools import execute_tool
        from routes.hosts import _apply_jobs, _apply_lock
        host_id = _make_host(app)
        try:
            with app.app_context():
                idle = json.loads(execute_tool("manage_host_updates", {"host_id": host_id, "action": "cancel"}, _admin()))
                with _apply_lock:
                    _apply_jobs[host_id] = {"log": [], "running": True, "success": None, "cancelled": False}
                done = json.loads(execute_tool("manage_host_updates", {"host_id": host_id, "action": "cancel"}, _admin()))
                assert _apply_jobs[host_id]["cancelled"] is True
                assert _last_audit("host_apply_updates_cancel").resource_id == host_id
            assert idle["success"] is False
            assert done["success"] is True
        finally:
            _cleanup(app, host_id)
