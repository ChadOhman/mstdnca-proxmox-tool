"""Backup tools for the AI assistant (core/ai_tools.py) and PBS datastores in get_host_status.

- list_backups needs only guest access; manage_backup requires can_manage_guests and is two-phase.
- Archives are proven to belong to the guest before delete/restore/protect (routes/guests._resolve_guest_backup).
- Restore additionally requires confirm_name == guest name, like the web form.
"""
import json
from unittest.mock import patch

from models import AuditLog, Guest, ProxmoxHost, Setting, db
from tests.test_ai_guest_actions import _last_audit, _no_manage_user
from tests.test_ai_live_tools import GIB, _admin, _cleanup, _fake_client, _make_host_and_guest

VOLID = "pbs-store:backup/ct/103/2026-09-01T02:00:00Z"
ARCHIVE = {"volid": VOLID, "ctime": 1_756_692_000, "size": 3 * GIB, "format": "pbs-ct",
           "protected": 1, "notes": "pre-upgrade", "verification": {"state": "ok"}}


class TestToolOffering:

    def test_offering_by_permission(self, app):
        from core.ai_tools import execute_tool, get_tools_for_user
        with app.app_context():
            assert {"list_backups", "manage_backup"} <= {t["name"] for t in get_tools_for_user(_admin())}
            user = _no_manage_user()
            names = {t["name"] for t in get_tools_for_user(user)}
            assert "list_backups" in names and "manage_backup" not in names
            with patch("clients.proxmox_api.ProxmoxClient") as client_cls:
                denied = json.loads(execute_tool(
                    "manage_backup", {"guest_id": 1, "action": "delete", "volid": VOLID, "confirm": True}, user))
            assert "can_manage_guests" in denied["error"]
            client_cls.assert_not_called()


class TestListBackups:

    def test_aggregates_all_storages_without_a_default(self, app):
        from core.ai_tools import execute_tool
        host_id, guest_id = _make_host_and_guest(app)
        fake = _fake_client(find_guest_node="lola", list_all_backups=[dict(ARCHIVE, storage="pbs-store")],
                            list_node_storages=[{"storage": "pbs-store"}, {"storage": "local"}])
        try:
            with app.app_context(), patch("clients.proxmox_api.ProxmoxClient", return_value=fake):
                Setting.set("backup_storage", "")
                result = json.loads(execute_tool("list_backups", {"guest_id": guest_id}, _admin()))
            assert result["count"] == 1
            assert result["backup_storages"] == ["pbs-store", "local"]
            assert result["defaults"] == {"storage": "", "mode": "snapshot", "compress": "zstd"}
            assert result["backups"][0] == {
                "volid": VOLID, "storage": "pbs-store", "created_at": "2025-09-01T02:00:00+00:00",
                "size": "3.0 GiB", "size_bytes": 3 * GIB, "format": "pbs-ct", "protected": True,
                "notes": "pre-upgrade", "verified": "ok",
            }
            fake.list_all_backups.assert_called_once_with("lola", 103)
            fake.list_backups.assert_not_called()
        finally:
            _cleanup(app, host_id, guest_id)

    def test_uses_guest_default_storage(self, app):
        from core.ai_tools import execute_tool
        host_id, guest_id = _make_host_and_guest(app)
        fake = _fake_client(find_guest_node="lola", list_backups=[dict(ARCHIVE)], list_node_storages=[])
        try:
            with app.app_context(), patch("clients.proxmox_api.ProxmoxClient", return_value=fake):
                g = Guest.query.get(guest_id)
                g.backup_storage, g.backup_mode = "pbs-store", "stop"
                db.session.commit()
                result = json.loads(execute_tool("list_backups", {"guest_id": guest_id}, _admin()))
            assert result["defaults"]["storage"] == "pbs-store" and result["defaults"]["mode"] == "stop"
            assert result["backups"][0]["storage"] == "pbs-store"
            fake.list_backups.assert_called_once_with("lola", 103, "pbs-store")
            fake.list_all_backups.assert_not_called()
        finally:
            _cleanup(app, host_id, guest_id)


class TestManageBackupCreate:

    def test_no_storage_configured(self, app):
        from core.ai_tools import execute_tool
        host_id, guest_id = _make_host_and_guest(app)
        try:
            with app.app_context():
                Setting.set("backup_storage", "")
                result = json.loads(execute_tool("manage_backup", {"guest_id": guest_id, "action": "create"}, _admin()))
            assert "No backup storage is configured" in result["error"]
        finally:
            _cleanup(app, host_id, guest_id)

    def test_validation(self, app):
        from core.ai_tools import execute_tool
        host_id, guest_id = _make_host_and_guest(app)
        try:
            with app.app_context():
                bad_mode = json.loads(execute_tool(
                    "manage_backup", {"guest_id": guest_id, "action": "create", "storage": "local", "mode": "warp"},
                    _admin()))
                bad_action = json.loads(execute_tool("manage_backup", {"guest_id": guest_id, "action": "prune"}, _admin()))
                no_volid = json.loads(execute_tool("manage_backup", {"guest_id": guest_id, "action": "delete"}, _admin()))
            assert "Invalid mode" in bad_mode["error"]
            assert "Invalid action" in bad_action["error"]
            assert "volid is required" in no_volid["error"]
        finally:
            _cleanup(app, host_id, guest_id)

    def test_preview_resolves_defaults_without_proxmox(self, app):
        from core.ai_tools import execute_tool
        host_id, guest_id = _make_host_and_guest(app)
        try:
            with app.app_context(), patch("clients.proxmox_api.ProxmoxClient") as client_cls:
                Guest.query.get(guest_id).backup_storage = "pbs-store"
                db.session.commit()
                result = json.loads(execute_tool(
                    "manage_backup", {"guest_id": guest_id, "action": "create", "protected": True}, _admin()))
            client_cls.assert_not_called()
            assert result["status"] == "confirmation_required"
            assert "snapshot backup of 'swizzin' to storage 'pbs-store'" in result["message"]
            assert result["pending_action"] == {
                "tool": "manage_backup", "guest_id": guest_id, "guest": "swizzin", "action": "create",
                "storage": "pbs-store", "mode": "snapshot", "compress": "zstd", "protected": True, "notes": "",
            }
        finally:
            _cleanup(app, host_id, guest_id)

    def test_confirmed_create_runs_and_tracks_task(self, app):
        from core.ai_tools import execute_tool
        host_id, guest_id = _make_host_and_guest(app)
        fake = _fake_client(find_guest_node="lola", create_backup=(True, "UPID:lola:0003:vzdump"))
        try:
            with app.app_context(), patch("clients.proxmox_api.ProxmoxClient", return_value=fake), \
                    patch("routes.api.start_proxmox_job") as start_job:
                result = json.loads(execute_tool(
                    "manage_backup",
                    {"guest_id": guest_id, "action": "create", "storage": "local", "mode": "stop",
                     "compress": "gzip", "notes": "before rebuild", "confirm": True}, _admin()))
                audit = _last_audit("guest_backup_create")
                assert audit.resource_id == guest_id
                assert audit.details == {"storage": "local", "mode": "stop", "via": "ai_assistant"}
                assert start_job.call_args.args[1:] == ("backup", "UPID:lola:0003:vzdump", "lola")
            assert result["success"] is True and result["task"] == "UPID:lola:0003:vzdump"
            fake.create_backup.assert_called_once_with("lola", 103, "local", mode="stop", compress="gzip",
                                                       protected=False, notes="before rebuild")
        finally:
            _cleanup(app, host_id, guest_id)


class TestManageBackupArchives:

    def test_archive_must_belong_to_guest(self, app):
        from core.ai_tools import execute_tool
        host_id, guest_id = _make_host_and_guest(app)
        fake = _fake_client(find_guest_node="lola", list_all_backups=[])
        try:
            with app.app_context(), patch("clients.proxmox_api.ProxmoxClient", return_value=fake):
                Setting.set("backup_storage", "")
                result = json.loads(execute_tool(
                    "manage_backup",
                    {"guest_id": guest_id, "action": "delete", "volid": "local:backup/vzdump-lxc-999.tar.zst",
                     "confirm": True}, _admin()))
            assert "does not belong to this guest" in result["error"]
            fake.delete_backup.assert_not_called()
        finally:
            _cleanup(app, host_id, guest_id)

    def test_confirmed_delete_and_protect(self, app):
        from core.ai_tools import execute_tool
        host_id, guest_id = _make_host_and_guest(app)
        fake = _fake_client(find_guest_node="lola", list_all_backups=[dict(ARCHIVE, storage="pbs-store")],
                            delete_backup=(True, "deleted"), update_backup_protection=(True, "ok"))
        try:
            with app.app_context(), patch("clients.proxmox_api.ProxmoxClient", return_value=fake):
                Setting.set("backup_storage", "")
                unprotect = json.loads(execute_tool(
                    "manage_backup", {"guest_id": guest_id, "action": "unprotect", "volid": VOLID, "confirm": True},
                    _admin()))
                assert _last_audit("guest_backup_protect").details == {
                    "volid": VOLID, "protected": False, "via": "ai_assistant"}
                delete = json.loads(execute_tool(
                    "manage_backup", {"guest_id": guest_id, "action": "delete", "volid": VOLID, "confirm": True},
                    _admin()))
                assert _last_audit("guest_backup_delete").details == {"volid": VOLID, "via": "ai_assistant"}
            assert unprotect == {"success": True, "message": "Backup is now unprotected."}
            assert delete == {"success": True, "message": "Backup deleted."}
            fake.update_backup_protection.assert_called_once_with("lola", "pbs-store", VOLID, False)
            fake.delete_backup.assert_called_once_with("lola", "pbs-store", VOLID)
        finally:
            _cleanup(app, host_id, guest_id)

    def test_restore_requires_typed_guest_name(self, app):
        from core.ai_tools import execute_tool
        host_id, guest_id = _make_host_and_guest(app)
        fake = _fake_client(find_guest_node="lola", list_all_backups=[dict(ARCHIVE, storage="pbs-store")],
                            restore_backup=(True, "UPID:lola:0004:restore"))
        try:
            with app.app_context(), patch("clients.proxmox_api.ProxmoxClient", return_value=fake), \
                    patch("routes.api.start_proxmox_job") as start_job:
                Setting.set("backup_storage", "")
                preview = json.loads(execute_tool(
                    "manage_backup", {"guest_id": guest_id, "action": "restore", "volid": VOLID}, _admin()))
                wrong_name = json.loads(execute_tool(
                    "manage_backup",
                    {"guest_id": guest_id, "action": "restore", "volid": VOLID, "confirm": True,
                     "confirm_name": "swizzin-old"}, _admin()))
                fake.restore_backup.assert_not_called()
                before = AuditLog.query.filter_by(action="guest_backup_restore").count()
                done = json.loads(execute_tool(
                    "manage_backup",
                    {"guest_id": guest_id, "action": "restore", "volid": VOLID, "confirm": True,
                     "confirm_name": "swizzin"}, _admin()))
                assert AuditLog.query.filter_by(action="guest_backup_restore").count() == before + 1
                assert _last_audit("guest_backup_restore").details["storage"] == "pbs-store"
                assert start_job.call_args.args[1:] == ("restore", "UPID:lola:0004:restore", "lola")
            assert preview["status"] == "confirmation_required"
            assert "DESTRUCTIVE" in preview["message"] and '"confirm_name": "swizzin"' in preview["message"]
            assert "confirm_name must exactly match" in wrong_name["error"]
            assert done["success"] is True and done["task"] == "UPID:lola:0004:restore"
            fake.restore_backup.assert_called_once_with("lola", 103, "ct", VOLID, storage="pbs-store")
        finally:
            _cleanup(app, host_id, guest_id)

    def test_proxmox_failure_is_generic(self, app):
        from core.ai_tools import execute_tool
        host_id, guest_id = _make_host_and_guest(app)
        fake = _fake_client(find_guest_node="lola", list_all_backups=[dict(ARCHIVE, storage="pbs-store")],
                            delete_backup=(False, "volume is protected: secret-path"))
        try:
            with app.app_context(), patch("clients.proxmox_api.ProxmoxClient", return_value=fake):
                Setting.set("backup_storage", "")
                result = json.loads(execute_tool(
                    "manage_backup", {"guest_id": guest_id, "action": "delete", "volid": VOLID, "confirm": True},
                    _admin()))
            assert result["success"] is False
            assert "secret-path" not in result["message"]
        finally:
            _cleanup(app, host_id, guest_id)


class TestHostStatusPbsDatastores:

    def test_pbs_host_lists_datastores(self, app):
        from core.ai_tools import execute_tool
        with app.app_context():
            host = ProxmoxHost(name="ai-pbs", hostname="10.0.0.30", host_type="pbs")
            db.session.add(host)
            db.session.commit()
            host_id = host.id
        fake = _fake_client(
            get_node_status={"cpu_usage": 3.0, "cpu_threads": 4, "loadavg": [0.1, 0.1, 0.1],
                             "memory_used": 2 * GIB, "memory_total": 8 * GIB, "swap_used": 0, "swap_total": 0,
                             "rootfs_used": 5 * GIB, "rootfs_total": 20 * GIB, "uptime": 10, "pbsversion": "3.2"},
            get_all_datastores_with_status=[{"name": "main", "used": 600 * GIB, "total": 1000 * GIB, "group_count": 12}],
        )
        try:
            with app.app_context(), patch("clients.pbs_client.PBSClient", return_value=fake):
                result = json.loads(execute_tool("get_host_status", {"host_id": host_id}, _admin()))
            assert result[0]["online"] is True and result[0]["version"] == "3.2"
            assert result[0]["storage"] == [{
                "name": "main", "type": "pbs-datastore", "active": True,
                "used_bytes": 600 * GIB, "total_bytes": 1000 * GIB, "percent": 60.0,
                "human": "600.0 GiB of 1000.0 GiB (60.0%)", "backup_groups": 12,
            }]
        finally:
            with app.app_context():
                db.session.delete(ProxmoxHost.query.get(host_id))
                db.session.commit()
