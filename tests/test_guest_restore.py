"""Tests for the restore-from-backup workflow (routes/guests.py)."""
from unittest.mock import MagicMock, patch

import pytest

from models import AuditLog, Guest, ProxmoxHost, Role, User, db


def _login(client, username, password):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )


@pytest.fixture()
def restore_guest(app):
    """Seed a guest linked to a Proxmox host; clean up after."""
    with app.app_context():
        host = ProxmoxHost(name="test-only-restore-node", hostname="test-only-restore.local", host_type="pve")
        db.session.add(host)
        db.session.flush()
        guest = Guest(
            name="_restore-target",
            guest_type="ct",
            vmid=140,
            proxmox_host_id=host.id,
        )
        db.session.add(guest)
        db.session.commit()
        gid = guest.id
        hid = host.id

    yield gid

    with app.app_context():
        g = Guest.query.get(gid)
        if g:
            db.session.delete(g)
        h = ProxmoxHost.query.get(hid)
        if h:
            db.session.delete(h)
        db.session.commit()


class TestBackupListing:
    """The guest detail page lists backups annotated with their storage."""

    @patch("routes.guests.ProxmoxClient")
    def test_detail_lists_backups(self, mock_client_cls, app, auth_client, restore_guest):
        gid = restore_guest
        mock = MagicMock()
        mock.find_guest_node.return_value = "pve1"
        mock.get_replication_jobs.return_value = []
        mock.get_nodes.return_value = [{"node": "pve1"}]
        mock.list_snapshots.return_value = []
        mock.list_node_storages.return_value = [{"storage": "pbs-prod", "content": "backup"}]
        mock.get_guest_config.return_value = {
            "type": "ct", "cores": 1, "sockets": 1, "vcpus": 1, "cpu_type": "",
            "memory_mb": 512, "swap_mb": 0, "balloon": None, "disks": [],
        }
        mock.list_all_backups.return_value = [
            {"volid": "pbs-prod:backup/ct/140/2026-07-01", "size": 2147483648,
             "ctime": 1719800000, "storage": "pbs-prod"},
        ]
        mock_client_cls.return_value = mock

        resp = auth_client.get(f"/guests/{gid}")
        assert resp.status_code == 200
        assert b"pbs-prod:backup/ct/140/2026-07-01" in resp.data or b"backup/ct/140" in resp.data
        # Restore action link is rendered
        assert f"/guests/{gid}/backup".encode() in resp.data
        mock.list_all_backups.assert_called_once_with("pve1", 140)


class TestRestorePermission:
    """Restore requires can_manage_guests; a read-only viewer is denied."""

    @patch("routes.guests.ProxmoxClient")
    def test_restore_denied_for_viewer(self, mock_client_cls, app, client, restore_guest):
        gid = restore_guest
        with app.app_context():
            viewer_role = Role.query.filter_by(name="viewer").first()
            assert viewer_role.can_manage_guests is False  # guard
            user = User(username="restore_viewer", display_name="Restore Viewer", role_id=viewer_role.id)
            user.set_password("ViewerPass123!")
            db.session.add(user)
            db.session.commit()

        _login(client, "restore_viewer", "ViewerPass123!")
        volid = "pbs-prod:backup/ct/140/2026-07-01"
        resp = client.post(
            f"/guests/{gid}/backup/{volid}/restore",
            data={"confirm_name": "_restore-target"},
            follow_redirects=False,
        )
        # Redirected without dispatching a restore
        assert resp.status_code == 302
        mock_client_cls.assert_not_called()

        with app.app_context():
            User.query.filter_by(username="restore_viewer").delete()
            db.session.commit()


class TestRestoreConfirmation:
    """Restore requires the confirmation text to equal the guest name."""

    @patch("routes.api.start_proxmox_job")
    @patch("routes.guests.ProxmoxClient")
    def test_wrong_confirm_text_blocks_restore(self, mock_client_cls, mock_job, app, auth_client, restore_guest):
        gid = restore_guest
        volid = "pbs-prod:backup/ct/140/2026-07-01"
        resp = auth_client.post(
            f"/guests/{gid}/backup/{volid}/restore",
            data={"confirm_name": "wrong-name"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "/restore" in resp.headers["Location"]  # bounced back to confirm page
        # No API call, no job dispatched
        mock_client_cls.assert_not_called()
        mock_job.assert_not_called()

    def test_confirm_page_renders(self, auth_client, restore_guest):
        gid = restore_guest
        volid = "pbs-prod:backup/ct/140/2026-07-01"
        resp = auth_client.get(f"/guests/{gid}/backup/{volid}/restore")
        assert resp.status_code == 200
        assert b"_restore-target" in resp.data
        assert b"confirm_name" in resp.data


class TestRestoreSuccess:
    """Correct confirmation dispatches the restore, audit-logs, and wires task progress."""

    @patch("routes.api.start_proxmox_job")
    @patch("routes.guests.ProxmoxClient")
    def test_restore_dispatches_and_logs(self, mock_client_cls, mock_job, app, auth_client, restore_guest):
        gid = restore_guest
        mock = MagicMock()
        mock.find_guest_node.return_value = "pve1"
        mock.restore_backup.return_value = (True, "UPID:pve1:restore:1234")
        mock_client_cls.return_value = mock

        volid = "pbs-prod:backup/ct/140/2026-07-01"
        resp = auth_client.post(
            f"/guests/{gid}/backup/{volid}/restore",
            data={"confirm_name": "_restore-target"},
            follow_redirects=False,
        )
        # Redirects to the task-progress page for the restore job
        assert resp.status_code == 302
        assert "/task/" in resp.headers["Location"]
        assert "restore" in resp.headers["Location"]

        # API call used the guest's type/vmid/archive
        mock.restore_backup.assert_called_once()
        args, kwargs = mock.restore_backup.call_args
        assert args[0] == "pve1"
        assert args[1] == 140
        assert args[2] == "ct"
        assert args[3] == volid
        assert kwargs.get("storage") == "pbs-prod"

        # Task progress wiring
        mock_job.assert_called_once()
        job_args = mock_job.call_args[0]
        assert job_args[1] == "restore"
        assert job_args[2] == "UPID:pve1:restore:1234"
        assert job_args[3] == "pve1"

        # Audit log recorded with archive + guest
        with app.app_context():
            log = (AuditLog.query
                   .filter_by(action="guest_backup_restore", resource_type="guest", resource_id=gid)
                   .order_by(AuditLog.id.desc()).first())
            assert log is not None
            assert log.details is not None
            assert log.details.get("volid") == volid
            assert log.details.get("storage") == "pbs-prod"


class TestRestoreClient:
    """Unit tests for the ProxmoxClient restore/list methods."""

    def test_restore_backup_qemu_params(self):
        from clients.proxmox_api import ProxmoxClient
        client = ProxmoxClient.__new__(ProxmoxClient)
        api = MagicMock()
        api.nodes.return_value.qemu.post.return_value = "UPID:qemu"
        client._api = api

        ok, upid = client.restore_backup("pve1", 100, "vm", "pbs:backup/vm/100/x", storage="local-lvm")
        assert ok is True
        assert upid == "UPID:qemu"
        api.nodes.return_value.qemu.post.assert_called_once_with(
            vmid=100, archive="pbs:backup/vm/100/x", force=1, storage="local-lvm"
        )

    def test_restore_backup_lxc_params(self):
        from clients.proxmox_api import ProxmoxClient
        client = ProxmoxClient.__new__(ProxmoxClient)
        api = MagicMock()
        api.nodes.return_value.lxc.post.return_value = "UPID:lxc"
        client._api = api

        ok, upid = client.restore_backup("pve1", 140, "ct", "pbs:backup/ct/140/x")
        assert ok is True
        assert upid == "UPID:lxc"
        api.nodes.return_value.lxc.post.assert_called_once_with(
            vmid=140, ostemplate="pbs:backup/ct/140/x", restore=1, force=1
        )

    def test_list_all_backups_aggregates_storages(self):
        from clients.proxmox_api import ProxmoxClient
        client = ProxmoxClient.__new__(ProxmoxClient)
        client._api = MagicMock()

        with patch.object(client, "list_node_storages", return_value=[
            {"storage": "s1"}, {"storage": "s2"},
        ]), patch.object(client, "list_backups", side_effect=[
            [{"volid": "s1:a", "ctime": 10}],
            [{"volid": "s2:b", "ctime": 20}],
        ]):
            result = client.list_all_backups("pve1", 140)

        assert [r["volid"] for r in result] == ["s2:b", "s1:a"]  # newest first
        assert result[0]["storage"] == "s2"
        assert result[1]["storage"] == "s1"
