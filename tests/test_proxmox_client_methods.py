"""Unit tests for ProxmoxClient methods in clients/proxmox_api.py.

These mock the proxmoxer .api attribute directly (no real connection, no Flask
app/DB needed) and assert the exact resource path and kwargs sent to the
mocked .post/.get/.put/.delete calls, following the pattern established in
tests/test_guest_clone_migrate.py and tests/test_guest_restore.py.
"""
from unittest.mock import MagicMock

from clients.proxmox_api import ProxmoxClient


def _client_with_api():
    """Build a ProxmoxClient whose .api is a MagicMock (no real connection)."""
    client = ProxmoxClient(MagicMock())
    client._api = MagicMock()
    return client


class TestPowerOps:
    def test_start_vm(self):
        client = _client_with_api()
        endpoint = client._api.nodes.return_value.qemu.return_value.status.start
        ok, msg = client.start_guest("node-a", 100, "vm")
        assert ok is True
        assert "vm/100" in msg
        endpoint.post.assert_called_once_with()

    def test_start_ct_uses_lxc_endpoint(self):
        client = _client_with_api()
        endpoint = client._api.nodes.return_value.lxc.return_value.status.start
        ok, msg = client.start_guest("node-a", 200, "ct")
        assert ok is True
        assert "ct/200" in msg
        endpoint.post.assert_called_once_with()

    def test_start_guest_error_returns_false(self):
        client = _client_with_api()
        client._api.nodes.return_value.qemu.return_value.status.start.post.side_effect = RuntimeError("no power")
        ok, msg = client.start_guest("node-a", 100, "vm")
        assert ok is False
        assert "no power" in msg

    def test_shutdown_vm(self):
        client = _client_with_api()
        endpoint = client._api.nodes.return_value.qemu.return_value.status.shutdown
        ok, msg = client.shutdown_guest("node-a", 100, "vm")
        assert ok is True
        assert "vm/100" in msg
        endpoint.post.assert_called_once_with()

    def test_shutdown_ct(self):
        client = _client_with_api()
        endpoint = client._api.nodes.return_value.lxc.return_value.status.shutdown
        ok, _ = client.shutdown_guest("node-a", 200, "ct")
        assert ok is True
        endpoint.post.assert_called_once_with()

    def test_stop_vm(self):
        client = _client_with_api()
        endpoint = client._api.nodes.return_value.qemu.return_value.status.stop
        ok, msg = client.stop_guest("node-a", 100, "vm")
        assert ok is True
        assert "vm/100" in msg
        endpoint.post.assert_called_once_with()

    def test_stop_ct_uses_lxc_endpoint(self):
        client = _client_with_api()
        endpoint = client._api.nodes.return_value.lxc.return_value.status.stop
        ok, _ = client.stop_guest("node-a", 200, "ct")
        assert ok is True
        endpoint.post.assert_called_once_with()

    def test_stop_guest_error_returns_false(self):
        client = _client_with_api()
        client._api.nodes.return_value.qemu.return_value.status.stop.post.side_effect = RuntimeError("wedged")
        ok, msg = client.stop_guest("node-a", 100, "vm")
        assert ok is False
        assert "wedged" in msg

    def test_reboot_vm(self):
        client = _client_with_api()
        endpoint = client._api.nodes.return_value.qemu.return_value.status.reboot
        ok, msg = client.reboot_guest("node-a", 100, "vm")
        assert ok is True
        assert "vm/100" in msg
        endpoint.post.assert_called_once_with()

    def test_reboot_ct_uses_lxc_endpoint(self):
        client = _client_with_api()
        endpoint = client._api.nodes.return_value.lxc.return_value.status.reboot
        ok, _ = client.reboot_guest("node-a", 200, "ct")
        assert ok is True
        endpoint.post.assert_called_once_with()


class TestSnapshotOps:
    def test_create_snapshot_vm(self):
        client = _client_with_api()
        endpoint = client._api.nodes.return_value.qemu.return_value.snapshot
        endpoint.post.return_value = "UPID:snap"
        ok, upid = client.create_snapshot("node-a", 100, "vm", "snap1", description="pre-upgrade")
        assert ok is True
        assert upid == "UPID:snap"
        endpoint.post.assert_called_once_with(snapname="snap1", description="pre-upgrade")

    def test_create_snapshot_ct_default_description(self):
        client = _client_with_api()
        endpoint = client._api.nodes.return_value.lxc.return_value.snapshot
        endpoint.post.return_value = "UPID:snapct"
        ok, upid = client.create_snapshot("node-a", 200, "ct", "snap2")
        assert ok is True
        assert upid == "UPID:snapct"
        endpoint.post.assert_called_once_with(snapname="snap2", description="")

    def test_create_snapshot_error_returns_false(self):
        client = _client_with_api()
        client._api.nodes.return_value.qemu.return_value.snapshot.post.side_effect = RuntimeError("no space")
        ok, msg = client.create_snapshot("node-a", 100, "vm", "snap1")
        assert ok is False
        assert "no space" in msg

    def test_delete_snapshot_vm(self):
        client = _client_with_api()
        snap = client._api.nodes.return_value.qemu.return_value.snapshot
        snap.return_value.delete.return_value = "UPID:del"
        ok, upid = client.delete_snapshot("node-a", 100, "vm", "snap1")
        assert ok is True
        assert upid == "UPID:del"
        snap.assert_called_once_with("snap1")
        snap.return_value.delete.assert_called_once_with()

    def test_delete_snapshot_ct_uses_lxc_endpoint(self):
        client = _client_with_api()
        snap = client._api.nodes.return_value.lxc.return_value.snapshot
        snap.return_value.delete.return_value = "UPID:delct"
        ok, upid = client.delete_snapshot("node-a", 200, "ct", "snap2")
        assert ok is True
        assert upid == "UPID:delct"
        snap.assert_called_once_with("snap2")

    def test_delete_snapshot_error_returns_false(self):
        client = _client_with_api()
        client._api.nodes.return_value.qemu.return_value.snapshot.return_value.delete.side_effect = RuntimeError(
            "not found"
        )
        ok, msg = client.delete_snapshot("node-a", 100, "vm", "snap1")
        assert ok is False
        assert "not found" in msg

    def test_rollback_snapshot_vm(self):
        client = _client_with_api()
        snap = client._api.nodes.return_value.qemu.return_value.snapshot
        snap.return_value.rollback.post.return_value = "UPID:roll"
        ok, upid = client.rollback_snapshot("node-a", 100, "vm", "snap1")
        assert ok is True
        assert upid == "UPID:roll"
        snap.assert_called_once_with("snap1")
        snap.return_value.rollback.post.assert_called_once_with()

    def test_rollback_snapshot_ct_uses_lxc_endpoint(self):
        client = _client_with_api()
        snap = client._api.nodes.return_value.lxc.return_value.snapshot
        snap.return_value.rollback.post.return_value = "UPID:rollct"
        ok, upid = client.rollback_snapshot("node-a", 200, "ct", "snap2")
        assert ok is True
        assert upid == "UPID:rollct"


class TestBackupOps:
    def test_create_backup_minimal(self):
        client = _client_with_api()
        endpoint = client._api.nodes.return_value.vzdump
        endpoint.post.return_value = "UPID:backup"
        ok, upid = client.create_backup("node-a", 100, "local-storage")
        assert ok is True
        assert upid == "UPID:backup"
        endpoint.post.assert_called_once_with(vmid=100, storage="local-storage", mode="snapshot", compress="zstd")

    def test_create_backup_protected_with_notes(self):
        client = _client_with_api()
        endpoint = client._api.nodes.return_value.vzdump
        endpoint.post.return_value = "UPID:backup2"
        ok, upid = client.create_backup(
            "node-a", 100, "local-storage", mode="stop", compress="gzip", protected=True, notes="test-only-notes"
        )
        assert ok is True
        assert upid == "UPID:backup2"
        endpoint.post.assert_called_once_with(
            vmid=100, storage="local-storage", mode="stop", compress="gzip", protected=1,
            **{"notes-template": "test-only-notes"},
        )

    def test_create_backup_error_returns_false(self):
        client = _client_with_api()
        client._api.nodes.return_value.vzdump.post.side_effect = RuntimeError("disk full")
        ok, msg = client.create_backup("node-a", 100, "local-storage")
        assert ok is False
        assert "disk full" in msg

    def test_delete_backup(self):
        client = _client_with_api()
        content = client._api.nodes.return_value.storage.return_value.content
        volid = "local-storage:backup/vm/100/x"
        ok, msg = client.delete_backup("node-a", "local-storage", volid)
        assert ok is True
        assert volid in msg
        client._api.nodes.return_value.storage.assert_called_once_with("local-storage")
        content.assert_called_once_with(volid)
        content.return_value.delete.assert_called_once_with()

    def test_delete_backup_error_returns_false(self):
        client = _client_with_api()
        client._api.nodes.return_value.storage.return_value.content.return_value.delete.side_effect = RuntimeError(
            "locked"
        )
        ok, msg = client.delete_backup("node-a", "local-storage", "local-storage:backup/vm/100/x")
        assert ok is False
        assert "locked" in msg

    def test_update_backup_protection_true(self):
        client = _client_with_api()
        content = client._api.nodes.return_value.storage.return_value.content
        volid = "local-storage:backup/vm/100/x"
        ok, msg = client.update_backup_protection("node-a", "local-storage", volid, True)
        assert ok is True
        assert "protected" in msg
        content.return_value.put.assert_called_once_with(protected=1)

    def test_update_backup_protection_false(self):
        client = _client_with_api()
        content = client._api.nodes.return_value.storage.return_value.content
        volid = "local-storage:backup/vm/100/x"
        ok, msg = client.update_backup_protection("node-a", "local-storage", volid, False)
        assert ok is True
        assert "unprotected" in msg
        content.return_value.put.assert_called_once_with(protected=0)

    def test_update_backup_notes(self):
        client = _client_with_api()
        content = client._api.nodes.return_value.storage.return_value.content
        volid = "local-storage:backup/vm/100/x"
        ok, msg = client.update_backup_notes("node-a", "local-storage", volid, "test-only-note-text")
        assert ok is True
        assert volid in msg
        content.return_value.put.assert_called_once_with(notes="test-only-note-text")


class TestReplicationOps:
    def test_get_replication_jobs_filters_by_vmid(self):
        client = _client_with_api()
        client._api.cluster.replication.get.return_value = [
            {"guest": 100, "target": "node-b", "id": "100-0"},
            {"guest": 200, "target": "node-c", "id": "200-0"},
        ]
        jobs = client.get_replication_jobs(100)
        assert jobs == [{"guest": 100, "target": "node-b", "id": "100-0"}]

    def test_get_replication_jobs_error_returns_empty_list(self):
        client = _client_with_api()
        client._api.cluster.replication.get.side_effect = RuntimeError("conn fail")
        assert client.get_replication_jobs(100) == []

    def test_create_replication_basic(self):
        client = _client_with_api()
        endpoint = client._api.cluster.replication
        endpoint.post.return_value = None
        ok, msg = client.create_replication(100, "node-b")
        assert ok is True
        assert "node-b" in msg
        assert "100" in msg
        endpoint.post.assert_called_once_with(id="100-0", target="node-b", schedule="*/15", type="local")

    def test_create_replication_with_rate(self):
        client = _client_with_api()
        endpoint = client._api.cluster.replication
        ok, _ = client.create_replication(100, "node-b", schedule="*/5", rate=50)
        assert ok is True
        endpoint.post.assert_called_once_with(id="100-0", target="node-b", schedule="*/5", type="local", rate=50)

    def test_create_replication_error_returns_false(self):
        client = _client_with_api()
        client._api.cluster.replication.post.side_effect = RuntimeError("duplicate job")
        ok, msg = client.create_replication(100, "node-b")
        assert ok is False
        assert "duplicate job" in msg

    def test_delete_replication(self):
        client = _client_with_api()
        job = client._api.cluster.replication
        ok, msg = client.delete_replication("100-0")
        assert ok is True
        assert "100-0" in msg
        job.assert_called_once_with("100-0")
        job.return_value.delete.assert_called_once_with()

    def test_delete_replication_error_returns_false(self):
        client = _client_with_api()
        client._api.cluster.replication.return_value.delete.side_effect = RuntimeError("not found")
        ok, msg = client.delete_replication("100-0")
        assert ok is False
        assert "not found" in msg


class TestMiscOps:
    def test_get_next_vmid(self):
        client = _client_with_api()
        client._api.cluster.nextid.get.return_value = "105"
        assert client.get_next_vmid() == 105

    def test_get_next_vmid_error_returns_none(self):
        client = _client_with_api()
        client._api.cluster.nextid.get.side_effect = RuntimeError("no vmid")
        assert client.get_next_vmid() is None

    def test_list_node_storages_filters_by_content_type(self):
        client = _client_with_api()
        client._api.nodes.return_value.storage.get.return_value = [
            {"storage": "s1", "content": "images,rootdir"},
            {"storage": "s2", "content": "backup,iso"},
        ]
        result = client.list_node_storages("node-a")
        assert result == [{"storage": "s2", "content": "backup,iso"}]

    def test_list_node_storages_no_filter_when_content_type_falsy(self):
        client = _client_with_api()
        storages = [
            {"storage": "s1", "content": "images,rootdir"},
            {"storage": "s2", "content": "backup,iso"},
        ]
        client._api.nodes.return_value.storage.get.return_value = storages
        result = client.list_node_storages("node-a", content_type=None)
        assert result == storages

    def test_list_node_storages_error_returns_empty_list(self):
        client = _client_with_api()
        client._api.nodes.return_value.storage.get.side_effect = RuntimeError("boom")
        assert client.list_node_storages("node-a") == []
