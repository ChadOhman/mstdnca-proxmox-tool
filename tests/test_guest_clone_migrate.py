"""Tests for guest clone and migrate routes + ProxmoxClient clone/migrate methods."""
from unittest.mock import MagicMock, patch

import pytest

from clients.proxmox_api import ProxmoxClient
from models import AuditLog, Guest, ProxmoxHost, Role, User, db


def _login(client, username, password):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def host(app):
    host_id = None
    with app.app_context():
        h = ProxmoxHost(name="node-a", hostname="10.0.0.1", host_type="pve")
        db.session.add(h)
        db.session.commit()
        host_id = h.id
    yield host_id
    with app.app_context():
        h = ProxmoxHost.query.get(host_id)
        if h:
            for g in Guest.query.filter_by(proxmox_host_id=h.id).all():
                db.session.delete(g)
            db.session.delete(h)
            db.session.commit()


def _detail_ready_mock():
    """A ProxmoxClient mock whose detail-page methods return renderable values,
    so following a redirect to guest_detail.html does not blow up on MagicMocks."""
    inst = MagicMock()
    inst.find_guest_node.return_value = "node-a"
    inst.get_nodes.return_value = [{"node": "node-a"}, {"node": "node-b"}]
    inst.list_cluster_nodes.return_value = ["node-a", "node-b"]
    inst.get_next_vmid.return_value = 150
    inst.get_replication_jobs.return_value = []
    inst.list_snapshots.return_value = []
    inst.list_node_storages.return_value = []
    inst.get_guest_config.return_value = None
    inst.list_backups.return_value = []
    return inst


def _make_guest(app, host_id, guest_type="vm", vmid=100):
    with app.app_context():
        g = Guest(name=f"_cm-{guest_type}-{vmid}", guest_type=guest_type,
                  vmid=vmid, proxmox_host_id=host_id, power_state="running")
        db.session.add(g)
        db.session.commit()
        return g.id


@pytest.fixture()
def vm_guest(app, host):
    guest_id = _make_guest(app, host, "vm", 100)
    yield guest_id
    with app.app_context():
        g = Guest.query.get(guest_id)
        if g:
            db.session.delete(g)
            db.session.commit()


@pytest.fixture()
def ct_guest(app, host):
    guest_id = _make_guest(app, host, "ct", 200)
    yield guest_id
    with app.app_context():
        g = Guest.query.get(guest_id)
        if g:
            db.session.delete(g)
            db.session.commit()


# ---------------------------------------------------------------------------
# ProxmoxClient method tests (mock the proxmoxer .api attribute)
# ---------------------------------------------------------------------------


def _client_with_api():
    """Build a ProxmoxClient whose .api is a MagicMock (no real connection)."""
    client = ProxmoxClient(MagicMock())
    client._api = MagicMock()
    return client


class TestClientClone:
    def test_clone_vm_full(self):
        client = _client_with_api()
        endpoint = client._api.nodes.return_value.qemu.return_value.clone
        endpoint.post.return_value = "UPID:clone"

        ok, upid = client.clone_guest("node-a", 100, "vm", 150, name="copy",
                                      full=True, target_storage="local-lvm")
        assert ok is True
        assert upid == "UPID:clone"
        endpoint.post.assert_called_once_with(newid=150, full=1, name="copy", storage="local-lvm")

    def test_clone_vm_linked_omits_storage(self):
        client = _client_with_api()
        endpoint = client._api.nodes.return_value.qemu.return_value.clone
        endpoint.post.return_value = "UPID:clone"

        ok, _ = client.clone_guest("node-a", 100, "vm", 150, name=None, full=False,
                                   target_storage="local-lvm")
        assert ok is True
        # Linked clone => full=0 and storage NOT passed
        endpoint.post.assert_called_once_with(newid=150, full=0)

    def test_clone_ct_uses_lxc_endpoint(self):
        client = _client_with_api()
        endpoint = client._api.nodes.return_value.lxc.return_value.clone
        endpoint.post.return_value = "UPID:cloct"

        ok, upid = client.clone_guest("node-a", 200, "ct", 250, name="ctcopy", full=True)
        assert ok is True
        assert upid == "UPID:cloct"
        endpoint.post.assert_called_once_with(newid=250, full=1, name="ctcopy")

    def test_clone_error_returns_false(self):
        client = _client_with_api()
        client._api.nodes.return_value.qemu.return_value.clone.post.side_effect = RuntimeError("boom")
        ok, msg = client.clone_guest("node-a", 100, "vm", 150)
        assert ok is False
        assert "boom" in msg


class TestClientMigrate:
    def test_migrate_running_vm_is_online(self):
        client = _client_with_api()
        endpoint = client._api.nodes.return_value.qemu.return_value.migrate
        endpoint.post.return_value = "UPID:mig"

        ok, upid = client.migrate_guest("node-a", 100, "vm", "node-b", online=True)
        assert ok is True
        assert upid == "UPID:mig"
        endpoint.post.assert_called_once_with(target="node-b", online=1)

    def test_migrate_stopped_vm_no_online(self):
        client = _client_with_api()
        endpoint = client._api.nodes.return_value.qemu.return_value.migrate
        endpoint.post.return_value = "UPID:mig"

        ok, _ = client.migrate_guest("node-a", 100, "vm", "node-b", online=False)
        assert ok is True
        endpoint.post.assert_called_once_with(target="node-b")

    def test_migrate_running_ct_uses_restart(self):
        client = _client_with_api()
        endpoint = client._api.nodes.return_value.lxc.return_value.migrate
        endpoint.post.return_value = "UPID:migct"

        ok, _ = client.migrate_guest("node-a", 200, "ct", "node-b", online=True)
        assert ok is True
        # LXC live migration uses restart=1, never online=1
        endpoint.post.assert_called_once_with(target="node-b", restart=1)

    def test_migrate_online_none_queries_status(self):
        client = _client_with_api()
        endpoint = client._api.nodes.return_value.qemu.return_value.migrate
        endpoint.post.return_value = "UPID:mig"
        with patch.object(client, "get_guest_status", return_value="running") as gs:
            ok, _ = client.migrate_guest("node-a", 100, "vm", "node-b")
        assert ok is True
        gs.assert_called_once_with("node-a", 100, "vm")
        endpoint.post.assert_called_once_with(target="node-b", online=1)

    def test_migrate_error_returns_false(self):
        client = _client_with_api()
        client._api.nodes.return_value.qemu.return_value.migrate.post.side_effect = RuntimeError("nope")
        ok, msg = client.migrate_guest("node-a", 100, "vm", "node-b", online=False)
        assert ok is False
        assert "nope" in msg


class TestClientHelpers:
    def test_list_cluster_nodes_sorted(self):
        client = _client_with_api()
        client._api.nodes.get.return_value = [{"node": "node-b"}, {"node": "node-a"}]
        assert client.list_cluster_nodes() == ["node-a", "node-b"]

    def test_get_next_vmid(self):
        client = _client_with_api()
        client._api.cluster.nextid.get.return_value = "123"
        assert client.get_next_vmid() == 123


# ---------------------------------------------------------------------------
# Route tests — clone
# ---------------------------------------------------------------------------


class TestCloneRoute:
    @patch("routes.guests.ProxmoxClient")
    def test_clone_vm_dispatch(self, mock_cls, app, auth_client, vm_guest):
        inst = MagicMock()
        inst.find_guest_node.return_value = "node-a"
        inst.clone_guest.return_value = (True, "UPID:clone")
        mock_cls.return_value = inst

        with patch("routes.api.start_proxmox_job", return_value="clone:1"):
            resp = auth_client.post(f"/guests/{vm_guest}/clone",
                                    data={"newid": "150", "name": "copy", "clone_type": "full"},
                                    follow_redirects=False)
        assert resp.status_code == 302
        assert "/clone/progress" in resp.headers["Location"]
        inst.clone_guest.assert_called_once_with("node-a", 100, "vm", 150,
                                                 name="copy", full=True, target_storage=None)

        with app.app_context():
            log = (AuditLog.query.filter_by(action="guest_clone", resource_id=vm_guest)
                   .order_by(AuditLog.id.desc()).first())
            assert log is not None

    @patch("routes.guests.ProxmoxClient")
    def test_clone_ct_linked(self, mock_cls, app, auth_client, ct_guest):
        inst = MagicMock()
        inst.find_guest_node.return_value = "node-a"
        inst.clone_guest.return_value = (True, "UPID:cloct")
        mock_cls.return_value = inst

        with patch("routes.api.start_proxmox_job", return_value="clone:1"):
            resp = auth_client.post(f"/guests/{ct_guest}/clone",
                                    data={"newid": "250", "clone_type": "linked"},
                                    follow_redirects=False)
        assert resp.status_code == 302
        inst.clone_guest.assert_called_once_with("node-a", 200, "ct", 250,
                                                 name=None, full=False, target_storage=None)

    @patch("routes.guests.ProxmoxClient")
    def test_clone_invalid_vmid_rejected(self, mock_cls, auth_client, vm_guest):
        inst = _detail_ready_mock()
        mock_cls.return_value = inst
        resp = auth_client.post(f"/guests/{vm_guest}/clone",
                                data={"newid": "abc"}, follow_redirects=True)
        assert resp.status_code == 200
        assert "must be a number" in resp.get_data(as_text=True)
        inst.clone_guest.assert_not_called()

    @patch("routes.guests.ProxmoxClient")
    def test_clone_same_vmid_rejected(self, mock_cls, auth_client, vm_guest):
        inst = _detail_ready_mock()
        mock_cls.return_value = inst
        resp = auth_client.post(f"/guests/{vm_guest}/clone",
                                data={"newid": "100"}, follow_redirects=True)
        assert resp.status_code == 200
        assert "must differ" in resp.get_data(as_text=True)
        inst.clone_guest.assert_not_called()

    def test_clone_denied_for_viewer(self, app, client, vm_guest):
        with app.app_context():
            viewer_role = Role.query.filter_by(name="viewer").first()
            assert viewer_role.can_manage_guests is False
            u = User(username="cm_viewer_clone", display_name="V", role_id=viewer_role.id)
            u.set_password("ViewerPass123!")
            db.session.add(u)
            db.session.commit()

        _login(client, "cm_viewer_clone", "ViewerPass123!")
        with patch("routes.guests.ProxmoxClient") as mock_cls:
            resp = client.post(f"/guests/{vm_guest}/clone",
                               data={"newid": "150"}, follow_redirects=True)
            assert resp.status_code == 200
            assert "Permission denied" in resp.get_data(as_text=True)
            mock_cls.assert_not_called()

        with app.app_context():
            User.query.filter_by(username="cm_viewer_clone").delete()
            db.session.commit()


# ---------------------------------------------------------------------------
# Route tests — migrate
# ---------------------------------------------------------------------------


class TestMigrateRoute:
    @patch("routes.guests.ProxmoxClient")
    def test_migrate_vm_dispatch(self, mock_cls, app, auth_client, vm_guest):
        inst = MagicMock()
        inst.find_guest_node.return_value = "node-a"
        inst.list_cluster_nodes.return_value = ["node-a", "node-b"]
        inst.migrate_guest.return_value = (True, "UPID:mig")
        mock_cls.return_value = inst

        with patch("routes.api.start_proxmox_job", return_value="migrate:1"):
            resp = auth_client.post(f"/guests/{vm_guest}/migrate",
                                    data={"target_node": "node-b"}, follow_redirects=False)
        assert resp.status_code == 302
        assert "/migrate/progress" in resp.headers["Location"]
        # online defaults to None so the client decides online/restart per guest state
        inst.migrate_guest.assert_called_once_with("node-a", 100, "vm", "node-b")

        with app.app_context():
            log = (AuditLog.query.filter_by(action="guest_migrate", resource_id=vm_guest)
                   .order_by(AuditLog.id.desc()).first())
            assert log is not None
            assert log.details.get("target_node") == "node-b"

    @patch("routes.guests.ProxmoxClient")
    def test_migrate_missing_target_rejected(self, mock_cls, auth_client, vm_guest):
        inst = _detail_ready_mock()
        mock_cls.return_value = inst
        resp = auth_client.post(f"/guests/{vm_guest}/migrate",
                                data={"target_node": ""}, follow_redirects=True)
        assert resp.status_code == 200
        assert "Target node is required" in resp.get_data(as_text=True)
        inst.migrate_guest.assert_not_called()

    @patch("routes.guests.ProxmoxClient")
    def test_migrate_same_node_rejected(self, mock_cls, auth_client, vm_guest):
        inst = _detail_ready_mock()
        mock_cls.return_value = inst
        resp = auth_client.post(f"/guests/{vm_guest}/migrate",
                                data={"target_node": "node-a"}, follow_redirects=True)
        assert resp.status_code == 200
        assert "must differ" in resp.get_data(as_text=True)
        inst.migrate_guest.assert_not_called()

    @patch("routes.guests.ProxmoxClient")
    def test_migrate_unknown_node_rejected(self, mock_cls, auth_client, vm_guest):
        inst = _detail_ready_mock()
        mock_cls.return_value = inst
        resp = auth_client.post(f"/guests/{vm_guest}/migrate",
                                data={"target_node": "node-zzz"}, follow_redirects=True)
        assert resp.status_code == 200
        assert "Unknown target node" in resp.get_data(as_text=True)
        inst.migrate_guest.assert_not_called()

    def test_migrate_denied_for_viewer(self, app, client, vm_guest):
        with app.app_context():
            viewer_role = Role.query.filter_by(name="viewer").first()
            u = User(username="cm_viewer_mig", display_name="V", role_id=viewer_role.id)
            u.set_password("ViewerPass123!")
            db.session.add(u)
            db.session.commit()

        _login(client, "cm_viewer_mig", "ViewerPass123!")
        with patch("routes.guests.ProxmoxClient") as mock_cls:
            resp = client.post(f"/guests/{vm_guest}/migrate",
                               data={"target_node": "node-b"}, follow_redirects=True)
            assert resp.status_code == 200
            assert "Permission denied" in resp.get_data(as_text=True)
            mock_cls.assert_not_called()

        with app.app_context():
            User.query.filter_by(username="cm_viewer_mig").delete()
            db.session.commit()
