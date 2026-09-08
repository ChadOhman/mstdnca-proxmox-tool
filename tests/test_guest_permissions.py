"""Negative-permission tests for guest CRUD/action routes (routes/guests.py).

Every mutating guest route in routes/guests.py gates on
``current_user.can_manage_guests`` before doing anything else. A read-only
``viewer`` (can_manage_guests=False) must be turned away *and* must not
trigger any side effect: no Guest row created/changed/deleted, no audit log
row written, and no ProxmoxClient call dispatched. Asserting only the 302
status code is not enough — both the allow and the deny path redirect, so a
status-only assertion can't tell them apart (see issue #131). This mirrors
the pattern established in tests/test_guest_restore.py::TestRestorePermission
and tests/test_guest_clone_migrate.py.
"""
from unittest.mock import MagicMock, patch

import pytest

from models import AuditLog, Guest, ProxmoxHost, Role, Tag, User, db


def _login(client, username, password):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )


@pytest.fixture()
def viewer_user(app):
    """A real viewer-role user, created via the models and logged in via /login."""
    with app.app_context():
        viewer_role = Role.query.filter_by(name="viewer").first()
        assert viewer_role.can_manage_guests is False  # guard: viewer must be read-only
        user = User(username="gp_viewer", display_name="GP Viewer", role_id=viewer_role.id)
        user.set_password("ViewerPass123!")
        db.session.add(user)
        db.session.commit()

    yield "gp_viewer", "ViewerPass123!"

    with app.app_context():
        User.query.filter_by(username="gp_viewer").delete()
        db.session.commit()


@pytest.fixture()
def host(app):
    with app.app_context():
        h = ProxmoxHost(name="gp-node", hostname="test-only-gp-node.local", host_type="pve")
        db.session.add(h)
        db.session.commit()
        host_id = h.id
    yield host_id
    with app.app_context():
        for g in Guest.query.filter_by(proxmox_host_id=host_id).all():
            db.session.delete(g)
        h = ProxmoxHost.query.get(host_id)
        if h:
            db.session.delete(h)
        db.session.commit()


@pytest.fixture()
def guest(app, host):
    """A guest linked to a Proxmox host, with a vmid so power/clone/migrate/snapshot routes proceed
    past the "must be linked" precondition and reach the permission-gated client call."""
    with app.app_context():
        g = Guest(name="_gp-target", guest_type="ct", vmid=180, proxmox_host_id=host,
                   power_state="running")
        db.session.add(g)
        db.session.commit()
        gid = g.id
    yield gid
    with app.app_context():
        g = Guest.query.get(gid)
        if g:
            db.session.delete(g)
            db.session.commit()


@pytest.fixture()
def tag(app):
    with app.app_context():
        t = Tag(name="_gp-tag", color="#abcdef")
        db.session.add(t)
        db.session.commit()
        tid = t.id
    yield tid
    with app.app_context():
        t = Tag.query.get(tid)
        if t:
            db.session.delete(t)
            db.session.commit()


def _audit_count(app, action, resource_id=None):
    """Count AuditLog rows for `action` (optionally scoped to `resource_id`).

    NOTE: SQLite reuses integer primary keys after the row with the current
    max rowid is deleted, so a fixture-created guest's id can coincide with a
    guest used (and cleaned up) by an earlier test elsewhere in the suite —
    including one that legitimately logged this same `action` for that old
    guest. Callers must therefore compare a *delta* (count taken right after
    fixture setup vs. after the request under test), never assume a zero
    baseline.
    """
    with app.app_context():
        q = AuditLog.query.filter_by(action=action)
        if resource_id is not None:
            q = q.filter_by(resource_id=resource_id)
        return q.count()


class TestAddDenied:
    def test_viewer_cannot_add_guest(self, app, client, viewer_user):
        username, password = viewer_user
        _login(client, username, password)

        with app.app_context():
            before = Guest.query.filter_by(name="_gp-new-guest").count()

        resp = client.post("/guests/add", data={"name": "_gp-new-guest", "guest_type": "ct"},
                            follow_redirects=False)
        assert resp.status_code == 302

        with app.app_context():
            after = Guest.query.filter_by(name="_gp-new-guest").count()
        assert after == before == 0

    def test_admin_can_add_guest(self, app, auth_client):
        """Positive control: proves the assertion above would actually fail for the allow path."""
        resp = auth_client.post("/guests/add", data={"name": "_gp-new-guest-admin", "guest_type": "ct"},
                                 follow_redirects=False)
        assert resp.status_code == 302
        with app.app_context():
            created = Guest.query.filter_by(name="_gp-new-guest-admin").first()
            assert created is not None
            db.session.delete(created)
            db.session.commit()


class TestEditDenied:
    def test_viewer_cannot_edit_guest(self, app, client, viewer_user, guest, tag):
        username, password = viewer_user
        _login(client, username, password)
        before = _audit_count(app, "guest_edit", guest)

        resp = client.post(f"/guests/{guest}/edit",
                            data={"connection_method": "winrm", "tag_ids": [str(tag)]},
                            follow_redirects=False)
        assert resp.status_code == 302

        with app.app_context():
            g = Guest.query.get(guest)
            assert g.connection_method != "winrm"
            assert [t.id for t in g.tags] == []  # tag assignment did not go through
        assert _audit_count(app, "guest_edit", guest) == before

    def test_admin_can_edit_guest(self, app, auth_client, guest, tag):
        resp = auth_client.post(f"/guests/{guest}/edit",
                                 data={"connection_method": "winrm", "tag_ids": [str(tag)]},
                                 follow_redirects=False)
        assert resp.status_code == 302
        with app.app_context():
            g = Guest.query.get(guest)
            assert g.connection_method == "winrm"
            assert [t.id for t in g.tags] == [tag]


class TestDeleteDenied:
    def test_viewer_cannot_delete_guest(self, app, client, viewer_user, guest):
        username, password = viewer_user
        _login(client, username, password)
        before = _audit_count(app, "guest_delete", guest)

        resp = client.post(f"/guests/{guest}/delete", follow_redirects=False)
        assert resp.status_code == 302

        with app.app_context():
            assert Guest.query.get(guest) is not None
        assert _audit_count(app, "guest_delete", guest) == before


class TestPowerActionDenied:
    @patch("routes.guests.ProxmoxClient")
    def test_viewer_cannot_start_guest(self, mock_cls, app, client, viewer_user, guest):
        username, password = viewer_user
        _login(client, username, password)
        before = _audit_count(app, "guest_power", guest)

        resp = client.post(f"/guests/{guest}/power/start", follow_redirects=False)
        assert resp.status_code == 302
        mock_cls.assert_not_called()

        with app.app_context():
            g = Guest.query.get(guest)
            assert g.power_state == "running"  # unchanged (fixture default)
        assert _audit_count(app, "guest_power", guest) == before

    @patch("routes.guests.ProxmoxClient")
    def test_admin_start_guest_calls_client(self, mock_cls, app, auth_client, guest):
        inst = MagicMock()
        inst.find_guest_node.return_value = "gp-node"
        inst.start_guest.return_value = (True, "UPID:start")
        mock_cls.return_value = inst

        resp = auth_client.post(f"/guests/{guest}/power/start", follow_redirects=False)
        assert resp.status_code == 302
        inst.start_guest.assert_called_once()


class TestCloneDenied:
    @patch("routes.guests.ProxmoxClient")
    def test_viewer_cannot_clone_guest(self, mock_cls, app, client, viewer_user, guest):
        username, password = viewer_user
        _login(client, username, password)
        before = _audit_count(app, "guest_clone", guest)

        resp = client.post(f"/guests/{guest}/clone", data={"newid": "999"}, follow_redirects=False)
        assert resp.status_code == 302
        mock_cls.assert_not_called()
        assert _audit_count(app, "guest_clone", guest) == before


class TestMigrateDenied:
    @patch("routes.guests.ProxmoxClient")
    def test_viewer_cannot_migrate_guest(self, mock_cls, app, client, viewer_user, guest):
        username, password = viewer_user
        _login(client, username, password)
        before = _audit_count(app, "guest_migrate", guest)

        resp = client.post(f"/guests/{guest}/migrate", data={"target_node": "other-node"},
                            follow_redirects=False)
        assert resp.status_code == 302
        mock_cls.assert_not_called()
        assert _audit_count(app, "guest_migrate", guest) == before


class TestSnapshotCreateDenied:
    @patch("routes.guests.ProxmoxClient")
    def test_viewer_cannot_create_snapshot(self, mock_cls, app, client, viewer_user, guest):
        username, password = viewer_user
        _login(client, username, password)
        before = _audit_count(app, "guest_snapshot_create", guest)

        resp = client.post(f"/guests/{guest}/snapshot/create", data={"snapname": "_gp-snap"},
                            follow_redirects=False)
        assert resp.status_code == 302
        mock_cls.assert_not_called()
        assert _audit_count(app, "guest_snapshot_create", guest) == before

    @patch("routes.api.start_proxmox_job")
    @patch("routes.guests.ProxmoxClient")
    def test_admin_create_snapshot_calls_client(self, mock_cls, mock_job, app, auth_client, guest):
        inst = MagicMock()
        inst.find_guest_node.return_value = "gp-node"
        inst.create_snapshot.return_value = (True, "UPID:snap")
        mock_cls.return_value = inst

        resp = auth_client.post(f"/guests/{guest}/snapshot/create", data={"snapname": "_gp-snap"},
                                 follow_redirects=False)
        assert resp.status_code == 302
        inst.create_snapshot.assert_called_once()


class TestTagAssignmentDenied:
    """Tag assignment happens via the tag_ids field on add/edit — there is no
    dedicated tag-assignment route. A viewer must not be able to attach tags
    to a guest via either path."""

    def test_viewer_cannot_assign_tags_on_add(self, app, client, viewer_user, tag):
        username, password = viewer_user
        _login(client, username, password)

        resp = client.post("/guests/add",
                            data={"name": "_gp-tagged-add", "guest_type": "ct", "tag_ids": [str(tag)]},
                            follow_redirects=False)
        assert resp.status_code == 302

        with app.app_context():
            created = Guest.query.filter_by(name="_gp-tagged-add").first()
            assert created is None

    def test_viewer_cannot_assign_tags_on_edit(self, app, client, viewer_user, guest, tag):
        username, password = viewer_user
        _login(client, username, password)

        resp = client.post(f"/guests/{guest}/edit", data={"tag_ids": [str(tag)]}, follow_redirects=False)
        assert resp.status_code == 302

        with app.app_context():
            g = Guest.query.get(guest)
            assert [t.id for t in g.tags] == []
