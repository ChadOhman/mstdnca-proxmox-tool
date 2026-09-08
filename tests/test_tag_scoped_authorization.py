"""Tag-scope enforcement across every state-changing route (GHSA-hjq8-j54x-c7rr).

A permission flag says *what* a user may do; the tag scope says *which guests*
they may do it to.  Before this suite the two were only combined on guest read
pages, so a scoped non-admin holding ``can_manage_guests`` / ``can_edit_services``
/ ``can_update`` could act on any guest by supplying its id.

Every test here uses a user who **holds the relevant permission flag** but has
**no tag overlap** with the target guest, and asserts both the refusal and the
absence of the side effect (no ProxmoxClient / SSH call, no row change).
"""
from unittest.mock import MagicMock, patch

import pytest

from models import (
    ExporterInstance,
    Guest,
    GuestService,
    HostExporterInstance,
    ProxmoxHost,
    Role,
    Tag,
    User,
    db,
)

_PASSWORD = "test-only-ScopedPass1!"


def _login(client, username, password=_PASSWORD):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )


def _make_role(name, **flags):
    """Create (or reuse) a non-builtin role with the given permission flags."""
    role = Role.query.filter_by(name=name).first()
    if role is None:
        role = Role(name=name, display_name=name, level=flags.pop("level", 1))
        db.session.add(role)
    else:
        flags.pop("level", None)
    for field, value in flags.items():
        setattr(role, field, value)
    db.session.flush()
    return role


def _make_user(username, role):
    user = User.query.filter_by(username=username).first()
    if user is None:
        user = User(username=username, display_name=username, role_id=role.id)
        db.session.add(user)
    user.role_id = role.id
    user.set_password(_PASSWORD)
    db.session.flush()
    return user


# ---------------------------------------------------------------------------
# Fixtures: one guest tagged "owned", one tagged "foreign"; users only ever
# hold the "owned" tag, so every request below crosses the tag boundary.
# ---------------------------------------------------------------------------

@pytest.fixture()
def scoped(app):
    with app.app_context():
        owned_tag = Tag(name="_scoped-owned", color="#00ff00")
        foreign_tag = Tag(name="_scoped-foreign", color="#ff0000")
        host = ProxmoxHost(name="_scoped-node", hostname="test-only-scoped.local", host_type="pve")
        db.session.add_all([owned_tag, foreign_tag, host])
        db.session.flush()

        owned = Guest(name="_scoped-owned-guest", guest_type="ct", vmid=910,
                      proxmox_host_id=host.id, power_state="running", enabled=True)
        owned.tags.append(owned_tag)
        foreign = Guest(name="_scoped-foreign-guest", guest_type="ct", vmid=911,
                        proxmox_host_id=host.id, power_state="running", enabled=True)
        foreign.tags.append(foreign_tag)
        db.session.add_all([owned, foreign])
        db.session.flush()

        foreign_svc = GuestService(guest_id=foreign.id, service_name="postgresql",
                                   unit_name="postgresql.service", port=5432, status="running")
        db.session.add(foreign_svc)

        # Roles: each holds one capability but is not admin-tier.
        manager = _make_role("_scoped_manager", level=1, can_manage_guests=True)
        svc_editor = _make_role("_scoped_svc", level=1, can_view_services=True, can_edit_services=True)
        updater = _make_role("_scoped_updater", level=1, can_update=True)
        viewer = _make_role("_scoped_viewer", level=1)

        users = {
            "manager": _make_user("_scoped_manager_user", manager),
            "svc": _make_user("_scoped_svc_user", svc_editor),
            "updater": _make_user("_scoped_updater_user", updater),
            "viewer": _make_user("_scoped_viewer_user", viewer),
        }
        for user in users.values():
            user.allowed_tags.append(owned_tag)
        db.session.commit()

        ctx = {
            "owned_guest": owned.id,
            "foreign_guest": foreign.id,
            "foreign_service": foreign_svc.id,
            "host": host.id,
            "usernames": {k: u.username for k, u in users.items()},
        }

    yield ctx

    with app.app_context():
        ExporterInstance.query.filter(
            ExporterInstance.guest_id.in_([ctx["owned_guest"], ctx["foreign_guest"]])
        ).delete(synchronize_session=False)
        HostExporterInstance.query.filter_by(host_id=ctx["host"]).delete(synchronize_session=False)
        GuestService.query.filter(
            GuestService.guest_id.in_([ctx["owned_guest"], ctx["foreign_guest"]])
        ).delete(synchronize_session=False)
        for gid in (ctx["owned_guest"], ctx["foreign_guest"]):
            g = db.session.get(Guest, gid)
            if g:
                db.session.delete(g)
        host = db.session.get(ProxmoxHost, ctx["host"])
        if host:
            db.session.delete(host)
        for username in ctx["usernames"].values():
            u = User.query.filter_by(username=username).first()
            if u:
                u.allowed_tags = []
                db.session.delete(u)
        db.session.flush()
        for role_name in ("_scoped_manager", "_scoped_svc", "_scoped_updater", "_scoped_viewer"):
            r = Role.query.filter_by(name=role_name).first()
            if r:
                db.session.delete(r)
        for tag_name in ("_scoped-owned", "_scoped-foreign"):
            t = Tag.query.filter_by(name=tag_name).first()
            if t:
                db.session.delete(t)
        db.session.commit()


# ---------------------------------------------------------------------------
# routes/guests.py
# ---------------------------------------------------------------------------

class TestGuestRoutesTagScope:
    @patch("routes.guests.ProxmoxClient")
    def test_power_action_denied_across_tags(self, mock_client_cls, client, scoped):
        _login(client, scoped["usernames"]["manager"])
        resp = client.post(f"/guests/{scoped['foreign_guest']}/power/stop", follow_redirects=False)
        assert resp.status_code == 302
        assert "/guests/" in resp.headers["Location"]
        mock_client_cls.assert_not_called()

    @patch("routes.guests.ProxmoxClient")
    def test_snapshot_rollback_denied_across_tags(self, mock_client_cls, client, scoped):
        _login(client, scoped["usernames"]["manager"])
        resp = client.post(f"/guests/{scoped['foreign_guest']}/snapshot/snap1/rollback",
                           follow_redirects=False)
        assert resp.status_code == 302
        mock_client_cls.assert_not_called()

    @patch("routes.guests.ProxmoxClient")
    def test_restore_denied_across_tags(self, mock_client_cls, client, scoped):
        _login(client, scoped["usernames"]["manager"])
        resp = client.post(
            f"/guests/{scoped['foreign_guest']}/backup/pbs:backup/ct/911/2026-01-01/restore",
            data={"confirm_name": "_scoped-foreign-guest"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        mock_client_cls.assert_not_called()

    def test_delete_denied_across_tags(self, app, client, scoped):
        _login(client, scoped["usernames"]["manager"])
        resp = client.post(f"/guests/{scoped['foreign_guest']}/delete", follow_redirects=False)
        assert resp.status_code == 302
        with app.app_context():
            assert db.session.get(Guest, scoped["foreign_guest"]) is not None

    def test_edit_denied_across_tags(self, app, client, scoped):
        _login(client, scoped["usernames"]["manager"])
        resp = client.post(f"/guests/{scoped['foreign_guest']}/edit",
                           data={"connection_method": "api"}, follow_redirects=False)
        assert resp.status_code == 302
        with app.app_context():
            guest = db.session.get(Guest, scoped["foreign_guest"])
            assert guest.connection_method != "api"

    @patch("routes.guests.ProxmoxClient")
    def test_owned_guest_still_reachable(self, mock_client_cls, client, scoped):
        """The guard must not lock a scoped user out of their own guests."""
        mock_client_cls.return_value = MagicMock(find_guest_node=MagicMock(return_value=None))
        _login(client, scoped["usernames"]["manager"])
        resp = client.get(f"/guests/{scoped['owned_guest']}")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# routes/services.py
# ---------------------------------------------------------------------------

class TestServiceRoutesTagScope:
    @patch("routes.services.service_action")
    def test_control_denied_across_tags(self, mock_action, client, scoped):
        _login(client, scoped["usernames"]["svc"])
        resp = client.post(f"/services/{scoped['foreign_service']}/restart", follow_redirects=False)
        assert resp.status_code == 302
        assert "/services" in resp.headers["Location"]
        mock_action.assert_not_called()

    @patch("routes.services.get_service_logs")
    def test_logs_denied_across_tags(self, mock_logs, client, scoped):
        _login(client, scoped["usernames"]["svc"])
        resp = client.post(f"/services/{scoped['foreign_service']}/logs")
        assert resp.status_code == 403
        mock_logs.assert_not_called()

    @patch("routes.services.get_service_stats")
    def test_detail_denied_across_tags(self, mock_stats, client, scoped):
        _login(client, scoped["usernames"]["svc"])
        resp = client.get(f"/services/{scoped['foreign_service']}/detail", follow_redirects=False)
        assert resp.status_code == 302
        mock_stats.assert_not_called()

    def test_pg_roles_denied_across_tags(self, client, scoped):
        _login(client, scoped["usernames"]["svc"])
        resp = client.get(f"/services/{scoped['foreign_service']}/pg/roles")
        assert resp.status_code == 403

    def test_pg_vacuum_denied_across_tags(self, client, scoped):
        _login(client, scoped["usernames"]["svc"])
        resp = client.post(f"/services/{scoped['foreign_service']}/pg/vacuum",
                           json={"database": "mastodon"})
        assert resp.status_code == 403

    def test_pg_explain_denied_across_tags(self, client, scoped):
        _login(client, scoped["usernames"]["svc"])
        resp = client.post(f"/services/{scoped['foreign_service']}/pg/explain",
                           json={"database": "mastodon", "query": "SELECT 1"})
        assert resp.status_code == 403

    def test_assign_denied_across_tags(self, app, client, scoped):
        _login(client, scoped["usernames"]["svc"])
        resp = client.post(f"/services/{scoped['foreign_guest']}/assign",
                           data={"service_key": "redis"}, follow_redirects=False)
        assert resp.status_code == 302
        with app.app_context():
            assert GuestService.query.filter_by(
                guest_id=scoped["foreign_guest"], service_name="redis"
            ).first() is None

    def test_index_is_tag_scoped(self, client, scoped):
        _login(client, scoped["usernames"]["svc"])
        resp = client.get("/services/")
        assert resp.status_code == 200
        assert b"_scoped-foreign-guest" not in resp.data


# ---------------------------------------------------------------------------
# routes/api.py
# ---------------------------------------------------------------------------

class TestApiRoutesTagScope:
    def test_scan_requires_can_update(self, client, scoped):
        """A tagged viewer must not be able to open an SSH scan on their own guest."""
        _login(client, scoped["usernames"]["viewer"])
        with patch("routes.api.threading.Thread") as mock_thread:
            resp = client.post(f"/api/scan/{scoped['owned_guest']}", follow_redirects=False)
        assert resp.status_code == 302
        mock_thread.assert_not_called()

    def test_scan_denied_across_tags(self, client, scoped):
        _login(client, scoped["usernames"]["updater"])
        with patch("routes.api.threading.Thread") as mock_thread:
            resp = client.post(f"/api/scan/{scoped['foreign_guest']}", follow_redirects=False)
        assert resp.status_code == 302
        mock_thread.assert_not_called()

    def test_update_cancel_requires_can_update(self, client, scoped):
        from routes.api import UpdateJob, _update_jobs

        gid = scoped["owned_guest"]
        _update_jobs[gid] = UpdateJob(gid, "_scoped-owned-guest")
        try:
            _login(client, scoped["usernames"]["viewer"])
            resp = client.post(f"/api/apply/{gid}/cancel")
            assert resp.status_code == 403
            assert _update_jobs[gid].cancel_requested is False
        finally:
            _update_jobs.pop(gid, None)

    def test_task_cancel_requires_can_manage_guests(self, client, scoped):
        from routes.api import ProxmoxJob, _proxmox_jobs

        gid = scoped["owned_guest"]
        key = f"migrate:{gid}"
        _proxmox_jobs[key] = ProxmoxJob(
            guest_id=gid, guest_name="_scoped-owned-guest", job_type="migrate",
            upid="UPID:test", node="node1", host_model=None,
        )
        try:
            _login(client, scoped["usernames"]["updater"])
            resp = client.post(f"/api/task/{gid}/migrate/cancel")
            assert resp.status_code == 403
            assert _proxmox_jobs[key].cancel_requested is False
        finally:
            _proxmox_jobs.pop(key, None)

    @patch("clients.proxmox_api.ProxmoxClient")
    def test_dashboard_guest_stats_filtered_by_tag(self, mock_client_cls, app, client, scoped):
        """Live stats never list a guest outside the caller's tags, whatever ?tag= says."""
        with app.app_context():
            role = Role.query.filter_by(name="_scoped_manager").first()
            role.can_view_hosts = True
            db.session.commit()

        mock = MagicMock()
        mock.get_all_guests.return_value = [
            {"vmid": 910, "name": "_scoped-owned-guest", "status": "running", "type": "lxc",
             "mem": 1, "maxmem": 2, "disk": 1, "maxdisk": 2, "cpu": 0.1, "uptime": 5},
            {"vmid": 911, "name": "_scoped-foreign-guest", "status": "running", "type": "lxc",
             "mem": 1, "maxmem": 2, "disk": 1, "maxdisk": 2, "cpu": 0.9, "uptime": 5},
        ]
        mock_client_cls.return_value = mock

        _login(client, scoped["usernames"]["manager"])
        resp = client.get("/api/dashboard/guest-stats")
        assert resp.status_code == 200
        names = [g["name"] for g in resp.get_json()["guests"]]
        assert "_scoped-foreign-guest" not in names

    @patch("clients.proxmox_api.ProxmoxClient")
    def test_host_guest_stats_filtered_by_tag(self, mock_client_cls, app, client, scoped):
        with app.app_context():
            role = Role.query.filter_by(name="_scoped_manager").first()
            role.can_view_hosts = True
            db.session.commit()

        mock = MagicMock()
        mock.get_local_node_name.return_value = None
        mock.get_all_guests.return_value = [
            {"vmid": 910, "status": "running", "mem": 1, "maxmem": 2,
             "disk": 1, "maxdisk": 2, "cpu": 0.1},
            {"vmid": 911, "status": "running", "mem": 1, "maxmem": 2,
             "disk": 1, "maxdisk": 2, "cpu": 0.9},
        ]
        mock_client_cls.return_value = mock

        _login(client, scoped["usernames"]["manager"])
        resp = client.get(f"/api/hosts/{scoped['host']}/guest-stats")
        assert resp.status_code == 200
        assert "911" not in resp.get_json()["stats"]


# ---------------------------------------------------------------------------
# routes/prometheus_app.py
# ---------------------------------------------------------------------------

class TestExporterRoutesTagScope:
    @pytest.fixture()
    def instances(self, app, scoped):
        with app.app_context():
            exporter = ExporterInstance(guest_id=scoped["foreign_guest"],
                                        exporter_type="postgres_exporter",
                                        port=9187, status="pending")
            host_exporter = HostExporterInstance(host_id=scoped["host"],
                                                 exporter_type="node_exporter",
                                                 port=9100, status="pending")
            db.session.add_all([exporter, host_exporter])
            db.session.commit()
            return {"exporter": exporter.id, "host_exporter": host_exporter.id}

    def test_exporter_install_denied_across_tags(self, client, scoped, instances):
        _login(client, scoped["usernames"]["updater"])
        with patch("routes.prometheus_app._threading.Thread") as mock_thread:
            resp = client.post(f"/prometheus/exporters/{instances['exporter']}/install")
        assert resp.status_code == 403
        mock_thread.assert_not_called()

    def test_exporter_uninstall_denied_across_tags(self, client, scoped, instances):
        _login(client, scoped["usernames"]["updater"])
        with patch("routes.prometheus_app._threading.Thread") as mock_thread:
            resp = client.post(f"/prometheus/exporters/{instances['exporter']}/uninstall")
        assert resp.status_code == 403
        mock_thread.assert_not_called()

    def test_exporter_add_denied_across_tags(self, app, client, scoped):
        _login(client, scoped["usernames"]["updater"])
        resp = client.post("/prometheus/exporters/add",
                           data={"guest_id": str(scoped["foreign_guest"]),
                                 "exporter_type": "postgres_exporter"},
                           follow_redirects=False)
        assert resp.status_code == 302
        with app.app_context():
            assert ExporterInstance.query.filter_by(
                guest_id=scoped["foreign_guest"], exporter_type="postgres_exporter"
            ).count() == 0

    def test_host_exporter_install_requires_admin(self, client, scoped, instances):
        _login(client, scoped["usernames"]["updater"])
        with patch("routes.prometheus_app._threading.Thread") as mock_thread:
            resp = client.post(f"/prometheus/host-exporters/{instances['host_exporter']}/install")
        assert resp.status_code == 403
        mock_thread.assert_not_called()

    def test_host_exporter_delete_requires_admin(self, app, client, scoped, instances):
        _login(client, scoped["usernames"]["updater"])
        resp = client.post(f"/prometheus/host-exporters/{instances['host_exporter']}/delete",
                           follow_redirects=False)
        assert resp.status_code == 302
        with app.app_context():
            assert db.session.get(HostExporterInstance, instances["host_exporter"]) is not None

    def test_exporter_listing_is_tag_scoped(self, client, scoped, instances):
        _login(client, scoped["usernames"]["updater"])
        resp = client.get("/prometheus/exporters")
        assert resp.status_code == 200
        assert resp.get_json()["exporters"] == []


# ---------------------------------------------------------------------------
# routes/terminal.py — can_ssh is no longer implied by admin tier
# ---------------------------------------------------------------------------

class TestTerminalCanSsh:
    @pytest.fixture()
    def admin_no_ssh(self, app):
        with app.app_context():
            role = _make_role("_scoped_admin_nossh", level=3, can_ssh=False,
                              can_manage_guests=True, can_view_hosts=True)
            user = _make_user("_scoped_admin_nossh_user", role)
            guest = Guest(name="_scoped-nossh-guest", guest_type="ct", vmid=912, enabled=True)
            db.session.add(guest)
            db.session.commit()
            ctx = {"username": user.username, "guest": guest.id}
        yield ctx
        with app.app_context():
            g = db.session.get(Guest, ctx["guest"])
            if g:
                db.session.delete(g)
            u = User.query.filter_by(username=ctx["username"]).first()
            if u:
                db.session.delete(u)
            db.session.flush()
            r = Role.query.filter_by(name="_scoped_admin_nossh").first()
            if r:
                db.session.delete(r)
            db.session.commit()

    def test_level3_without_can_ssh_denied_index(self, client, admin_no_ssh):
        _login(client, admin_no_ssh["username"])
        resp = client.get("/terminal/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/terminal" not in resp.headers["Location"]

    @patch("routes.terminal._resolve_guest_ip")
    def test_level3_without_can_ssh_denied_connect(self, mock_resolve, client, admin_no_ssh):
        _login(client, admin_no_ssh["username"])
        resp = client.get(f"/terminal/{admin_no_ssh['guest']}", follow_redirects=False)
        assert resp.status_code == 302
        mock_resolve.assert_not_called()

    @patch("routes.terminal._resolve_guest_ip")
    def test_level3_without_can_ssh_denied_popout(self, mock_resolve, client, admin_no_ssh):
        _login(client, admin_no_ssh["username"])
        resp = client.get(f"/terminal/{admin_no_ssh['guest']}/popout", follow_redirects=False)
        assert resp.status_code == 302
        mock_resolve.assert_not_called()

    def test_level3_without_can_ssh_denied_adhoc(self, client, admin_no_ssh):
        _login(client, admin_no_ssh["username"])
        with client.session_transaction() as sess:
            sess.pop(f"terminal_cred_{admin_no_ssh['guest']}", None)
        resp = client.post(f"/terminal/{admin_no_ssh['guest']}/connect-adhoc",
                           data={"username": "root", "password": "test-only-pw"},
                           follow_redirects=False)
        assert resp.status_code == 302
        with client.session_transaction() as sess:
            assert f"terminal_cred_{admin_no_ssh['guest']}" not in sess


# ---------------------------------------------------------------------------
# Collaboration fan-out
# ---------------------------------------------------------------------------

class TestCollaborationFanOut:
    def _drain(self, q):
        events = []
        while not q.empty():
            events.append(q.get_nowait())
        return events

    def test_guest_activity_not_delivered_to_other_tags(self):
        from core.collaboration import CollaborationHub

        hub = CollaborationHub()
        q_admin = hub.connect(1, "admin", "Admin", is_admin=True)
        q_owner = hub.connect(2, "owner", "Owner", tag_ids={7})
        q_other = hub.connect(3, "other", "Other", tag_ids={9})

        hub.broadcast({"type": "activity", "action": "guest_power_off",
                       "resource_type": "guest", "resource_name": "secret-guest",
                       "guest_id": 42, "guest_tag_ids": [7]})

        def activity(q):
            return [e for e in self._drain(q) if e.get("type") == "activity"]

        assert len(activity(q_admin)) == 1
        owner_events = activity(q_owner)
        assert len(owner_events) == 1
        # The internal routing key is stripped before delivery
        assert "guest_tag_ids" not in owner_events[0]
        assert owner_events[0]["guest_id"] == 42
        assert activity(q_other) == []

    def test_untagged_guest_activity_is_admin_only(self):
        from core.collaboration import CollaborationHub

        hub = CollaborationHub()
        q_admin = hub.connect(1, "admin", "Admin", is_admin=True)
        q_scoped = hub.connect(2, "scoped", "Scoped", tag_ids={7})

        hub.broadcast({"type": "activity", "action": "guest_delete",
                       "resource_type": "guest", "guest_id": 5, "guest_tag_ids": []})

        assert [e for e in self._drain(q_admin) if e.get("type") == "activity"]
        assert [e for e in self._drain(q_scoped) if e.get("type") == "activity"] == []

    def test_non_guest_activity_reaches_everyone(self):
        from core.collaboration import CollaborationHub

        hub = CollaborationHub()
        q_scoped = hub.connect(2, "scoped", "Scoped", tag_ids={7})
        hub.broadcast({"type": "activity", "action": "host_add", "resource_type": "host"})
        assert [e for e in self._drain(q_scoped) if e.get("type") == "activity"]

    def test_log_action_attaches_guest_tag_ids(self, app, scoped):
        from auth.audit import log_action

        with app.app_context(), patch("core.collaboration.collab_hub") as mock_hub:
            guest = db.session.get(Guest, scoped["foreign_guest"])
            tag_ids = [t.id for t in guest.tags]
            log_action("guest_power_off", "guest", resource_id=guest.id, resource_name=guest.name)
            db.session.rollback()

        payload = mock_hub.broadcast.call_args[0][0]
        assert payload["guest_id"] == scoped["foreign_guest"]
        assert payload["guest_tag_ids"] == tag_ids

    def test_ssh_disconnect_is_not_broadcast(self, app, scoped):
        from auth.audit import log_action

        with app.app_context(), patch("core.collaboration.collab_hub") as mock_hub:
            log_action("guest_ssh_disconnect", "guest", resource_id=scoped["owned_guest"],
                       resource_name="_scoped-owned-guest")
            db.session.rollback()

        mock_hub.broadcast.assert_not_called()
