"""Route tests for routes/terminal.py (HTTP endpoints only — WebSocket handlers
are intentionally out of scope; see issue #131).

routes/terminal.py had zero route tests before this file: the missing
per-guest authorization, tag-less non-admin denial, stale/mismatched follow
sessions, and the CSRF origin check on connect-adhoc were all unexercised.
"""
from unittest.mock import patch

import pytest

from core.collaboration import terminal_registry
from models import Credential, Guest, Role, Tag, User, db


def _login(client, username, password):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )


@pytest.fixture()
def viewer_user(app):
    """viewer role: can_ssh=False — must be turned away before any guest lookup."""
    with app.app_context():
        viewer_role = Role.query.filter_by(name="viewer").first()
        assert viewer_role.can_ssh is False  # guard
        user = User(username="term_viewer", display_name="Term Viewer", role_id=viewer_role.id)
        user.set_password("ViewerPass123!")
        db.session.add(user)
        db.session.commit()
    yield "term_viewer", "ViewerPass123!"
    with app.app_context():
        User.query.filter_by(username="term_viewer").delete()
        db.session.commit()


@pytest.fixture()
def operator_user(app):
    """operator role: can_ssh=True but not admin and not tag-scoped to any guest —
    used to prove the can_access_guest() tag gate (not just can_ssh) is enforced."""
    with app.app_context():
        operator_role = Role.query.filter_by(name="operator").first()
        assert operator_role.can_ssh is True  # guard
        assert operator_role.can_manage_guests is False  # guard: not effectively admin
        user = User(username="term_operator", display_name="Term Operator", role_id=operator_role.id)
        user.set_password("OperatorPass123!")
        db.session.add(user)
        db.session.commit()
    yield "term_operator", "OperatorPass123!"
    with app.app_context():
        User.query.filter_by(username="term_operator").delete()
        db.session.commit()


@pytest.fixture()
def guest(app):
    """A guest with a resolvable IP directly on the row (skips Proxmox/UniFi
    IP-resolution branches so GET routes don't need those clients mocked)."""
    with app.app_context():
        g = Guest(name="_term-target", guest_type="ct", ip_address="10.0.0.42")
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
def tagged_guest(app):
    """A guest with a tag, plus a credential, for the admin-render happy path."""
    with app.app_context():
        tag = Tag(name="_term-tag", color="#112233")
        cred = Credential(name="_term-cred", username="root", auth_type="password",
                           encrypted_value="unused-in-this-test")
        g = Guest(name="_term-tagged", guest_type="ct", ip_address="10.0.0.43")
        g.tags.append(tag)
        db.session.add_all([tag, cred, g])
        db.session.commit()
        gid = g.id
        tag_id = tag.id
    yield gid
    with app.app_context():
        g = Guest.query.get(gid)
        if g:
            db.session.delete(g)
        t = Tag.query.get(tag_id)
        if t:
            db.session.delete(t)
        Credential.query.filter_by(name="_term-cred").delete()
        db.session.commit()


class TestConnectPermission:
    def test_viewer_without_can_ssh_redirected(self, app, client, viewer_user, guest):
        username, password = viewer_user
        _login(client, username, password)

        resp = client.get(f"/terminal/{guest}", follow_redirects=False)
        assert resp.status_code == 302
        with app.test_request_context():
            from flask import url_for
            assert resp.headers["Location"].endswith(url_for("dashboard.index"))

    def test_tagless_non_admin_denied(self, app, client, operator_user, guest):
        """operator has can_ssh=True but the guest has no tags, so
        can_access_guest() must still deny access (untagged guests are admin-only)."""
        username, password = operator_user
        _login(client, username, password)

        resp = client.get(f"/terminal/{guest}", follow_redirects=False)
        assert resp.status_code == 302
        assert "/terminal" in resp.headers["Location"]

    def test_admin_connect_renders(self, app, auth_client, tagged_guest):
        with patch("routes.terminal.paramiko"), patch("clients.proxmox_api.ProxmoxClient"):
            resp = auth_client.get(f"/terminal/{tagged_guest}", follow_redirects=False)
        assert resp.status_code == 200
        assert b"_term-tagged" in resp.data


class TestFollowPermission:
    def test_viewer_without_can_ssh_redirected(self, app, client, viewer_user, guest):
        username, password = viewer_user
        _login(client, username, password)

        resp = client.get(f"/terminal/{guest}/follow/does-not-exist", follow_redirects=False)
        assert resp.status_code == 302

    def test_unknown_session_id_redirects(self, app, auth_client, tagged_guest):
        resp = auth_client.get(f"/terminal/{tagged_guest}/follow/not-a-real-session-id",
                                follow_redirects=False)
        assert resp.status_code == 302
        assert "/terminal" in resp.headers["Location"]

    def test_mismatched_guest_session_redirects(self, app, auth_client, tagged_guest, guest):
        """A session that exists but belongs to a DIFFERENT guest must redirect,
        not silently attach the follower to the wrong session."""
        term_session = terminal_registry.create(
            guest_id=guest, guest_name="_term-target",
            owner_user_id=1, owner_username="admin",
        )
        try:
            resp = auth_client.get(f"/terminal/{tagged_guest}/follow/{term_session.session_id}",
                                    follow_redirects=False)
            assert resp.status_code == 302
            assert "/terminal" in resp.headers["Location"]
        finally:
            terminal_registry.remove(term_session.session_id)

    def test_admin_follow_valid_session_renders(self, app, auth_client, tagged_guest):
        term_session = terminal_registry.create(
            guest_id=tagged_guest, guest_name="_term-tagged",
            owner_user_id=1, owner_username="admin",
        )
        try:
            with patch("routes.terminal.paramiko"), patch("clients.proxmox_api.ProxmoxClient"):
                resp = auth_client.get(
                    f"/terminal/{tagged_guest}/follow/{term_session.session_id}",
                    follow_redirects=False,
                )
            assert resp.status_code == 200
        finally:
            terminal_registry.remove(term_session.session_id)


class TestConnectAdhocCsrf:
    """connect-adhoc is a POST route, so it goes through app.py's global
    same-origin CSRF check (_csrf_origin_check) before it ever reaches the
    can_ssh/can_access_guest checks in routes/terminal.py."""

    def test_cross_site_origin_is_blocked(self, app, auth_client, tagged_guest):
        resp = auth_client.post(
            f"/terminal/{tagged_guest}/connect-adhoc",
            data={"username": "root", "password": "test-only-pw"},
            headers={"Origin": "https://evil.example.com"},
        )
        assert resp.status_code == 403

    def test_same_origin_is_allowed_through_to_handler(self, app, auth_client, tagged_guest):
        resp = auth_client.post(
            f"/terminal/{tagged_guest}/connect-adhoc",
            data={"username": "root", "password": "test-only-pw"},
            headers={"Origin": "http://localhost"},
            follow_redirects=False,
        )
        # Not blocked by CSRF (would be 403); reaches the handler and redirects
        # back to the connect view.
        assert resp.status_code == 302
        assert f"/terminal/{tagged_guest}" in resp.headers["Location"]

    def test_viewer_without_can_ssh_denied(self, app, client, viewer_user, guest):
        username, password = viewer_user
        _login(client, username, password)

        resp = client.post(
            f"/terminal/{guest}/connect-adhoc",
            data={"username": "root", "password": "test-only-pw"},
            headers={"Origin": "http://localhost"},
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with client.session_transaction() as sess:
            assert f"terminal_cred_{guest}" not in sess


class TestPopoutPermission:
    def test_viewer_without_can_ssh_redirected(self, app, client, viewer_user, guest):
        username, password = viewer_user
        _login(client, username, password)

        resp = client.get(f"/terminal/{guest}/popout", follow_redirects=False)
        assert resp.status_code == 302

    def test_admin_popout_renders(self, app, auth_client, tagged_guest):
        with patch("routes.terminal.paramiko"), patch("clients.proxmox_api.ProxmoxClient"):
            resp = auth_client.get(f"/terminal/{tagged_guest}/popout", follow_redirects=False)
        assert resp.status_code == 200
