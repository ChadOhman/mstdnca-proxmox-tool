"""Tests for the builtin moderator role: a level-2 role whose only grant is
can_moderate, giving access to the moderation blueprint's operational surface
and nothing else (see routes/moderation.py, routes/guests.py, routes/trends.py).
"""

import pytest

from models import DEFAULT_ROLES

# ---------------------------------------------------------------------------
# Nav: only the moderation link should be visible
# ---------------------------------------------------------------------------


class TestModeratorNav:
    def test_moderator_nav_shows_only_moderation(self, moderator_client):
        resp = moderator_client.get("/", follow_redirects=False)
        assert resp.status_code == 200
        assert b'href="/moderation"' in resp.data
        for hidden in (b'href="/guests"', b'href="/trends"', b'href="/terminal"',
                       b'href="/hosts"', b'href="/security"', b'href="/settings"'):
            assert hidden not in resp.data, f"{hidden!r} should not be shown to a moderator"


# ---------------------------------------------------------------------------
# Everything outside the moderator's grant redirects to the dashboard
# ---------------------------------------------------------------------------


class TestModeratorDenied:
    @pytest.mark.parametrize("path", [
        "/guests/",
        "/trends/",
        "/hosts/",
        "/terminal/",
        "/security/",
        "/settings/",
        "/schedules/",
        "/services/",
        "/applications/",
        "/ipmi/",
        "/unifi/",
        "/credentials/",
    ])
    def test_moderator_redirected_to_dashboard(self, moderator_client, path):
        resp = moderator_client.get(path, follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers.get("Location", "") == "/", \
            f"{path} redirected to {resp.headers.get('Location')!r}, expected the dashboard root"


# ---------------------------------------------------------------------------
# Routes the moderator *is* allowed to use
# ---------------------------------------------------------------------------


class TestModeratorAllowed:
    @pytest.mark.parametrize("path", [
        "/",
        "/moderation/",
        "/moderation/?tab=mastodon",
        "/profile",
    ])
    def test_moderator_allowed_routes(self, moderator_client, path):
        resp = moderator_client.get(path, follow_redirects=False)
        assert resp.status_code == 200

    def test_moderator_collab_presence(self, moderator_client):
        resp = moderator_client.post(
            "/api/collab/presence",
            json={"page": "/moderation/"},
            follow_redirects=False,
        )
        assert resp.status_code == 200

    def test_moderator_moderation_page_hides_config(self, moderator_client):
        resp = moderator_client.get("/moderation/", follow_redirects=False)
        assert resp.status_code == 200
        assert b"managed by an administrator" in resp.data
        assert b"/moderation/mastodon/save" not in resp.data
        assert b"/moderation/mastodon/welcome/save" not in resp.data

    def test_admin_moderation_page_shows_welcome_config(self, auth_client):
        resp = auth_client.get("/moderation/?tab=mastodon", follow_redirects=False)
        assert resp.status_code == 200
        assert b"/moderation/mastodon/welcome/save" in resp.data

    def test_moderator_can_reach_watch_and_summary(self, moderator_client):
        resp = moderator_client.get("/moderation/mastodon/watch", follow_redirects=False)
        assert resp.status_code == 200
        resp = moderator_client.get("/moderation/mastodon/summary", follow_redirects=False)
        assert resp.status_code == 200

    def test_moderator_dashboard_shows_moderation_summary_card(self, moderator_client):
        resp = moderator_client.get("/", follow_redirects=False)
        assert resp.status_code == 200
        # The JS that fetches the summary references this id unconditionally, so
        # check for the (Jinja-gated) HTML element itself rather than the bare id.
        assert b'id="moderationSummaryCard"' in resp.data


# ---------------------------------------------------------------------------
# Dashboard: the moderation summary card is gated on can_moderate, not just
# on being logged in -- a viewer (can_moderate=False) must not see it.
# ---------------------------------------------------------------------------


class TestModerationSummaryCardHiddenForViewer:
    def test_viewer_dashboard_hides_moderation_summary_card(self, app, client):
        from models import Role, User, db

        with app.app_context():
            viewer_role = Role.query.filter_by(name="viewer").first()
            user = User(username="_mod_summary_viewer", display_name="V", role_id=viewer_role.id)
            user.set_password("test-only-ViewerPass123!")
            db.session.add(user)
            db.session.commit()
        try:
            client.post("/login", data={"username": "_mod_summary_viewer", "password": "test-only-ViewerPass123!"})
            resp = client.get("/", follow_redirects=False)
            assert resp.status_code == 200
            assert b'id="moderationSummaryCard"' not in resp.data
        finally:
            with app.app_context():
                User.query.filter_by(username="_mod_summary_viewer").delete()
                db.session.commit()


# ---------------------------------------------------------------------------
# Model: the builtin moderator role definition
# ---------------------------------------------------------------------------


class TestModeratorRoleDefinition:
    def test_default_roles_has_moderator(self):
        moderator = next((r for r in DEFAULT_ROLES if r["name"] == "moderator"), None)
        assert moderator is not None
        assert moderator["level"] == 2
        assert moderator["is_builtin"] is True
        assert moderator["can_moderate"] is True
        for key, value in moderator.items():
            if key.startswith("can_") and key != "can_moderate":
                assert value is False, f"moderator role should not grant {key}"

    def test_can_moderate_staff_is_admin_tier_only(self):
        by_name = {r["name"]: r for r in DEFAULT_ROLES}
        assert by_name["super_admin"]["can_moderate_staff"] is True
        assert by_name["admin"]["can_moderate_staff"] is True
        assert by_name["operator"]["can_moderate_staff"] is False
        assert by_name["viewer"]["can_moderate_staff"] is False
        assert by_name["moderator"]["can_moderate_staff"] is False
