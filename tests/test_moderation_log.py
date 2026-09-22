"""Tests for the Moderation page's Activity log tab.

Covers routes/moderation.py's log() route and _moderation_log_query() helper,
templates/moderation_log.html's rendering (sensitive-key filtering, admin
links), and the retention purge in core/scheduler.py::_purge_old_audit_logs,
which is gated by the same core/moderation_log.py::moderation_log_filter()
definition used here.
"""

from datetime import datetime, timedelta, timezone

import pytest

from models import AuditLog, Role, Setting, User, db

_VIEWER_PASSWORD = "test-only-ModLogViewerPass123!"


@pytest.fixture()
def viewer_client(app):
    """A test client logged in as a low-privilege (viewer, no can_moderate) user."""
    with app.app_context():
        role = Role.query.filter_by(name="viewer").first()
        user = User.query.filter_by(username="_modlog_viewer").first()
        if user is None:
            user = User(username="_modlog_viewer", display_name="Mod Log Viewer", role_id=role.id)
            user.set_password(_VIEWER_PASSWORD)
            db.session.add(user)
            db.session.commit()
    with app.test_client() as c:
        c.post("/login", data={"username": "_modlog_viewer", "password": _VIEWER_PASSWORD}, follow_redirects=False)
        yield c


@pytest.fixture()
def seeded_rows(app):
    """Seed a small, distinctive set of AuditLog rows: two moderation-visible
    rows (an account action and a report action, both attributed to admin), a
    system-attributed moderation row, and a non-moderation row that must never
    appear on the activity log.
    """
    with app.app_context():
        admin = User.query.filter_by(username="admin").first()
        rows = [
            AuditLog(
                user_id=admin.id, action="mastodon_account_suspend", resource_type="mastodon_account",
                resource_name="test-only-suspended@example.com",
                details={"account_id": "4242", "type": "suspend", "password": "should-not-render"},
                ip_address="203.0.113.5",
            ),
            AuditLog(
                user_id=admin.id, action="mastodon_report_resolve", resource_type="mastodon_report",
                resource_name="report 99", details={"report_id": "99"}, ip_address="203.0.113.5",
            ),
            AuditLog(
                user_id=None, action="moderation_check", resource_type="moderation",
                details={"matched": 3, "unmatched": 0, "auto_ban": False},
            ),
            AuditLog(
                user_id=admin.id, action="user_add", resource_type="user",
                resource_name="test-only-not-moderation",
            ),
        ]
        db.session.add_all(rows)
        db.session.commit()
        ids = [r.id for r in rows]
    yield ids
    with app.app_context():
        AuditLog.query.filter(AuditLog.id.in_(ids)).delete(synchronize_session=False)
        db.session.commit()


class TestModerationLogAccess:
    def test_moderator_sees_moderation_rows_not_general_rows(self, moderator_client, seeded_rows):
        resp = moderator_client.get("/moderation/log")
        assert resp.status_code == 200
        assert b'title="mastodon_account_suspend"' in resp.data
        assert b"test-only-not-moderation" not in resp.data

    def test_viewer_redirected(self, viewer_client):
        resp = viewer_client.get("/moderation/log", follow_redirects=False)
        assert resp.status_code == 302

    def test_tab_log_query_param_redirects_to_log_route(self, moderator_client):
        resp = moderator_client.get("/moderation/?tab=log", follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers.get("Location", "").rstrip("/").endswith("/moderation/log")

    def test_activity_log_pill_present_on_every_tab(self, moderator_client):
        for path in ("/moderation/", "/moderation/?tab=mastodon", "/moderation/log"):
            resp = moderator_client.get(path)
            assert resp.status_code == 200
            assert b'id="log-tab"' in resp.data


class TestModerationLogIpVisibility:
    # Two separate tests (rather than one test using both client fixtures)
    # deliberately: Flask's test client context manager doesn't nest cleanly
    # across two independently-logged-in fixtures active in the same test.
    def test_ip_hidden_for_moderator(self, moderator_client, seeded_rows):
        resp = moderator_client.get("/moderation/log")
        assert b"203.0.113.5" not in resp.data

    def test_ip_shown_for_admin(self, auth_client, seeded_rows):
        resp = auth_client.get("/moderation/log")
        assert b"203.0.113.5" in resp.data


class TestModerationLogDetailBadges:
    def test_sensitive_detail_value_never_rendered(self, moderator_client, seeded_rows):
        resp = moderator_client.get("/moderation/log")
        assert b"should-not-render" not in resp.data

    def test_non_sensitive_detail_is_rendered_as_a_badge(self, moderator_client, seeded_rows):
        resp = moderator_client.get("/moderation/log")
        assert b"account_id: 4242" in resp.data


class TestModerationLogLinks:
    def test_report_and_account_links_use_instance_url(self, moderator_client, seeded_rows, app):
        with app.app_context():
            original = Setting.get("moderation_mastodon_api_url", "")
            Setting.set("moderation_mastodon_api_url", "https://masto.test-only.example")
            db.session.commit()
        try:
            resp = moderator_client.get("/moderation/log")
            assert b"https://masto.test-only.example/admin/accounts/4242" in resp.data
            assert b"https://masto.test-only.example/admin/reports/99" in resp.data
        finally:
            with app.app_context():
                Setting.set("moderation_mastodon_api_url", original)
                db.session.commit()

    def test_no_link_rendered_when_instance_url_unset(self, moderator_client, seeded_rows, app):
        with app.app_context():
            original = Setting.get("moderation_mastodon_api_url", "")
            Setting.set("moderation_mastodon_api_url", "")
            db.session.commit()
        try:
            resp = moderator_client.get("/moderation/log")
            assert b"/admin/accounts/4242" not in resp.data
            assert b"/admin/reports/99" not in resp.data
        finally:
            with app.app_context():
                Setting.set("moderation_mastodon_api_url", original)
                db.session.commit()


class TestModerationLogFilters:
    def test_kind_filter_accounts(self, moderator_client, seeded_rows):
        resp = moderator_client.get("/moderation/log?kind=accounts")
        assert b'title="mastodon_account_suspend"' in resp.data
        assert b'title="mastodon_report_resolve"' not in resp.data

    def test_kind_filter_reports(self, moderator_client, seeded_rows):
        resp = moderator_client.get("/moderation/log?kind=reports")
        assert b'title="mastodon_report_resolve"' in resp.data
        assert b'title="mastodon_account_suspend"' not in resp.data

    def test_unknown_kind_is_ignored(self, moderator_client, seeded_rows):
        resp = moderator_client.get("/moderation/log?kind=not-a-real-kind")
        assert resp.status_code == 200
        assert b'title="mastodon_account_suspend"' in resp.data
        assert b'title="mastodon_report_resolve"' in resp.data

    def test_actor_filter_system(self, moderator_client, seeded_rows):
        resp = moderator_client.get("/moderation/log?actor=system")
        assert resp.status_code == 200
        assert b'title="moderation_check"' in resp.data
        assert b'title="mastodon_account_suspend"' not in resp.data

    def test_actor_filter_by_username(self, moderator_client, seeded_rows):
        resp = moderator_client.get("/moderation/log?actor=admin")
        assert resp.status_code == 200
        assert b'title="mastodon_account_suspend"' in resp.data
        assert b'title="moderation_check"' not in resp.data

    def test_q_filter_matches_resource_name(self, moderator_client, seeded_rows):
        resp = moderator_client.get("/moderation/log?q=suspended")
        assert b'title="mastodon_account_suspend"' in resp.data
        assert b'title="mastodon_report_resolve"' not in resp.data


class TestModerationLogPagination:
    def test_page_2_has_rows(self, moderator_client, app):
        with app.app_context():
            admin = User.query.filter_by(username="admin").first()
            rows = [
                AuditLog(
                    user_id=admin.id, action="mastodon_account_note", resource_type="mastodon_account",
                    resource_name=f"test-only-page-{i}",
                )
                for i in range(60)
            ]
            db.session.add_all(rows)
            db.session.commit()
            ids = [r.id for r in rows]
        try:
            resp = moderator_client.get("/moderation/log?kind=accounts&page=2")
            assert resp.status_code == 200
            assert b"test-only-page-" in resp.data
        finally:
            with app.app_context():
                AuditLog.query.filter(AuditLog.id.in_(ids)).delete(synchronize_session=False)
                db.session.commit()


class TestModerationLogPurgeRetention:
    def test_purge_respects_configurable_moderation_retention(self, app):
        from core.scheduler import _purge_old_audit_logs

        with app.app_context():
            original_retention = Setting.get("moderation_log_retention_days", "")
            Setting.set("moderation_log_retention_days", "365")
            db.session.commit()

            now = datetime.now(timezone.utc)
            rows = [
                AuditLog(
                    action="mastodon_account_suspend", resource_type="mastodon_account",
                    resource_name="test-only-purge-mod-survives", timestamp=now - timedelta(days=200),
                ),
                AuditLog(
                    action="user_add", resource_type="user",
                    resource_name="test-only-purge-general-deleted", timestamp=now - timedelta(days=200),
                ),
                AuditLog(
                    action="moderation_check", resource_type="moderation",
                    resource_name="test-only-purge-mod-deleted", timestamp=now - timedelta(days=400),
                ),
            ]
            db.session.add_all(rows)
            db.session.commit()
            ids = [r.id for r in rows]

        try:
            _purge_old_audit_logs(app)
            with app.app_context():
                remaining = {r.resource_name for r in AuditLog.query.filter(AuditLog.id.in_(ids)).all()}
            assert "test-only-purge-mod-survives" in remaining
            assert "test-only-purge-general-deleted" not in remaining
            assert "test-only-purge-mod-deleted" not in remaining
        finally:
            with app.app_context():
                AuditLog.query.filter(AuditLog.id.in_(ids)).delete(synchronize_session=False)
                Setting.set("moderation_log_retention_days", original_retention)
                db.session.commit()
