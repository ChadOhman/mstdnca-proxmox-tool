"""Tests for the reporter-notice routes: preview, send, and config save.

Mirrors tests/test_welcome_routes.py. See core/moderation_watch.py
(send_report_notice, report_notice_record, get_report_notice_settings) for
the underlying logic and routes/moderation.py for the route implementations
under test here.
"""

from unittest.mock import MagicMock, patch

import pytest

from core.mastodon_admin import MastodonAPIError

_SETTINGS_KEYS_TO_CLEAN = [
    "moderation_bot_token",
    "moderation_report_notice_template",
    "moderation_mastodon_api_url",
    "moderation_mastodon_max_chars",
]


def _last_audit(app, action):
    from models import AuditLog

    with app.app_context():
        return AuditLog.query.filter_by(action=action).order_by(AuditLog.id.desc()).first()


@pytest.fixture()
def bot_client():
    """Patch the route-level bot client factory with a MagicMock client."""
    client = MagicMock()
    with patch("routes.moderation._get_bot_client", return_value=(client, None)):
        yield client


@pytest.fixture(autouse=True)
def _clean_report_notice_state(app):
    yield
    with app.app_context():
        from models import ModerationReportNotice, Setting, db

        for key in _SETTINGS_KEYS_TO_CLEAN:
            row = Setting.query.filter_by(key=key).first()
            if row:
                db.session.delete(row)
        ModerationReportNotice.query.delete()
        db.session.commit()


# ---------------------------------------------------------------------------
# GET /mastodon/reports/<id>/notify/preview
# ---------------------------------------------------------------------------


class TestReportNoticePreview:
    def test_blank_acct_is_400(self, auth_client):
        resp = auth_client.get("/moderation/mastodon/reports/1/notify/preview")
        assert resp.status_code == 400

    def test_preview_returns_mention_text_and_max_chars(self, auth_client):
        resp = auth_client.get(
            "/moderation/mastodon/reports/1/notify/preview",
            query_string={"reporter_acct": "reporter@remote.example", "display_name": "Reporter"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["mention"] == "@reporter@remote.example"
        assert isinstance(data["text"], str)
        assert data["text"]
        assert isinstance(data["max_chars"], int)
        assert data["already_notified_at"] is None

    def test_preview_reflects_already_notified(self, app, auth_client):
        from models import ModerationReportNotice, db

        with app.app_context():
            db.session.add(ModerationReportNotice(
                report_id="1", reporter_account_id="9", reporter_acct="reporter@remote.example",
                status_id="s1",
            ))
            db.session.commit()

        resp = auth_client.get(
            "/moderation/mastodon/reports/1/notify/preview",
            query_string={"reporter_acct": "reporter@remote.example"},
        )
        assert resp.status_code == 200
        assert resp.get_json()["already_notified_at"] is not None

    def test_moderator_client_allowed(self, moderator_client):
        resp = moderator_client.get(
            "/moderation/mastodon/reports/1/notify/preview",
            query_string={"reporter_acct": "reporter@remote.example"},
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# POST /mastodon/reports/<id>/notify
# ---------------------------------------------------------------------------


class TestReportNotify:
    def test_not_configured_is_400(self, auth_client):
        with patch("routes.moderation._get_bot_client", return_value=(None, "Welcome bot token not configured")):
            resp = auth_client.post(
                "/moderation/mastodon/reports/1/notify",
                data={"reporter_acct": "reporter@remote.example", "text": "Thanks!"},
            )
        assert resp.status_code == 400
        assert resp.get_json() == {"ok": False, "error": "Welcome bot is not configured"}

    def test_blank_acct_is_400(self, auth_client, bot_client):
        resp = auth_client.post("/moderation/mastodon/reports/1/notify", data={"text": "Thanks!"})
        assert resp.status_code == 400
        bot_client.post_direct.assert_not_called()

    def test_blank_text_is_400(self, auth_client, bot_client):
        resp = auth_client.post(
            "/moderation/mastodon/reports/1/notify",
            data={"reporter_acct": "reporter@remote.example"},
        )
        assert resp.status_code == 400
        bot_client.post_direct.assert_not_called()

    def test_send_creates_record_and_returns_notice(self, app, auth_client, bot_client):
        bot_client.post_direct.return_value = {"id": "9", "url": "u", "account_acct": None}
        resp = auth_client.post(
            "/moderation/mastodon/reports/1/notify",
            data={
                "reporter_id": "42",
                "reporter_acct": "reporter@remote.example",
                "display_name": "Reporter",
                "text": "Thanks for reporting!",
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["notice"]["status_id"] == "9"
        assert data["notice"]["sent_at"] is not None

        with app.app_context():
            from models import ModerationReportNotice
            rec = ModerationReportNotice.query.filter_by(report_id="1").first()
            assert rec is not None
            assert rec.reporter_acct == "reporter@remote.example"
            assert rec.reporter_account_id == "42"
            assert rec.status_id == "9"
            assert rec.sent_by_user_id is not None

    def test_second_send_is_409_already_notified(self, auth_client, bot_client):
        bot_client.post_direct.return_value = {"id": "9", "url": "u", "account_acct": None}
        first = auth_client.post(
            "/moderation/mastodon/reports/2/notify",
            data={"reporter_acct": "dup@remote.example", "text": "Thanks!"},
        )
        assert first.status_code == 200

        second = auth_client.post(
            "/moderation/mastodon/reports/2/notify",
            data={"reporter_acct": "dup@remote.example", "text": "Thanks again!"},
        )
        assert second.status_code == 409
        assert second.get_json() == {"ok": False, "error": "already notified"}
        assert bot_client.post_direct.call_count == 1

    def test_force_resends_with_different_idempotency_key(self, auth_client, bot_client):
        bot_client.post_direct.return_value = {"id": "9", "url": "u", "account_acct": None}
        auth_client.post(
            "/moderation/mastodon/reports/3/notify",
            data={"reporter_acct": "again@remote.example", "text": "Thanks!"},
        )
        first_key = bot_client.post_direct.call_args.kwargs["idempotency_key"]

        bot_client.post_direct.return_value = {"id": "10", "url": "u", "account_acct": None}
        resp = auth_client.post(
            "/moderation/mastodon/reports/3/notify",
            data={"reporter_acct": "again@remote.example", "text": "Thanks again!", "force": "1"},
        )
        assert resp.status_code == 200
        assert resp.get_json()["notice"]["status_id"] == "10"
        assert bot_client.post_direct.call_count == 2
        second_key = bot_client.post_direct.call_args.kwargs["idempotency_key"]
        assert first_key != second_key

    def test_mastodon_error_is_502_and_no_row(self, app, auth_client, bot_client):
        bot_client.post_direct.side_effect = MastodonAPIError("Text can't be blank")
        resp = auth_client.post(
            "/moderation/mastodon/reports/4/notify",
            data={"reporter_acct": "broken@remote.example", "text": "Thanks!"},
        )
        assert resp.status_code == 502
        assert resp.get_json()["error"] == "Text can't be blank"
        with app.app_context():
            from models import ModerationReportNotice
            assert ModerationReportNotice.query.filter_by(report_id="4").count() == 0

    def test_over_limit_text_is_400(self, auth_client, bot_client):
        resp = auth_client.post(
            "/moderation/mastodon/reports/5/notify",
            data={"reporter_acct": "x@remote.example", "text": "a" * 600},
        )
        assert resp.status_code == 400
        assert "Message would be" in resp.get_json()["error"]
        bot_client.post_direct.assert_not_called()

    def test_moderator_client_allowed(self, moderator_client, bot_client):
        bot_client.post_direct.return_value = {"id": "9", "url": "u", "account_acct": None}
        resp = moderator_client.post(
            "/moderation/mastodon/reports/6/notify",
            data={"reporter_acct": "mod@remote.example", "text": "Thanks!"},
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# POST /mastodon/report_notice/save
# ---------------------------------------------------------------------------


class TestReportNoticeSave:
    def test_moderator_is_denied(self, moderator_client):
        resp = moderator_client.post(
            "/moderation/mastodon/report_notice/save",
            data={"report_notice_template": "Thanks {username}"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert resp.headers.get("Location", "").endswith("/moderation/")

    def test_bad_template_saves_nothing(self, app, auth_client):
        with app.app_context():
            from models import Setting
            Setting.set("moderation_report_notice_template", "original")

        resp = auth_client.post(
            "/moderation/mastodon/report_notice/save",
            data={"report_notice_template": "Thanks {username"},
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            from models import Setting
            assert Setting.get("moderation_report_notice_template") == "original"

    def test_good_template_persists_and_audits(self, app, auth_client):
        resp = auth_client.post(
            "/moderation/mastodon/report_notice/save",
            data={"report_notice_template": "Thanks for report #{report_id}, {username}!"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "tab=mastodon" in resp.headers.get("Location", "")

        with app.app_context():
            from models import Setting
            assert Setting.get("moderation_report_notice_template") == "Thanks for report #{report_id}, {username}!"
        assert _last_audit(app, "moderation_report_notice_config_save") is not None

    def test_template_fitting_1000_not_500_accepted_with_higher_limit(self, app, auth_client):
        with app.app_context():
            from models import Setting
            Setting.set("moderation_mastodon_max_chars", "1000")

        long_template = "Thanks {username}! " + ("x" * 700)
        resp = auth_client.post(
            "/moderation/mastodon/report_notice/save",
            data={"report_notice_template": long_template},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "tab=mastodon" in resp.headers.get("Location", "")

        with app.app_context():
            from models import Setting
            assert Setting.get("moderation_report_notice_template") == long_template
