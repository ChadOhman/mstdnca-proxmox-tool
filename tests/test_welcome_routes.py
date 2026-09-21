"""Tests for the welcome-bot routes: send/re-send, config save/test, and the
``welcomed_at`` annotation on ``/mastodon/new_accounts``.

See core/moderation_watch.py (send_welcome, build_bot_client, get_welcome_settings)
for the underlying logic (covered by tests/test_welcome_bot.py) and
routes/moderation.py for the route implementations under test here.
"""

from unittest.mock import MagicMock, patch

import pytest

from core.mastodon_admin import MastodonAPIError

_SETTINGS_KEYS_TO_CLEAN = [
    "moderation_bot_token",
    "moderation_welcome_template",
    "moderation_welcome_enabled",
    "moderation_mastodon_api_url",
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
def _clean_welcome_state(app):
    yield
    with app.app_context():
        from models import ModerationWelcome, Setting, db

        for key in _SETTINGS_KEYS_TO_CLEAN:
            row = Setting.query.filter_by(key=key).first()
            if row:
                db.session.delete(row)
        ModerationWelcome.query.delete()
        db.session.commit()


# ---------------------------------------------------------------------------
# POST /mastodon/accounts/<id>/welcome
# ---------------------------------------------------------------------------


class TestWelcomeSend:
    def test_not_configured_is_400(self, auth_client):
        with patch("routes.moderation._get_bot_client", return_value=(None, "Welcome bot token not configured")):
            resp = auth_client.post(
                "/moderation/mastodon/accounts/42/welcome",
                data={"acct": "newbie@example.social"},
            )
        assert resp.status_code == 400
        assert resp.get_json() == {"ok": False, "error": "Welcome bot is not configured"}

    def test_blank_acct_is_400(self, auth_client, bot_client):
        resp = auth_client.post("/moderation/mastodon/accounts/42/welcome", data={})
        assert resp.status_code == 400
        bot_client.post_direct.assert_not_called()

    def test_send_creates_record_and_returns_manual(self, app, auth_client, bot_client):
        bot_client.post_direct.return_value = {"id": "9", "url": "u", "account_acct": None}
        resp = auth_client.post(
            "/moderation/mastodon/accounts/42/welcome",
            data={"acct": "newbie@example.social", "display_name": "Newbie"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["welcome"]["status_id"] == "9"
        assert data["welcome"]["automatic"] is False
        assert data["welcome"]["sent_at"] is not None

        with app.app_context():
            from models import ModerationWelcome
            rec = ModerationWelcome.query.filter_by(mastodon_account_id="42").first()
            assert rec is not None
            assert rec.acct == "newbie@example.social"
            assert rec.status_id == "9"
            assert rec.sent_by_user_id is not None

    def test_second_send_is_409_already_welcomed(self, auth_client, bot_client):
        bot_client.post_direct.return_value = {"id": "9", "url": "u", "account_acct": None}
        first = auth_client.post(
            "/moderation/mastodon/accounts/43/welcome", data={"acct": "dup@example.social"}
        )
        assert first.status_code == 200

        second = auth_client.post(
            "/moderation/mastodon/accounts/43/welcome", data={"acct": "dup@example.social"}
        )
        assert second.status_code == 409
        assert second.get_json() == {"ok": False, "error": "already welcomed"}
        assert bot_client.post_direct.call_count == 1

    def test_force_resends(self, auth_client, bot_client):
        bot_client.post_direct.return_value = {"id": "9", "url": "u", "account_acct": None}
        auth_client.post("/moderation/mastodon/accounts/44/welcome", data={"acct": "again@example.social"})

        bot_client.post_direct.return_value = {"id": "10", "url": "u", "account_acct": None}
        resp = auth_client.post(
            "/moderation/mastodon/accounts/44/welcome",
            data={"acct": "again@example.social", "force": "1"},
        )
        assert resp.status_code == 200
        assert resp.get_json()["welcome"]["status_id"] == "10"
        assert bot_client.post_direct.call_count == 2

    def test_mastodon_error_is_502_and_no_row(self, app, auth_client, bot_client):
        bot_client.post_direct.side_effect = MastodonAPIError("Text can't be blank")
        resp = auth_client.post(
            "/moderation/mastodon/accounts/45/welcome", data={"acct": "broken@example.social"}
        )
        assert resp.status_code == 502
        assert resp.get_json()["error"] == "Text can't be blank"
        with app.app_context():
            from models import ModerationWelcome
            assert ModerationWelcome.query.filter_by(mastodon_account_id="45").count() == 0

    def test_moderator_client_allowed(self, moderator_client, bot_client):
        bot_client.post_direct.return_value = {"id": "9", "url": "u", "account_acct": None}
        resp = moderator_client.post(
            "/moderation/mastodon/accounts/46/welcome", data={"acct": "mod@example.social"}
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# POST /mastodon/welcome/save
# ---------------------------------------------------------------------------


class TestWelcomeSave:
    def test_moderator_is_denied(self, moderator_client):
        resp = moderator_client.post(
            "/moderation/mastodon/welcome/save",
            data={"welcome_template": "Hi {username}"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert resp.headers.get("Location", "").endswith("/moderation/")

    def test_bad_template_saves_nothing(self, app, auth_client):
        with app.app_context():
            from models import Setting
            Setting.set("moderation_welcome_template", "original")

        resp = auth_client.post(
            "/moderation/mastodon/welcome/save",
            data={"welcome_template": "Hi {username", "welcome_enabled": "on"},
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            from models import Setting
            assert Setting.get("moderation_welcome_template") == "original"
            assert Setting.get("moderation_welcome_enabled", "false") == "false"

    def test_good_save_blank_token_keeps_existing(self, app, auth_client):
        from auth.credential_store import encrypt

        with app.app_context():
            from models import Setting
            Setting.set("moderation_bot_token", encrypt("test-only-existing-token"))

        resp = auth_client.post(
            "/moderation/mastodon/welcome/save",
            data={"welcome_template": "Hi {username}!", "welcome_enabled": "on"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "tab=mastodon" in resp.headers.get("Location", "")

        with app.app_context():
            from auth.credential_store import decrypt
            from models import Setting
            assert Setting.get("moderation_welcome_template") == "Hi {username}!"
            assert Setting.get("moderation_welcome_enabled") == "true"
            assert decrypt(Setting.get("moderation_bot_token")) == "test-only-existing-token"
        assert _last_audit(app, "moderation_welcome_config_save") is not None

    def test_good_save_with_token_encrypts_it(self, app, auth_client):
        resp = auth_client.post(
            "/moderation/mastodon/welcome/save",
            data={
                "welcome_template": "Hi {username}!",
                "bot_token": "test-only-new-bot-token",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            from auth.credential_store import decrypt
            from models import Setting
            assert decrypt(Setting.get("moderation_bot_token")) == "test-only-new-bot-token"
            # welcome_enabled was omitted from the form -> unchecked -> "false"
            assert Setting.get("moderation_welcome_enabled") == "false"


# ---------------------------------------------------------------------------
# POST /mastodon/welcome/test
# ---------------------------------------------------------------------------


class TestWelcomeTest:
    def test_returns_verified_account(self, auth_client, bot_client):
        bot_client.verify.return_value = {
            "id": "9", "acct": "bot@example.social", "display_name": "Bot", "bot": True,
        }
        resp = auth_client.post("/moderation/mastodon/welcome/test")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["account"]["acct"] == "bot@example.social"

    def test_moderator_is_denied(self, moderator_client, bot_client):
        resp = moderator_client.post("/moderation/mastodon/welcome/test", follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers.get("Location", "").endswith("/moderation/")


# ---------------------------------------------------------------------------
# GET /mastodon/new_accounts -- welcomed_at annotation
# ---------------------------------------------------------------------------


class TestNewAccountsWelcomedAt:
    def test_rows_carry_welcomed_at_null_and_set(self, app, auth_client):
        from models import ModerationWelcome, db

        with app.app_context():
            db.session.add(ModerationWelcome(mastodon_account_id="7", acct="w@d.example", status_id="1"))
            db.session.commit()

        client = MagicMock()
        client.list_local_accounts.return_value = [
            {"id": "7", "acct": "w@d.example", "created_at": "2026-01-01T00:00:00Z",
             "statuses_count": 0, "last_login_at": None},
            {"id": "8", "acct": "n@d.example", "created_at": "2026-01-01T00:00:00Z",
             "statuses_count": 0, "last_login_at": None},
        ]
        with patch("routes.moderation._get_mastodon_client", return_value=(client, None)):
            resp = auth_client.get("/moderation/mastodon/new_accounts")

        assert resp.status_code == 200
        accounts = {a["id"]: a["welcomed_at"] for a in resp.get_json()["accounts"]}
        assert accounts["7"] is not None
        assert accounts["8"] is None

        with app.app_context():
            ModerationWelcome.query.filter_by(mastodon_account_id="7").delete()
            db.session.commit()
