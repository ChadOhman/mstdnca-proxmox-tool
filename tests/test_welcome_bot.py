"""Tests for the welcome-bot feature: template rendering, ``MastodonBotClient``,
``send_welcome``, and the ``_send_welcomes`` step wired into ``run_watch_poll``.

Uses the real (file-backed, session-scoped) ``app`` fixture and real
``ModerationWelcome``/``ModerationAlert``/``ModerationWatch`` rows, same as
``tests/test_moderation_watch.py``. The Mastodon Admin/Bot API clients are
plain ``MagicMock()`` objects for the poll-integration tests; the transport
tests fake ``urllib.request.urlopen`` directly, mirroring
``TestClientTransport`` in ``tests/test_mastodon_moderation.py``.

``log_action`` and the moderation-watch notifier functions are patched
globally for every test in this module via an autouse fixture, since they are
side effects irrelevant to the behaviour under test here.
"""
import io
import json
import urllib.error
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from core.mastodon_admin import (
    DEFAULT_REPORT_NOTICE_TEMPLATE,
    DEFAULT_WELCOME_TEMPLATE,
    MAX_STATUS_CHARS,
    MastodonAPIError,
    MastodonBotClient,
    render_report_notice,
    render_report_notice_body,
    render_welcome,
    validate_report_notice_template,
    validate_welcome_template,
)

API = "https://masto.example"

_WELCOME_SETTINGS_KEYS = [
    "moderation_watch_alerts_enabled",
    "moderation_watch_new_account_cursor",
    "moderation_watch_silent_last_scan_at",
    "moderation_watch_last_run_at",
    "moderation_watch_last_run_result",
    "moderation_watch_backoff_until",
    "moderation_welcome_enabled",
    "moderation_welcome_template",
    "moderation_bot_token",
    "moderation_mastodon_api_url",
    "moderation_mastodon_max_chars",
    "moderation_mastodon_max_chars_checked_at",
    "moderation_report_notice_template",
]


def _resp(payload, headers=None, raw=None):
    """Build a context-manager mock that looks like a urlopen response."""
    m = MagicMock()
    m.__enter__.return_value = m
    m.read.return_value = raw if raw is not None else json.dumps(payload).encode()
    m.headers = headers or {}
    m.status = 200
    return m


def _http_error(code, body=None):
    fp = io.BytesIO(json.dumps(body).encode() if body is not None else b"")
    return urllib.error.HTTPError("https://masto.example/x", code, "reason", {}, fp)


@pytest.fixture(autouse=True)
def _patch_watch_dependencies(monkeypatch):
    """Patch log_action and the notifier functions for every test in this module."""
    import core.moderation_watch as mw
    import core.notifier as notifier_mod

    monkeypatch.setattr(mw, "log_action", MagicMock())
    monkeypatch.setattr(notifier_mod, "send_moderation_alert_notification", MagicMock(), raising=False)
    monkeypatch.setattr(notifier_mod, "send_moderation_silent_login_summary", MagicMock(), raising=False)
    yield


@pytest.fixture(autouse=True)
def _clean_welcome_state(app):
    """Reset every welcome/watch Setting and delete every relevant row after each test."""
    yield
    with app.app_context():
        from models import ModerationAlert, ModerationReportNotice, ModerationWatch, ModerationWelcome, Setting, db

        for key in _WELCOME_SETTINGS_KEYS:
            row = Setting.query.filter_by(key=key).first()
            if row:
                db.session.delete(row)
        ModerationWelcome.query.delete()
        ModerationReportNotice.query.delete()
        ModerationAlert.query.delete()
        ModerationWatch.query.delete()
        db.session.commit()


def _account(account_id, *, username="newbie", display_name="Newbie", acct=None, created_at=None):
    return {
        "id": account_id,
        "username": username,
        "display_name": display_name,
        "acct": acct or f"{username}@example.social",
        "created_at": created_at or datetime.now(timezone.utc).isoformat(),
        "statuses_count": 0,
        "last_status_at": None,
        "last_login_at": None,
    }


def _reporter(reporter_id, *, username="reporter", display_name=None, acct=None):
    return {
        "id": reporter_id,
        "username": username,
        "display_name": display_name or username.capitalize(),
        "acct": acct or f"{username}@example.social",
    }


def _client(list_local_accounts=None):
    client = MagicMock()
    client.budget_ok.return_value = True
    client.rate_limit = None
    client.list_local_accounts.return_value = [] if list_local_accounts is None else list_local_accounts
    client.account_statuses.return_value = []
    # A bare MagicMock() return value isn't JSON-serializable, and run_watch_poll
    # always persists its result -- give the status-limit refresh step something real.
    client.max_status_chars.return_value = 500
    return client


def _bot_client(*, budget_ok=True, verify_id="bot-1", post_status_id="9001"):
    bot = MagicMock()
    bot.budget_ok.return_value = budget_ok
    bot.verify.return_value = {"id": verify_id, "acct": "bot@example.social", "display_name": "Bot", "bot": True}
    bot.post_direct.return_value = {
        "id": post_status_id, "url": "u", "created_at": "", "excerpt": "", "sensitive": False,
        "media_count": 0, "visibility": "direct", "account_acct": None,
    }
    return bot


# ---------------------------------------------------------------------------
# render_welcome / validate_welcome_template
# ---------------------------------------------------------------------------


class TestRenderWelcome:
    def test_substitutes_all_three_variables(self):
        template = "Hi {username} aka {display_name} ({acct})"
        account = {"username": "bob", "display_name": "Bob B", "acct": "bob@example.social"}
        assert render_welcome(template, account) == "@bob Hi bob aka Bob B (bob@example.social)"

    def test_leaves_unknown_placeholder_literal(self):
        template = "Hello {username}, {foo} bar"
        account = {"username": "bob", "display_name": "Bob", "acct": "bob@example.social"}
        assert render_welcome(template, account) == "@bob Hello bob, {foo} bar"

    def test_prefixes_the_mention(self):
        template = "Welcome aboard!"
        account = {"username": "alice", "display_name": "Alice", "acct": "alice@example.social"}
        assert render_welcome(template, account) == "@alice Welcome aboard!"

    def test_display_name_falls_back_to_username(self):
        template = "Hi {display_name}"
        account = {"username": "carol", "display_name": "", "acct": "carol@example.social"}
        assert render_welcome(template, account) == "@carol Hi carol"

    def test_raises_over_500_chars(self):
        template = "x" * 600
        account = {"username": "bob", "display_name": "Bob", "acct": "bob@example.social"}
        with pytest.raises(ValueError, match="500"):
            render_welcome(template, account)


class TestValidateWelcomeTemplate:
    def test_empty_is_an_error(self):
        assert validate_welcome_template("") is not None
        assert validate_welcome_template("   ") is not None

    def test_over_length_is_an_error(self):
        assert validate_welcome_template("x" * 600) is not None

    def test_unbalanced_brace_is_an_error(self):
        assert validate_welcome_template("Hi {username") is not None
        assert validate_welcome_template("Hi { there") is not None

    def test_positional_field_is_an_error(self):
        assert validate_welcome_template("Hi {0}, welcome") is not None

    def test_good_template_is_none(self):
        assert validate_welcome_template("Welcome {username}! Enjoy your stay, {display_name}.") is None

    def test_default_template_validates(self):
        assert validate_welcome_template(DEFAULT_WELCOME_TEMPLATE) is None
        assert len(DEFAULT_WELCOME_TEMPLATE) <= MAX_STATUS_CHARS


# ---------------------------------------------------------------------------
# render_report_notice / validate_report_notice_template
# ---------------------------------------------------------------------------


class TestRenderReportNotice:
    def test_substitutes_all_four_variables(self):
        template = "Hi {username} aka {display_name} ({acct}), re report #{report_id}"
        reporter = {"username": "bob", "display_name": "Bob B", "acct": "bob@example.social"}

        result = render_report_notice(template, reporter, 42)

        assert result == "@bob@example.social Hi bob aka Bob B (bob@example.social), re report #42"

    def test_remote_acct_used_in_the_mention(self):
        template = "Thanks for #{report_id}"
        reporter = {"username": "carol", "display_name": "Carol", "acct": "carol@remote.example"}

        result = render_report_notice(template, reporter, 7)

        assert result.startswith("@carol@remote.example ")

    def test_body_helper_has_no_mention(self):
        template = "Hi {username}, re #{report_id}"
        reporter = {"username": "dan", "display_name": "Dan", "acct": "dan@example.social"}

        body = render_report_notice_body(template, reporter, 3)

        assert body == "Hi dan, re #3"
        assert "@" not in body

    def test_raises_over_limit_with_report_notice_label(self):
        template = "x" * 600
        reporter = {"username": "eve", "display_name": "Eve", "acct": "eve@example.social"}

        with pytest.raises(ValueError, match="Report notice"):
            render_report_notice(template, reporter, 1)

    def test_max_chars_override_accepts_a_long_body(self):
        template = "y" * 1500 + " #{report_id}"
        reporter = {"username": "fay", "display_name": "Fay", "acct": "fay@example.social"}

        result = render_report_notice(template, reporter, 9, max_chars=5000)

        assert len(result) < 5000


class TestValidateReportNoticeTemplate:
    def test_empty_is_an_error(self):
        assert validate_report_notice_template("") is not None
        assert validate_report_notice_template("   ") is not None

    def test_unbalanced_brace_is_an_error(self):
        assert validate_report_notice_template("Hi {username") is not None
        assert validate_report_notice_template("Hi { there") is not None

    def test_positional_field_is_an_error(self):
        assert validate_report_notice_template("Hi {0}, thanks") is not None

    def test_over_length_is_an_error(self):
        assert validate_report_notice_template("x" * 600) is not None

    def test_default_template_validates(self):
        assert validate_report_notice_template(DEFAULT_REPORT_NOTICE_TEMPLATE) is None
        assert len(DEFAULT_REPORT_NOTICE_TEMPLATE) <= 270

    def test_max_chars_is_honoured(self):
        template = "x" * 200 + " #{report_id}"

        assert validate_report_notice_template(template) is None
        assert validate_report_notice_template(template, max_chars=120) is not None


# ---------------------------------------------------------------------------
# MastodonBotClient
# ---------------------------------------------------------------------------


class TestMastodonBotClient:
    @patch("core.mastodon_admin.open_no_redirect")
    def test_post_direct_body_headers_and_bearer(self, mock_urlopen):
        mock_urlopen.return_value = _resp({
            "id": "9001", "url": "u9001", "created_at": "2026-09-21T00:00:00Z",
            "content": "hi", "account": {"acct": "bot@example.social"},
        })
        client = MastodonBotClient(API, "tok123")

        client.post_direct("hello there", idempotency_key="welcome-55")

        req = mock_urlopen.call_args[0][0]
        assert req.get_header("Authorization") == "Bearer tok123"
        assert req.get_header("Idempotency-key") == "welcome-55"
        body = json.loads(mock_urlopen.call_args[1]["data"].decode())
        assert body == {"status": "hello there", "visibility": "direct"}

    @patch("core.mastodon_admin.open_no_redirect")
    def test_post_direct_returns_summarized_status(self, mock_urlopen):
        mock_urlopen.return_value = _resp({
            "id": "9001", "url": "u9001", "created_at": "2026-09-21T00:00:00Z",
            "content": "hi", "account": {"acct": "bot@example.social"},
        })
        client = MastodonBotClient(API, "tok123")

        out = client.post_direct("hello", idempotency_key="welcome-55")

        assert out["id"] == "9001"
        assert out["account_acct"] == "bot@example.social"

    @patch("core.mastodon_admin.open_no_redirect")
    def test_post_direct_raises_on_http_error(self, mock_urlopen):
        mock_urlopen.side_effect = _http_error(422, {"error": "Text can't be blank"})
        client = MastodonBotClient(API, "tok123")

        with pytest.raises(MastodonAPIError):
            client.post_direct("", idempotency_key="welcome-1")

    @patch("core.mastodon_admin.open_no_redirect")
    def test_verify_reduces_fields(self, mock_urlopen):
        mock_urlopen.return_value = _resp({
            "id": "9", "acct": "bot@example.social", "display_name": "Bot", "bot": True,
            "email": "bot@example.social", "locked": False,
        })
        client = MastodonBotClient(API, "tok123")

        out = client.verify()

        assert out == {"id": "9", "acct": "bot@example.social", "display_name": "Bot", "bot": True}


# ---------------------------------------------------------------------------
# send_welcome
# ---------------------------------------------------------------------------


class TestSendWelcome:
    def test_creates_record_and_audits(self, app):
        import core.moderation_watch as mw

        with app.app_context():
            bot = _bot_client(post_status_id="1001")
            account = _account("55")

            record, err = mw.send_welcome(bot, account)

            assert err is None
            assert record is not None
            assert record.mastodon_account_id == "55"
            assert record.acct == account["acct"]
            assert record.status_id == "1001"
            assert record.sent_by_user_id is None
            bot.post_direct.assert_called_once()
            _, kwargs = bot.post_direct.call_args
            assert kwargs["idempotency_key"] == "welcome-55"

            mw.log_action.assert_called_once()
            args, kwargs = mw.log_action.call_args
            assert args[0] == "mastodon_welcome_send"
            assert kwargs.get("audience") == "moderators"
            assert kwargs["details"]["automatic"] is True

    def test_second_call_already_welcomed_no_post(self, app):
        from core.moderation_watch import send_welcome
        from models import ModerationWelcome

        with app.app_context():
            bot = _bot_client()
            account = _account("56")

            first, first_err = send_welcome(bot, account)
            assert first_err is None

            second, second_err = send_welcome(bot, account)

            assert second is None
            assert second_err == "already welcomed"
            assert bot.post_direct.call_count == 1
            assert ModerationWelcome.query.filter_by(mastodon_account_id="56").count() == 1

    def test_force_reposts_and_updates_record(self, app):
        from core.moderation_watch import send_welcome

        with app.app_context():
            bot = _bot_client(post_status_id="1001")
            account = _account("57")

            first, _ = send_welcome(bot, account)
            first_status_id = first.status_id

            bot.post_direct.return_value = {
                "id": "2002", "url": "u", "created_at": "", "excerpt": "", "sensitive": False,
                "media_count": 0, "visibility": "direct", "account_acct": None,
            }
            second, err = send_welcome(bot, account, force=True)

            assert err is None
            assert bot.post_direct.call_count == 2
            assert second.id == first.id
            assert second.status_id == "2002"
            assert second.status_id != first_status_id

    def test_mastodon_api_error_leaves_no_record(self, app):
        from core.moderation_watch import send_welcome
        from models import ModerationWelcome

        with app.app_context():
            bot = _bot_client()
            bot.post_direct.side_effect = MastodonAPIError("Text can't be blank")
            account = _account("58")

            record, err = send_welcome(bot, account)

            assert record is None
            assert err == "Text can't be blank"
            assert ModerationWelcome.query.filter_by(mastodon_account_id="58").count() == 0

    def test_rendering_error_never_posts(self, app):
        from core.moderation_watch import send_welcome

        with app.app_context():
            bot = _bot_client()
            account = _account("59")

            record, err = send_welcome(bot, account, template="x" * 600)

            assert record is None
            from core.moderation_watch import WELCOME_RENDER_ERROR

            assert err == WELCOME_RENDER_ERROR  # fixed text: never the exception message
            bot.post_direct.assert_not_called()


# ---------------------------------------------------------------------------
# send_report_notice
# ---------------------------------------------------------------------------


class TestSendReportNotice:
    def test_creates_record_and_audits(self, app):
        import core.moderation_watch as mw

        with app.app_context():
            bot = _bot_client(post_status_id="3001")
            reporter = _reporter("r1")

            record, err = mw.send_report_notice(bot, "101", reporter)

            assert err is None
            assert record is not None
            assert record.report_id == "101"
            assert record.reporter_account_id == "r1"
            assert record.reporter_acct == reporter["acct"]
            assert record.status_id == "3001"
            assert record.sent_by_user_id is None
            bot.post_direct.assert_called_once()
            _, kwargs = bot.post_direct.call_args
            assert kwargs["idempotency_key"] == "report-notice-101"

            mw.log_action.assert_called_once()
            args, kwargs = mw.log_action.call_args
            assert args[0] == "mastodon_report_notice_send"
            assert kwargs.get("audience") == "moderators"
            assert kwargs["details"]["report_id"] == "101"
            assert kwargs["details"]["reporter_acct"] == reporter["acct"]
            assert kwargs["details"]["forced"] is False

    def test_second_call_already_notified_no_post(self, app):
        from core.moderation_watch import send_report_notice
        from models import ModerationReportNotice

        with app.app_context():
            bot = _bot_client()
            reporter = _reporter("r2")

            first, first_err = send_report_notice(bot, "102", reporter)
            assert first_err is None

            second, second_err = send_report_notice(bot, "102", reporter)

            assert second is None
            assert second_err == "already notified"
            assert bot.post_direct.call_count == 1
            assert ModerationReportNotice.query.filter_by(report_id="102").count() == 1

    def test_force_reposts_with_new_idempotency_key_and_updates_record(self, app):
        from core.moderation_watch import send_report_notice

        with app.app_context():
            bot = _bot_client(post_status_id="3001")
            reporter = _reporter("r3")

            first, _ = send_report_notice(bot, "103", reporter)
            _, first_kwargs = bot.post_direct.call_args
            first_key = first_kwargs["idempotency_key"]

            bot.post_direct.return_value = {
                "id": "3002", "url": "u", "created_at": "", "excerpt": "", "sensitive": False,
                "media_count": 0, "visibility": "direct", "account_acct": None,
            }
            second, err = send_report_notice(bot, "103", reporter, force=True)

            assert err is None
            assert bot.post_direct.call_count == 2
            _, second_kwargs = bot.post_direct.call_args
            assert second_kwargs["idempotency_key"] != first_key
            assert second.id == first.id
            assert second.status_id == "3002"

    def test_edited_text_used_verbatim_with_mention_prefixed(self, app):
        from core.moderation_watch import send_report_notice

        with app.app_context():
            bot = _bot_client()
            reporter = _reporter("r4", acct="r4@remote.example")

            record, err = send_report_notice(bot, "104", reporter, text="Custom thank you message.")

            assert err is None
            args, _ = bot.post_direct.call_args
            assert args[0] == "@r4@remote.example Custom thank you message."

    def test_over_length_edited_text_posts_nothing_and_error_mentions_limit(self, app):
        from core.moderation_watch import send_report_notice

        with app.app_context():
            bot = _bot_client()
            reporter = _reporter("r5")

            record, err = send_report_notice(bot, "105", reporter, text="x" * 600)

            assert record is None
            assert "Message would be" in err
            assert str(MAX_STATUS_CHARS) in err
            bot.post_direct.assert_not_called()

    def test_api_error_leaves_no_row(self, app):
        from core.moderation_watch import send_report_notice
        from models import ModerationReportNotice

        with app.app_context():
            bot = _bot_client()
            bot.post_direct.side_effect = MastodonAPIError("Text can't be blank")
            reporter = _reporter("r6")

            record, err = send_report_notice(bot, "106", reporter)

            assert record is None
            assert err == "Text can't be blank"
            assert ModerationReportNotice.query.filter_by(report_id="106").count() == 0

    def test_rendering_error_never_posts(self, app):
        from core.moderation_watch import REPORT_NOTICE_RENDER_ERROR, send_report_notice
        from models import Setting

        with app.app_context():
            Setting.set("moderation_report_notice_template", "x" * 600)
            bot = _bot_client()
            reporter = _reporter("r7")

            record, err = send_report_notice(bot, "107", reporter)

            assert record is None
            assert err == REPORT_NOTICE_RENDER_ERROR  # fixed text: never the exception message
            bot.post_direct.assert_not_called()

    def test_stored_limit_of_5000_lets_a_long_text_through(self, app):
        from core.moderation_watch import send_report_notice
        from models import Setting

        with app.app_context():
            Setting.set("moderation_mastodon_max_chars", "5000")
            bot = _bot_client()
            reporter = _reporter("r8")

            record, err = send_report_notice(bot, "108", reporter, text="y" * 1500)

            assert err is None
            assert record is not None
            bot.post_direct.assert_called_once()


# ---------------------------------------------------------------------------
# _send_welcomes / run_watch_poll integration
# ---------------------------------------------------------------------------


class TestSendWelcomesIntegration:
    def test_bootstrap_run_sends_nothing(self, app):
        from core.moderation_watch import run_watch_poll
        from models import Setting

        now = datetime.now(timezone.utc)
        with app.app_context():
            Setting.set("moderation_watch_silent_last_scan_at", now.isoformat())
            Setting.set("moderation_welcome_enabled", "true")
            newest = _account("a1", username="a", created_at=now.isoformat())
            client = _client(list_local_accounts=[newest])
            bot = _bot_client()

            result = run_watch_poll(client, bot_client=bot, now=now)

            assert result["bootstrapped"] is True
            assert result["welcomed"] == 0
            bot.post_direct.assert_not_called()

    def test_second_run_welcomes_new_accounts_and_records_them(self, app):
        from core.moderation_watch import run_watch_poll
        from models import ModerationWelcome, Setting

        now = datetime.now(timezone.utc)
        with app.app_context():
            Setting.set("moderation_watch_silent_last_scan_at", now.isoformat())
            Setting.set("moderation_watch_new_account_cursor", (now - timedelta(days=1)).isoformat())
            Setting.set("moderation_welcome_enabled", "true")
            new_acct = _account("n1", username="newbie", created_at=now.isoformat())
            client = _client(list_local_accounts=[new_acct])
            bot = _bot_client()

            result = run_watch_poll(client, bot_client=bot, now=now)

            assert result["welcomed"] == 1
            bot.post_direct.assert_called_once()
            assert ModerationWelcome.query.filter_by(mastodon_account_id="n1").count() == 1

    def test_disabled_setting_sends_nothing(self, app):
        from core.moderation_watch import run_watch_poll
        from models import Setting

        now = datetime.now(timezone.utc)
        with app.app_context():
            Setting.set("moderation_watch_silent_last_scan_at", now.isoformat())
            Setting.set("moderation_watch_new_account_cursor", (now - timedelta(days=1)).isoformat())
            # moderation_welcome_enabled left at its "false" default
            new_acct = _account("n1b", username="newbie2", created_at=now.isoformat())
            client = _client(list_local_accounts=[new_acct])
            bot = _bot_client()

            result = run_watch_poll(client, bot_client=bot, now=now)

            assert result["welcomed"] == 0
            bot.post_direct.assert_not_called()

    def test_skips_already_welcomed_and_bots_own_account(self, app):
        from core.moderation_watch import run_watch_poll
        from models import ModerationWelcome, Setting, db

        now = datetime.now(timezone.utc)
        with app.app_context():
            Setting.set("moderation_watch_silent_last_scan_at", now.isoformat())
            Setting.set("moderation_watch_new_account_cursor", (now - timedelta(days=1)).isoformat())
            Setting.set("moderation_welcome_enabled", "true")

            db.session.add(ModerationWelcome(mastodon_account_id="w1", acct="already@example.social"))
            db.session.commit()

            bot_owned = _account("bot-1", username="bot", created_at=(now - timedelta(hours=1)).isoformat())
            already_welcomed = _account("w1", username="already", created_at=(now - timedelta(hours=2)).isoformat())
            fresh = _account("f1", username="fresh", created_at=(now - timedelta(hours=3)).isoformat())
            client = _client(list_local_accounts=[bot_owned, already_welcomed, fresh])
            bot = _bot_client(verify_id="bot-1")

            result = run_watch_poll(client, bot_client=bot, now=now)

            assert result["welcomed"] == 1
            bot.post_direct.assert_called_once()
            _, kwargs = bot.post_direct.call_args
            assert kwargs["idempotency_key"] == "welcome-f1"
            assert ModerationWelcome.query.filter_by(mastodon_account_id="bot-1").count() == 0

    def test_respects_the_per_run_cap(self, app, monkeypatch):
        import core.moderation_watch as mw
        from models import ModerationWelcome, Setting

        monkeypatch.setattr(mw, "MAX_WELCOMES_PER_RUN", 2)

        now = datetime.now(timezone.utc)
        with app.app_context():
            Setting.set("moderation_watch_silent_last_scan_at", now.isoformat())
            Setting.set("moderation_watch_new_account_cursor", (now - timedelta(days=1)).isoformat())
            Setting.set("moderation_welcome_enabled", "true")

            accounts = [
                _account(f"cap{i}", username=f"cap{i}", created_at=(now - timedelta(hours=i)).isoformat())
                for i in range(4)
            ]
            client = _client(list_local_accounts=accounts)
            bot = _bot_client()

            result = mw.run_watch_poll(client, bot_client=bot, now=now)

            assert result["welcomed"] == 2
            assert ModerationWelcome.query.count() == 2

    def test_stops_and_defers_when_budget_not_ok(self, app):
        from core.moderation_watch import run_watch_poll
        from models import ModerationWelcome, Setting

        now = datetime.now(timezone.utc)
        with app.app_context():
            Setting.set("moderation_watch_silent_last_scan_at", now.isoformat())
            Setting.set("moderation_watch_new_account_cursor", (now - timedelta(days=1)).isoformat())
            Setting.set("moderation_welcome_enabled", "true")

            new_acct = _account("bud1", username="bud1", created_at=now.isoformat())
            client = _client(list_local_accounts=[new_acct])
            bot = _bot_client(budget_ok=False)

            result = run_watch_poll(client, bot_client=bot, now=now)

            assert result["deferred"] is True
            assert result["welcomed"] == 0
            bot.post_direct.assert_not_called()
            assert ModerationWelcome.query.count() == 0

    def test_send_errors_land_in_result_errors(self, app):
        from core.moderation_watch import run_watch_poll
        from models import Setting

        now = datetime.now(timezone.utc)
        with app.app_context():
            Setting.set("moderation_watch_silent_last_scan_at", now.isoformat())
            Setting.set("moderation_watch_new_account_cursor", (now - timedelta(days=1)).isoformat())
            Setting.set("moderation_welcome_enabled", "true")

            new_acct = _account("err1", username="err1", created_at=now.isoformat())
            client = _client(list_local_accounts=[new_acct])
            bot = _bot_client()
            bot.post_direct.side_effect = MastodonAPIError("Text can't be blank")

            result = run_watch_poll(client, bot_client=bot, now=now)

            assert result["welcomed"] == 0
            assert any("send_welcome" in e for e in result["errors"])

    def test_welcomed_count_persisted_in_run_json(self, app):
        from core.moderation_watch import run_watch_poll
        from models import Setting

        now = datetime.now(timezone.utc)
        with app.app_context():
            Setting.set("moderation_watch_silent_last_scan_at", now.isoformat())
            Setting.set("moderation_watch_new_account_cursor", (now - timedelta(days=1)).isoformat())
            Setting.set("moderation_welcome_enabled", "true")

            new_acct = _account("json1", username="json1", created_at=now.isoformat())
            client = _client(list_local_accounts=[new_acct])
            bot = _bot_client()

            run_watch_poll(client, bot_client=bot, now=now)

            payload = json.loads(Setting.get("moderation_watch_last_run_result"))
            assert payload["welcomed"] == 1

    def test_verify_failure_does_not_block_welcomes(self, app):
        """A broken bot token (verify() fails) still lets welcomes go out -- just
        without the self-exclusion check."""
        from core.moderation_watch import run_watch_poll
        from models import Setting

        now = datetime.now(timezone.utc)
        with app.app_context():
            Setting.set("moderation_watch_silent_last_scan_at", now.isoformat())
            Setting.set("moderation_watch_new_account_cursor", (now - timedelta(days=1)).isoformat())
            Setting.set("moderation_welcome_enabled", "true")

            new_acct = _account("verr1", username="verr1", created_at=now.isoformat())
            client = _client(list_local_accounts=[new_acct])
            bot = _bot_client()
            bot.verify.side_effect = MastodonAPIError("bad token")

            result = run_watch_poll(client, bot_client=bot, now=now)

            assert result["welcomed"] == 1
