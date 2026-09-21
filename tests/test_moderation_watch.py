"""Tests for core/moderation_watch.py: the watched-account poll, new-signup
discovery, and silent-login scan that back the (upcoming) moderation watch UI.

Uses the real (file-backed, session-scoped) ``app`` fixture and real
ModerationWatch/ModerationAlert rows rather than mocking the DB -- these
models and their query patterns are exactly what's under test. The Mastodon
Admin API client itself is a plain ``MagicMock()`` (not ``spec=``, since
``core.mastodon_admin.MastodonAdminClient`` is being extended by another
change landing concurrently on this branch).

``log_action`` and the two notifier functions are patched globally for every
test in this module via an autouse fixture, since they are side effects
(audit log broadcast, outbound notifications) that are irrelevant to the
behaviour under test here and are covered by their own test suites.
"""
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from core.mastodon_admin import MastodonAPIError

_WATCH_SETTINGS_KEYS = [
    "moderation_watch_alerts_enabled",
    "moderation_watch_poll_minutes",
    "moderation_watch_auto_watch_days",
    "moderation_watch_silent_login_days",
    "moderation_watch_silent_min_age_days",
    "moderation_watch_silent_scan_window_days",
    "moderation_watch_new_account_cursor",
    "moderation_watch_silent_last_scan_at",
    "moderation_watch_last_run_at",
    "moderation_watch_last_run_result",
    "moderation_watch_backoff_until",
]


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
def _clean_watch_state(app):
    """Reset every moderation-watch Setting and delete every watch/alert row after each test.

    These models and settings are only touched by this test module, so a
    blanket reset avoids state leaking between tests (the ``app`` fixture is
    session-scoped) without needing per-test try/finally bookkeeping.
    """
    yield
    with app.app_context():
        from models import ModerationAlert, ModerationWatch, Setting, db

        for key in _WATCH_SETTINGS_KEYS:
            row = Setting.query.filter_by(key=key).first()
            if row:
                db.session.delete(row)
        ModerationAlert.query.delete()
        ModerationWatch.query.delete()
        db.session.commit()


def _client(*, budget_ok=True, rate_limit=None, list_local_accounts=None, account_statuses=None):
    client = MagicMock()
    client.budget_ok.return_value = budget_ok
    client.rate_limit = rate_limit
    client.list_local_accounts.return_value = [] if list_local_accounts is None else list_local_accounts
    client.account_statuses.return_value = [] if account_statuses is None else account_statuses
    return client


def _silent_scan_client(accounts_for_silent_scan, *, budget_ok=True):
    """A client whose list_local_accounts only returns accounts on the silent-scan call
    (identified by ``max_pages=10``); the bootstrap/discover call always gets [].
    """
    client = MagicMock()
    client.budget_ok.return_value = budget_ok
    client.rate_limit = None
    client.account_statuses.return_value = []

    def _list_accounts(*args, **kwargs):
        if kwargs.get("max_pages") == 10:
            return accounts_for_silent_scan
        return []

    client.list_local_accounts.side_effect = _list_accounts
    return client


def _disable_discover_and_silent(now):
    """Pre-seed settings so discover/silent-login are no-ops for a check-watched-only test."""
    from models import Setting

    Setting.set("moderation_watch_new_account_cursor", now.isoformat())
    Setting.set("moderation_watch_silent_last_scan_at", now.isoformat())


# ---------------------------------------------------------------------------
# get_watch_settings
# ---------------------------------------------------------------------------


class TestGetWatchSettings:
    def test_defaults(self, app):
        from core.moderation_watch import get_watch_settings

        with app.app_context():
            settings = get_watch_settings()
            assert settings["alerts_enabled"] is False
            assert settings["poll_minutes"] == 5
            assert settings["auto_watch_days"] == 0
            assert settings["silent_login_days"] == 7
            assert settings["silent_min_age_days"] == 14
            assert settings["silent_scan_window_days"] == 90

    def test_auto_watch_days_clamped_to_0_90(self, app):
        from core.moderation_watch import get_watch_settings
        from models import Setting

        with app.app_context():
            Setting.set("moderation_watch_auto_watch_days", "500")
            assert get_watch_settings()["auto_watch_days"] == 90
            Setting.set("moderation_watch_auto_watch_days", "-5")
            assert get_watch_settings()["auto_watch_days"] == 0

    def test_alerts_enabled_parses_true(self, app):
        from core.moderation_watch import get_watch_settings
        from models import Setting

        with app.app_context():
            Setting.set("moderation_watch_alerts_enabled", "true")
            assert get_watch_settings()["alerts_enabled"] is True

    def test_non_numeric_falls_back_to_default(self, app):
        from core.moderation_watch import get_watch_settings
        from models import Setting

        with app.app_context():
            Setting.set("moderation_watch_silent_login_days", "not-a-number")
            assert get_watch_settings()["silent_login_days"] == 7


# ---------------------------------------------------------------------------
# record_alert
# ---------------------------------------------------------------------------


class TestRecordAlert:
    def test_creates_new_account_alert(self, app):
        from core.moderation_watch import record_alert
        from models import ModerationAlert

        with app.app_context():
            alert = record_alert("new_account", {"id": "acc1", "acct": "acc1@example.social"})
            assert alert is not None
            assert alert.kind == "new_account"
            assert ModerationAlert.query.filter_by(dedupe_key="new_account:acc1:").count() == 1

    def test_dedupe_returns_none_for_existing(self, app):
        from core.moderation_watch import record_alert

        with app.app_context():
            first = record_alert("new_account", {"id": "acc2", "acct": "acc2@example.social"})
            second = record_alert("new_account", {"id": "acc2", "acct": "acc2@example.social"})
            assert first is not None
            assert second is None

    def test_watched_post_alert_includes_status_fields(self, app):
        from core.moderation_watch import record_alert
        from models import ModerationAlert

        with app.app_context():
            status = {"id": "999", "url": "https://example.social/@x/999", "excerpt": "hello", "visibility": "public"}
            record_alert("watched_post", {"id": "acc3", "acct": "acc3@example.social"}, status)
            row = ModerationAlert.query.filter_by(dedupe_key="watched_post:acc3:999").first()
            assert row is not None
            assert row.status_url == status["url"]
            assert row.excerpt == "hello"

    def test_log_action_called_with_audience_moderators(self, app):
        import core.moderation_watch as mw

        with app.app_context():
            mw.record_alert("new_account", {"id": "acc4", "acct": "acc4@example.social"})

            mw.log_action.assert_called_once()
            args, kwargs = mw.log_action.call_args
            assert args[0] == "moderation_alert_new_account"
            assert kwargs.get("audience") == "moderators"

    def test_notifies_on_watched_post(self, app):
        import core.moderation_watch as mw
        import core.notifier as notifier_mod

        with app.app_context():
            status = {"id": "1001", "url": "u1001", "excerpt": "hey", "visibility": "public"}
            mw.record_alert("watched_post", {"id": "acc5", "acct": "acc5@example.social"}, status)

        notifier_mod.send_moderation_alert_notification.assert_called_once_with(
            "watched_post", "acc5@example.social", url="u1001", excerpt="hey"
        )

    def test_no_notify_when_notify_false(self, app):
        import core.moderation_watch as mw
        import core.notifier as notifier_mod

        with app.app_context():
            mw.record_alert(
                "silent_login", {"id": "acc6", "acct": "acc6@example.social", "excerpt": "x"}, notify=False
            )

        notifier_mod.send_moderation_alert_notification.assert_not_called()

    def test_integrity_error_race_returns_none(self, app, monkeypatch):
        from sqlalchemy.exc import IntegrityError

        from core.moderation_watch import record_alert
        from models import db

        with app.app_context():
            def _raise_flush():
                raise IntegrityError("INSERT", {}, Exception("unique constraint"))

            monkeypatch.setattr(db.session, "flush", _raise_flush)

            result = record_alert("new_account", {"id": "race1", "acct": "race@example.social"})
            assert result is None

        monkeypatch.undo()
        with app.app_context():
            from models import ModerationAlert

            assert ModerationAlert.query.filter_by(mastodon_account_id="race1").count() == 0


# ---------------------------------------------------------------------------
# run_watch_poll - new account discovery / bootstrap
# ---------------------------------------------------------------------------


class TestDiscoverNewAccounts:
    def test_bootstrap_sets_cursor_without_alerts(self, app):
        from core.moderation_watch import run_watch_poll
        from models import ModerationAlert, Setting

        now = datetime.now(timezone.utc)
        with app.app_context():
            Setting.set("moderation_watch_silent_last_scan_at", now.isoformat())
            assert Setting.get("moderation_watch_new_account_cursor") is None

            newest = {
                "id": "a2", "acct": "b@example.social", "created_at": "2026-09-20T12:00:00+00:00",
                "statuses_count": 0, "last_status_at": None, "last_login_at": None,
            }
            client = _client(list_local_accounts=[newest])

            result = run_watch_poll(client, now=now)

            assert result["bootstrapped"] is True
            assert Setting.get("moderation_watch_new_account_cursor") == "2026-09-20T12:00:00+00:00"
            assert ModerationAlert.query.count() == 0
            assert result["alerts"]["new_account"] == 0

    def test_second_run_produces_one_alert_and_advances_cursor(self, app):
        from core.moderation_watch import run_watch_poll
        from models import ModerationAlert, Setting

        now = datetime.now(timezone.utc)
        with app.app_context():
            Setting.set("moderation_watch_silent_last_scan_at", now.isoformat())
            Setting.set("moderation_watch_new_account_cursor", (now - timedelta(days=1)).isoformat())

            new_acct = {
                "id": "n1", "acct": "newbie@example.social", "username": "newbie",
                "created_at": now.isoformat(), "statuses_count": 0,
                "last_status_at": None, "last_login_at": None,
            }
            client = _client(list_local_accounts=[new_acct])

            result = run_watch_poll(client, now=now)

            client.list_local_accounts.assert_called_once()
            _, kwargs = client.list_local_accounts.call_args
            assert "newer_than" in kwargs

            assert result["alerts"]["new_account"] == 1
            assert ModerationAlert.query.filter_by(kind="new_account", mastodon_account_id="n1").count() == 1
            assert Setting.get("moderation_watch_new_account_cursor") == now.isoformat()

    def test_auto_watch_creates_expiring_watch(self, app):
        from core.moderation_watch import run_watch_poll
        from models import ModerationWatch, Setting

        now = datetime.now(timezone.utc)
        with app.app_context():
            Setting.set("moderation_watch_silent_last_scan_at", now.isoformat())
            Setting.set("moderation_watch_new_account_cursor", (now - timedelta(days=1)).isoformat())
            Setting.set("moderation_watch_auto_watch_days", "7")

            new_acct = {
                "id": "n2", "acct": "auto@example.social", "created_at": now.isoformat(),
                "statuses_count": 0, "last_status_at": None, "last_login_at": None,
            }
            client = _client(list_local_accounts=[new_acct])

            run_watch_poll(client, now=now)

            watch = ModerationWatch.query.filter_by(mastodon_account_id="n2").first()
            assert watch is not None
            assert watch.auto_added is True
            assert watch.last_status_id is None
            assert watch.expires_at is not None
            expected = (now + timedelta(days=7)).replace(tzinfo=None)
            assert abs((watch.expires_at - expected).total_seconds()) < 2

    def test_auto_watch_disabled_by_default(self, app):
        from core.moderation_watch import run_watch_poll
        from models import ModerationWatch, Setting

        now = datetime.now(timezone.utc)
        with app.app_context():
            Setting.set("moderation_watch_silent_last_scan_at", now.isoformat())
            Setting.set("moderation_watch_new_account_cursor", (now - timedelta(days=1)).isoformat())

            new_acct = {
                "id": "n3", "acct": "noauto@example.social", "created_at": now.isoformat(),
                "statuses_count": 0, "last_status_at": None, "last_login_at": None,
            }
            client = _client(list_local_accounts=[new_acct])

            run_watch_poll(client, now=now)

            assert ModerationWatch.query.filter_by(mastodon_account_id="n3").first() is None


# ---------------------------------------------------------------------------
# run_watch_poll - watched-post checks
# ---------------------------------------------------------------------------


class TestCheckWatched:
    def test_null_cursor_only_seeds(self, app):
        from core.moderation_watch import run_watch_poll
        from models import ModerationAlert, ModerationWatch, db

        now = datetime.now(timezone.utc)
        with app.app_context():
            _disable_discover_and_silent(now)
            db.session.add(ModerationWatch(mastodon_account_id="w-null", acct="w@example.social"))
            db.session.commit()

            client = _client(account_statuses=[
                {"id": "900", "url": "u900", "created_at": now.isoformat(), "excerpt": "hi", "visibility": "public"}
            ])

            result = run_watch_poll(client, now=now)

            client.account_statuses.assert_called_once_with("w-null", limit=1)
            watch = ModerationWatch.query.filter_by(mastodon_account_id="w-null").first()
            assert watch.last_status_id == "900"
            assert watch.last_checked_at is not None
            assert result["alerts"]["watched_post"] == 0
            assert ModerationAlert.query.filter_by(mastodon_account_id="w-null").count() == 0

    def test_since_id_passed_alerts_created_and_cursor_advances(self, app):
        from core.moderation_watch import run_watch_poll
        from models import ModerationAlert, ModerationWatch, db

        now = datetime.now(timezone.utc)
        with app.app_context():
            _disable_discover_and_silent(now)
            db.session.add(ModerationWatch(mastodon_account_id="w-since", acct="w@example.social",
                                            last_status_id="100"))
            db.session.commit()

            client = _client(account_statuses=[
                {"id": "103", "url": "u103", "created_at": now.isoformat(), "excerpt": "c", "visibility": "public"},
                {"id": "102", "url": "u102", "created_at": now.isoformat(), "excerpt": "b", "visibility": "public"},
                {"id": "101", "url": "u101", "created_at": now.isoformat(), "excerpt": "a", "visibility": "public"},
            ])

            result = run_watch_poll(client, now=now)

            client.account_statuses.assert_called_once_with("w-since", since_id="100")
            watch = ModerationWatch.query.filter_by(mastodon_account_id="w-since").first()
            assert watch.last_status_id == "103"
            assert result["alerts"]["watched_post"] == 3
            assert ModerationAlert.query.filter_by(mastodon_account_id="w-since").count() == 3

    def test_second_identical_run_dedupes(self, app):
        from core.moderation_watch import run_watch_poll
        from models import ModerationAlert, ModerationWatch, db

        now = datetime.now(timezone.utc)
        with app.app_context():
            _disable_discover_and_silent(now)
            db.session.add(ModerationWatch(mastodon_account_id="w-dup", acct="w@example.social",
                                            last_status_id="100"))
            db.session.commit()

            client = _client(account_statuses=[
                {"id": "101", "url": "u101", "created_at": now.isoformat(), "excerpt": "a", "visibility": "public"},
            ])

            first_result = run_watch_poll(client, now=now)
            assert first_result["alerts"]["watched_post"] == 1

            second_result = run_watch_poll(client, now=now)
            assert second_result["alerts"]["watched_post"] == 0

            assert ModerationAlert.query.filter_by(mastodon_account_id="w-dup").count() == 1

    def test_caps_requests_per_run(self, app, monkeypatch):
        import core.moderation_watch as mw
        from models import ModerationWatch, db

        monkeypatch.setattr(mw, "MAX_WATCH_REQUESTS_PER_RUN", 2)

        now = datetime.now(timezone.utc)
        with app.app_context():
            _disable_discover_and_silent(now)
            for i in range(4):
                db.session.add(ModerationWatch(mastodon_account_id=f"cap{i}", acct=f"cap{i}@example.social",
                                                last_status_id="1"))
            db.session.commit()

            client = _client()

            result = mw.run_watch_poll(client, now=now)

            assert result["checked"] == 2
            assert result["watch_total"] == 4

    def test_budget_not_ok_defers_and_leaves_watches_unchecked(self, app):
        from core.moderation_watch import run_watch_poll
        from models import ModerationWatch, db

        now = datetime.now(timezone.utc)
        with app.app_context():
            _disable_discover_and_silent(now)
            db.session.add(ModerationWatch(mastodon_account_id="bud1", acct="b@example.social"))
            db.session.commit()

            client = _client(budget_ok=False)

            result = run_watch_poll(client, now=now)

            assert result["deferred"] is True
            assert result["checked"] == 0
            watch = ModerationWatch.query.filter_by(mastodon_account_id="bud1").first()
            assert watch.last_checked_at is None


# ---------------------------------------------------------------------------
# run_watch_poll - silent login scan
# ---------------------------------------------------------------------------


class TestSilentLoginScan:
    def _account(self, now, *, age_days, login_days_ago, statuses_count=0):
        return {
            "id": "s-boundary", "acct": "silent@example.social", "statuses_count": statuses_count,
            "created_at": (now - timedelta(days=age_days)).isoformat(),
            "last_login_at": (now - timedelta(days=login_days_ago)).isoformat(),
            "last_status_at": None,
        }

    def test_flags_account_past_both_thresholds(self, app):
        from core.moderation_watch import run_watch_poll
        from models import ModerationAlert, Setting

        now = datetime.now(timezone.utc)
        with app.app_context():
            Setting.set("moderation_watch_silent_login_days", "7")
            Setting.set("moderation_watch_silent_min_age_days", "14")
            acct = self._account(now, age_days=20, login_days_ago=3)
            client = _silent_scan_client([acct])

            result = run_watch_poll(client, now=now)

            assert result["alerts"]["silent_login"] == 1
            alert = ModerationAlert.query.filter_by(kind="silent_login", mastodon_account_id="s-boundary").first()
            assert alert is not None
            assert "0 posts" in alert.excerpt
            assert Setting.get("moderation_watch_silent_last_scan_at") is not None

    @pytest.mark.parametrize("age_days,login_days_ago,should_flag", [
        (14, 7, True),    # exactly at both boundaries -> inclusive
        (13, 7, False),   # not old enough yet
        (14, 8, False),   # login too stale (not "recent" relative to threshold)
        (15, 6, True),    # comfortably past both thresholds
    ])
    def test_boundary_conditions(self, app, age_days, login_days_ago, should_flag):
        from core.moderation_watch import run_watch_poll
        from models import Setting

        now = datetime.now(timezone.utc)
        with app.app_context():
            Setting.set("moderation_watch_silent_login_days", "7")
            Setting.set("moderation_watch_silent_min_age_days", "14")
            acct = self._account(now, age_days=age_days, login_days_ago=login_days_ago)
            client = _silent_scan_client([acct])

            result = run_watch_poll(client, now=now)

            assert result["alerts"]["silent_login"] == (1 if should_flag else 0)

    def test_accounts_with_posts_are_not_flagged(self, app):
        from core.moderation_watch import run_watch_poll

        now = datetime.now(timezone.utc)
        with app.app_context():
            acct = self._account(now, age_days=20, login_days_ago=3, statuses_count=5)
            client = _silent_scan_client([acct])

            result = run_watch_poll(client, now=now)

            assert result["alerts"]["silent_login"] == 0

    def test_24h_gate_skips_repeat_scan(self, app):
        from core.moderation_watch import run_watch_poll
        from models import Setting

        now = datetime.now(timezone.utc)
        with app.app_context():
            recent_scan = (now - timedelta(hours=1)).isoformat()
            Setting.set("moderation_watch_silent_last_scan_at", recent_scan)

            acct = self._account(now, age_days=30, login_days_ago=1)
            client = _silent_scan_client([acct])

            result = run_watch_poll(client, now=now)

            assert result["alerts"]["silent_login"] == 0
            silent_scan_calls = [c for c in client.list_local_accounts.call_args_list
                                  if c.kwargs.get("max_pages") == 10]
            assert silent_scan_calls == []
            assert Setting.get("moderation_watch_silent_last_scan_at") == recent_scan

    def test_single_summary_call_for_multiple_flagged_accounts(self, app):
        import core.notifier as notifier_mod
        from core.moderation_watch import run_watch_poll

        now = datetime.now(timezone.utc)
        with app.app_context():
            accts = [self._account(now, age_days=30, login_days_ago=1) for _ in range(3)]
            for i, acct in enumerate(accts):
                acct["id"] = f"multi{i}"
                acct["acct"] = f"multi{i}@example.social"
            client = _silent_scan_client(accts)

            result = run_watch_poll(client, now=now)

            assert result["alerts"]["silent_login"] == 3
        notifier_mod.send_moderation_silent_login_summary.assert_called_once()
        args, _ = notifier_mod.send_moderation_silent_login_summary.call_args
        assert args[0] == 3
        assert len(args[1]) == 3


# ---------------------------------------------------------------------------
# run_watch_poll - prune
# ---------------------------------------------------------------------------


class TestPrune:
    def test_prunes_expired_watches(self, app):
        from core.moderation_watch import run_watch_poll
        from models import ModerationWatch, db

        now = datetime.now(timezone.utc)
        with app.app_context():
            _disable_discover_and_silent(now)
            db.session.add(ModerationWatch(mastodon_account_id="exp1", acct="e@example.social",
                                            expires_at=now - timedelta(days=1)))
            db.session.add(ModerationWatch(mastodon_account_id="keep1", acct="k@example.social"))
            db.session.commit()

            client = _client()
            run_watch_poll(client, now=now)

            remaining = {w.mastodon_account_id for w in ModerationWatch.query.all()}
            assert "exp1" not in remaining
            assert "keep1" in remaining

    def test_prunes_old_acknowledged_alerts_only(self, app):
        from core.moderation_watch import ALERT_RETENTION_DAYS, run_watch_poll
        from models import ModerationAlert, db

        now = datetime.now(timezone.utc)
        with app.app_context():
            _disable_discover_and_silent(now)
            db.session.add_all([
                ModerationAlert(kind="new_account", dedupe_key="new_account:old:", mastodon_account_id="old",
                                 acct="old@example.social",
                                 acknowledged_at=now - timedelta(days=ALERT_RETENTION_DAYS + 1)),
                ModerationAlert(kind="new_account", dedupe_key="new_account:old2:", mastodon_account_id="old2",
                                 acct="old2@example.social"),
                ModerationAlert(kind="new_account", dedupe_key="new_account:recent:", mastodon_account_id="recent",
                                 acct="recent@example.social", acknowledged_at=now - timedelta(days=1)),
            ])
            db.session.commit()

            client = _client()
            run_watch_poll(client, now=now)

            remaining_ids = {a.mastodon_account_id for a in ModerationAlert.query.all()}
            assert "old" not in remaining_ids
            assert "old2" in remaining_ids
            assert "recent" in remaining_ids


# ---------------------------------------------------------------------------
# run_watch_poll - error handling / rate limits
# ---------------------------------------------------------------------------


class TestErrorHandling:
    def test_one_step_error_does_not_stop_others(self, app):
        from core.moderation_watch import run_watch_poll

        now = datetime.now(timezone.utc)
        with app.app_context():
            client = _client()

            def _raise(*args, **kwargs):
                raise MastodonAPIError("boom", http_status=500)

            client.list_local_accounts.side_effect = _raise

            result = run_watch_poll(client, now=now)

            assert any("discover_new_accounts" in e for e in result["errors"])
            assert any("scan_silent_logins" in e for e in result["errors"])
            assert result["backoff_until"] is None

    def test_429_sets_backoff_and_aborts_remaining(self, app):
        from core.moderation_watch import run_watch_poll
        from models import Setting

        now = datetime.now(timezone.utc)
        with app.app_context():
            client = _client()

            def _raise(*args, **kwargs):
                raise MastodonAPIError("rate limited", http_status=429, retry_after=120)

            client.list_local_accounts.side_effect = _raise

            result = run_watch_poll(client, now=now)

            assert result["backoff_until"] is not None
            assert len(result["errors"]) == 1
            # scan_silent_logins never got to run since discover aborted the whole poll
            assert Setting.get("moderation_watch_silent_last_scan_at") is None


# ---------------------------------------------------------------------------
# run_watch_poll - persisted result shape
# ---------------------------------------------------------------------------


class TestPersistedResultShape:
    def test_persisted_json_shape_and_no_pii(self, app):
        from core.moderation_watch import run_watch_poll
        from models import Setting

        now = datetime.now(timezone.utc)
        with app.app_context():
            client = _client()
            run_watch_poll(client, now=now)

            raw = Setting.get("moderation_watch_last_run_result")
            assert raw is not None
            payload = json.loads(raw)
            assert set(payload.keys()) == {
                "checked", "watch_total", "alerts", "deferred", "bootstrapped",
                "backoff_until", "errors", "rate_limit",
            }
            lowered = raw.lower()
            assert "email" not in lowered
            assert '"ip"' not in lowered
            assert Setting.get("moderation_watch_last_run_at") is not None
