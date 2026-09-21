"""Tests for the moderation-watch routes: watched accounts, alerts, new local
account discovery, the manual poll trigger, the always-200 dashboard summary,
and the admin-only watch settings form.

See core/moderation_watch.py for the underlying poll logic (covered by
tests/test_moderation_watch.py) and routes/moderation.py for the route
implementations under test here.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from core.mastodon_admin import MastodonAdminClient, MastodonAPIError

# Every Setting key this module's tests may write, cleaned up after each test
# so nothing leaks into other test modules sharing the session-scoped ``app``.
_SETTINGS_KEYS_TO_CLEAN = [
    "moderation_watch_alerts_enabled",
    "moderation_watch_poll_minutes",
    "moderation_watch_auto_watch_days",
    "moderation_watch_silent_login_days",
    "moderation_watch_silent_min_age_days",
    "moderation_watch_silent_scan_window_days",
    "moderation_watch_last_run_at",
    "moderation_watch_last_run_result",
    "moderation_watch_backoff_until",
    "moderation_mastodon_api_url",
    "moderation_mastodon_api_token",
]


def _last_audit(app, action):
    from models import AuditLog

    with app.app_context():
        return AuditLog.query.filter_by(action=action).order_by(AuditLog.id.desc()).first()


@pytest.fixture()
def masto_client():
    """Patch the route-level client factory with a MagicMock client."""
    client = MagicMock(spec=MastodonAdminClient)
    with patch("routes.moderation._get_mastodon_client", return_value=(client, None)):
        yield client


@pytest.fixture(autouse=True)
def _clean_watch_state(app):
    """Delete every watch/alert row and moderation-watch Setting after each test.

    Also resets the module-level "manual poll running" flag in case a test
    left it set (e.g. the 409-while-running test sets it directly).
    """
    yield
    with app.app_context():
        from models import ModerationAlert, ModerationWatch, Setting, db

        for key in _SETTINGS_KEYS_TO_CLEAN:
            row = Setting.query.filter_by(key=key).first()
            if row:
                db.session.delete(row)
        ModerationAlert.query.delete()
        ModerationWatch.query.delete()
        db.session.commit()

    import routes.moderation as moderation_routes
    moderation_routes._watch_poll_state["running"] = False


def _add_watch(app, **kwargs):
    from models import ModerationWatch, db

    with app.app_context():
        defaults = {"mastodon_account_id": "1", "acct": "user@example.social", "reason": "test"}
        defaults.update(kwargs)
        watch = ModerationWatch(**defaults)
        db.session.add(watch)
        db.session.commit()
        return watch.id


def _add_alert(app, **kwargs):
    from models import ModerationAlert, db

    with app.app_context():
        defaults = {"kind": "watched_post", "mastodon_account_id": "1", "acct": "user@example.social"}
        defaults.update(kwargs)
        defaults.setdefault(
            "dedupe_key",
            ModerationAlert.make_dedupe_key(defaults["kind"], defaults["mastodon_account_id"], defaults.get("status_id")),
        )
        alert = ModerationAlert(**defaults)
        db.session.add(alert)
        db.session.commit()
        return alert.id


class _SyncThread:
    """A drop-in ``threading.Thread`` replacement that runs ``target`` inline
    on ``start()``, so a route's background-job test can assert on the result
    deterministically instead of racing a real thread."""

    def __init__(self, target=None, daemon=None):
        self._target = target

    def start(self):
        self._target()


# ---------------------------------------------------------------------------
# POST /mastodon/watch (add)
# ---------------------------------------------------------------------------


class TestWatchAdd:
    def test_add_seeds_last_status_id_and_audits(self, app, auth_client, masto_client):
        masto_client.account_statuses.return_value = [{"id": "555", "url": "https://x/555"}]
        resp = auth_client.post("/moderation/mastodon/watch", data={
            "account_id": "42", "acct": "newbie@example.social", "reason": "watching closely", "days": "10",
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["watch"]["acct"] == "newbie@example.social"
        assert data["watch"]["reason"] == "watching closely"
        masto_client.account_statuses.assert_called_once_with("42", limit=1)

        with app.app_context():
            from models import ModerationWatch
            watch = ModerationWatch.query.filter_by(mastodon_account_id="42").first()
            assert watch is not None
            assert watch.last_status_id == "555"
            assert watch.expires_at is not None

        entry = _last_audit(app, "mastodon_watch_add")
        assert entry.resource_name == "newbie@example.social"
        assert entry.details == {"account_id": "42", "days": 10}

    def test_add_zero_days_is_indefinite_and_no_prior_statuses(self, app, auth_client, masto_client):
        masto_client.account_statuses.return_value = []
        resp = auth_client.post("/moderation/mastodon/watch", data={
            "account_id": "43", "acct": "x@y.example", "days": "0",
        })
        assert resp.status_code == 200
        with app.app_context():
            from models import ModerationWatch
            watch = ModerationWatch.query.filter_by(mastodon_account_id="43").first()
            assert watch.expires_at is None
            assert watch.last_status_id is None

    def test_add_duplicate_is_409(self, app, auth_client, masto_client):
        _add_watch(app, mastodon_account_id="99", acct="dup@example.social")
        resp = auth_client.post("/moderation/mastodon/watch", data={"account_id": "99", "acct": "dup@example.social"})
        assert resp.status_code == 409
        assert resp.get_json() == {"ok": False, "error": "Already watched"}
        masto_client.account_statuses.assert_not_called()

    def test_add_bad_account_id_is_400(self, auth_client, masto_client):
        resp = auth_client.post("/moderation/mastodon/watch", data={"account_id": "abc", "acct": "x@y.example"})
        assert resp.status_code == 400
        masto_client.account_statuses.assert_not_called()

    def test_add_missing_acct_is_400(self, auth_client, masto_client):
        resp = auth_client.post("/moderation/mastodon/watch", data={"account_id": "1"})
        assert resp.status_code == 400

    def test_add_mastodon_failure_is_502_and_nothing_inserted(self, app, auth_client, masto_client):
        masto_client.account_statuses.side_effect = MastodonAPIError("Mastodon API returned HTTP 500", 500)
        resp = auth_client.post("/moderation/mastodon/watch", data={"account_id": "77", "acct": "x@y.example"})
        assert resp.status_code == 502
        with app.app_context():
            from models import ModerationWatch
            assert ModerationWatch.query.filter_by(mastodon_account_id="77").first() is None


# ---------------------------------------------------------------------------
# GET /mastodon/watch (list), POST .../delete (remove)
# ---------------------------------------------------------------------------


class TestWatchListAndRemove:
    def test_list_serializes_watch(self, app, auth_client, masto_client):
        watch_id = _add_watch(app, mastodon_account_id="10", acct="a@b.example", auto_added=True)
        resp = auth_client.get("/moderation/mastodon/watch")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        w = next(x for x in data["watches"] if x["id"] == watch_id)
        assert w["account_id"] == "10"
        assert w["acct"] == "a@b.example"
        assert w["auto_added"] is True
        assert w["added_by"] == "system"

    def test_list_last_run_and_backoff(self, app, auth_client, masto_client):
        from models import Setting

        with app.app_context():
            Setting.set("moderation_watch_last_run_result", json.dumps({
                "checked": 3, "watch_total": 5, "alerts": {"watched_post": 1, "new_account": 0, "silent_login": 0},
                "deferred": False, "errors": [], "rate_limit": None,
            }))
            Setting.set("moderation_watch_last_run_at", "2026-01-01T00:00:00+00:00")
            Setting.set("moderation_watch_backoff_until", "2026-01-01T00:05:00+00:00")
        resp = auth_client.get("/moderation/mastodon/watch")
        data = resp.get_json()
        assert data["last_run"]["checked"] == 3
        assert data["last_run"]["at"] == "2026-01-01T00:00:00+00:00"
        assert data["backoff_until"] == "2026-01-01T00:05:00+00:00"

    def test_list_no_last_run_is_none(self, auth_client, masto_client):
        resp = auth_client.get("/moderation/mastodon/watch")
        data = resp.get_json()
        assert data["last_run"] is None
        assert data["backoff_until"] is None

    def test_remove_deletes_row_and_audits(self, app, auth_client, masto_client):
        watch_id = _add_watch(app, mastodon_account_id="55", acct="gone@example.social")
        resp = auth_client.post(f"/moderation/mastodon/watch/{watch_id}/delete")
        assert resp.status_code == 200
        with app.app_context():
            from models import ModerationWatch, db
            assert db.session.get(ModerationWatch, watch_id) is None
        assert _last_audit(app, "mastodon_watch_remove").resource_name == "gone@example.social"

    def test_remove_missing_is_404(self, auth_client, masto_client):
        resp = auth_client.post("/moderation/mastodon/watch/999999/delete")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# GET /mastodon/alerts, ack, ack_all
# ---------------------------------------------------------------------------


class TestAlerts:
    def test_list_default_excludes_acked(self, app, auth_client, masto_client):
        open_id = _add_alert(app, mastodon_account_id="1", acct="a@b", kind="watched_post", status_id="s1")
        acked_id = _add_alert(app, mastodon_account_id="2", acct="c@d", kind="new_account",
                               acknowledged_at=datetime.now(timezone.utc))
        resp = auth_client.get("/moderation/mastodon/alerts")
        ids = [a["id"] for a in resp.get_json()["alerts"]]
        assert open_id in ids
        assert acked_id not in ids

    def test_include_acked(self, app, auth_client, masto_client):
        acked_id = _add_alert(app, mastodon_account_id="2", acct="c@d", kind="new_account",
                               acknowledged_at=datetime.now(timezone.utc))
        resp = auth_client.get("/moderation/mastodon/alerts?include_acked=1")
        ids = [a["id"] for a in resp.get_json()["alerts"]]
        assert acked_id in ids

    def test_filter_by_kind(self, app, auth_client, masto_client):
        _add_alert(app, mastodon_account_id="1", acct="a", kind="watched_post", status_id="s1")
        _add_alert(app, mastodon_account_id="2", acct="b", kind="silent_login")
        resp = auth_client.get("/moderation/mastodon/alerts?kind=silent_login")
        kinds = {a["kind"] for a in resp.get_json()["alerts"]}
        assert kinds == {"silent_login"}

    def test_bad_kind_is_400(self, auth_client, masto_client):
        resp = auth_client.get("/moderation/mastodon/alerts?kind=nonsense")
        assert resp.status_code == 400

    def test_limit_is_clamped(self, app, auth_client, masto_client):
        for i in range(5):
            _add_alert(app, mastodon_account_id=str(i), acct=f"u{i}", kind="watched_post", status_id=str(i))
        resp = auth_client.get("/moderation/mastodon/alerts?limit=2")
        assert len(resp.get_json()["alerts"]) == 2

    def test_watched_flag(self, app, auth_client, masto_client):
        _add_watch(app, mastodon_account_id="1", acct="w@atched.example")
        _add_alert(app, mastodon_account_id="1", acct="w@atched.example", kind="watched_post", status_id="s1")
        _add_alert(app, mastodon_account_id="2", acct="not@watched.example", kind="watched_post", status_id="s2")
        resp = auth_client.get("/moderation/mastodon/alerts")
        watched_by_account = {a["account_id"]: a["watched"] for a in resp.get_json()["alerts"]}
        assert watched_by_account["1"] is True
        assert watched_by_account["2"] is False

    def test_ack_sets_fields_and_is_idempotent(self, app, auth_client, masto_client):
        alert_id = _add_alert(app, mastodon_account_id="1", acct="a", kind="new_account")
        resp = auth_client.post(f"/moderation/mastodon/alerts/{alert_id}/ack")
        assert resp.status_code == 200
        resp2 = auth_client.post(f"/moderation/mastodon/alerts/{alert_id}/ack")
        assert resp2.status_code == 200
        with app.app_context():
            from models import ModerationAlert, db
            alert = db.session.get(ModerationAlert, alert_id)
            assert alert.acknowledged_at is not None

    def test_ack_missing_is_404(self, auth_client, masto_client):
        resp = auth_client.post("/moderation/mastodon/alerts/999999/ack")
        assert resp.status_code == 404

    def test_ack_all_returns_count_and_audits(self, app, auth_client, masto_client):
        _add_alert(app, mastodon_account_id="1", acct="a", kind="watched_post", status_id="s1")
        _add_alert(app, mastodon_account_id="2", acct="b", kind="new_account")
        resp = auth_client.post("/moderation/mastodon/alerts/ack_all")
        assert resp.status_code == 200
        assert resp.get_json()["count"] == 2
        assert _last_audit(app, "mastodon_alerts_ack_all") is not None
        resp2 = auth_client.get("/moderation/mastodon/alerts")
        assert resp2.get_json()["alerts"] == []

    def test_ack_all_filters_by_kind(self, app, auth_client, masto_client):
        _add_alert(app, mastodon_account_id="1", acct="a", kind="watched_post", status_id="s1")
        _add_alert(app, mastodon_account_id="2", acct="b", kind="new_account")
        resp = auth_client.post("/moderation/mastodon/alerts/ack_all", data={"kind": "watched_post"})
        assert resp.get_json()["count"] == 1
        resp2 = auth_client.get("/moderation/mastodon/alerts?kind=new_account")
        assert len(resp2.get_json()["alerts"]) == 1


# ---------------------------------------------------------------------------
# GET /mastodon/new_accounts
# ---------------------------------------------------------------------------


class TestNewAccounts:
    def test_clamps_days_and_marks_watched(self, app, auth_client, masto_client):
        _add_watch(app, mastodon_account_id="7", acct="w@d.example")
        masto_client.list_local_accounts.return_value = [
            {"id": "7", "acct": "w@d.example", "created_at": "2026-01-01T00:00:00Z", "statuses_count": 0, "last_login_at": None},
            {"id": "8", "acct": "n@d.example", "created_at": "2026-01-01T00:00:00Z", "statuses_count": 0, "last_login_at": None},
        ]
        resp = auth_client.get("/moderation/mastodon/new_accounts?days=999")
        assert resp.status_code == 200
        _, kwargs = masto_client.list_local_accounts.call_args
        assert kwargs["max_pages"] == 3
        accounts = resp.get_json()["accounts"]
        watched = {a["id"]: a["watched"] for a in accounts}
        assert watched["7"] is True
        assert watched["8"] is False

    def test_default_days_is_7(self, auth_client, masto_client):
        masto_client.list_local_accounts.return_value = []
        resp = auth_client.get("/moderation/mastodon/new_accounts")
        assert resp.status_code == 200
        _, kwargs = masto_client.list_local_accounts.call_args
        delta_days = (datetime.now(timezone.utc) - kwargs["newer_than"]).total_seconds() / 86400
        assert 6.9 <= delta_days <= 7.1

    def test_days_below_one_is_clamped_to_one(self, auth_client, masto_client):
        masto_client.list_local_accounts.return_value = []
        auth_client.get("/moderation/mastodon/new_accounts?days=-5")
        _, kwargs = masto_client.list_local_accounts.call_args
        delta_days = (datetime.now(timezone.utc) - kwargs["newer_than"]).total_seconds() / 86400
        assert 0.9 <= delta_days <= 1.1


# ---------------------------------------------------------------------------
# GET /mastodon/summary
# ---------------------------------------------------------------------------


class TestSummary:
    def test_not_configured(self, auth_client):
        resp = auth_client.get("/moderation/mastodon/summary")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["configured"] is False
        assert data["open_reports"] is None
        assert data["pending_accounts"] is None
        assert data["live_error"] is None

    def _configure_mastodon(self, app):
        from auth.credential_store import encrypt
        from models import Setting

        with app.app_context():
            Setting.set("moderation_mastodon_api_url", "https://example.social")
            Setting.set("moderation_mastodon_api_token", encrypt("tok"))

    def test_configured_with_live_counts(self, app, auth_client, masto_client):
        self._configure_mastodon(app)
        masto_client.open_report_count.return_value = (3, False)
        masto_client.pending_account_count.return_value = (1, True)
        resp = auth_client.get("/moderation/mastodon/summary")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["configured"] is True
        assert data["open_reports"] == {"count": 3, "more": False}
        assert data["pending_accounts"] == {"count": 1, "more": True}
        assert data["live_error"] is None

    def test_configured_live_error_never_502(self, app, auth_client, masto_client):
        self._configure_mastodon(app)
        masto_client.open_report_count.side_effect = MastodonAPIError("Mastodon API returned HTTP 500", 500)
        resp = auth_client.get("/moderation/mastodon/summary")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["open_reports"] is None
        assert data["pending_accounts"] is None
        assert data["live_error"] == "Mastodon API returned HTTP 500"

    def test_counts_come_from_local_rows(self, app, auth_client):
        _add_watch(app, mastodon_account_id="1", acct="a@b")
        _add_alert(app, mastodon_account_id="1", acct="a@b", kind="watched_post", status_id="s1")
        resp = auth_client.get("/moderation/mastodon/summary")
        data = resp.get_json()
        assert data["watch_total"] == 1
        assert data["unacked_total"] == 1
        assert data["unacked"]["watched_post"] == 1
        assert len(data["recent_alerts"]) == 1
        assert data["recent_alerts"][0]["watched"] is True


# ---------------------------------------------------------------------------
# POST /mastodon/watch/poll
# ---------------------------------------------------------------------------


class TestWatchPollNow:
    def test_unconfigured_is_400(self, auth_client):
        with patch("core.moderation_watch.build_admin_client",
                   return_value=(None, "Mastodon API URL or token not configured")):
            resp = auth_client.post("/moderation/mastodon/watch/poll")
        assert resp.status_code == 400

    def test_already_running_is_409(self, auth_client):
        import routes.moderation as moderation_routes

        with patch("core.moderation_watch.build_admin_client", return_value=(MagicMock(), None)):
            moderation_routes._watch_poll_state["running"] = True
            try:
                resp = auth_client.post("/moderation/mastodon/watch/poll")
            finally:
                moderation_routes._watch_poll_state["running"] = False
        assert resp.status_code == 409

    def test_starts_runs_poll_and_audits(self, app, auth_client):
        import routes.moderation as moderation_routes

        client = MagicMock()
        with patch("core.moderation_watch.build_admin_client", return_value=(client, None)), \
             patch("core.moderation_watch.run_watch_poll") as run_poll, \
             patch.object(moderation_routes._threading, "Thread", _SyncThread):
            resp = auth_client.post("/moderation/mastodon/watch/poll")
        assert resp.status_code == 200
        assert resp.get_json() == {"ok": True, "started": True}
        run_poll.assert_called_once_with(client)
        assert moderation_routes._watch_poll_state["running"] is False
        assert _last_audit(app, "mastodon_watch_poll_now") is not None


# ---------------------------------------------------------------------------
# POST /mastodon/watch/save (admin-only)
# ---------------------------------------------------------------------------


class TestWatchSave:
    def test_moderator_is_denied(self, moderator_client):
        resp = moderator_client.post("/moderation/mastodon/watch/save", data={"poll_minutes": "5"},
                                      follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers.get("Location", "").endswith("/moderation/")

    def test_admin_saves_and_reschedules(self, app, auth_client):
        with patch("core.scheduler.reschedule_moderation_watch") as mock_reschedule:
            resp = auth_client.post("/moderation/mastodon/watch/save", data={
                "alerts_enabled": "on",
                "poll_minutes": "15",
                "auto_watch_days": "5",
                "silent_login_days": "10",
                "silent_min_age_days": "20",
                "silent_scan_window_days": "100",
            }, follow_redirects=False)
        assert resp.status_code == 302
        assert "tab=mastodon" in resp.headers.get("Location", "")

        with app.app_context():
            from core.moderation_watch import get_watch_settings
            settings = get_watch_settings()
        assert settings["alerts_enabled"] is True
        assert settings["poll_minutes"] == 15
        assert settings["auto_watch_days"] == 5
        assert settings["silent_login_days"] == 10
        assert settings["silent_min_age_days"] == 20
        assert settings["silent_scan_window_days"] == 100
        mock_reschedule.assert_called_once_with(15)
        assert _last_audit(app, "moderation_watch_config_save") is not None

    def test_bad_interval_saves_nothing(self, app, auth_client):
        with app.app_context():
            from models import Setting
            Setting.set("moderation_watch_poll_minutes", "5")

        with patch("core.scheduler.reschedule_moderation_watch") as mock_reschedule:
            resp = auth_client.post("/moderation/mastodon/watch/save", data={
                "poll_minutes": "999999",
                "auto_watch_days": "5",
            }, follow_redirects=False)
        assert resp.status_code == 302
        mock_reschedule.assert_not_called()

        with app.app_context():
            from models import Setting
            assert Setting.get("moderation_watch_poll_minutes") == "5"
            assert Setting.get("moderation_watch_auto_watch_days") != "5"


# ---------------------------------------------------------------------------
# Inline <script> blocks must be syntactically valid JS (CSP forbids eval, so
# a syntax error would only ever show up in the browser console).
# ---------------------------------------------------------------------------


class TestTemplateScriptSyntax:
    _SCRIPT_RE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script\b[^>]*>", re.DOTALL | re.IGNORECASE)

    def _assert_scripts_are_valid(self, html):
        if shutil.which("node") is None:
            pytest.skip("node is not available on this machine")
        blocks = self._SCRIPT_RE.findall(html)
        assert blocks, "expected at least one inline <script> block"
        for i, block in enumerate(blocks):
            fd, path = tempfile.mkstemp(suffix=".js")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(block)
                result = subprocess.run(["node", "--check", path], capture_output=True, text=True)
                assert result.returncode == 0, f"inline script block {i} failed node --check:\n{result.stderr}"
            finally:
                os.remove(path)

    def test_moderation_mastodon_tab_scripts_are_valid(self, auth_client):
        resp = auth_client.get("/moderation/?tab=mastodon")
        assert resp.status_code == 200
        self._assert_scripts_are_valid(resp.get_data(as_text=True))

    def test_dashboard_scripts_are_valid(self, auth_client):
        resp = auth_client.get("/")
        assert resp.status_code == 200
        self._assert_scripts_are_valid(resp.get_data(as_text=True))
