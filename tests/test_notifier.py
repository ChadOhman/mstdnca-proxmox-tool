"""Tests for notifier.py — Discord webhook notification helpers.

All outbound HTTP calls are intercepted with unittest.mock.patch so no real
network activity occurs.  The test suite exercises:
- _send_discord / _get_discord_config helpers
- send_test_notification
- send_update_notification (scan result aggregation, security/normal paths, dedup)
- send_host_update_notification
- send_mastodon_update_notification
- send_ghost_update_notification
- send_peertube_update_notification
- send_elk_update_notification
- send_jitsi_update_notification
- send_upgrade_started_notification / send_upgrade_result_notification
- send_exporter_notification
- send_app_update_notification
- Error handling: HTTP errors, network exceptions, disabled / unconfigured states
"""
import json
import urllib.error
from io import BytesIO
from unittest.mock import MagicMock, patch

from core.notifier import (
    _get_discord_config,
    _send_discord,
    send_app_update_notification,
    send_elk_update_notification,
    send_exporter_notification,
    send_ghost_update_notification,
    send_host_update_notification,
    send_jitsi_update_notification,
    send_mastodon_update_notification,
    send_peertube_update_notification,
    send_test_notification,
    send_update_notification,
    send_updates_applied_notification,
    send_upgrade_result_notification,
    send_upgrade_started_notification,
)
from models import Setting, db

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_urlopen_mock(status=204, body=b""):
    """Return a context-manager mock whose .status attribute is *status*."""
    fake_resp = MagicMock()
    fake_resp.status = status
    fake_resp.read.return_value = body
    fake_resp.__enter__ = MagicMock(return_value=fake_resp)
    fake_resp.__exit__ = MagicMock(return_value=False)
    return fake_resp


def _make_http_error(code=400, reason="Bad Request", body=b""):
    """Construct a urllib.error.HTTPError with a readable body."""
    err = urllib.error.HTTPError(
        url="https://discord.com/api/webhooks/test",
        code=code,
        msg=reason,
        hdrs=None,
        fp=BytesIO(body),
    )
    return err


def _make_scan_result(
    guest_name="web01",
    guest_type="ct",
    total_updates=3,
    security_updates=0,
    status="success",
):
    """Build a minimal scan-result-like object (plain namespace)."""
    guest = MagicMock()
    guest.name = guest_name
    guest.guest_type = guest_type

    result = MagicMock()
    result.guest = guest
    result.status = status
    result.total_updates = total_updates
    result.security_updates = security_updates
    return result


# ---------------------------------------------------------------------------
# _get_discord_config
# ---------------------------------------------------------------------------

class TestGetDiscordConfig:
    def test_enabled_true_when_setting_is_true(self, app):
        with app.app_context():
            Setting.set("discord_enabled", "true")
            Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/123/abc")
            cfg = _get_discord_config()
            assert cfg["enabled"] is True

    def test_enabled_false_when_setting_is_false(self, app):
        with app.app_context():
            Setting.set("discord_enabled", "false")
            cfg = _get_discord_config()
            assert cfg["enabled"] is False

    def test_enabled_false_when_setting_missing(self, app):
        with app.app_context():
            # Remove the setting entirely
            s = Setting.query.filter_by(key="discord_enabled").first()
            if s:
                db.session.delete(s)
                db.session.commit()
            cfg = _get_discord_config()
            assert cfg["enabled"] is False

    def test_webhook_url_returned(self, app):
        with app.app_context():
            Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/999/xyz")
            cfg = _get_discord_config()
            assert cfg["webhook_url"] == "https://discord.com/api/webhooks/999/xyz"

    def test_webhook_url_none_when_not_set(self, app):
        with app.app_context():
            s = Setting.query.filter_by(key="discord_webhook_url").first()
            if s:
                db.session.delete(s)
                db.session.commit()
            cfg = _get_discord_config()
            assert cfg["webhook_url"] is None


# ---------------------------------------------------------------------------
# _send_discord
# ---------------------------------------------------------------------------

class TestSendDiscord:
    """Tests for the internal _send_discord helper."""

    def test_disabled_returns_false_with_message(self, app):
        with app.app_context():
            Setting.set("discord_enabled", "false")
            ok, msg = _send_discord([{"title": "test"}])
            assert ok is False
            assert "disabled" in msg.lower()

    def test_missing_webhook_url_returns_false(self, app):
        with app.app_context():
            Setting.set("discord_enabled", "true")
            s = Setting.query.filter_by(key="discord_webhook_url").first()
            if s:
                db.session.delete(s)
                db.session.commit()
            ok, msg = _send_discord([{"title": "test"}])
            assert ok is False
            assert "webhook" in msg.lower() or "url" in msg.lower() or "configured" in msg.lower()

    def test_successful_204_response(self, app):
        with app.app_context():
            Setting.set("discord_enabled", "true")
            Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")

        fake_resp = _make_urlopen_mock(status=204)
        with patch("urllib.request.urlopen", return_value=fake_resp):
            with app.app_context():
                ok, msg = _send_discord([{"title": "Hello"}])

        assert ok is True
        assert "success" in msg.lower()

    def test_successful_200_response(self, app):
        with app.app_context():
            Setting.set("discord_enabled", "true")
            Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")

        fake_resp = _make_urlopen_mock(status=200)
        with patch("urllib.request.urlopen", return_value=fake_resp):
            with app.app_context():
                ok, msg = _send_discord([{"title": "Hello"}])

        assert ok is True

    def test_non_2xx_response_returns_false(self, app):
        with app.app_context():
            Setting.set("discord_enabled", "true")
            Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")

        fake_resp = _make_urlopen_mock(status=500)
        with patch("urllib.request.urlopen", return_value=fake_resp):
            with app.app_context():
                ok, msg = _send_discord([{"title": "Hello"}])

        assert ok is False
        assert "500" in msg

    def test_http_error_returns_false_with_code(self, app):
        with app.app_context():
            Setting.set("discord_enabled", "true")
            Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")

        err = _make_http_error(code=401, reason="Unauthorized")
        with patch("urllib.request.urlopen", side_effect=err):
            with app.app_context():
                ok, msg = _send_discord([{"title": "Hello"}])

        assert ok is False
        assert "401" in msg

    def test_http_error_with_json_body(self, app):
        with app.app_context():
            Setting.set("discord_enabled", "true")
            Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")

        body = json.dumps({"message": "Invalid Webhook Token"}).encode()
        err = _make_http_error(code=401, reason="Unauthorized", body=body)
        with patch("urllib.request.urlopen", side_effect=err):
            with app.app_context():
                ok, msg = _send_discord([])

        assert ok is False
        assert "Invalid Webhook Token" in msg

    def test_network_exception_returns_false(self, app):
        with app.app_context():
            Setting.set("discord_enabled", "true")
            Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")

        with patch("urllib.request.urlopen", side_effect=Exception("connection reset")):
            with app.app_context():
                ok, msg = _send_discord([{"title": "Hi"}])

        assert ok is False
        assert "connection reset" in msg

    def test_payload_is_json_and_embeds_key(self, app):
        """The JSON payload sent to Discord must have an 'embeds' key."""
        with app.app_context():
            Setting.set("discord_enabled", "true")
            Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")

        fake_resp = _make_urlopen_mock(status=204)
        captured_requests = []

        def fake_urlopen(req, timeout=None):
            captured_requests.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                _send_discord([{"title": "Check payload", "color": 123}])

        assert len(captured_requests) == 1
        req = captured_requests[0]
        body = json.loads(req.data.decode())
        assert "embeds" in body
        assert body["embeds"][0]["title"] == "Check payload"

    def test_request_uses_post_method(self, app):
        with app.app_context():
            Setting.set("discord_enabled", "true")
            Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                _send_discord([{"title": "method check"}])

        assert captured[0].method == "POST"

    def test_request_content_type_header(self, app):
        with app.app_context():
            Setting.set("discord_enabled", "true")
            Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                _send_discord([{"title": "header check"}])

        assert captured[0].get_header("Content-type") == "application/json"


# ---------------------------------------------------------------------------
# send_test_notification
# ---------------------------------------------------------------------------

class TestSendTestNotification:
    def test_happy_path_returns_ok_true(self, app):
        with app.app_context():
            Setting.set("discord_enabled", "true")
            Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")

        fake_resp = _make_urlopen_mock(status=204)
        with patch("urllib.request.urlopen", return_value=fake_resp):
            with app.app_context():
                ok, msg = send_test_notification()

        assert ok is True

    def test_disabled_returns_false(self, app):
        with app.app_context():
            Setting.set("discord_enabled", "false")
            ok, msg = send_test_notification()

        assert ok is False

    def test_no_webhook_url_returns_false(self, app):
        with app.app_context():
            Setting.set("discord_enabled", "true")
            s = Setting.query.filter_by(key="discord_webhook_url").first()
            if s:
                db.session.delete(s)
                db.session.commit()
            ok, msg = send_test_notification()

        assert ok is False

    def test_embed_has_correct_title(self, app):
        with app.app_context():
            Setting.set("discord_enabled", "true")
            Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_test_notification()

        body = json.loads(captured[0].data.decode())
        embed = body["embeds"][0]
        assert "Mastodon Canada Administration Tool" in embed["title"]

    def test_embed_description_mentions_discord(self, app):
        with app.app_context():
            Setting.set("discord_enabled", "true")
            Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_test_notification()

        body = json.loads(captured[0].data.decode())
        desc = body["embeds"][0]["description"].lower()
        assert "discord" in desc

    def test_network_failure_returns_false(self, app):
        with app.app_context():
            Setting.set("discord_enabled", "true")
            Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")

        with patch("urllib.request.urlopen", side_effect=OSError("network down")):
            with app.app_context():
                ok, msg = send_test_notification()

        assert ok is False
        assert "network down" in msg


# ---------------------------------------------------------------------------
# send_update_notification
# ---------------------------------------------------------------------------

class TestSendUpdateNotification:
    def _enable_discord(self, app):
        Setting.set("discord_enabled", "true")
        Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")
        Setting.set("discord_notify_updates", "true")
        Setting.set("discord_notify_updates_security_only", "false")

    def test_no_results_sends_nothing(self, app):
        with app.app_context():
            self._enable_discord(app)

        with patch("urllib.request.urlopen") as mock_open:
            with app.app_context():
                send_update_notification([])

        mock_open.assert_not_called()

    def test_all_success_zero_updates_sends_nothing(self, app):
        with app.app_context():
            self._enable_discord(app)

        results = [_make_scan_result(total_updates=0)]
        with patch("urllib.request.urlopen") as mock_open:
            with app.app_context():
                send_update_notification(results)

        mock_open.assert_not_called()

    def test_error_results_are_skipped(self, app):
        with app.app_context():
            self._enable_discord(app)

        results = [_make_scan_result(status="error", total_updates=5)]
        with patch("urllib.request.urlopen") as mock_open:
            with app.app_context():
                send_update_notification(results)

        mock_open.assert_not_called()

    def test_normal_updates_triggers_send(self, app):
        with app.app_context():
            self._enable_discord(app)

        fake_resp = _make_urlopen_mock(status=204)
        results = [_make_scan_result(total_updates=5, security_updates=0)]

        with patch("urllib.request.urlopen", return_value=fake_resp) as mock_open:
            with app.app_context():
                send_update_notification(results)

        mock_open.assert_called_once()

    def test_security_updates_trigger_red_color(self, app):
        with app.app_context():
            self._enable_discord(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        results = [_make_scan_result(total_updates=3, security_updates=2)]
        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_update_notification(results)

        body = json.loads(captured[0].data.decode())
        # _COLOR_RED = 14431557
        assert body["embeds"][0]["color"] == 14431557

    def test_normal_updates_use_yellow_color(self, app):
        with app.app_context():
            self._enable_discord(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        results = [_make_scan_result(total_updates=4, security_updates=0)]
        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_update_notification(results)

        body = json.loads(captured[0].data.decode())
        # _COLOR_YELLOW = 16761095
        assert body["embeds"][0]["color"] == 16761095

    def test_embed_includes_guest_name_in_fields(self, app):
        with app.app_context():
            self._enable_discord(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        results = [_make_scan_result(guest_name="mastodon01", total_updates=2)]
        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_update_notification(results)

        body = json.loads(captured[0].data.decode())
        fields = body["embeds"][0]["fields"]
        field_names = [f["name"] for f in fields]
        assert any("mastodon01" in n for n in field_names)

    def test_multiple_guests_each_get_a_field(self, app):
        with app.app_context():
            self._enable_discord(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        results = [
            _make_scan_result(guest_name="web01", total_updates=1),
            _make_scan_result(guest_name="db01", total_updates=3),
        ]
        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_update_notification(results)

        body = json.loads(captured[0].data.decode())
        assert len(body["embeds"][0]["fields"]) == 2

    def test_notify_updates_disabled_sends_nothing(self, app):
        with app.app_context():
            Setting.set("discord_enabled", "true")
            Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")
            Setting.set("discord_notify_updates", "false")

        results = [_make_scan_result(total_updates=5)]
        with patch("urllib.request.urlopen") as mock_open:
            with app.app_context():
                send_update_notification(results)

        mock_open.assert_not_called()

    def test_security_only_mode_skips_non_security(self, app):
        with app.app_context():
            self._enable_discord(app)
            Setting.set("discord_notify_updates_security_only", "true")

        results = [_make_scan_result(total_updates=5, security_updates=0)]
        with patch("urllib.request.urlopen") as mock_open:
            with app.app_context():
                send_update_notification(results)

        mock_open.assert_not_called()

    def test_security_only_mode_sends_for_security_updates(self, app):
        with app.app_context():
            self._enable_discord(app)
            Setting.set("discord_notify_updates_security_only", "true")

        fake_resp = _make_urlopen_mock(status=204)
        results = [_make_scan_result(total_updates=3, security_updates=2)]

        with patch("urllib.request.urlopen", return_value=fake_resp) as mock_open:
            with app.app_context():
                send_update_notification(results)

        mock_open.assert_called_once()

    def test_security_critical_title_contains_emoji_marker(self, app):
        with app.app_context():
            self._enable_discord(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        results = [_make_scan_result(total_updates=1, security_updates=1)]
        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_update_notification(results)

        body = json.loads(captured[0].data.decode())
        title = body["embeds"][0]["title"]
        assert "CRITICAL" in title or "security" in title.lower()

    def test_embed_has_footer(self, app):
        with app.app_context():
            self._enable_discord(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        results = [_make_scan_result(total_updates=2)]
        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_update_notification(results)

        body = json.loads(captured[0].data.decode())
        assert "footer" in body["embeds"][0]

    def test_discord_send_failure_is_logged_not_raised(self, app):
        """A Discord send failure must not propagate as an exception."""
        with app.app_context():
            self._enable_discord(app)

        results = [_make_scan_result(total_updates=1)]
        with patch("urllib.request.urlopen", side_effect=Exception("network error")):
            with app.app_context():
                # Should not raise
                send_update_notification(results)

    def test_dedup_skips_when_hash_unchanged(self, app):
        """Same scan results should not trigger a second notification."""
        with app.app_context():
            self._enable_discord(app)

        fake_resp = _make_urlopen_mock(status=204)
        results = [_make_scan_result(guest_name="web01", total_updates=3, security_updates=1)]

        # First call — should send and store hash
        with patch("urllib.request.urlopen", return_value=fake_resp):
            with app.app_context():
                send_update_notification(results)

        # Second call with same results — should skip
        with patch("urllib.request.urlopen") as mock_open:
            with app.app_context():
                send_update_notification(results)

        mock_open.assert_not_called()

    def test_dedup_sends_when_results_change(self, app):
        """Changed scan results should trigger a new notification."""
        with app.app_context():
            self._enable_discord(app)

        fake_resp = _make_urlopen_mock(status=204)
        results_v1 = [_make_scan_result(guest_name="web01", total_updates=3)]

        # First call
        with patch("urllib.request.urlopen", return_value=fake_resp):
            with app.app_context():
                send_update_notification(results_v1)

        # Second call with different results
        results_v2 = [_make_scan_result(guest_name="web01", total_updates=5)]
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_update_notification(results_v2)

        assert len(captured) == 1  # notification was sent


# ---------------------------------------------------------------------------
# send_host_update_notification
# ---------------------------------------------------------------------------


class TestSendHostUpdateNotification:
    def _enable(self, app):
        Setting.set("discord_enabled", "true")
        Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")
        Setting.set("discord_notify_updates", "true")

    def test_happy_path_sends_notification(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        host_results = [
            {"name": "pve1", "host_type": "pve", "update_count": 5},
            {"name": "pbs1", "host_type": "pbs", "update_count": 2},
        ]

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_host_update_notification(host_results)

        assert len(captured) == 1
        body = json.loads(captured[0].data.decode())
        assert "7" in body["embeds"][0]["title"]  # 5 + 2 = 7

    def test_empty_results_sends_nothing(self, app):
        with app.app_context():
            self._enable(app)

        with patch("urllib.request.urlopen") as mock_open:
            with app.app_context():
                send_host_update_notification([])

        mock_open.assert_not_called()

    def test_zero_updates_sends_nothing(self, app):
        with app.app_context():
            self._enable(app)

        host_results = [{"name": "pve1", "host_type": "pve", "update_count": 0}]
        with patch("urllib.request.urlopen") as mock_open:
            with app.app_context():
                send_host_update_notification(host_results)

        mock_open.assert_not_called()

    def test_disabled_sends_nothing(self, app):
        with app.app_context():
            Setting.set("discord_notify_updates", "false")

        host_results = [{"name": "pve1", "host_type": "pve", "update_count": 3}]
        with patch("urllib.request.urlopen") as mock_open:
            with app.app_context():
                send_host_update_notification(host_results)

        mock_open.assert_not_called()

    def test_dedup_skips_when_hash_unchanged(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        host_results = [{"name": "pve1", "host_type": "pve", "update_count": 3}]

        # First call — sends
        with patch("urllib.request.urlopen", return_value=fake_resp):
            with app.app_context():
                send_host_update_notification(host_results)

        # Second call with same data — skipped
        with patch("urllib.request.urlopen") as mock_open:
            with app.app_context():
                send_host_update_notification(host_results)

        mock_open.assert_not_called()

    def test_dedup_sends_when_counts_change(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        results_v1 = [{"name": "pve1", "host_type": "pve", "update_count": 3}]

        with patch("urllib.request.urlopen", return_value=fake_resp):
            with app.app_context():
                send_host_update_notification(results_v1)

        results_v2 = [{"name": "pve1", "host_type": "pve", "update_count": 5}]
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_host_update_notification(results_v2)

        assert len(captured) == 1

    def test_embed_contains_host_type_labels(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        host_results = [
            {"name": "pve1", "host_type": "pve", "update_count": 1},
            {"name": "pbs1", "host_type": "pbs", "update_count": 1},
        ]

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_host_update_notification(host_results)

        body = json.loads(captured[0].data.decode())
        field_names = [f["name"] for f in body["embeds"][0]["fields"]]
        assert any("PVE" in n for n in field_names)
        assert any("PBS" in n for n in field_names)


# ---------------------------------------------------------------------------
# send_mastodon_update_notification
# ---------------------------------------------------------------------------

class TestSendMastodonUpdateNotification:
    def _enable(self, app):
        Setting.set("discord_enabled", "true")
        Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")
        Setting.set("discord_notify_mastodon", "true")

    def test_happy_path_returns_ok_true(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        with patch("urllib.request.urlopen", return_value=fake_resp):
            with app.app_context():
                ok, msg = send_mastodon_update_notification("4.2.0", "4.3.0", "https://github.com/r")

        assert ok is True

    def test_notification_disabled_returns_false(self, app):
        with app.app_context():
            Setting.set("discord_enabled", "true")
            Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")
            Setting.set("discord_notify_mastodon", "false")
            ok, msg = send_mastodon_update_notification("4.2.0", "4.3.0", None)

        assert ok is False
        assert "disabled" in msg.lower()

    def test_embed_title_contains_new_version(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_mastodon_update_notification("4.2.0", "4.3.1", "https://github.com/r")

        body = json.loads(captured[0].data.decode())
        title = body["embeds"][0]["title"]
        assert "4.3.1" in title

    def test_fields_contain_current_and_new_version(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_mastodon_update_notification("4.2.0", "4.3.1", None)

        body = json.loads(captured[0].data.decode())
        fields = body["embeds"][0]["fields"]
        field_values = [f["value"] for f in fields]
        assert any("4.2.0" in v for v in field_values)
        assert any("4.3.1" in v for v in field_values)

    def test_release_url_adds_extra_field(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        release_url = "https://github.com/mastodon/mastodon/releases/v4.3.1"
        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_mastodon_update_notification("4.2.0", "4.3.1", release_url)

        body = json.loads(captured[0].data.decode())
        fields = body["embeds"][0]["fields"]
        assert len(fields) == 3
        assert any(release_url in f["value"] for f in fields)

    def test_no_release_url_only_two_fields(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_mastodon_update_notification("4.2.0", "4.3.1", None)

        body = json.loads(captured[0].data.decode())
        assert len(body["embeds"][0]["fields"]) == 2

    def test_auto_upgrade_note_in_description(self, app):
        with app.app_context():
            self._enable(app)
            Setting.set("mastodon_auto_upgrade", "true")

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_mastodon_update_notification("4.2.0", "4.3.1", None)

        body = json.loads(captured[0].data.decode())
        desc = body["embeds"][0]["description"]
        assert "auto" in desc.lower() or "Auto" in desc

    def test_network_error_returns_false(self, app):
        with app.app_context():
            self._enable(app)

        with patch("urllib.request.urlopen", side_effect=OSError("timeout")):
            with app.app_context():
                ok, msg = send_mastodon_update_notification("4.2.0", "4.3.1", None)

        assert ok is False


# ---------------------------------------------------------------------------
# send_ghost_update_notification
# ---------------------------------------------------------------------------

class TestSendGhostUpdateNotification:
    def _enable(self, app):
        Setting.set("discord_enabled", "true")
        Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")
        Setting.set("discord_notify_ghost", "true")

    def test_happy_path_returns_ok_true(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        with patch("urllib.request.urlopen", return_value=fake_resp):
            with app.app_context():
                ok, msg = send_ghost_update_notification("5.0.0", "5.1.0", "https://github.com/r")

        assert ok is True

    def test_disabled_returns_false(self, app):
        with app.app_context():
            Setting.set("discord_notify_ghost", "false")
            ok, msg = send_ghost_update_notification("5.0.0", "5.1.0", None)

        assert ok is False
        assert "disabled" in msg.lower()

    def test_embed_title_contains_new_version(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_ghost_update_notification("5.0.0", "5.2.3", None)

        body = json.loads(captured[0].data.decode())
        assert "5.2.3" in body["embeds"][0]["title"]

    def test_fields_contain_both_versions(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_ghost_update_notification("5.0.0", "5.2.3", None)

        body = json.loads(captured[0].data.decode())
        values = [f["value"] for f in body["embeds"][0]["fields"]]
        assert any("5.0.0" in v for v in values)
        assert any("5.2.3" in v for v in values)

    def test_release_url_included_in_fields(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        url = "https://github.com/TryGhost/Ghost/releases/v5.2.3"
        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_ghost_update_notification("5.0.0", "5.2.3", url)

        body = json.loads(captured[0].data.decode())
        assert any(url in f["value"] for f in body["embeds"][0]["fields"])

    def test_auto_upgrade_note_in_description(self, app):
        with app.app_context():
            self._enable(app)
            Setting.set("ghost_auto_upgrade", "true")

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_ghost_update_notification("5.0.0", "5.2.3", None)

        body = json.loads(captured[0].data.decode())
        desc = body["embeds"][0]["description"]
        assert "auto" in desc.lower() or "Auto" in desc

    def test_manual_note_when_auto_upgrade_disabled(self, app):
        with app.app_context():
            self._enable(app)
            Setting.set("ghost_auto_upgrade", "false")

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_ghost_update_notification("5.0.0", "5.2.3", None)

        body = json.loads(captured[0].data.decode())
        desc = body["embeds"][0]["description"]
        assert "Log in" in desc


# ---------------------------------------------------------------------------
# send_peertube_update_notification
# ---------------------------------------------------------------------------

class TestSendPeertubeUpdateNotification:
    def _enable(self, app):
        Setting.set("discord_enabled", "true")
        Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")
        Setting.set("discord_notify_peertube", "true")

    def test_happy_path_returns_ok_true(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        with patch("urllib.request.urlopen", return_value=fake_resp):
            with app.app_context():
                ok, msg = send_peertube_update_notification("5.0.0", "6.0.0", "https://github.com/r")

        assert ok is True

    def test_disabled_returns_false(self, app):
        with app.app_context():
            Setting.set("discord_notify_peertube", "false")
            ok, msg = send_peertube_update_notification("5.0.0", "6.0.0", None)

        assert ok is False
        assert "disabled" in msg.lower()

    def test_embed_title_contains_new_version(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_peertube_update_notification("5.0.0", "6.0.0", None)

        body = json.loads(captured[0].data.decode())
        assert "6.0.0" in body["embeds"][0]["title"]

    def test_fields_contain_both_versions(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_peertube_update_notification("5.0.0", "6.0.0", None)

        body = json.loads(captured[0].data.decode())
        values = [f["value"] for f in body["embeds"][0]["fields"]]
        assert any("5.0.0" in v for v in values)
        assert any("6.0.0" in v for v in values)

    def test_release_url_included_in_fields(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        url = "https://github.com/Chocobozzz/PeerTube/releases/v6.0.0"
        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_peertube_update_notification("5.0.0", "6.0.0", url)

        body = json.loads(captured[0].data.decode())
        assert any(url in f["value"] for f in body["embeds"][0]["fields"])

    def test_auto_upgrade_note_in_description(self, app):
        with app.app_context():
            self._enable(app)
            Setting.set("peertube_auto_upgrade", "true")

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_peertube_update_notification("5.0.0", "6.0.0", None)

        body = json.loads(captured[0].data.decode())
        desc = body["embeds"][0]["description"]
        assert "auto" in desc.lower() or "Auto" in desc


# ---------------------------------------------------------------------------
# send_elk_update_notification
# ---------------------------------------------------------------------------

class TestSendElkUpdateNotification:
    def _enable(self, app):
        Setting.set("discord_enabled", "true")
        Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")
        Setting.set("discord_notify_elk", "true")

    def test_happy_path_returns_ok_true(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        with patch("urllib.request.urlopen", return_value=fake_resp):
            with app.app_context():
                ok, msg = send_elk_update_notification("0.11.0", "0.12.0", "https://github.com/r")

        assert ok is True

    def test_disabled_returns_false(self, app):
        with app.app_context():
            Setting.set("discord_notify_elk", "false")
            ok, msg = send_elk_update_notification("0.11.0", "0.12.0", None)

        assert ok is False
        assert "disabled" in msg.lower()

    def test_embed_title_contains_new_version(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_elk_update_notification("0.11.0", "0.12.0", None)

        body = json.loads(captured[0].data.decode())
        assert "0.12.0" in body["embeds"][0]["title"]

    def test_fields_contain_both_versions(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_elk_update_notification("0.11.0", "0.12.0", None)

        body = json.loads(captured[0].data.decode())
        values = [f["value"] for f in body["embeds"][0]["fields"]]
        assert any("0.11.0" in v for v in values)
        assert any("0.12.0" in v for v in values)

    def test_release_url_included_in_fields(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        url = "https://github.com/elk-zone/elk/releases/v0.12.0"
        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_elk_update_notification("0.11.0", "0.12.0", url)

        body = json.loads(captured[0].data.decode())
        assert any(url in f["value"] for f in body["embeds"][0]["fields"])

    def test_auto_upgrade_note_in_description(self, app):
        with app.app_context():
            self._enable(app)
            Setting.set("elk_auto_upgrade", "true")

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_elk_update_notification("0.11.0", "0.12.0", None)

        body = json.loads(captured[0].data.decode())
        desc = body["embeds"][0]["description"]
        assert "auto" in desc.lower() or "Auto" in desc


# ---------------------------------------------------------------------------
# send_jitsi_update_notification
# ---------------------------------------------------------------------------

class TestSendJitsiUpdateNotification:
    def _enable(self, app):
        Setting.set("discord_enabled", "true")
        Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")
        Setting.set("discord_notify_jitsi", "true")

    def test_happy_path_returns_ok_true(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        with patch("urllib.request.urlopen", return_value=fake_resp):
            with app.app_context():
                ok, msg = send_jitsi_update_notification("2.0.9location", "2.0.10location", None)

        assert ok is True

    def test_disabled_returns_false(self, app):
        with app.app_context():
            Setting.set("discord_notify_jitsi", "false")
            ok, msg = send_jitsi_update_notification("2.0.9", "2.0.10", None)

        assert ok is False
        assert "disabled" in msg.lower()

    def test_embed_title_contains_new_version(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_jitsi_update_notification("2.0.9", "2.0.10", None)

        body = json.loads(captured[0].data.decode())
        assert "2.0.10" in body["embeds"][0]["title"]

    def test_fields_contain_both_versions(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_jitsi_update_notification("2.0.9", "2.0.10", None)

        body = json.loads(captured[0].data.decode())
        values = [f["value"] for f in body["embeds"][0]["fields"]]
        assert any("2.0.9" in v for v in values)
        assert any("2.0.10" in v for v in values)

    def test_auto_upgrade_note_in_description(self, app):
        with app.app_context():
            self._enable(app)
            Setting.set("jitsi_auto_upgrade", "true")

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_jitsi_update_notification("2.0.9", "2.0.10", None)

        body = json.loads(captured[0].data.decode())
        desc = body["embeds"][0]["description"]
        assert "auto" in desc.lower() or "Auto" in desc


# ---------------------------------------------------------------------------
# send_upgrade_started_notification
# ---------------------------------------------------------------------------

class TestSendUpgradeStartedNotification:
    def _enable(self, app, service="mastodon"):
        Setting.set("discord_enabled", "true")
        Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")
        Setting.set(f"discord_notify_{service}_upgrade_started", "true")

    def test_happy_path_returns_ok_true(self, app):
        with app.app_context():
            self._enable(app, "mastodon")

        fake_resp = _make_urlopen_mock(status=204)
        with patch("urllib.request.urlopen", return_value=fake_resp):
            with app.app_context():
                ok, msg = send_upgrade_started_notification("mastodon", "4.3.0", "manual")

        assert ok is True

    def test_disabled_returns_false(self, app):
        with app.app_context():
            Setting.set("discord_notify_ghost_upgrade_started", "false")
            ok, msg = send_upgrade_started_notification("ghost", "5.1.0", "manual")

        assert ok is False
        assert "disabled" in msg.lower()

    def test_embed_title_contains_service_and_version(self, app):
        with app.app_context():
            self._enable(app, "peertube")

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_upgrade_started_notification("peertube", "6.0.0", "manual")

        body = json.loads(captured[0].data.decode())
        title = body["embeds"][0]["title"]
        assert "Peertube" in title
        assert "6.0.0" in title

    def test_auto_trigger_label(self, app):
        with app.app_context():
            self._enable(app, "elk")

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_upgrade_started_notification("elk", "0.12.0", "auto")

        body = json.loads(captured[0].data.decode())
        values = [f["value"] for f in body["embeds"][0]["fields"]]
        assert any("Automatic" in v for v in values)

    def test_works_for_all_services(self, app):
        for service in ["mastodon", "ghost", "peertube", "elk", "jitsi", "prometheus"]:
            with app.app_context():
                self._enable(app, service)

            fake_resp = _make_urlopen_mock(status=204)
            with patch("urllib.request.urlopen", return_value=fake_resp):
                with app.app_context():
                    ok, msg = send_upgrade_started_notification(service, "1.0.0", "manual")

            assert ok is True, f"Failed for service: {service}"

    def test_empty_version_omits_version_from_title(self, app):
        with app.app_context():
            self._enable(app, "prometheus")

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_upgrade_started_notification("prometheus", "", "manual")

        body = json.loads(captured[0].data.decode())
        title = body["embeds"][0]["title"]
        assert "to v" not in title


# ---------------------------------------------------------------------------
# send_upgrade_result_notification
# ---------------------------------------------------------------------------

class TestSendUpgradeResultNotification:
    def _enable(self, app, service="mastodon"):
        Setting.set("discord_enabled", "true")
        Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")
        Setting.set(f"discord_notify_{service}_upgrade_result", "true")

    def test_success_returns_ok_true(self, app):
        with app.app_context():
            self._enable(app, "ghost")

        fake_resp = _make_urlopen_mock(status=204)
        with patch("urllib.request.urlopen", return_value=fake_resp):
            with app.app_context():
                ok, msg = send_upgrade_result_notification("ghost", "5.1.0", True, "manual")

        assert ok is True

    def test_failure_returns_ok_true(self, app):
        with app.app_context():
            self._enable(app, "ghost")

        fake_resp = _make_urlopen_mock(status=204)
        with patch("urllib.request.urlopen", return_value=fake_resp):
            with app.app_context():
                ok, msg = send_upgrade_result_notification("ghost", "5.1.0", False, "manual")

        assert ok is True

    def test_disabled_returns_false(self, app):
        with app.app_context():
            Setting.set("discord_notify_peertube_upgrade_result", "false")
            ok, msg = send_upgrade_result_notification("peertube", "6.0.0", True, "manual")

        assert ok is False
        assert "disabled" in msg.lower()

    def test_success_uses_green_color(self, app):
        with app.app_context():
            self._enable(app, "mastodon")

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_upgrade_result_notification("mastodon", "4.3.0", True, "manual")

        body = json.loads(captured[0].data.decode())
        assert body["embeds"][0]["color"] == 8505220  # _COLOR_GREEN

    def test_failure_uses_red_color(self, app):
        with app.app_context():
            self._enable(app, "mastodon")

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_upgrade_result_notification("mastodon", "4.3.0", False, "manual")

        body = json.loads(captured[0].data.decode())
        assert body["embeds"][0]["color"] == 14431557  # _COLOR_RED

    def test_title_contains_succeeded_on_success(self, app):
        with app.app_context():
            self._enable(app, "jitsi")

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_upgrade_result_notification("jitsi", "2.0.10", True, "auto")

        body = json.loads(captured[0].data.decode())
        assert "succeeded" in body["embeds"][0]["title"]

    def test_title_contains_failed_on_failure(self, app):
        with app.app_context():
            self._enable(app, "jitsi")

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_upgrade_result_notification("jitsi", "2.0.10", False, "auto")

        body = json.loads(captured[0].data.decode())
        assert "failed" in body["embeds"][0]["title"]

    def test_works_for_all_services(self, app):
        for service in ["mastodon", "ghost", "peertube", "elk", "jitsi", "prometheus"]:
            with app.app_context():
                self._enable(app, service)

            fake_resp = _make_urlopen_mock(status=204)
            with patch("urllib.request.urlopen", return_value=fake_resp):
                with app.app_context():
                    ok, msg = send_upgrade_result_notification(service, "1.0.0", True, "manual")

            assert ok is True, f"Failed for service: {service}"


# ---------------------------------------------------------------------------
# send_exporter_notification
# ---------------------------------------------------------------------------

class TestSendExporterNotification:
    def _enable(self, app):
        Setting.set("discord_enabled", "true")
        Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")
        Setting.set("discord_notify_prometheus_upgrade_result", "true")

    def test_install_success_returns_ok_true(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        with patch("urllib.request.urlopen", return_value=fake_resp):
            with app.app_context():
                ok, msg = send_exporter_notification("install", "node_exporter", "web-01", True)

        assert ok is True

    def test_uninstall_success_returns_ok_true(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        with patch("urllib.request.urlopen", return_value=fake_resp):
            with app.app_context():
                ok, msg = send_exporter_notification("uninstall", "postgres_exporter", "db-01", True)

        assert ok is True

    def test_disabled_returns_false(self, app):
        with app.app_context():
            Setting.set("discord_notify_prometheus_upgrade_result", "false")
            ok, msg = send_exporter_notification("install", "node_exporter", "web-01", True)

        assert ok is False
        assert "disabled" in msg.lower()

    def test_install_failure_uses_red_color(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_exporter_notification("install", "node_exporter", "web-01", False)

        body = json.loads(captured[0].data.decode())
        assert body["embeds"][0]["color"] == 14431557  # _COLOR_RED

    def test_install_success_uses_green_color(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_exporter_notification("install", "node_exporter", "web-01", True)

        body = json.loads(captured[0].data.decode())
        assert body["embeds"][0]["color"] == 8505220  # _COLOR_GREEN

    def test_title_contains_exporter_type_and_action(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_exporter_notification("install", "redis_exporter", "cache-01", True)

        body = json.loads(captured[0].data.decode())
        title = body["embeds"][0]["title"]
        assert "redis_exporter" in title
        assert "install" in title.lower()

    def test_fields_contain_guest_name(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_exporter_notification("install", "node_exporter", "my-guest", True)

        body = json.loads(captured[0].data.decode())
        values = [f["value"] for f in body["embeds"][0]["fields"]]
        assert any("my-guest" in v for v in values)


# ---------------------------------------------------------------------------
# send_app_update_notification
# ---------------------------------------------------------------------------

class TestSendAppUpdateNotification:
    def _enable(self, app):
        Setting.set("discord_enabled", "true")
        Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")
        Setting.set("discord_notify_app", "true")

    def test_happy_path_returns_ok_true(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        with patch("urllib.request.urlopen", return_value=fake_resp):
            with app.app_context():
                ok, msg = send_app_update_notification("1.0.0", "1.1.0")

        assert ok is True

    def test_disabled_returns_false(self, app):
        with app.app_context():
            Setting.set("discord_notify_app", "false")
            ok, msg = send_app_update_notification("1.0.0", "1.1.0")

        assert ok is False
        assert "disabled" in msg.lower()

    def test_embed_title_contains_new_version(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_app_update_notification("1.0.0", "2.0.0")

        body = json.loads(captured[0].data.decode())
        assert "2.0.0" in body["embeds"][0]["title"]

    def test_fields_contain_current_and_new_version(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_app_update_notification("1.5.0", "2.0.0")

        body = json.loads(captured[0].data.decode())
        values = [f["value"] for f in body["embeds"][0]["fields"]]
        assert any("1.5.0" in v for v in values)
        assert any("2.0.0" in v for v in values)

    def test_auto_update_note_in_description(self, app):
        with app.app_context():
            self._enable(app)
            Setting.set("app_auto_update", "true")

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_app_update_notification("1.0.0", "2.0.0")

        body = json.loads(captured[0].data.decode())
        desc = body["embeds"][0]["description"]
        assert "auto" in desc.lower() or "Auto" in desc

    def test_manual_update_note_when_auto_off(self, app):
        with app.app_context():
            self._enable(app)
            Setting.set("app_auto_update", "false")

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_app_update_notification("1.0.0", "2.0.0")

        body = json.loads(captured[0].data.decode())
        desc = body["embeds"][0]["description"]
        assert "Settings" in desc or "settings" in desc or "Log in" in desc

    def test_embed_uses_cyan_color(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_app_update_notification("1.0.0", "2.0.0")

        body = json.loads(captured[0].data.decode())
        # _COLOR_CYAN = 5227511
        assert body["embeds"][0]["color"] == 5227511

    def test_network_error_returns_false(self, app):
        with app.app_context():
            self._enable(app)

        with patch("urllib.request.urlopen", side_effect=OSError("refused")):
            with app.app_context():
                ok, msg = send_app_update_notification("1.0.0", "2.0.0")

        assert ok is False

    def test_http_401_returns_false_with_code(self, app):
        with app.app_context():
            self._enable(app)

        err = _make_http_error(code=401, reason="Unauthorized")
        with patch("urllib.request.urlopen", side_effect=err):
            with app.app_context():
                ok, msg = send_app_update_notification("1.0.0", "2.0.0")

        assert ok is False
        assert "401" in msg


# ---------------------------------------------------------------------------
# send_updates_applied_notification
# ---------------------------------------------------------------------------

class TestSendUpdatesAppliedNotification:
    def _enable(self, app):
        Setting.set("discord_enabled", "true")
        Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")
        Setting.set("discord_notify_updates", "true")

    def test_empty_results_sends_nothing(self, app):
        with app.app_context():
            self._enable(app)

        with patch("urllib.request.urlopen") as mock_open:
            with app.app_context():
                send_updates_applied_notification([])

        mock_open.assert_not_called()

    def test_single_guest_sends_green_notification(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        results = [{"name": "web01", "type": "CT", "applied": 5, "security": 1}]
        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_updates_applied_notification(results)

        assert len(captured) == 1
        body = json.loads(captured[0].data.decode())
        embed = body["embeds"][0]
        assert embed["color"] == 8505220  # _COLOR_GREEN
        assert "5" in embed["description"]
        assert "1 security" in embed["fields"][0]["value"]

    def test_batch_with_hosts_and_guests(self, app):
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return fake_resp

        results = [
            {"name": "web01", "type": "CT", "applied": 5, "security": 0},
            {"name": "pve1", "type": "PVE", "applied": 3, "security": 0},
        ]
        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with app.app_context():
                send_updates_applied_notification(results)

        assert len(captured) == 1
        body = json.loads(captured[0].data.decode())
        assert "8" in body["embeds"][0]["description"]  # 5 + 3
        assert len(body["embeds"][0]["fields"]) == 2

    def test_disabled_sends_nothing(self, app):
        with app.app_context():
            Setting.set("discord_enabled", "true")
            Setting.set("discord_webhook_url", "https://discord.com/api/webhooks/1/tok")
            Setting.set("discord_notify_updates", "false")

        results = [{"name": "web01", "type": "CT", "applied": 5, "security": 0}]
        with patch("urllib.request.urlopen") as mock_open:
            with app.app_context():
                send_updates_applied_notification(results)

        mock_open.assert_not_called()

    def test_no_dedup(self, app):
        """Applied notifications should always send (no dedup)."""
        with app.app_context():
            self._enable(app)

        fake_resp = _make_urlopen_mock(status=204)
        results = [{"name": "web01", "type": "CT", "applied": 5, "security": 0}]

        for _ in range(2):
            with patch("urllib.request.urlopen", return_value=fake_resp) as mock_open:
                with app.app_context():
                    send_updates_applied_notification(results)
            mock_open.assert_called_once()
