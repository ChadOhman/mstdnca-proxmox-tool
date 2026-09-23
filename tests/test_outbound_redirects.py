"""GHSA-gj96-qjq5-q57h residuals: bearer-token clients must not follow redirects,
integration URLs are validated at save, and the last PromQL interpolation sites
escape their values.
"""
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import MagicMock, patch

import pytest

from models import ProxmoxHost, Setting, db


def _http_error(code, location=None):
    headers = {"Location": location} if location else {}
    return urllib.error.HTTPError("https://api.example/x", code, "moved", headers, None)


class _Redirecting(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server API
        self.send_response(302)
        self.send_header("Location", "http://127.0.0.1:9/never-reached")
        self.end_headers()

    def log_message(self, *_args):
        pass


@pytest.fixture()
def redirecting_server():
    server = HTTPServer(("127.0.0.1", 0), _Redirecting)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


# ---------------------------------------------------------------------------
# core.url_safety.open_no_redirect
# ---------------------------------------------------------------------------


class TestOpenNoRedirect:
    def test_real_302_is_raised_not_followed(self, redirecting_server):
        from core.url_safety import is_redirect, open_no_redirect

        req = urllib.request.Request(redirecting_server + "/x")
        req.add_header("Authorization", "Bearer test-only-token")
        with pytest.raises(urllib.error.HTTPError) as info:
            open_no_redirect(req, timeout=5)
        assert info.value.code == 302
        assert is_redirect(info.value)

    def test_is_redirect_only_for_3xx(self):
        from core.url_safety import is_redirect

        assert is_redirect(_http_error(301))
        assert is_redirect(_http_error(307))
        assert not is_redirect(_http_error(404))
        assert not is_redirect(ValueError("x"))

    def test_handler_refuses_every_redirect(self):
        from core.url_safety import _NoRedirectHandler

        handler = _NoRedirectHandler()
        req = urllib.request.Request("https://a.example/")
        assert handler.redirect_request(req, None, 302, "Found", {}, "https://b.example/") is None


# ---------------------------------------------------------------------------
# Mastodon and PeerTube clients
# ---------------------------------------------------------------------------


class TestMastodonClientRedirect:
    def test_redirect_is_refused_with_clear_error(self):
        from core.mastodon_admin import MastodonAdminClient, MastodonAPIError

        client = MastodonAdminClient("https://masto.example", "test-only-token")
        with patch("core.mastodon_admin.open_no_redirect",
                   side_effect=_http_error(302, "https://collector.attacker.invalid/")) as opener:
            with pytest.raises(MastodonAPIError, match="redirect"):
                client._request("GET", "/api/v1/accounts/1")
        # One attempt only: the token was never sent to the Location target.
        assert opener.call_count == 1

    def test_uses_no_redirect_opener_not_urlopen(self):
        from core.mastodon_admin import MastodonAdminClient

        client = MastodonAdminClient("https://masto.example", "t")
        resp = MagicMock()
        resp.__enter__ = MagicMock(return_value=resp)
        resp.__exit__ = MagicMock(return_value=False)
        resp.read.return_value = b"{}"
        resp.headers = {}
        with patch("core.mastodon_admin.open_no_redirect", return_value=resp) as opener, \
             patch("urllib.request.urlopen") as urlopen:
            client._request("GET", "/api/v1/x")
        opener.assert_called_once()
        urlopen.assert_not_called()


class TestPeerTubeClientRedirect:
    def test_fetch_users_refuses_redirect(self):
        from core.moderation import fetch_peertube_users

        with patch("core.moderation.open_no_redirect", side_effect=_http_error(301, "https://evil/")) as opener:
            users, err = fetch_peertube_users("https://pt.example", "test-only-token")
        assert users is None
        assert "redirect" in err
        assert opener.call_count == 1

    def test_ban_user_refuses_redirect(self):
        from core.moderation import ban_peertube_user

        with patch("core.moderation.open_no_redirect", side_effect=_http_error(307, "https://evil/")):
            ok, err = ban_peertube_user("https://pt.example", "test-only-token", 5, "spam")
        assert ok is False
        assert "redirect" in err


# ---------------------------------------------------------------------------
# Integration URLs validated at save
# ---------------------------------------------------------------------------


@pytest.fixture()
def _clean_api_urls(app):
    yield
    with app.app_context():
        Setting.set("moderation_mastodon_api_url", "")
        Setting.set("moderation_peertube_api_url", "")


class TestModerationApiUrlValidation:
    @pytest.mark.parametrize("value", ["http://masto.example", "ftp://masto.example", "masto.example",
                                       "https://masto.example/'; id", "https://masto.example/a b"])
    def test_mastodon_url_rejected(self, app, auth_client, _clean_api_urls, value):
        resp = auth_client.post("/moderation/mastodon/save", data={"mastodon_api_url": value},
                                follow_redirects=True)
        assert resp.status_code == 200
        assert b"Mastodon API URL" in resp.data
        with app.app_context():
            assert Setting.get("moderation_mastodon_api_url", "") == ""

    def test_mastodon_https_url_accepted_and_normalised(self, app, auth_client, _clean_api_urls):
        auth_client.post("/moderation/mastodon/save", data={"mastodon_api_url": "https://masto.example/"})
        with app.app_context():
            assert Setting.get("moderation_mastodon_api_url") == "https://masto.example"

    @pytest.mark.parametrize("value", ["http://pt.example", "pt.example", "https://pt.example/x'y"])
    def test_peertube_url_rejected(self, app, auth_client, _clean_api_urls, value):
        resp = auth_client.post("/moderation/save", data={"peertube_api_url": value}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"PeerTube API URL" in resp.data
        with app.app_context():
            assert Setting.get("moderation_peertube_api_url", "") == ""

    def test_peertube_https_url_accepted(self, app, auth_client, _clean_api_urls):
        auth_client.post("/moderation/save", data={"peertube_api_url": "https://pt.example/"})
        with app.app_context():
            assert Setting.get("moderation_peertube_api_url") == "https://pt.example"

    def test_empty_url_clears(self, app, auth_client, _clean_api_urls):
        with app.app_context():
            Setting.set("moderation_peertube_api_url", "https://pt.example")
        auth_client.post("/moderation/save", data={"peertube_api_url": ""})
        with app.app_context():
            assert Setting.get("moderation_peertube_api_url") == ""


# ---------------------------------------------------------------------------
# SSRF guard: non-global ranges is_private misses
# ---------------------------------------------------------------------------


class TestNonGlobalRangesBlocked:
    @pytest.mark.parametrize("ip", ["100.64.0.1", "100.127.255.254", "198.18.0.1", "192.0.0.8", "240.0.0.1"])
    def test_blocked(self, ip):
        from core.url_safety import _ip_is_blocked
        assert _ip_is_blocked(ip)

    @pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
    def test_public_allowed(self, ip):
        from core.url_safety import _ip_is_blocked
        assert not _ip_is_blocked(ip)


# ---------------------------------------------------------------------------
# PromQL: IPMI instance label and the unpoller metric prefix
# ---------------------------------------------------------------------------


class TestIpmiPromDebugEscapes:
    HOSTILE = 'x"} or up{job=~".*'

    @pytest.fixture()
    def hostile_host(self, app):
        with app.app_context():
            host = ProxmoxHost(name="test-only-ipmi-promql", hostname="ipmi-promql.local", host_type="pve",
                               ipmi_enabled=True, ipmi_address=self.HOSTILE)
            db.session.add(host)
            Setting.set("prometheus_enabled", "true")
            Setting.set("prometheus_url", "http://prom.example:9090")
            db.session.commit()
            host_id = host.id
        yield host_id
        with app.app_context():
            host = db.session.get(ProxmoxHost, host_id)
            if host is not None:
                db.session.delete(host)
            Setting.set("prometheus_enabled", "false")
            Setting.set("prometheus_url", "")
            db.session.commit()

    def test_instance_label_is_escaped(self, auth_client, hostile_host):
        with patch("clients.prometheus_query.PrometheusQueryClient.query", return_value=[]) as query:
            resp = auth_client.get(f"/ipmi/api/host/{hostile_host}/prom-debug")
        assert resp.status_code == 200, resp.get_json()
        assert query.called, resp.get_json()
        promql = query.call_args.args[0]
        assert 'instance="x\\"} or up{job=~\\".*"' in promql
        assert '} or up{' not in promql.replace('\\"} or up{', "")


class TestSettingsUnpollerPrefixValidation:
    @pytest.mark.parametrize("prefix", ['up"} or x{', "a b", "a;b", "a\nb", "a$(id)"])
    def test_hostile_prefix_rejected(self, app, auth_client, prefix):
        with app.app_context():
            Setting.set("unpoller_metric_prefix", "unpoller")
        resp = auth_client.post("/settings/unpoller", data={"unpoller_metric_prefix": prefix},
                                follow_redirects=True)
        assert resp.status_code == 200
        assert b"Metric prefix" in resp.data
        with app.app_context():
            assert Setting.get("unpoller_metric_prefix") == "unpoller"

    def test_valid_prefix_still_saves(self, app, auth_client):
        auth_client.post("/settings/unpoller", data={"unpoller_metric_prefix": "site_a"})
        with app.app_context():
            assert Setting.get("unpoller_metric_prefix") == "site_a"
            Setting.set("unpoller_metric_prefix", "unpoller")


# ---------------------------------------------------------------------------
# Cloudflare team domain: fullmatch
# ---------------------------------------------------------------------------


class TestTeamDomainFullmatch:
    def test_trailing_newline_rejected(self):
        from auth.cloudflare_access import _is_valid_team_domain

        assert _is_valid_team_domain("myteam.cloudflareaccess.com")
        assert not _is_valid_team_domain("myteam.cloudflareaccess.com\n")
        assert not _is_valid_team_domain("evil.com#.cloudflareaccess.com")
