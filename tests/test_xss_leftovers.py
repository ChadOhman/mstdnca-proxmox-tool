"""GHSA-qq45-f2h2-9j4q residuals: the last unescaped client-side sinks, Fediverse
URLs in href/src, moderators-only audit broadcasts, stored alert URLs, and the
CSP connect/img sources.
"""
from unittest.mock import patch

import pytest

from models import ModerationAlert, db


class TestJitsiSecureDomainUsersEscaped:
    def test_username_escaped_and_confirm_uses_data_attribute(self, auth_client):
        html = auth_client.get("/jitsi/upgrade").get_data(as_text=True)
        assert "const userEsc = escHtml(u);" in html
        assert "data-confirm=\"Delete user ' + userEsc + '?\"" in html
        assert "name=\"username\" value=\"' + userEsc + '\"" in html
        assert "escHtml(data.error)" in html

    def test_no_raw_username_concatenation(self, auth_client):
        html = auth_client.get("/jitsi/upgrade").get_data(as_text=True)
        assert "' + u + '" not in html
        assert "confirm(\\'Delete user" not in html


class TestModerationLinksAreHttpOnly:
    def test_every_fediverse_href_and_src_goes_through_safe_http_url(self, auth_client):
        html = auth_client.get("/moderation/").get_data(as_text=True)
        assert "function safeHttpUrl(u)" in html
        for sink in ("a.url", "s.url", "a.status_url", "a.avatar"):
            assert f"escHtml({sink})" not in html, sink
        assert html.count("safeHttpUrl(s.url)") == 3
        assert "safeHttpUrl(a.status_url)" in html
        assert "safeHttpUrl(a.avatar)" in html
        assert "(safeHttpUrl(a.url) || '#')" in html


class TestSettingsSinksEscaped:
    def test_geoip_messages_and_storage_options(self, auth_client):
        html = auth_client.get("/settings/").get_data(as_text=True)
        assert "escHtml(data.message || 'Upload successful')" in html
        assert "escHtml(data.path)" in html
        assert "escHtml(data.size_mb)" in html
        assert "escHtml(data.message || 'Database OK')" in html
        assert "escHtml(st.storage) + ' (' + escHtml(st.type) + ')'" in html
        assert "'<option value=\"' + st.storage + '\">'" not in html


class TestSharedEscaperOnly:
    def test_host_detail_has_no_local_escaper(self, app, auth_client):
        from models import ProxmoxHost
        with app.app_context():
            host = ProxmoxHost(name="test-only-esc-host", hostname="esc.local", host_type="pve")
            db.session.add(host)
            db.session.commit()
            host_id = host.id
        try:
            html = auth_client.get(f"/hosts/{host_id}").get_data(as_text=True)
            assert "function escHtml(" not in html
            assert "const lk = escHtml(s.lock);" in html
        finally:
            with app.app_context():
                host = db.session.get(ProxmoxHost, host_id)
                if host is not None:
                    db.session.delete(host)
                    db.session.commit()

    def test_ai_chat_uses_shared_escaper(self):
        import pathlib
        src = pathlib.Path("static/ai-chat.js").read_text(encoding="utf-8")
        assert "function escHtml(" not in src
        assert "escHtml(" in src  # still used, now the shared one


class TestStoredAlertUrlScheme:
    @pytest.mark.parametrize("bad", [
        "javascript:alert(1)", "data:text/html,x", "ftp://x/y", "https://x/y\"onmouseover=\"z",
        "https://x/y z", "", None, "https://" + "a" * 600,
    ])
    def test_non_http_or_hostile_url_not_stored(self, bad):
        from core.moderation_watch import _http_url_or_none
        assert _http_url_or_none(bad) is None

    def test_plain_https_url_kept(self):
        from core.moderation_watch import _http_url_or_none
        assert _http_url_or_none(" https://masto.example/@a/1 ") == "https://masto.example/@a/1"

    def test_record_alert_drops_javascript_url(self, app):
        from core.moderation_watch import record_alert
        with app.app_context():
            alert = record_alert(
                "watched_post",
                {"id": "424242", "acct": "test-only-xss@remote.example"},
                {"id": "999001", "url": "javascript:alert(1)", "excerpt": "hi"},
                notify=False,
            )
            try:
                assert alert is not None
                assert alert.status_url is None
            finally:
                ModerationAlert.query.filter_by(mastodon_account_id="424242").delete()
                db.session.commit()


class TestModerationAuditsAreModeratorsOnly:
    def test_config_save_broadcast_is_moderators_only(self, auth_client):
        with patch("core.collaboration.collab_hub") as hub:
            resp = auth_client.post("/moderation/save", data={"peertube_api_url": ""}, follow_redirects=False)
        assert resp.status_code in (302, 200)
        payloads = [c.args[0] for c in hub.broadcast.call_args_list if c.args[0].get("type") == "activity"]
        assert payloads, "no activity broadcast captured"
        assert all(p.get("moderators_only") is True for p in payloads)

    def test_every_audit_in_the_blueprint_goes_through_the_wrapper(self):
        import pathlib
        src = pathlib.Path("routes/moderation.py").read_text(encoding="utf-8")
        body = src.split("def _audit(", 1)[1]
        assert "    log_action(" not in body.split("return log_action(action, resource_type, **kwargs)", 1)[1]


class TestCspSources:
    def test_img_src_allows_https_and_connect_src_pins_host(self, client):
        resp = client.get("/login")
        csp = resp.headers.get("Content-Security-Policy", "")
        directives = {d.strip().split(" ", 1)[0]: d.strip() for d in csp.split(";") if d.strip()}
        assert "https:" in directives["img-src"].split()
        connect = directives["connect-src"].split()
        assert "ws:" not in connect and "wss:" not in connect
        assert any(t.startswith("ws://") and t != "ws://" for t in connect)
        assert any(t.startswith("wss://") and t != "wss://" for t in connect)
