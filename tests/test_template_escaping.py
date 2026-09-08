"""Tests for GHSA-qq45-f2h2-9j4q — client-side HTML-escaping of server-derived
values injected into ``innerHTML``, validation of the collab-presence ``page``
value, and secret masking in settings/prometheus forms.

Most of the actual XSS fixes live in client-side JS (calls to the shared
``escHtml()`` helper from static/esc.js before values are written into
``innerHTML``). Since pytest cannot execute that JS, these tests mostly act
as regression guards on the rendered template *source*: they assert that the
specific vulnerable sink for each finding now routes the server-derived value
through ``escHtml(...)`` and that the old, unescaped concatenation is gone.
Where the value is instead rendered directly by Jinja (which auto-escapes),
we assert the actual behaviour end-to-end with a hostile payload.
"""
from unittest.mock import patch

from models import Guest, db

HOSTILE = '<img src=x onerror=alert(1)>"\'&'
# Jinja/MarkupSafe escapes '"' as the numeric entity &#34; (not &quot;).
HOSTILE_ESCAPED = "&lt;img src=x onerror=alert(1)&gt;&#34;&#39;&amp;"


def _make_guest(app, name, **kwargs):
    with app.app_context():
        g = Guest(name=name, guest_type="ct", enabled=True, **kwargs)
        db.session.add(g)
        db.session.commit()
        return g.id


def _cleanup_guest(app, guest_id):
    with app.app_context():
        g = Guest.query.get(guest_id)
        if g:
            db.session.delete(g)
        db.session.commit()


# ---------------------------------------------------------------------------
# Render-check: every owned page must still render cleanly for an admin.
# ---------------------------------------------------------------------------

class TestPagesRenderCleanly:
    def test_root_renders(self, auth_client):
        resp = auth_client.get("/")
        assert resp.status_code == 200

    def test_login_renders(self, client):
        resp = client.get("/login")
        assert resp.status_code == 200

    def test_settings_renders(self, auth_client):
        resp = auth_client.get("/settings/")
        assert resp.status_code == 200

    def test_prometheus_manage_renders(self, auth_client):
        resp = auth_client.get("/prometheus/manage")
        assert resp.status_code == 200

    def test_jibri_manage_renders(self, auth_client):
        resp = auth_client.get("/jibri/manage")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# static/esc.js must load (in <head>, via base.html) before any inline
# script that calls escHtml(...).
# ---------------------------------------------------------------------------

class TestEscJsLoadOrder:
    def _assert_esc_js_before_usage(self, resp):
        text = resp.get_data(as_text=True)
        esc_js_idx = text.find("esc.js")
        assert esc_js_idx != -1, "static/esc.js script tag not found"
        first_use_idx = text.find("escHtml(")
        if first_use_idx != -1:
            assert esc_js_idx < first_use_idx, (
                "escHtml() is called before static/esc.js is loaded"
            )

    def test_dashboard(self, auth_client):
        self._assert_esc_js_before_usage(auth_client.get("/"))

    def test_settings(self, auth_client):
        self._assert_esc_js_before_usage(auth_client.get("/settings/"))

    def test_prometheus_manage(self, auth_client):
        self._assert_esc_js_before_usage(auth_client.get("/prometheus/manage"))

    def test_jibri_manage(self, auth_client):
        self._assert_esc_js_before_usage(auth_client.get("/jibri/manage"))

    def test_guest_detail(self, app, auth_client):
        gid = _make_guest(app, "_esc-order-guest")
        try:
            self._assert_esc_js_before_usage(auth_client.get(f"/guests/{gid}"))
        finally:
            _cleanup_guest(app, gid)


# ---------------------------------------------------------------------------
# base.html — activity toast (finding #1) and presence popover / follow
# navigation (finding #3).
# ---------------------------------------------------------------------------

class TestBaseHtmlEscaping:
    def test_toast_escapes_username_and_resource_name(self, auth_client):
        text = auth_client.get("/").get_data(as_text=True)
        assert "escHtml(event.username)" in text
        assert "escHtml(event.resource_name)" in text
        # The old unescaped template-literal sink must be gone.
        assert "${event.username}</strong>" not in text
        assert "${event.resource_name}</strong>" not in text

    def test_presence_page_guarded_by_is_safe_page(self, auth_client):
        text = auth_client.get("/").get_data(as_text=True)
        assert "function isSafePage(" in text
        # The href built for the "go to page" popover link is gated.
        assert "isSafePage(u.page)" in text
        # Both auto-navigate window.location.href assignments are gated.
        assert "isSafePage(live.page)" in text
        assert "isSafePage(target.page)" in text


# ---------------------------------------------------------------------------
# dashboard.html — host/guest names concatenated into innerHTML (finding #2).
# ---------------------------------------------------------------------------

class TestDashboardEscaping:
    def test_host_and_guest_names_escaped(self, auth_client):
        text = auth_client.get("/").get_data(as_text=True)
        for needle in (
            "escHtml(h.name)",
            "escHtml(g.name)",
            "escHtml(g.node)",
            "escHtml(g.lock)",
            "escHtml(host.name)",
        ):
            assert needle in text, f"missing {needle!r} in dashboard.html output"

        # Old unescaped concatenations must be gone.
        for bad in ("+ h.name +", "+ g.name +", "+ host.name +", "+ g.node +"):
            assert bad not in text

    def test_hostile_guest_name_escaped_in_reboot_alert(self, app, auth_client):
        """`g.name` in the guests_needing_reboot Jinja alert is auto-escaped."""
        gid = _make_guest(app, HOSTILE, reboot_required=True)
        try:
            resp = auth_client.get("/")
            text = resp.get_data(as_text=True)
            assert HOSTILE not in text
            assert HOSTILE_ESCAPED in text
        finally:
            _cleanup_guest(app, gid)


# ---------------------------------------------------------------------------
# jibri.html — recording filenames in text, value="", and confirm() (finding #4).
# ---------------------------------------------------------------------------

class TestJibriEscaping:
    def test_filename_escaped_and_confirm_uses_data_attribute(self, auth_client):
        text = auth_client.get("/jibri/manage").get_data(as_text=True)
        assert "const filenameEsc = escHtml(rec.filename);" in text
        # Replaced the inline onsubmit="confirm('Delete ' + rec.filename ...)"
        # sink with the app-wide data-confirm modal (base.html), populated
        # from the escaped value rather than string-interpolated JS.
        assert "'data-confirm=\"Delete ' + filenameEsc" in text
        assert "onsubmit=\"return confirm(\\'Delete '" not in text

    def test_no_raw_filename_concatenation(self, auth_client):
        text = auth_client.get("/jibri/manage").get_data(as_text=True)
        assert "+ rec.filename +" not in text
        assert "value=\"' + rec.filename + '\"" not in text


# ---------------------------------------------------------------------------
# settings.html — tag-name rows in the backup-defaults JS (finding #5).
# ---------------------------------------------------------------------------

class TestSettingsTagRowEscaping:
    def test_tag_name_escaped(self, auth_client):
        text = auth_client.get("/settings/").get_data(as_text=True)
        assert "const tagNameEsc = escHtml(tagName);" in text
        assert "+ tagName + '</span>" not in text


# ---------------------------------------------------------------------------
# guest_detail.html — UniFi network name (finding #5).
# ---------------------------------------------------------------------------

class TestGuestDetailEscaping:
    def test_unifi_ip_and_network_escaped(self, app, auth_client):
        # The UniFi panel (and the refreshUnifiStats() script containing the
        # fix) only renders when the guest resolves to a live UniFi client,
        # so give the guest a MAC address and stub the MAC->client lookup.
        gid = _make_guest(app, "_esc-guest-detail", mac_address="AA:BB:CC:DD:EE:FF")
        try:
            fake_client = {
                "mac": "AA:BB:CC:DD:EE:FF",
                "ip": "10.0.0.5",
                "network": "LAN",
                "tx_rate": None,
                "rx_rate": None,
                "tx_bytes": None,
                "rx_bytes": None,
                "uptime": None,
            }
            with patch(
                "routes.guests._get_unifi_mac_map",
                return_value={"AA:BB:CC:DD:EE:FF": fake_client},
            ):
                text = auth_client.get(f"/guests/{gid}").get_data(as_text=True)
            assert "escHtml(s.ip" in text
            assert "escHtml(s.network" in text
            assert "set('u-ip', s.ip" not in text
            assert "set('u-network', s.network" not in text
        finally:
            _cleanup_guest(app, gid)


# ---------------------------------------------------------------------------
# prometheus.html — data.message / data.error (finding #5).
# ---------------------------------------------------------------------------

class TestPrometheusTestConnectionEscaping:
    def test_message_and_error_escaped(self, auth_client):
        text = auth_client.get("/prometheus/manage").get_data(as_text=True)
        assert "escHtml(data.message)" in text
        assert "escHtml(data.error" in text
        assert "'>' + data.message + '</small>" not in text
        assert "'>' + (data.error || 'Connection failed') + '</small>" not in text
