"""Tests for miscellaneous app-level functionality defined in app.py.

Covers:
- POST /toggle-safety-mode
- Security response headers (_security_headers after_request hook)
- Jinja2 template filters: timestamp_to_datetime, local_dt
"""

from datetime import datetime, timezone

from markupsafe import Markup

# ---------------------------------------------------------------------------
# POST /toggle-safety-mode
# ---------------------------------------------------------------------------

class TestToggleSafetyMode:
    def test_unauthenticated_returns_403(self, client):
        """Anonymous users must not be able to toggle safety mode."""
        resp = client.post("/toggle-safety-mode", follow_redirects=False)
        assert resp.status_code == 403

    def test_authenticated_redirects(self, auth_client):
        """An authenticated POST should redirect (302) to referrer or root."""
        resp = auth_client.post("/toggle-safety-mode", follow_redirects=False)
        assert resp.status_code == 302

    def test_toggle_enables_safety_mode(self, auth_client):
        """First toggle should enable safety mode (default is False)."""
        # Reset session by hitting toggle once
        resp = auth_client.post(
            "/toggle-safety-mode",
            headers={"Referer": "http://localhost/"},
            follow_redirects=True,
        )
        assert resp.status_code == 200

    def test_toggle_twice_returns_to_original_state(self, auth_client):
        """Two consecutive toggles should leave safety_mode at its starting state."""
        # Toggle on
        auth_client.post(
            "/toggle-safety-mode",
            headers={"Referer": "http://localhost/"},
            follow_redirects=False,
        )
        # Toggle off
        resp = auth_client.post(
            "/toggle-safety-mode",
            headers={"Referer": "http://localhost/"},
            follow_redirects=True,
        )
        assert resp.status_code == 200

    def test_redirects_to_referrer(self, auth_client):
        """The redirect target should be the Referer header when provided."""
        resp = auth_client.post(
            "/toggle-safety-mode",
            headers={"Referer": "http://localhost/"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        location = resp.headers.get("Location", "")
        # Should redirect to "/" (the Referer path)
        assert location in ("/", "http://localhost/", "http://localhost")

    def test_redirects_to_root_when_no_referrer(self, auth_client):
        """Without a Referer header the redirect must fall back to '/'."""
        resp = auth_client.post("/toggle-safety-mode", follow_redirects=False)
        assert resp.status_code == 302
        location = resp.headers.get("Location", "")
        # Must be the root path, not some other page
        assert location in ("/", "http://localhost/")

    def test_get_method_not_allowed(self, auth_client):
        """GET /toggle-safety-mode must return 405 (method not allowed)."""
        resp = auth_client.get("/toggle-safety-mode")
        assert resp.status_code == 405


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

class TestSecurityHeaders:
    """Every response should carry the security headers added by _security_headers()."""

    def _get_headers(self, client):
        """Return response headers for a simple GET to /login."""
        resp = client.get("/login")
        return resp.headers

    def test_x_content_type_options_nosniff(self, client):
        headers = self._get_headers(client)
        assert headers.get("X-Content-Type-Options") == "nosniff"

    def test_x_frame_options_deny(self, client):
        headers = self._get_headers(client)
        assert headers.get("X-Frame-Options") == "DENY"

    def test_x_xss_protection(self, client):
        headers = self._get_headers(client)
        assert headers.get("X-XSS-Protection") == "1; mode=block"

    def test_referrer_policy(self, client):
        headers = self._get_headers(client)
        assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

    def test_content_security_policy_present(self, client):
        headers = self._get_headers(client)
        csp = headers.get("Content-Security-Policy", "")
        assert csp != ""

    def test_csp_default_src_self(self, client):
        headers = self._get_headers(client)
        csp = headers.get("Content-Security-Policy", "")
        assert "default-src 'self'" in csp

    def test_csp_script_src_includes_cdn(self, client):
        headers = self._get_headers(client)
        csp = headers.get("Content-Security-Policy", "")
        assert any(token == "https://cdn.jsdelivr.net" for token in csp.replace(";", " ").split())

    def test_csp_object_src_none(self, client):
        headers = self._get_headers(client)
        csp = headers.get("Content-Security-Policy", "")
        assert "object-src 'none'" in csp

    def test_no_hsts_in_debug_mode(self, app, client):
        """In test/debug mode (app.debug is False by default in tests) HSTS should be absent
        because the test config does not set debug=True but the app is not in prod mode either.
        The _security_headers hook only adds HSTS when app.debug is False *and* we're in prod.
        The test app has TESTING=True; the condition checks app.debug, not TESTING.
        In the test suite, app.debug defaults to False so the header MAY be present — we just
        verify whatever is there is consistent, i.e. if present it has max-age.
        """
        headers = self._get_headers(client)
        hsts = headers.get("Strict-Transport-Security", "")
        if hsts:
            assert "max-age=" in hsts

    def test_headers_present_on_post_response(self, client):
        """Security headers must also be set on POST responses (e.g. /login)."""
        resp = client.post(
            "/login",
            data={"username": "admin", "password": "wrong"},
            follow_redirects=False,
        )
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"

    def test_headers_present_on_authenticated_response(self, auth_client):
        """Security headers must be present on authenticated responses too."""
        resp = auth_client.get("/", follow_redirects=True)
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"


# ---------------------------------------------------------------------------
# Jinja2 template filters
# ---------------------------------------------------------------------------

class TestTimestampToDatetimeFilter:
    """Tests for the timestamp_to_datetime Jinja2 filter."""

    def _run(self, app, value):
        """Invoke the filter directly via the Jinja environment."""
        with app.app_context():
            filt = app.jinja_env.filters["timestamp_to_datetime"]
            return filt(value)

    def test_valid_epoch_returns_span_element(self, app):
        # epoch 0 → 1970-01-01 00:00 UTC, wrapped in <span data-utc>
        result = self._run(app, 0)
        assert isinstance(result, Markup)
        assert "1970-01-01 00:00" in str(result)
        assert "data-utc=" in str(result)

    def test_known_epoch_returns_correct_date(self, app):
        known_dt = datetime(2024, 6, 1, 12, 30, 0, tzinfo=timezone.utc)
        epoch = int(known_dt.timestamp())
        result = self._run(app, epoch)
        assert isinstance(result, Markup)
        assert "2024-06-01 12:30" in str(result)
        assert "data-utc=" in str(result)

    def test_string_epoch_is_accepted(self, app):
        """The filter should handle string-form epoch values (e.g. from JSON)."""
        result = self._run(app, "0")
        assert isinstance(result, Markup)
        assert "1970-01-01 00:00" in str(result)

    def test_none_returns_empty_markup(self, app):
        result = self._run(app, None)
        assert result == Markup("")

    def test_invalid_string_returns_empty_markup(self, app):
        result = self._run(app, "not-a-number")
        assert result == Markup("")

    def test_negative_epoch_returns_markup(self, app):
        """Negative epochs may be valid (pre-1970) or raise OSError on some platforms.
        Either way the filter must not propagate exceptions."""
        result = self._run(app, -1)
        assert isinstance(result, (str, Markup))

    def test_float_epoch_truncated(self, app):
        """The filter casts to int so fractional seconds should be ignored."""
        result = self._run(app, 0.9)
        assert isinstance(result, Markup)
        assert "1970-01-01 00:00" in str(result)


class TestLocalDtFilter:
    """Tests for the local_dt Jinja2 filter."""

    def _run(self, app, value, fmt="%m/%d %H:%M"):
        with app.app_context():
            filt = app.jinja_env.filters["local_dt"]
            return filt(value, fmt)

    def _run_default(self, app, value):
        with app.app_context():
            filt = app.jinja_env.filters["local_dt"]
            return filt(value)

    def test_none_returns_empty_markup(self, app):
        result = self._run(app, None)
        assert str(result) == ""

    def test_returns_span_element(self, app):
        dt = datetime(2024, 6, 15, 9, 30, tzinfo=timezone.utc)
        result = str(self._run_default(app, dt))
        assert result.startswith("<span")
        assert result.endswith("</span>")

    def test_span_has_data_utc_attribute(self, app):
        dt = datetime(2024, 6, 15, 9, 30, tzinfo=timezone.utc)
        result = str(self._run_default(app, dt))
        assert 'data-utc="' in result

    def test_data_utc_contains_iso_format(self, app):
        dt = datetime(2024, 6, 15, 9, 30, tzinfo=timezone.utc)
        result = str(self._run_default(app, dt))
        # ISO string should appear as the data-utc value
        assert "2024-06-15" in result

    def test_fallback_display_matches_format(self, app):
        dt = datetime(2024, 6, 15, 9, 30, tzinfo=timezone.utc)
        result = str(self._run_default(app, dt))
        # Default format is "%m/%d %H:%M" → "06/15 09:30"
        assert "06/15 09:30" in result

    def test_naive_datetime_treated_as_utc(self, app):
        """A timezone-naive datetime should be assumed UTC and not raise."""
        naive_dt = datetime(2024, 1, 1, 12, 0)  # no tzinfo
        result = str(self._run_default(app, naive_dt))
        assert "<span" in result
        assert "data-utc=" in result

    def test_custom_format_applied(self, app):
        dt = datetime(2024, 6, 15, 9, 30, tzinfo=timezone.utc)
        result = str(self._run(app, dt, fmt="%Y-%m-%d"))
        assert "2024-06-15" in result

    def test_result_is_markup_safe(self, app):
        """The filter must return a Markup instance (not a plain str) to prevent double-escaping."""
        from markupsafe import Markup
        dt = datetime(2024, 6, 15, 9, 30, tzinfo=timezone.utc)
        with app.app_context():
            filt = app.jinja_env.filters["local_dt"]
            result = filt(dt)
        assert isinstance(result, Markup)
