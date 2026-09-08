"""Tests for core/url_safety.py -- the SSRF guard for outbound URLs.

Covers the generalized validate_outbound_url() (malformed URLs, port
restriction, userinfo rejection) as well as the backward-compatible
validate_webhook_url() wrapper. See GHSA-gj96-qjq5-q57h.
"""
from unittest.mock import patch

from core.url_safety import validate_outbound_url, validate_webhook_url


def _patch_dns(ip="93.184.216.34", port=443):
    return patch("core.url_safety.socket.getaddrinfo", return_value=[(2, 1, 6, "", (ip, port))])


class TestMalformedUrls:
    """A malformed URL must return (False, reason), never raise."""

    def test_out_of_range_port_does_not_raise(self):
        ok, reason = validate_webhook_url("http://example.com:99999/")
        assert ok is False
        assert reason == "malformed url"

    def test_negative_port_does_not_raise(self):
        ok, reason = validate_webhook_url("http://example.com:-1/")
        assert ok is False
        assert reason == "malformed url"

    def test_garbage_url_does_not_raise(self):
        ok, reason = validate_webhook_url("http://[::1:2:3:4:5:6:7:8:9]/")
        assert ok is False

    def test_empty_string(self):
        ok, reason = validate_webhook_url("")
        assert ok is False

    def test_none(self):
        ok, reason = validate_webhook_url(None)
        assert ok is False


class TestPortRestriction:
    """Only standard web ports (80/443) are allowed by default."""

    def test_rejects_non_standard_port(self):
        """Port 8006 (the Proxmox API port) must be rejected."""
        with _patch_dns(port=8006):
            ok, reason = validate_webhook_url("https://push.example.com:8006/send")
        assert ok is False
        assert "port" in reason

    def test_allows_default_https_port_implicit(self):
        with _patch_dns(port=443):
            ok, _ = validate_webhook_url("https://push.example.com/send")
        assert ok is True

    def test_allows_explicit_standard_port(self):
        with _patch_dns(port=443):
            ok, _ = validate_webhook_url("https://push.example.com:443/send")
        assert ok is True

    def test_custom_allowed_ports_can_be_widened(self):
        """validate_outbound_url() callers may widen the port allowlist explicitly."""
        with _patch_dns(port=8443):
            ok, _ = validate_outbound_url("https://push.example.com:8443/send", allowed_ports=(443, 8443))
        assert ok is True


class TestUserinfoRejected:
    def test_rejects_embedded_credentials(self):
        ok, reason = validate_webhook_url("https://user:pass@push.example.com/send")
        assert ok is False
        assert "userinfo" in reason or "credential" in reason


class TestAllowedHosts:
    def test_rejects_host_not_in_allowlist(self):
        with _patch_dns():
            ok, reason = validate_outbound_url(
                "https://not-allowed.example.com/x", allowed_hosts={"allowed.example.com"}
            )
        assert ok is False
        assert "host" in reason

    def test_accepts_host_in_allowlist(self):
        with _patch_dns():
            ok, _ = validate_outbound_url(
                "https://allowed.example.com/x", allowed_hosts={"allowed.example.com"}
            )
        assert ok is True

    def test_allowlist_is_case_insensitive(self):
        with _patch_dns():
            ok, _ = validate_outbound_url(
                "https://ALLOWED.example.com/x", allowed_hosts={"allowed.example.com"}
            )
        assert ok is True


class TestExistingSsrfGuards:
    """Regression coverage for the pre-existing private/loopback/link-local checks."""

    def test_rejects_loopback(self):
        ok, _ = validate_webhook_url("http://127.0.0.1/metrics")
        assert ok is False

    def test_rejects_private_ip(self):
        ok, _ = validate_webhook_url("http://10.0.0.5/admin")
        assert ok is False

    def test_rejects_metadata_endpoint(self):
        ok, _ = validate_webhook_url("http://169.254.169.254/latest/meta-data/")
        assert ok is False

    def test_rejects_non_http_scheme(self):
        ok, reason = validate_webhook_url("file:///etc/passwd")
        assert ok is False
        assert "http" in reason
