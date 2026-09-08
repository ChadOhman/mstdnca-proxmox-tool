"""Tests for clients/unifi_geoip.py's _is_private() helper.

Mirrors tests/test_local_network.py::TestIsTrusted — _is_private() gates
whether an IP is ever sent to the GeoIP database/lookup, so it needs the
same boundary coverage: every private/reserved block it claims to cover,
loopback, link-local, IPv6 equivalents, public v4/v6 addresses, and the
fail-safe behavior on invalid/empty input (issue #131).
"""
from clients.unifi_geoip import _is_private


class TestIsPrivate:
    # -- IPv4 RFC1918 blocks -------------------------------------------------

    def test_10_block_start(self):
        assert _is_private("10.0.0.0") is True

    def test_10_block_middle(self):
        assert _is_private("10.100.200.1") is True

    def test_10_block_end(self):
        assert _is_private("10.255.255.255") is True

    def test_just_outside_10_block(self):
        assert _is_private("11.0.0.0") is False

    def test_172_16_block_start(self):
        assert _is_private("172.16.0.0") is True

    def test_172_16_block_end(self):
        assert _is_private("172.31.255.255") is True

    def test_just_below_172_16_block(self):
        assert _is_private("172.15.255.255") is False

    def test_just_above_172_31_block(self):
        assert _is_private("172.32.0.0") is False

    def test_192_168_block_start(self):
        assert _is_private("192.168.0.0") is True

    def test_192_168_block_end(self):
        assert _is_private("192.168.255.255") is True

    def test_just_outside_192_168_block(self):
        assert _is_private("192.169.0.0") is False

    # -- Loopback and link-local ---------------------------------------------

    def test_ipv4_loopback(self):
        assert _is_private("127.0.0.1") is True

    def test_ipv4_loopback_block_end(self):
        assert _is_private("127.255.255.255") is True

    def test_ipv4_link_local_start(self):
        assert _is_private("169.254.0.0") is True

    def test_ipv4_link_local_end(self):
        assert _is_private("169.254.255.255") is True

    def test_just_outside_link_local(self):
        assert _is_private("169.255.0.0") is False

    # -- IPv6 -----------------------------------------------------------------

    def test_ipv6_loopback(self):
        assert _is_private("::1") is True

    def test_ipv6_unique_local_start(self):
        assert _is_private("fc00::") is True

    def test_ipv6_unique_local_middle(self):
        assert _is_private("fd12:3456:789a::1") is True

    def test_ipv6_link_local(self):
        assert _is_private("fe80::1") is True

    def test_ipv6_public(self):
        assert _is_private("2001:4860:4860::8888") is False

    # -- Public IPv4 ------------------------------------------------------------

    def test_public_ip_google_dns(self):
        assert _is_private("8.8.8.8") is False

    def test_public_ip_cloudflare_dns(self):
        assert _is_private("1.1.1.1") is False

    # -- Invalid / empty input: fail closed (treated as private/skip) --------

    def test_invalid_ip_string_returns_true(self):
        assert _is_private("not-an-ip") is True

    def test_empty_string_returns_true(self):
        assert _is_private("") is True

    def test_partial_ip_returns_true(self):
        assert _is_private("10.0.0") is True
