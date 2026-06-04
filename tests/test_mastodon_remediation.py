"""Tests for Mastodon runtime version remediation (Ruby / Node.js / Bundler)."""
from apps.mastodon import _bundler_from_lock, _node_major_from_range


class TestNodeMajorFromRange:
    def test_gte(self):
        assert _node_major_from_range(">=22") == 22

    def test_caret_with_patch(self):
        assert _node_major_from_range("^22.1.0") == 22

    def test_dot_x(self):
        assert _node_major_from_range("22.x") == 22

    def test_bounded_range_takes_floor(self):
        assert _node_major_from_range(">=20 <23") == 20

    def test_empty(self):
        assert _node_major_from_range("") is None

    def test_none(self):
        assert _node_major_from_range(None) is None


class TestBundlerFromLock:
    def test_extracts_version(self):
        lock = "GEM\n  remote: https://rubygems.org/\n\nBUNDLED WITH\n   2.5.11\n"
        assert _bundler_from_lock(lock) == "2.5.11"

    def test_missing_section(self):
        assert _bundler_from_lock("GEM\n  specs:\n") is None

    def test_empty(self):
        assert _bundler_from_lock("") is None

    def test_none(self):
        assert _bundler_from_lock(None) is None
