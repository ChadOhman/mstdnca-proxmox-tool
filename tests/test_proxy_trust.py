"""Regression tests for explicit reverse-proxy trust (TRUSTED_PROXY_COUNT).

These go through the real WSGI stack (``client.get(...)``) rather than
``test_request_context``, because the whole point of the setting is *where* in
the stack ``REMOTE_ADDR`` gets rewritten: ProxyFix runs as WSGI middleware and
is skipped entirely when no proxy hop is trusted.  A request context built by
hand never exercises that.
"""

import time

import pytest

from app import create_app
from models import AuditLog, Setting, User
from models import db as _db

_ADMIN_PASSWORD = "test-only-ProxyPass1!"

# A public peer sending forged forwarded headers that name a trusted LAN address.
_SPOOF_HEADERS = {
    "X-Forwarded-For": "10.0.0.5",
    "X-Real-IP": "10.0.0.5",
    "CF-Connecting-IP": "10.0.0.5",
}


def _make_app(trusted_proxy_count, secret):
    application = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SECRET_KEY": secret,
        "WTF_CSRF_ENABLED": False,
        "TRUSTED_PROXY_COUNT": trusted_proxy_count,
    })
    with application.app_context():
        admin = User.query.filter_by(username="admin").first()
        admin.set_password(_ADMIN_PASSWORD)
        Setting.set("local_bypass_enabled", "true")
        Setting.set("trusted_subnets", "10.0.0.0/8")
        _db.session.commit()
    return application


@pytest.fixture(scope="module")
def direct_app():
    """Default deployment: no proxy trusted, ProxyFix not installed."""
    return _make_app(0, "test-only-direct-secret-key-0001")


@pytest.fixture(scope="module")
def proxied_app():
    """Deployment behind exactly one operator-controlled proxy."""
    return _make_app(1, "test-only-proxied-secret-key-0001")


def _last_ip(application, action):
    with application.app_context():
        entry = (AuditLog.query
                 .filter_by(action=action)
                 .order_by(AuditLog.id.desc())
                 .first())
        return entry.ip_address if entry else None


# ---------------------------------------------------------------------------
# ProxyFix installation
# ---------------------------------------------------------------------------

class TestProxyFixInstallation:
    def test_not_installed_by_default(self, direct_app):
        assert type(direct_app.wsgi_app).__name__ != "ProxyFix"

    def test_installed_when_count_positive(self, proxied_app):
        assert type(proxied_app.wsgi_app).__name__ == "ProxyFix"

    def test_hop_count_matches_config(self, proxied_app):
        fix = proxied_app.wsgi_app
        assert (fix.x_for, fix.x_proto, fix.x_host, fix.x_prefix) == (1, 1, 1, 1)

    def test_config_default_is_zero(self):
        from config import Config
        assert Config.TRUSTED_PROXY_COUNT == 0

    def test_unparseable_env_value_falls_back_to_zero(self, monkeypatch):
        import config

        monkeypatch.setenv("TRUSTED_PROXY_COUNT", "yes-please")
        assert config._trusted_proxy_count() == 0
        monkeypatch.setenv("TRUSTED_PROXY_COUNT", "-3")
        assert config._trusted_proxy_count() == 0
        monkeypatch.setenv("TRUSTED_PROXY_COUNT", "2")
        assert config._trusted_proxy_count() == 2


# ---------------------------------------------------------------------------
# Default config: forwarded headers must not authenticate or re-key anything
# ---------------------------------------------------------------------------

class TestDirectDeployment:
    def test_public_peer_spoofing_xff_is_not_auto_authenticated(self, direct_app):
        """The advisory's core finding: one forged header must not yield a session."""
        with direct_app.test_client() as c:
            resp = c.get(
                "/",
                environ_base={"REMOTE_ADDR": "203.0.113.9"},
                headers=_SPOOF_HEADERS,
                follow_redirects=False,
            )
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_loopback_peer_spoofing_xff_is_not_auto_authenticated(self, direct_app):
        with direct_app.test_client() as c:
            resp = c.get(
                "/",
                environ_base={"REMOTE_ADDR": "127.0.0.1"},
                headers=_SPOOF_HEADERS,
                follow_redirects=False,
            )
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_audit_log_records_the_real_peer(self, direct_app):
        with direct_app.test_client() as c:
            c.post(
                "/login",
                data={"username": "admin", "password": "test-only-wrong"},
                environ_base={"REMOTE_ADDR": "203.0.113.9"},
                headers=_SPOOF_HEADERS,
            )
        assert _last_ip(direct_app, "login_failed") == "203.0.113.9"

    def test_rate_limit_key_is_the_real_peer(self, direct_app):
        from routes.auth import _failed_attempts, _failed_lock

        with _failed_lock:
            _failed_attempts.clear()
        with direct_app.test_client() as c:
            for spoof in ("10.0.0.5", "10.0.0.6", "10.0.0.7"):
                c.post(
                    "/login",
                    data={"username": "admin", "password": "test-only-wrong"},
                    environ_base={"REMOTE_ADDR": "203.0.113.9"},
                    headers={"X-Forwarded-For": spoof, "CF-Connecting-IP": spoof},
                )
        # Rotating the spoofed header must not create three separate buckets.
        assert list(_failed_attempts) == ["203.0.113.9"]
        assert len(_failed_attempts["203.0.113.9"]) == 3
        with _failed_lock:
            _failed_attempts.clear()

    def test_lockout_cannot_be_evaded_by_rotating_forwarded_header(self, direct_app):
        from routes.auth import _FAIL_LIMIT, _failed_attempts, _failed_lock

        with _failed_lock:
            _failed_attempts.clear()
        with direct_app.test_client() as c:
            for i in range(_FAIL_LIMIT):
                c.post(
                    "/login",
                    data={"username": "admin", "password": "test-only-wrong"},
                    environ_base={"REMOTE_ADDR": "198.51.100.4"},
                    headers={"X-Forwarded-For": f"10.0.0.{i + 1}"},
                )
            resp = c.post(
                "/login",
                data={"username": "admin", "password": _ADMIN_PASSWORD},
                environ_base={"REMOTE_ADDR": "198.51.100.4"},
                headers={"X-Forwarded-For": "10.0.0.250"},
                follow_redirects=False,
            )
        # Locked out: the correct password no longer produces a redirect.
        assert resp.status_code == 200
        assert b"Too many failed login attempts" in resp.data
        with _failed_lock:
            _failed_attempts.clear()


# ---------------------------------------------------------------------------
# TRUSTED_PROXY_COUNT=1: forwarded headers are honoured
# ---------------------------------------------------------------------------

class TestProxiedDeployment:
    def test_forwarded_ip_is_used_for_the_bypass(self, proxied_app):
        with proxied_app.test_client() as c:
            resp = c.get(
                "/",
                environ_base={"REMOTE_ADDR": "127.0.0.1"},
                headers={"X-Forwarded-For": "10.0.0.99"},
                follow_redirects=False,
            )
        assert resp.status_code == 200

    def test_forwarded_untrusted_ip_still_rejected(self, proxied_app):
        with proxied_app.test_client() as c:
            resp = c.get(
                "/",
                environ_base={"REMOTE_ADDR": "127.0.0.1"},
                headers={"X-Forwarded-For": "8.8.8.8"},
                follow_redirects=False,
            )
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_audit_log_records_the_forwarded_ip(self, proxied_app):
        with proxied_app.test_client() as c:
            c.post(
                "/login",
                data={"username": "admin", "password": "test-only-wrong"},
                environ_base={"REMOTE_ADDR": "127.0.0.1"},
                headers={"X-Forwarded-For": "198.51.100.22"},
            )
        assert _last_ip(proxied_app, "login_failed") == "198.51.100.22"

    def test_cf_connecting_ip_wins_behind_a_loopback_proxy(self, proxied_app):
        """Cloudflare's own header is preferred when the peer really is the proxy."""
        with proxied_app.test_client() as c:
            c.post(
                "/login",
                data={"username": "admin", "password": "test-only-wrong"},
                environ_base={"REMOTE_ADDR": "127.0.0.1"},
                headers={
                    "X-Forwarded-For": "198.51.100.30",
                    "CF-Connecting-IP": "198.51.100.31",
                },
            )
        assert _last_ip(proxied_app, "login_failed") == "198.51.100.31"

    def test_cf_connecting_ip_ignored_when_the_peer_is_public(self, proxied_app):
        """A public peer is not proxy infrastructure, so its CF header is ignored."""
        with proxied_app.test_client() as c:
            c.post(
                "/login",
                data={"username": "admin", "password": "test-only-wrong"},
                environ_base={"REMOTE_ADDR": "8.8.4.4"},
                headers={
                    "X-Forwarded-For": "198.51.100.40",
                    "CF-Connecting-IP": "10.0.0.5",
                },
            )
        # ProxyFix honoured X-Forwarded-For (the operator declared one hop), but
        # the CF header did not get to override it.
        assert _last_ip(proxied_app, "login_failed") == "198.51.100.40"

    def test_garbage_cf_connecting_ip_is_ignored(self, proxied_app):
        with proxied_app.test_client() as c:
            c.post(
                "/login",
                data={"username": "admin", "password": "test-only-wrong"},
                environ_base={"REMOTE_ADDR": "127.0.0.1"},
                headers={
                    "X-Forwarded-For": "198.51.100.50",
                    "CF-Connecting-IP": "not-an-ip-address",
                },
            )
        assert _last_ip(proxied_app, "login_failed") == "198.51.100.50"


# ---------------------------------------------------------------------------
# Rate-limit dictionaries must not grow without bound
# ---------------------------------------------------------------------------

class TestRateLimitEviction:
    def test_web_bucket_is_dropped_once_it_expires(self):
        from routes import auth as auth_routes

        with auth_routes._failed_lock:
            auth_routes._failed_attempts.clear()
            auth_routes._failed_attempts["203.0.113.1"] = [
                time.time() - auth_routes._FAIL_WINDOW - 1
            ]
        assert auth_routes._check_rate_limit("198.51.100.1") is False
        assert "203.0.113.1" not in auth_routes._failed_attempts

    def test_web_check_does_not_create_a_bucket(self):
        from routes import auth as auth_routes

        with auth_routes._failed_lock:
            auth_routes._failed_attempts.clear()
        assert auth_routes._check_rate_limit("203.0.113.77") is False
        assert auth_routes._failed_attempts == {}

    def test_web_dict_stays_bounded_under_rotating_ips(self):
        from routes import auth as auth_routes

        with auth_routes._failed_lock:
            auth_routes._failed_attempts.clear()
        for i in range(auth_routes._FAIL_MAX_KEYS + 500):
            auth_routes._record_failed_login(f"203.0.113.{i % 256}-{i}")
        assert len(auth_routes._failed_attempts) <= auth_routes._FAIL_MAX_KEYS
        with auth_routes._failed_lock:
            auth_routes._failed_attempts.clear()

    def test_api_bucket_is_dropped_once_it_expires(self):
        from auth import jwt_auth

        with jwt_auth._api_failed_lock:
            jwt_auth._api_failed_attempts.clear()
            jwt_auth._api_failed_attempts["203.0.113.2"] = [
                time.time() - jwt_auth._API_FAIL_WINDOW - 1
            ]
        assert jwt_auth.check_api_rate_limit("198.51.100.2") is False
        assert "203.0.113.2" not in jwt_auth._api_failed_attempts

    def test_api_check_does_not_create_a_bucket(self):
        from auth import jwt_auth

        with jwt_auth._api_failed_lock:
            jwt_auth._api_failed_attempts.clear()
        assert jwt_auth.check_api_rate_limit("203.0.113.88") is False
        assert jwt_auth._api_failed_attempts == {}

    def test_api_dict_stays_bounded_under_rotating_ips(self):
        from auth import jwt_auth

        with jwt_auth._api_failed_lock:
            jwt_auth._api_failed_attempts.clear()
        for i in range(jwt_auth._API_FAIL_MAX_KEYS + 500):
            jwt_auth.record_api_failed_login(f"198.51.100.{i % 256}-{i}")
        assert len(jwt_auth._api_failed_attempts) <= jwt_auth._API_FAIL_MAX_KEYS
        with jwt_auth._api_failed_lock:
            jwt_auth._api_failed_attempts.clear()

    def test_api_lockout_still_triggers(self):
        from auth import jwt_auth

        with jwt_auth._api_failed_lock:
            jwt_auth._api_failed_attempts.clear()
        for _ in range(jwt_auth._API_FAIL_LIMIT):
            jwt_auth.record_api_failed_login("203.0.113.5")
        assert jwt_auth.check_api_rate_limit("203.0.113.5") is True
        with jwt_auth._api_failed_lock:
            jwt_auth._api_failed_attempts.clear()


# ---------------------------------------------------------------------------
# Startup warning
# ---------------------------------------------------------------------------

class TestStartupWarning:
    """Operators upgrading behind cloudflared need to be told about the setting."""

    @staticmethod
    def _warn(application, caplog):
        from auth.local_network import _warn_if_proxy_trust_missing

        caplog.clear()
        with caplog.at_level("WARNING", logger="auth.local_network"):
            _warn_if_proxy_trust_missing(application)
        return caplog.text

    def test_warns_when_bypass_enabled_without_proxy_trust(self, direct_app, caplog):
        with direct_app.app_context():
            Setting.set("cf_access_enabled", "false")
            Setting.set("local_bypass_enabled", "true")
            _db.session.commit()
        text = self._warn(direct_app, caplog)
        assert "TRUSTED_PROXY_COUNT" in text
        assert "local-network bypass" in text

    def test_warns_when_cf_access_enabled_without_proxy_trust(self, direct_app, caplog):
        with direct_app.app_context():
            Setting.set("cf_access_enabled", "true")
            Setting.set("local_bypass_enabled", "false")
            _db.session.commit()
        assert "Cloudflare Access" in self._warn(direct_app, caplog)
        with direct_app.app_context():
            Setting.set("cf_access_enabled", "false")
            Setting.set("local_bypass_enabled", "true")
            _db.session.commit()

    def test_silent_when_neither_feature_is_enabled(self, direct_app, caplog):
        with direct_app.app_context():
            Setting.set("cf_access_enabled", "false")
            Setting.set("local_bypass_enabled", "false")
            _db.session.commit()
        assert self._warn(direct_app, caplog) == ""
        with direct_app.app_context():
            Setting.set("local_bypass_enabled", "true")
            _db.session.commit()

    def test_silent_when_a_proxy_hop_is_trusted(self, proxied_app, caplog):
        assert self._warn(proxied_app, caplog) == ""

    def test_warning_is_not_fatal_without_a_settings_table(self, caplog):
        """A warning must never turn into a startup failure."""
        from auth.local_network import _warn_if_proxy_trust_missing

        class _Boom:
            config = {"TRUSTED_PROXY_COUNT": 0}

            def app_context(self):
                raise RuntimeError("no database yet")

        _warn_if_proxy_trust_missing(_Boom())  # must not raise


# ---------------------------------------------------------------------------
# Trusted-subnet validation
# ---------------------------------------------------------------------------

class TestTrustedSubnetValidation:
    def _post(self, auth_client, subnets):
        return auth_client.post(
            "/security/access/local-bypass",
            data={"local_bypass_enabled": "on", "trusted_subnets": subnets},
            follow_redirects=True,
        )

    @pytest.mark.parametrize("subnets", ["0.0.0.0/0", "::/0", "10.0.0.0/8, 0.0.0.0/0"])
    def test_zero_length_prefix_is_rejected(self, app, auth_client, subnets):
        with app.app_context():
            Setting.set("trusted_subnets", "192.168.5.0/24")
            _db.session.commit()

        resp = self._post(auth_client, subnets)
        assert resp.status_code == 200
        assert b"matches every address on the internet" in resp.data
        with app.app_context():
            assert Setting.get("trusted_subnets") == "192.168.5.0/24"

    def test_broad_range_is_saved_with_a_warning(self, app, auth_client):
        resp = self._post(auth_client, "10.0.0.0/7")
        assert resp.status_code == 200
        assert b"very broad or not a private range" in resp.data
        with app.app_context():
            assert Setting.get("trusted_subnets") == "10.0.0.0/7"

    def test_public_range_is_saved_with_a_warning(self, app, auth_client):
        resp = self._post(auth_client, "8.8.8.0/24")
        assert resp.status_code == 200
        assert b"very broad or not a private range" in resp.data

    def test_private_range_saves_without_warning(self, app, auth_client):
        resp = self._post(auth_client, "192.168.10.0/24")
        assert resp.status_code == 200
        assert b"very broad or not a private range" not in resp.data
        with app.app_context():
            assert Setting.get("trusted_subnets") == "192.168.10.0/24"
            Setting.set("local_bypass_enabled", "false")
            _db.session.commit()

    def test_ui_default_matches_the_middleware_default(self, app):
        """routes.security and auth.local_network must agree on "nothing trusted"."""
        from auth.local_network import DEFAULT_TRUSTED_SUBNETS
        from routes.security import _get_access_settings

        with app.app_context():
            existing = Setting.query.filter_by(key="trusted_subnets").first()
            previous = existing.value if existing else None
            if existing:
                _db.session.delete(existing)
                _db.session.commit()
            try:
                assert _get_access_settings()["trusted_subnets"] == DEFAULT_TRUSTED_SUBNETS
            finally:
                if previous is not None:
                    Setting.set("trusted_subnets", previous)
                    _db.session.commit()
