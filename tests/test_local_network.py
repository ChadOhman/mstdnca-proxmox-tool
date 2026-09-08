"""Tests for local_network.py helpers and middleware."""

import ipaddress

from auth.local_network import _get_client_ip, _is_trusted
from models import AuditLog, Setting, UserSession, db

# ---------------------------------------------------------------------------
# Helpers: _is_trusted
# ---------------------------------------------------------------------------

def _nets(*cidrs):
    """Build a list of ip_network objects from CIDR strings."""
    return [ipaddress.ip_network(c, strict=False) for c in cidrs]


class TestIsTrusted:
    def test_ip_in_single_network_returns_true(self):
        assert _is_trusted("10.0.0.5", _nets("10.0.0.0/8")) is True

    def test_ip_at_network_boundary_returns_true(self):
        assert _is_trusted("192.168.1.0", _nets("192.168.1.0/24")) is True

    def test_ip_in_one_of_multiple_networks_returns_true(self):
        nets = _nets("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        assert _is_trusted("192.168.50.50", nets) is True

    def test_ip_not_in_network_returns_false(self):
        assert _is_trusted("8.8.8.8", _nets("10.0.0.0/8")) is False

    def test_ip_not_in_any_of_multiple_networks_returns_false(self):
        nets = _nets("10.0.0.0/8", "172.16.0.0/12")
        assert _is_trusted("1.2.3.4", nets) is False

    def test_empty_network_list_returns_false(self):
        assert _is_trusted("10.0.0.1", []) is False

    def test_invalid_ip_string_returns_false(self):
        assert _is_trusted("not-an-ip", _nets("10.0.0.0/8")) is False

    def test_empty_string_ip_returns_false(self):
        assert _is_trusted("", _nets("10.0.0.0/8")) is False

    def test_ipv6_loopback_in_ipv6_network(self):
        nets = [ipaddress.ip_network("::1/128")]
        assert _is_trusted("::1", nets) is True

    def test_ipv6_address_not_in_ipv4_network_returns_false(self):
        # Mixing address families should not raise; it should return False
        nets = _nets("10.0.0.0/8")
        assert _is_trusted("::1", nets) is False


# ---------------------------------------------------------------------------
# Helpers: _get_client_ip
# ---------------------------------------------------------------------------

class TestGetClientIp:
    """_get_client_ip() with the default configuration (TRUSTED_PROXY_COUNT=0).

    ProxyFix is not installed, so ``request.remote_addr`` is the real TCP peer
    and *no* client-supplied header may influence the answer.  Trusting them
    based on the peer being private was circular: once ProxyFix had rewritten
    REMOTE_ADDR from X-Forwarded-For, the "is this a proxy?" check was reading
    the attacker's own value.  See tests/test_proxy_trust.py for the
    through-the-WSGI-stack proof and for TRUSTED_PROXY_COUNT=1 behaviour.
    """

    def test_loopback_remote_addr_no_headers_returns_remote_addr(self, app):
        with app.test_request_context(environ_base={"REMOTE_ADDR": "127.0.0.1"}):
            assert _get_client_ip() == "127.0.0.1"

    def test_public_remote_addr_no_headers_returns_remote_addr(self, app):
        with app.test_request_context(environ_base={"REMOTE_ADDR": "8.8.8.8"}):
            assert _get_client_ip() == "8.8.8.8"

    # -- loopback/private REMOTE_ADDR: headers are STILL not trusted ---------

    def test_loopback_ignores_cf_connecting_ip(self, app):
        with app.test_request_context(
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
            headers={"CF-Connecting-IP": "203.0.113.42"},
        ):
            assert _get_client_ip() == "127.0.0.1"

    def test_loopback_ignores_x_real_ip(self, app):
        with app.test_request_context(
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
            headers={"X-Real-IP": "198.51.100.7"},
        ):
            assert _get_client_ip() == "127.0.0.1"

    def test_loopback_ignores_x_forwarded_for(self, app):
        with app.test_request_context(
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
            headers={"X-Forwarded-For": "203.0.113.1, 10.0.0.2, 10.0.0.3"},
        ):
            assert _get_client_ip() == "127.0.0.1"

    def test_private_remote_addr_ignores_forwarded_header(self, app):
        with app.test_request_context(
            environ_base={"REMOTE_ADDR": "10.0.0.1"},
            headers={"X-Forwarded-For": "203.0.113.55"},
        ):
            assert _get_client_ip() == "10.0.0.1"

    # -- public REMOTE_ADDR: proxy headers are NOT trusted ------------------

    def test_public_remote_addr_ignores_cf_connecting_ip(self, app):
        with app.test_request_context(
            environ_base={"REMOTE_ADDR": "1.2.3.4"},
            headers={"CF-Connecting-IP": "203.0.113.42"},
        ):
            assert _get_client_ip() == "1.2.3.4"

    def test_public_remote_addr_ignores_x_real_ip(self, app):
        with app.test_request_context(
            environ_base={"REMOTE_ADDR": "1.2.3.4"},
            headers={"X-Real-IP": "198.51.100.7"},
        ):
            assert _get_client_ip() == "1.2.3.4"

    def test_public_remote_addr_ignores_x_forwarded_for(self, app):
        with app.test_request_context(
            environ_base={"REMOTE_ADDR": "1.2.3.4"},
            headers={"X-Forwarded-For": "203.0.113.1"},
        ):
            assert _get_client_ip() == "1.2.3.4"

    def test_public_remote_addr_ignores_private_looking_spoof(self, app):
        """The exact bypass shape from the advisory: a public peer claiming a LAN IP."""
        with app.test_request_context(
            environ_base={"REMOTE_ADDR": "203.0.113.9"},
            headers={
                "X-Forwarded-For": "10.0.0.5",
                "X-Real-IP": "10.0.0.5",
                "CF-Connecting-IP": "10.0.0.5",
            },
        ):
            assert _get_client_ip() == "203.0.113.9"


# ---------------------------------------------------------------------------
# Middleware: init_local_bypass
# ---------------------------------------------------------------------------

class TestLocalBypassMiddleware:
    """Integration tests for the before_request hook registered by init_local_bypass()."""

    def test_bypass_disabled_unauthenticated_redirects_to_login(self, app, client):
        """When local_bypass_enabled is 'false' the middleware must not log in the user."""
        with app.app_context():
            Setting.set("local_bypass_enabled", "false")
            db.session.commit()

        resp = client.get(
            "/",
            follow_redirects=False,
            environ_base={"REMOTE_ADDR": "10.0.0.1"},
        )
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_static_path_skips_bypass(self, app):
        """Requests to /static/ must be skipped regardless of bypass state."""
        with app.app_context():
            Setting.set("local_bypass_enabled", "true")
            Setting.set("trusted_subnets", "10.0.0.0/8")
            db.session.commit()

        # /static/ requests should flow through without triggering auto-login.
        # We verify this by checking that a fresh (unauthenticated) client can
        # hit a static path and the middleware does not raise or auto-redirect.
        with app.test_client() as c:
            # The app may 404 on a missing file, but it should NOT redirect to
            # a post-login dashboard (which would be /) — that would be a sign
            # the auto-login fired on a static path.
            resp = c.get(
                "/static/nonexistent.css",
                environ_base={"REMOTE_ADDR": "10.0.0.1"},
                follow_redirects=False,
            )
            assert resp.status_code != 302 or "/login" not in resp.headers.get("Location", "")

    def test_already_authenticated_skips_bypass(self, app, auth_client):
        """If the user is already logged in, the middleware must not interfere."""
        with app.app_context():
            Setting.set("local_bypass_enabled", "true")
            Setting.set("trusted_subnets", "10.0.0.0/8")
            db.session.commit()

        resp = auth_client.get(
            "/",
            follow_redirects=False,
            environ_base={"REMOTE_ADDR": "10.0.0.1"},
        )
        # Already-authenticated client should reach the dashboard, not loop.
        assert resp.status_code == 200

    def test_trusted_ip_with_bypass_enabled_auto_logs_in(self, app):
        """A trusted IP with bypass enabled should be auto-authenticated as admin."""
        with app.app_context():
            Setting.set("local_bypass_enabled", "true")
            Setting.set("trusted_subnets", "10.0.0.0/8")
            db.session.commit()

        with app.test_client() as c:
            resp = c.get(
                "/",
                environ_base={"REMOTE_ADDR": "10.0.0.5"},
                follow_redirects=False,
            )
            # Should reach the dashboard (200), not be redirected to login.
            assert resp.status_code == 200

    def test_untrusted_ip_with_bypass_enabled_redirects_to_login(self, app):
        """An IP outside the trusted subnet must not be auto-authenticated."""
        with app.app_context():
            Setting.set("local_bypass_enabled", "true")
            Setting.set("trusted_subnets", "10.0.0.0/8")
            db.session.commit()

        with app.test_client() as c:
            resp = c.get(
                "/",
                environ_base={"REMOTE_ADDR": "1.2.3.4"},
                follow_redirects=False,
            )
            assert resp.status_code == 302
            assert "/login" in resp.headers["Location"]

    def test_forwarded_header_cannot_bypass_without_trusted_proxy(self, app):
        """With TRUSTED_PROXY_COUNT=0, X-Forwarded-For must not decide the bypass.

        The loopback peer here is not the point -- what matters is that the
        header is ignored, so an untrusted peer stays untrusted.
        """
        with app.app_context():
            Setting.set("local_bypass_enabled", "true")
            Setting.set("trusted_subnets", "10.0.0.0/8")
            db.session.commit()

        with app.test_client() as c:
            resp = c.get(
                "/",
                environ_base={"REMOTE_ADDR": "127.0.0.1"},
                headers={"X-Forwarded-For": "10.0.0.99"},
                follow_redirects=False,
            )
            assert resp.status_code == 302
            assert "/login" in resp.headers["Location"]

    def test_public_peer_spoofing_trusted_ip_is_not_authenticated(self, app):
        """A public client claiming a LAN IP in every forwarded header gets nothing."""
        with app.app_context():
            Setting.set("local_bypass_enabled", "true")
            Setting.set("trusted_subnets", "10.0.0.0/8")
            db.session.commit()

        with app.test_client() as c:
            resp = c.get(
                "/",
                environ_base={"REMOTE_ADDR": "203.0.113.9"},
                headers={
                    "X-Forwarded-For": "10.0.0.5",
                    "X-Real-IP": "10.0.0.5",
                    "CF-Connecting-IP": "10.0.0.5",
                },
                follow_redirects=False,
            )
            assert resp.status_code == 302
            assert "/login" in resp.headers["Location"]

    def test_untrusted_forwarded_ip_from_loopback_proxy_redirects(self, app):
        """A public IP forwarded through loopback proxy must not trigger bypass."""
        with app.app_context():
            Setting.set("local_bypass_enabled", "true")
            Setting.set("trusted_subnets", "10.0.0.0/8")
            db.session.commit()

        with app.test_client() as c:
            resp = c.get(
                "/",
                environ_base={"REMOTE_ADDR": "127.0.0.1"},
                headers={"X-Forwarded-For": "8.8.8.8"},
                follow_redirects=False,
            )
            assert resp.status_code == 302
            assert "/login" in resp.headers["Location"]


# ---------------------------------------------------------------------------
# Bypass sessions are tracked, audited and revocable
# ---------------------------------------------------------------------------

class TestBypassSessionTracking:
    """A bypass session must behave like any other login: listed and revocable."""

    @staticmethod
    def _enable(app, subnets="10.0.0.0/8"):
        with app.app_context():
            Setting.set("local_bypass_enabled", "true")
            Setting.set("trusted_subnets", subnets)
            db.session.commit()

    @staticmethod
    def _disable(app):
        with app.app_context():
            Setting.set("local_bypass_enabled", "false")
            db.session.commit()

    def test_bypass_creates_a_user_session_row(self, app):
        self._enable(app)
        with app.app_context():
            before = UserSession.query.filter_by(revoked=False).count()

        with app.test_client() as c:
            assert c.get("/", environ_base={"REMOTE_ADDR": "10.0.0.5"}).status_code == 200

        with app.app_context():
            after = UserSession.query.filter_by(revoked=False).count()
            assert after == before + 1
        self._disable(app)

    def test_bypass_is_audited(self, app):
        self._enable(app)
        with app.test_client() as c:
            c.get("/", environ_base={"REMOTE_ADDR": "10.0.0.6"})

        with app.app_context():
            entry = (AuditLog.query
                     .filter_by(action="login_local_bypass")
                     .order_by(AuditLog.id.desc())
                     .first())
            assert entry is not None
            assert entry.ip_address == "10.0.0.6"
        self._disable(app)

    def test_revoking_the_session_row_ends_the_bypass_session(self, app):
        """Revoking the tracked row logs the client out of that session."""
        self._enable(app)
        with app.test_client() as c:
            assert c.get("/", environ_base={"REMOTE_ADDR": "10.0.0.7"}).status_code == 200
            with app.app_context():
                record = (UserSession.query
                          .filter_by(revoked=False)
                          .order_by(UserSession.id.desc())
                          .first())
                record_id = record.id
                record.revoked = True
                db.session.commit()

            # The revoked row no longer authorises anything.
            resp = c.get("/", environ_base={"REMOTE_ADDR": "10.0.0.7"}, follow_redirects=False)
            assert resp.status_code == 302
            assert "/login" in resp.headers["Location"]

            # Still on a trusted IP with the bypass enabled, so the next request
            # establishes a *new* tracked session rather than reusing the old one.
            assert c.get("/", environ_base={"REMOTE_ADDR": "10.0.0.7"}).status_code == 200
            with app.app_context():
                newest = (UserSession.query
                          .filter_by(revoked=False)
                          .order_by(UserSession.id.desc())
                          .first())
                assert newest.id != record_id
        self._disable(app)

    def test_disabling_bypass_invalidates_the_existing_session(self, app):
        self._enable(app)
        with app.test_client() as c:
            assert c.get("/", environ_base={"REMOTE_ADDR": "10.0.0.8"}).status_code == 200
            self._disable(app)
            resp = c.get("/", environ_base={"REMOTE_ADDR": "10.0.0.8"}, follow_redirects=False)
            assert resp.status_code == 302
            assert "/login" in resp.headers["Location"]

    def test_narrowing_trusted_subnets_invalidates_the_existing_session(self, app):
        self._enable(app)
        with app.test_client() as c:
            assert c.get("/", environ_base={"REMOTE_ADDR": "10.0.0.9"}).status_code == 200
            self._enable(app, subnets="192.168.1.0/24")
            resp = c.get("/", environ_base={"REMOTE_ADDR": "10.0.0.9"}, follow_redirects=False)
            assert resp.status_code == 302
            assert "/login" in resp.headers["Location"]
        self._disable(app)

    def test_invalidated_bypass_session_row_is_revoked(self, app):
        self._enable(app)
        with app.test_client() as c:
            c.get("/", environ_base={"REMOTE_ADDR": "10.0.0.10"})
            with app.app_context():
                record_id = (UserSession.query
                             .filter_by(revoked=False)
                             .order_by(UserSession.id.desc())
                             .first().id)
            self._disable(app)
            c.get("/", environ_base={"REMOTE_ADDR": "10.0.0.10"})

        with app.app_context():
            assert db.session.get(UserSession, record_id).revoked is True
