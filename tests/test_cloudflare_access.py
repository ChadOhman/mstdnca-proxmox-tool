"""Tests for cloudflare_access.py — config helpers, user provisioning, and middleware."""

import json
import time
from unittest.mock import MagicMock, patch

import auth.cloudflare_access as cloudflare_access
from models import Setting, User, db

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reset_jwks_cache():
    """Clear the module-level JWKS cache between tests."""
    cloudflare_access._jwks_cache["keys"] = None
    cloudflare_access._jwks_cache["fetched_at"] = 0


def _make_fake_urlopen(payload: dict):
    """Return a context-manager mock that yields a fake HTTP response body."""
    fake_resp = MagicMock()
    fake_resp.read.return_value = json.dumps(payload).encode()
    fake_resp.__enter__ = MagicMock(return_value=fake_resp)
    fake_resp.__exit__ = MagicMock(return_value=False)
    return fake_resp


# ---------------------------------------------------------------------------
# _get_cf_config()
# ---------------------------------------------------------------------------

class TestGetCfConfig:
    """_get_cf_config() reads all five CF settings from the DB via Setting.get()."""

    def test_defaults_when_no_settings_stored(self, app):
        """Without any DB rows all keys should return their default values."""
        with app.app_context():
            cfg = cloudflare_access._get_cf_config()

        assert cfg["enabled"] is False
        assert cfg["team_domain"] == ""
        assert cfg["audience"] == ""
        assert cfg["auto_provision"] is True
        assert cfg["bypass_local_auth"] is False

    def test_enabled_true_when_setting_is_true(self, app):
        with app.app_context():
            Setting.set("cf_access_enabled", "true")
            cfg = cloudflare_access._get_cf_config()

        assert cfg["enabled"] is True

        with app.app_context():
            Setting.set("cf_access_enabled", "false")

    def test_team_domain_and_audience_returned(self, app):
        with app.app_context():
            Setting.set("cf_access_team_domain", "myteam.cloudflareaccess.com")
            Setting.set("cf_access_audience", "abc123audience")
            cfg = cloudflare_access._get_cf_config()

        assert cfg["team_domain"] == "myteam.cloudflareaccess.com"
        assert cfg["audience"] == "abc123audience"

        with app.app_context():
            Setting.set("cf_access_team_domain", "")
            Setting.set("cf_access_audience", "")

    def test_auto_provision_false_when_setting_is_false(self, app):
        with app.app_context():
            Setting.set("cf_access_auto_provision", "false")
            cfg = cloudflare_access._get_cf_config()

        assert cfg["auto_provision"] is False

        with app.app_context():
            Setting.set("cf_access_auto_provision", "true")

    def test_bypass_local_auth_true_when_setting_is_true(self, app):
        with app.app_context():
            Setting.set("cf_access_bypass_local_auth", "true")
            cfg = cloudflare_access._get_cf_config()

        assert cfg["bypass_local_auth"] is True

        with app.app_context():
            Setting.set("cf_access_bypass_local_auth", "false")

    def test_config_returns_all_five_keys(self, app):
        with app.app_context():
            cfg = cloudflare_access._get_cf_config()

        expected_keys = {"enabled", "team_domain", "audience", "auto_provision", "bypass_local_auth"}
        assert set(cfg.keys()) == expected_keys


# ---------------------------------------------------------------------------
# _get_or_create_cf_user()
# ---------------------------------------------------------------------------

class TestGetOrCreateCfUser:
    """Auto-provisioning logic for CF Access users."""

    _EMAIL = "cf_test_user@example.com"

    def _cleanup(self, app):
        with app.app_context():
            u = User.query.filter_by(username=self._EMAIL).first()
            if u:
                db.session.delete(u)
                db.session.commit()

    def test_creates_new_user_when_none_exists(self, app):
        self._cleanup(app)
        try:
            with app.app_context():
                Setting.set("cf_access_auto_provision", "true")
                user = cloudflare_access._get_or_create_cf_user(self._EMAIL)
                assert user is not None
                assert user.username == self._EMAIL
        finally:
            self._cleanup(app)

    def test_new_user_has_viewer_role(self, app):
        self._cleanup(app)
        try:
            with app.app_context():
                Setting.set("cf_access_auto_provision", "true")
                user = cloudflare_access._get_or_create_cf_user(self._EMAIL)
                role_name = user.role_obj.name if user.role_obj else None
                assert role_name == "viewer"
        finally:
            self._cleanup(app)

    def test_new_user_created_via_is_cloudflare(self, app):
        self._cleanup(app)
        try:
            with app.app_context():
                Setting.set("cf_access_auto_provision", "true")
                user = cloudflare_access._get_or_create_cf_user(self._EMAIL)
                assert user.created_via == "cloudflare"
        finally:
            self._cleanup(app)

    def test_new_user_display_name_uses_email_local_part(self, app):
        self._cleanup(app)
        try:
            with app.app_context():
                Setting.set("cf_access_auto_provision", "true")
                user = cloudflare_access._get_or_create_cf_user(self._EMAIL)
                # email = "cf_test_user@example.com" → local part is "cf_test_user"
                assert user.display_name == "cf_test_user"
        finally:
            self._cleanup(app)

    def test_new_user_display_name_uses_provided_name(self, app):
        self._cleanup(app)
        try:
            with app.app_context():
                Setting.set("cf_access_auto_provision", "true")
                user = cloudflare_access._get_or_create_cf_user(self._EMAIL, name="Alice Smith")
                assert user.display_name == "Alice Smith"
        finally:
            self._cleanup(app)

    def test_returns_existing_user_without_creating_duplicate(self, app):
        self._cleanup(app)
        try:
            with app.app_context():
                Setting.set("cf_access_auto_provision", "true")
                user_first = cloudflare_access._get_or_create_cf_user(self._EMAIL)
                first_id = user_first.id
                user_second = cloudflare_access._get_or_create_cf_user(self._EMAIL)

            assert user_second.id == first_id
            with app.app_context():
                count = User.query.filter_by(username=self._EMAIL).count()
            assert count == 1
        finally:
            self._cleanup(app)

    def test_returns_none_when_auto_provision_disabled(self, app):
        self._cleanup(app)
        with app.app_context():
            Setting.set("cf_access_auto_provision", "false")
            user = cloudflare_access._get_or_create_cf_user(self._EMAIL)

        assert user is None

        with app.app_context():
            Setting.set("cf_access_auto_provision", "true")

    def test_returns_none_when_viewer_role_missing(self, app):
        """If the viewer role is somehow absent, provisioning must not crash but return None."""
        self._cleanup(app)
        with app.app_context():
            Setting.set("cf_access_auto_provision", "true")
            # Temporarily hide the viewer role by patching the query result
            with patch("auth.cloudflare_access.Role") as mock_role_cls:
                mock_role_cls.query.filter_by.return_value.first.return_value = None
                # _get_cf_config() also calls Setting, leave that intact via User/db
                user = cloudflare_access._get_or_create_cf_user("nobody@example.com")

        assert user is None


# ---------------------------------------------------------------------------
# _fetch_jwks()
# ---------------------------------------------------------------------------

class TestFetchJwks:
    """JWKS fetching and cache behaviour."""

    def setup_method(self):
        _reset_jwks_cache()

    def teardown_method(self):
        _reset_jwks_cache()

    def test_fetches_keys_from_url(self, app):
        fake_keys = [{"kty": "RSA", "kid": "key1"}]
        fake_resp = _make_fake_urlopen({"keys": fake_keys, "public_certs": []})

        with app.app_context():
            with patch("auth.cloudflare_access.urlopen", return_value=fake_resp):
                # Patch RSAAlgorithm.from_jwk so parsing fake keys doesn't raise
                with patch("auth.cloudflare_access.pyjwt.algorithms.RSAAlgorithm.from_jwk",
                           return_value=MagicMock()):
                    keys = cloudflare_access._fetch_jwks("myteam.cloudflareaccess.com")

        assert keys == fake_keys

    def test_populates_cache_after_fetch(self, app):
        fake_keys = [{"kty": "RSA", "kid": "key2"}]
        fake_resp = _make_fake_urlopen({"keys": fake_keys, "public_certs": []})

        with app.app_context():
            with patch("auth.cloudflare_access.urlopen", return_value=fake_resp):
                with patch("auth.cloudflare_access.pyjwt.algorithms.RSAAlgorithm.from_jwk",
                           return_value=MagicMock()):
                    cloudflare_access._fetch_jwks("myteam.cloudflareaccess.com")

        assert cloudflare_access._jwks_cache["keys"] == fake_keys
        assert cloudflare_access._jwks_cache["fetched_at"] > 0

    def test_returns_cached_keys_without_refetching(self, app):
        """When the cache is warm and not expired, urlopen must not be called again."""
        cloudflare_access._jwks_cache["keys"] = [{"kty": "RSA", "kid": "cached"}]
        cloudflare_access._jwks_cache["fetched_at"] = time.time()  # just fetched

        with app.app_context():
            with patch("auth.cloudflare_access.urlopen") as mock_open:
                keys = cloudflare_access._fetch_jwks("myteam.cloudflareaccess.com")

        mock_open.assert_not_called()
        assert keys == [{"kty": "RSA", "kid": "cached"}]

    def test_refetches_when_cache_expired(self, app):
        """Expired cache (older than JWKS_CACHE_TTL) must trigger a new fetch."""
        cloudflare_access._jwks_cache["keys"] = [{"kty": "RSA", "kid": "stale"}]
        cloudflare_access._jwks_cache["fetched_at"] = (
            time.time() - cloudflare_access.JWKS_CACHE_TTL - 1
        )

        new_keys = [{"kty": "RSA", "kid": "fresh"}]
        fake_resp = _make_fake_urlopen({"keys": new_keys, "public_certs": []})

        with app.app_context():
            with patch("auth.cloudflare_access.urlopen", return_value=fake_resp):
                with patch("auth.cloudflare_access.pyjwt.algorithms.RSAAlgorithm.from_jwk",
                           return_value=MagicMock()):
                    keys = cloudflare_access._fetch_jwks("myteam.cloudflareaccess.com")

        assert keys == new_keys

    def test_returns_stale_cache_on_network_error(self, app):
        """If the network call raises, the stale (but non-None) cached keys are returned."""
        cloudflare_access._jwks_cache["keys"] = [{"kty": "RSA", "kid": "stale-fallback"}]
        cloudflare_access._jwks_cache["fetched_at"] = (
            time.time() - cloudflare_access.JWKS_CACHE_TTL - 1
        )

        with app.app_context():
            with patch("auth.cloudflare_access.urlopen", side_effect=OSError("connection refused")):
                keys = cloudflare_access._fetch_jwks("myteam.cloudflareaccess.com")

        assert keys == [{"kty": "RSA", "kid": "stale-fallback"}]

    def test_returns_empty_list_on_network_error_with_empty_cache(self, app):
        """If no stale keys exist and the network call fails, return an empty list."""
        with app.app_context():
            with patch("auth.cloudflare_access.urlopen", side_effect=OSError("timeout")):
                keys = cloudflare_access._fetch_jwks("myteam.cloudflareaccess.com")

        assert keys == []

    def test_uses_correct_certs_url(self, app):
        """The request URL must include the team domain and the standard path."""
        fake_resp = _make_fake_urlopen({"keys": [], "public_certs": []})
        captured_urls = []

        def fake_urlopen(req, timeout=10):
            captured_urls.append(req.full_url)
            return fake_resp

        with app.app_context():
            with patch("auth.cloudflare_access.urlopen", side_effect=fake_urlopen):
                cloudflare_access._fetch_jwks("example.cloudflareaccess.com")

        assert len(captured_urls) == 1
        assert "example.cloudflareaccess.com" in captured_urls[0]
        assert "/cdn-cgi/access/certs" in captured_urls[0]


# ---------------------------------------------------------------------------
# Middleware: _check_cf_access (registered via init_cf_access)
# ---------------------------------------------------------------------------

class TestCfAccessMiddleware:
    """Integration tests for the before_request hook."""

    def _set_cf_enabled(self, app, *, enabled, team_domain="myteam.cloudflareaccess.com",
                        audience="aud123", bypass_local=False):
        with app.app_context():
            Setting.set("cf_access_enabled", "true" if enabled else "false")
            Setting.set("cf_access_team_domain", team_domain)
            Setting.set("cf_access_audience", audience)
            Setting.set("cf_access_bypass_local_auth", "true" if bypass_local else "false")

    def test_disabled_middleware_does_not_auto_login(self, app):
        """When cf_access_enabled is false the middleware must not authenticate the user."""
        self._set_cf_enabled(app, enabled=False)

        with app.test_client() as c:
            resp = c.get("/", follow_redirects=False)

        # Unauthenticated client should be redirected to login, not to dashboard
        assert resp.status_code == 302
        assert "/login" in resp.headers.get("Location", "")

    def test_enabled_but_no_jwt_header_no_auto_login(self, app):
        """CF is enabled but no Cf-Access-Jwt-Assertion header → no automatic login."""
        self._set_cf_enabled(app, enabled=True)

        with app.test_client() as c:
            resp = c.get("/", follow_redirects=False)

        assert resp.status_code == 302
        assert "/login" in resp.headers.get("Location", "")

    def test_enabled_no_jwt_bypass_enabled_blocks_non_login_paths(self, app):
        """bypass_local_auth=true with no JWT token must block non-login endpoints with 403."""
        self._set_cf_enabled(app, enabled=True, bypass_local=True)

        with app.test_client() as c:
            resp = c.get("/", follow_redirects=False,
                         environ_base={"REMOTE_ADDR": "1.2.3.4"})

        # The middleware should 403 for protected paths when bypass is on and no token
        assert resp.status_code == 403

    def test_enabled_no_jwt_bypass_allows_login_page(self, app):
        """bypass_local_auth=true with no JWT token must still allow /login."""
        self._set_cf_enabled(app, enabled=True, bypass_local=True)

        with app.test_client() as c:
            resp = c.get("/login", follow_redirects=False)

        assert resp.status_code == 200

    def test_static_path_skips_cf_check(self, app):
        """Requests to /static/ must bypass CF Access validation entirely."""
        self._set_cf_enabled(app, enabled=True, bypass_local=True)

        with app.test_client() as c:
            # A missing static file will 404, but it must not be blocked with 403
            resp = c.get("/static/nonexistent.css", follow_redirects=False)

        assert resp.status_code != 403

    def test_already_authenticated_skips_cf_check(self, app, auth_client):
        """If the user is already logged in the CF middleware must be a no-op."""
        self._set_cf_enabled(app, enabled=True, bypass_local=True)

        # auth_client is already logged in — dashboard should be reachable
        resp = auth_client.get("/", follow_redirects=False)
        assert resp.status_code == 200

    def test_valid_jwt_auto_provisions_and_logs_in_user(self, app):
        """A valid (mocked) JWT should auto-provision and log in the CF user."""
        _cleanup_email = "jwt_test@example.com"

        # Ensure clean state
        with app.app_context():
            u = User.query.filter_by(username=_cleanup_email).first()
            if u:
                db.session.delete(u)
                db.session.commit()

        self._set_cf_enabled(app, enabled=True, bypass_local=False)

        with app.app_context():
            Setting.set("cf_access_auto_provision", "true")

        fake_payload = {"email": _cleanup_email, "name": "JWT Tester"}

        with app.test_client() as c:
            with patch("auth.cloudflare_access.validate_cf_token", return_value=fake_payload):
                resp = c.get(
                    "/",
                    headers={"Cf-Access-Jwt-Assertion": "fake.jwt.token"},
                    follow_redirects=False,
                )

        # Should reach dashboard (200), not redirect to login
        assert resp.status_code == 200

        # Verify user was created in DB
        with app.app_context():
            user = User.query.filter_by(username=_cleanup_email).first()
            assert user is not None
            assert user.created_via == "cloudflare"
            db.session.delete(user)
            db.session.commit()

    def test_invalid_jwt_bypass_off_does_not_block(self, app):
        """An invalid token with bypass_local_auth=false should not block (just skip auto-login)."""
        self._set_cf_enabled(app, enabled=True, bypass_local=False)

        with app.test_client() as c:
            with patch("auth.cloudflare_access.validate_cf_token",
                       side_effect=ValueError("bad sig")):
                resp = c.get(
                    "/",
                    headers={"Cf-Access-Jwt-Assertion": "bad.jwt.token"},
                    follow_redirects=False,
                )

        # No bypass → fall through to normal auth flow (redirect to login)
        assert resp.status_code == 302
        assert "/login" in resp.headers.get("Location", "")

    def test_invalid_jwt_bypass_on_returns_403(self, app):
        """An invalid token with bypass_local_auth=true must return 403."""
        self._set_cf_enabled(app, enabled=True, bypass_local=True)

        with app.test_client() as c:
            with patch("auth.cloudflare_access.validate_cf_token",
                       side_effect=ValueError("expired")):
                resp = c.get(
                    "/",
                    headers={"Cf-Access-Jwt-Assertion": "expired.jwt.token"},
                    follow_redirects=False,
                    environ_base={"REMOTE_ADDR": "1.2.3.4"},
                )

        assert resp.status_code == 403

    def test_no_team_domain_skips_cf_check(self, app):
        """If team_domain is empty, the middleware must skip even if CF is enabled."""
        with app.app_context():
            Setting.set("cf_access_enabled", "true")
            Setting.set("cf_access_team_domain", "")
            Setting.set("cf_access_audience", "aud123")
            Setting.set("cf_access_bypass_local_auth", "false")

        with app.test_client() as c:
            resp = c.get("/", follow_redirects=False)

        # No domain → skip CF, fall through to normal login redirect
        assert resp.status_code == 302
        assert "/login" in resp.headers.get("Location", "")

    def test_jwt_from_cookie_is_accepted(self, app):
        """CF_Authorization cookie should be used when no header is present."""
        _cleanup_email = "cookie_test@example.com"

        with app.app_context():
            u = User.query.filter_by(username=_cleanup_email).first()
            if u:
                db.session.delete(u)
                db.session.commit()

        self._set_cf_enabled(app, enabled=True, bypass_local=False)

        with app.app_context():
            Setting.set("cf_access_auto_provision", "true")

        fake_payload = {"email": _cleanup_email, "name": "Cookie User"}

        with app.test_client() as c:
            c.set_cookie("CF_Authorization", "fake.cookie.token")
            with patch("auth.cloudflare_access.validate_cf_token", return_value=fake_payload):
                resp = c.get("/", follow_redirects=False)

        assert resp.status_code == 200

        with app.app_context():
            user = User.query.filter_by(username=_cleanup_email).first()
            if user:
                db.session.delete(user)
                db.session.commit()


# ---------------------------------------------------------------------------
# CF Access sessions are tracked server-side (revocable, listed, audited)
# ---------------------------------------------------------------------------

class TestCfAccessSessionTracking:
    """A CF Access login must produce a UserSession row like any other login.

    Without one the session lives only in the signed cookie: it never appears in
    the session list and cannot be terminated short of rotating SECRET_KEY.
    """

    _EMAIL = "cf_session_test@example.com"

    def _enable(self, app):
        with app.app_context():
            Setting.set("cf_access_enabled", "true")
            Setting.set("cf_access_team_domain", "myteam.cloudflareaccess.com")
            Setting.set("cf_access_audience", "aud123")
            Setting.set("cf_access_bypass_local_auth", "false")
            Setting.set("cf_access_auto_provision", "true")
            db.session.commit()

    def _disable(self, app):
        with app.app_context():
            Setting.set("cf_access_enabled", "false")
            user = User.query.filter_by(username=self._EMAIL).first()
            if user:
                db.session.delete(user)
            db.session.commit()

    def test_cf_login_creates_a_user_session_row(self, app):
        from models import UserSession

        self._enable(app)
        payload = {"email": self._EMAIL, "name": "CF Session Tester"}
        try:
            with app.test_client() as c, patch(
                "auth.cloudflare_access.validate_cf_token", return_value=payload
            ):
                assert c.get("/", headers={"Cf-Access-Jwt-Assertion": "fake.jwt"}).status_code == 200

            with app.app_context():
                user = User.query.filter_by(username=self._EMAIL).first()
                assert user is not None
                assert UserSession.query.filter_by(user_id=user.id, revoked=False).count() == 1
        finally:
            self._disable(app)

    def test_cf_login_is_audited(self, app):
        from models import AuditLog

        self._enable(app)
        payload = {"email": self._EMAIL, "name": "CF Session Tester"}
        try:
            with app.test_client() as c, patch(
                "auth.cloudflare_access.validate_cf_token", return_value=payload
            ):
                c.get("/", headers={"Cf-Access-Jwt-Assertion": "fake.jwt"})

            with app.app_context():
                user = User.query.filter_by(username=self._EMAIL).first()
                entry = (AuditLog.query
                         .filter_by(action="login_cloudflare", user_id=user.id)
                         .first())
                assert entry is not None
        finally:
            self._disable(app)

    def test_revoking_the_row_ends_the_cf_session(self, app):
        from models import UserSession

        self._enable(app)
        payload = {"email": self._EMAIL, "name": "CF Session Tester"}
        try:
            with app.test_client() as c, patch(
                "auth.cloudflare_access.validate_cf_token", return_value=payload
            ):
                assert c.get("/", headers={"Cf-Access-Jwt-Assertion": "fake.jwt"}).status_code == 200

                with app.app_context():
                    record = UserSession.query.filter_by(revoked=False).order_by(
                        UserSession.id.desc()).first()
                    record.revoked = True
                    db.session.commit()

                # The cookie alone must no longer authorise the request; without a
                # CF header there is nothing left to re-authenticate with.
                resp = c.get("/", follow_redirects=False)
                assert resp.status_code == 302
                assert "/login" in resp.headers["Location"]
        finally:
            self._disable(app)
