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

    def test_refuses_to_fetch_for_invalid_team_domain(self, app):
        """An .endswith()-style bypass string must never reach urlopen -- it's
        used to build the JWKS fetch URL (SSRF primitive; GHSA-gj96-qjq5-q57h)."""
        with app.app_context():
            with patch("auth.cloudflare_access.urlopen") as mock_open:
                keys = cloudflare_access._fetch_jwks("evil.com#.cloudflareaccess.com")

        mock_open.assert_not_called()
        assert keys == []

    def test_refuses_suffix_bypass_domain(self, app):
        with app.app_context():
            with patch("auth.cloudflare_access.urlopen") as mock_open:
                keys = cloudflare_access._fetch_jwks("evil.com.cloudflareaccess.com.evil.com")

        mock_open.assert_not_called()
        assert keys == []


# ---------------------------------------------------------------------------
# _is_valid_team_domain() -- shared strict validator used by the JWKS URL
# builder above and the logout redirect in routes/auth.py.
# ---------------------------------------------------------------------------

class TestIsValidTeamDomain:
    def test_accepts_well_formed_domain(self):
        assert cloudflare_access._is_valid_team_domain("myteam.cloudflareaccess.com") is True

    def test_accepts_hyphenated_and_numeric_team_names(self):
        assert cloudflare_access._is_valid_team_domain("my-team-2.cloudflareaccess.com") is True

    def test_rejects_endswith_bypass(self):
        """A naive `.endswith(".cloudflareaccess.com")` check would accept this."""
        assert cloudflare_access._is_valid_team_domain("evil.com#.cloudflareaccess.com") is False

    def test_rejects_suffix_bypass(self):
        assert cloudflare_access._is_valid_team_domain("evil.com.cloudflareaccess.com.evil.com") is False

    def test_rejects_empty(self):
        assert cloudflare_access._is_valid_team_domain("") is False

    def test_rejects_none(self):
        assert cloudflare_access._is_valid_team_domain(None) is False

    def test_rejects_other_scheme_prefix(self):
        assert cloudflare_access._is_valid_team_domain("https://myteam.cloudflareaccess.com") is False

    def test_is_case_insensitive(self):
        assert cloudflare_access._is_valid_team_domain("MyTeam.CloudflareAccess.com") is True


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
# POST /logout -- Cloudflare Access logout redirect (routes/auth.py)
# ---------------------------------------------------------------------------

class TestCfLogoutRedirect:
    """A logged-out CF-provisioned user is redirected to the CF logout URL,
    but only when team_domain is a strictly valid *.cloudflareaccess.com value.
    A naive `.endswith()` check would accept "evil.com#.cloudflareaccess.com"
    and turn this into an open redirect (GHSA-gj96-qjq5-q57h)."""

    def _login_cf_user(self, app, email, team_domain="myteam.cloudflareaccess.com"):
        with app.app_context():
            Setting.set("cf_access_enabled", "true")
            Setting.set("cf_access_team_domain", team_domain)
            Setting.set("cf_access_audience", "aud123")
            Setting.set("cf_access_bypass_local_auth", "false")
            Setting.set("cf_access_auto_provision", "true")

        c = app.test_client()
        fake_payload = {"email": email, "name": "CF User"}
        with patch("auth.cloudflare_access.validate_cf_token", return_value=fake_payload):
            resp = c.get("/", headers={"Cf-Access-Jwt-Assertion": "fake.jwt.token"}, follow_redirects=False)
        assert resp.status_code == 200
        return c

    def test_logout_redirects_to_valid_team_domain(self, app):
        email = "logout_valid@example.com"
        with app.app_context():
            u = User.query.filter_by(username=email).first()
            if u:
                db.session.delete(u)
                db.session.commit()

        c = self._login_cf_user(app, email)
        resp = c.post("/logout", follow_redirects=False)

        assert resp.status_code == 302
        assert resp.headers["Location"] == "https://myteam.cloudflareaccess.com/cdn-cgi/access/logout"

        with app.app_context():
            u = User.query.filter_by(username=email).first()
            if u:
                db.session.delete(u)
                db.session.commit()

    def test_logout_does_not_redirect_for_bypass_team_domain(self, app):
        """An invalid (bypass-style) team_domain must fall back to the normal
        /login redirect, not an attacker-controlled URL."""
        email = "logout_bypass@example.com"
        with app.app_context():
            u = User.query.filter_by(username=email).first()
            if u:
                db.session.delete(u)
                db.session.commit()

        c = self._login_cf_user(app, email)
        # Swap in a malicious value right before logout so the login step
        # itself doesn't depend on the malicious domain being accepted.
        with app.app_context():
            Setting.set("cf_access_team_domain", "evil.com#.cloudflareaccess.com")

        resp = c.post("/logout", follow_redirects=False)

        assert resp.status_code == 302
        location = resp.headers.get("Location", "")
        assert "evil.com" not in location
        assert "/login" in location

        with app.app_context():
            u = User.query.filter_by(username=email).first()
            if u:
                db.session.delete(u)
                db.session.commit()
