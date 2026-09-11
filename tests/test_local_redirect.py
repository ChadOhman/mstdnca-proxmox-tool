"""core.local_redirect: referrer / ?next= targets are resolved via the URL map, never echoed."""

import pytest

from core.local_redirect import redirect_back, resolve_local_url
from tests.conftest import _TEST_ADMIN_PASSWORD


class TestResolveLocalUrl:
    @pytest.mark.parametrize("target", [None, "", "   ", 42])
    def test_empty_or_non_string_is_rejected(self, app, target):
        with app.test_request_context("/"):
            assert resolve_local_url(target) is None

    def test_root_path_resolves_to_dashboard(self, app):
        with app.test_request_context("/"):
            assert resolve_local_url("/") == "/"

    def test_absolute_url_on_own_host_is_accepted(self, app):
        with app.test_request_context("/", base_url="http://localhost"):
            assert resolve_local_url("http://localhost/login") == "/login"

    @pytest.mark.parametrize("target", [
        "http://evil.example/login",
        "https://evil.example/",
        "//evil.example/login",
        "///evil.example/login",
        "javascript:alert(1)",
        "ftp://localhost/login",
    ])
    def test_other_hosts_and_schemes_are_rejected(self, app, target):
        with app.test_request_context("/", base_url="http://localhost"):
            assert resolve_local_url(target) is None

    def test_unknown_path_is_rejected(self, app):
        with app.test_request_context("/"):
            assert resolve_local_url("/definitely-not-a-route") is None

    def test_relative_path_is_rejected(self, app):
        with app.test_request_context("/"):
            assert resolve_local_url("login") is None

    def test_static_files_are_rejected(self, app):
        with app.test_request_context("/"):
            assert resolve_local_url("/static/app.js") is None

    def test_query_string_is_preserved_but_rebuilt(self, app):
        with app.test_request_context("/"):
            assert resolve_local_url("/login?next=%2Fhosts&x=1") == "/login?next=/hosts&x=1"

    def test_missing_trailing_slash_resolves_to_canonical_route(self, app):
        with app.test_request_context("/?next=/hosts"):
            # werkzeug's canonical-slash hop must not drag the *current* request's
            # query string along; only the target's own query survives.
            assert resolve_local_url("/hosts") == "/hosts/"
            assert resolve_local_url("/hosts?page=2") == "/hosts/?page=2"

    def test_url_for_reserved_kwargs_cannot_be_injected(self, app):
        with app.test_request_context("/"):
            # _external / _scheme would otherwise let a query string build an absolute URL.
            resolved = resolve_local_url("/login?_external=1&_scheme=https")
            assert resolved == "/login"

    def test_path_traversal_and_encoding_are_normalised(self, app):
        with app.test_request_context("/"):
            assert resolve_local_url("/%6cogin") == "/login"
            assert resolve_local_url("/login/../hosts") is None


class TestRedirectBack:
    def test_uses_referer_when_it_is_our_own_route(self, app):
        with app.test_request_context("/", headers={"Referer": "http://localhost/login"}):
            resp = redirect_back("dashboard.index")
        assert resp.status_code == 302
        assert resp.headers["Location"] == "/login"

    def test_falls_back_when_referer_is_foreign(self, app):
        with app.test_request_context("/", headers={"Referer": "http://evil.example/login"}):
            resp = redirect_back("dashboard.index")
        assert resp.headers["Location"] == "/"

    def test_falls_back_when_referer_missing(self, app):
        with app.test_request_context("/"):
            resp = redirect_back("auth.login")
        assert resp.headers["Location"] == "/login"


class TestRoutesUseSafeRedirects:
    def test_toggle_safety_mode_ignores_foreign_referer(self, auth_client):
        resp = auth_client.post(
            "/toggle-safety-mode",
            headers={"Referer": "http://localhost/", "Origin": "http://localhost"},
            follow_redirects=False,
        )
        assert resp.headers["Location"] in ("/", "http://localhost/")

    def test_login_next_to_own_route_is_honoured(self, app):
        with app.test_client() as c:
            resp = c.post(
                "/login?next=/hosts",
                data={"username": "admin", "password": _TEST_ADMIN_PASSWORD},
                follow_redirects=False,
            )
        assert resp.status_code == 302
        assert resp.headers["Location"].rstrip("/") == "/hosts"

    @pytest.mark.parametrize("next_value", [
        "http://evil.example/",
        "//evil.example/",
        "/no-such-route",
    ])
    def test_login_next_elsewhere_falls_back_to_dashboard(self, app, next_value):
        with app.test_client() as c:
            resp = c.post(
                f"/login?next={next_value}",
                data={"username": "admin", "password": _TEST_ADMIN_PASSWORD},
                follow_redirects=False,
            )
        assert resp.status_code == 302
        assert resp.headers["Location"] in ("/", "http://localhost/")
