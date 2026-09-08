"""Tests for auth routes and CSRF origin middleware."""


class TestLogin:
    def test_get_login_page(self, client):
        resp = client.get("/login")
        assert resp.status_code == 200
        assert b"login" in resp.data.lower()

    def test_valid_credentials_redirect(self, client):
        resp = client.post(
            "/login",
            data={"username": "admin", "password": "TestPass123!"},
            follow_redirects=False,
        )
        assert resp.status_code == 302

    def test_invalid_credentials_stays_on_login(self, client):
        resp = client.post(
            "/login",
            data={"username": "admin", "password": "wrongpassword"},
            follow_redirects=False,
        )
        # Either stays on login (200) or redirects back to login (302 to /login)
        assert resp.status_code in (200, 302)
        if resp.status_code == 302:
            assert "/login" in resp.headers.get("Location", "")

    def test_unauthenticated_redirects_to_login(self, client):
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


class TestLogout:
    def test_get_logout_returns_405(self, auth_client):
        """Logout must be POST-only (PR #4)."""
        resp = auth_client.get("/logout")
        assert resp.status_code == 405

    def test_post_logout_succeeds(self, auth_client):
        resp = auth_client.post("/logout", follow_redirects=False)
        assert resp.status_code in (200, 302)


class TestCsrfOriginCheck:
    def test_post_without_origin_is_allowed(self, client):
        """Non-browser clients (no Origin/Referer) must not be blocked."""
        resp = client.post(
            "/login",
            data={"username": "admin", "password": "TestPass123!"},
        )
        # Should process the request (200 or redirect), not 403
        assert resp.status_code != 403

    def test_post_with_matching_origin_is_allowed(self, client):
        resp = client.post(
            "/login",
            data={"username": "admin", "password": "TestPass123!"},
            headers={"Origin": "http://localhost"},
        )
        assert resp.status_code != 403

    def test_post_with_mismatched_origin_is_blocked(self, client):
        resp = client.post(
            "/login",
            data={"username": "admin", "password": "TestPass123!"},
            headers={"Origin": "https://evil.com"},
        )
        assert resp.status_code == 403


class TestUsernameCaseNormalisation:
    """Usernames are stored lower-cased, so login must normalise too (#127)."""

    def _make_user(self, app, username, password):
        from models import Role, User, db

        with app.app_context():
            role = Role.query.filter_by(name="viewer").first()
            user = User(username=username, display_name=username, role_id=role.id)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            return user.id

    def _delete_user(self, app, user_id):
        from models import User, db

        with app.app_context():
            user = User.query.get(user_id)
            if user:
                db.session.delete(user)
                db.session.commit()

    def test_mixed_case_login_matches_lowercase_account(self, app, client):
        user_id = self._make_user(app, "_case_test_user", "CasePass123!")
        try:
            resp = client.post(
                "/login",
                data={"username": "_Case_Test_User", "password": "CasePass123!"},
                follow_redirects=False,
            )
            assert resp.status_code == 302
            assert "/login" not in resp.headers.get("Location", "")
        finally:
            self._delete_user(app, user_id)

    def test_surrounding_whitespace_is_stripped(self, app, client):
        user_id = self._make_user(app, "_case_ws_user", "CasePass123!")
        try:
            resp = client.post(
                "/login",
                data={"username": "  _CASE_WS_USER  ", "password": "CasePass123!"},
                follow_redirects=False,
            )
            assert resp.status_code == 302
            assert "/login" not in resp.headers.get("Location", "")
        finally:
            self._delete_user(app, user_id)

    def test_admin_created_via_security_route_can_log_in_with_any_case(self, app, auth_client, client):
        from models import User, db

        resp = auth_client.post(
            "/security/users/add",
            data={"username": "MixedCaseAdmin", "display_name": "Mixed",
                  "password": "MixedPass123!"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        try:
            with app.app_context():
                assert User.query.filter_by(username="mixedcaseadmin").first() is not None

            login = client.post(
                "/login",
                data={"username": "MixedCaseAdmin", "password": "MixedPass123!"},
                follow_redirects=False,
            )
            assert login.status_code == 302
            assert "/login" not in login.headers.get("Location", "")
        finally:
            with app.app_context():
                user = User.query.filter_by(username="mixedcaseadmin").first()
                if user:
                    db.session.delete(user)
                    db.session.commit()
