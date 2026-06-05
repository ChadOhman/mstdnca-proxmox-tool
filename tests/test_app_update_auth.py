"""Tests for the shared app-update GitHub-token helpers."""


class TestGithubAuthHeaders:
    def test_empty_when_no_token(self, app):
        from core.app_update_auth import github_auth_headers
        from models import Setting
        with app.app_context():
            Setting.set("github_token", "")
            assert github_auth_headers() == {}

    def test_bearer_when_token_set(self, app):
        from auth.credential_store import encrypt
        from core.app_update_auth import github_auth_headers
        from models import Setting
        with app.app_context():
            Setting.set("github_token", encrypt("ghp_unit"))
            assert github_auth_headers() == {"Authorization": "Bearer ghp_unit"}


class TestGithubTokenEnv:
    def test_includes_token_when_set(self, app):
        from auth.credential_store import encrypt
        from core.app_update_auth import github_token_env
        from models import Setting
        with app.app_context():
            Setting.set("github_token", encrypt("ghp_env"))
            env = github_token_env()
            assert env.get("GITHUB_TOKEN") == "ghp_env"
            # it's a real os.environ copy, not a bare {GITHUB_TOKEN: ...} dict
            assert len(env) > 1

    def test_omits_token_when_unset(self, app):
        from core.app_update_auth import github_token_env
        from models import Setting
        with app.app_context():
            Setting.set("github_token", "")
            assert "GITHUB_TOKEN" not in github_token_env()
