"""Tests for the Mastodon 'make all accounts follow @account' button/route."""
from unittest.mock import MagicMock, patch


def _setup_settings(app):
    from models import Setting
    with app.app_context():
        Setting.set("mastodon_guest_id", "1")
        Setting.set("mastodon_user", "mastodon")
        Setting.set("mastodon_app_dir", "/home/mastodon/live")


class TestMastodonFollowAccount:
    def test_follow_announcements_runs_tootctl(self, app, auth_client):
        import routes.mastodon as rm
        _setup_settings(app)
        with patch.object(rm, "Guest") as MockGuest, \
             patch("core.scanner._execute_command", return_value=("Done", None)) as mexec:
            MockGuest.query.get.return_value = MagicMock()
            resp = auth_client.post(
                "/mastodon/follow-account",
                data={"account": "announcements"},
                follow_redirects=False,
            )
        assert resp.status_code == 302
        assert mexec.called
        cmd = mexec.call_args.args[1]
        assert "su - mastodon -c" in cmd
        assert "RAILS_ENV=production bin/tootctl accounts follow announcements" in cmd

    def test_defaults_to_announcements_when_blank(self, app, auth_client):
        import routes.mastodon as rm
        _setup_settings(app)
        with patch.object(rm, "Guest") as MockGuest, \
             patch("core.scanner._execute_command", return_value=("Done", None)) as mexec:
            MockGuest.query.get.return_value = MagicMock()
            auth_client.post("/mastodon/follow-account", data={}, follow_redirects=False)
        assert "accounts follow announcements" in mexec.call_args.args[1]

    def test_invalid_account_rejected_no_command(self, app, auth_client):
        import routes.mastodon as rm
        _setup_settings(app)
        with patch.object(rm, "Guest") as MockGuest, \
             patch("core.scanner._execute_command") as mexec:
            MockGuest.query.get.return_value = MagicMock()
            resp = auth_client.post(
                "/mastodon/follow-account",
                data={"account": "bad name!"},
                follow_redirects=False,
            )
        assert resp.status_code == 302
        assert not mexec.called

    def test_account_with_at_and_domain_rejected(self, app, auth_client):
        import routes.mastodon as rm
        _setup_settings(app)
        with patch.object(rm, "Guest") as MockGuest, \
             patch("core.scanner._execute_command") as mexec:
            MockGuest.query.get.return_value = MagicMock()
            resp = auth_client.post(
                "/mastodon/follow-account",
                data={"account": "user@example.com"},
                follow_redirects=False,
            )
        assert resp.status_code == 302
        assert not mexec.called

    def test_no_guest_configured_graceful(self, app, auth_client):
        from models import Setting
        with app.app_context():
            Setting.set("mastodon_guest_id", "")
        with patch("core.scanner._execute_command") as mexec:
            resp = auth_client.post(
                "/mastodon/follow-account",
                data={"account": "announcements"},
                follow_redirects=False,
            )
        assert resp.status_code == 302
        assert not mexec.called
