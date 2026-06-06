"""Tests for the Mastodon 'make all accounts follow @account' streaming job."""
from unittest.mock import MagicMock, patch


def _setup_settings(app):
    from models import Setting
    with app.app_context():
        Setting.set("mastodon_guest_id", "1")
        Setting.set("mastodon_user", "mastodon")
        Setting.set("mastodon_app_dir", "/home/mastodon/live")


class _ImmediateThread:
    """Stand-in for threading.Thread that runs the target synchronously on start()."""

    def __init__(self, target=None, daemon=None):
        self._target = target

    def start(self):
        if self._target:
            self._target()


class _FakeSSH:
    """Context-manager SSH stub whose execute_sudo_streaming feeds canned output."""

    def __init__(self, captured, code=0):
        self._captured = captured
        self._code = code

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute_sudo_streaming(self, command, callback, timeout=600, stop_fn=None):
        self._captured["cmd"] = command
        callback("Following 1/3...\n")
        callback("Following 2/3...\n")
        callback("Following 3/3...\n")
        return self._code


def _reset_job(rm):
    rm._follow_job.update({"running": False, "success": None, "log": []})


class TestMastodonFollowAccount:
    def test_start_streams_output_into_job(self, app, auth_client):
        import clients.ssh_client as sshmod
        import routes.mastodon as rm
        _setup_settings(app)
        _reset_job(rm)
        captured = {}
        guest = MagicMock()
        guest.ip_address = "10.0.0.5"
        guest.credential = MagicMock()
        with patch.object(rm, "Guest") as MockGuest, \
             patch.object(rm._threading, "Thread", _ImmediateThread), \
             patch.object(sshmod.SSHClient, "from_credential", return_value=_FakeSSH(captured)):
            MockGuest.query.get.return_value = guest
            resp = auth_client.post("/mastodon/follow-account", data={"account": "announcements"})

        assert resp.status_code == 200
        assert resp.get_json()["started"] is True
        assert "su - mastodon -c" in captured["cmd"]
        assert "RAILS_ENV=production bin/tootctl accounts follow announcements" in captured["cmd"]
        log = "".join(rm._follow_job["log"])
        assert "Following 2/3" in log
        assert rm._follow_job["success"] is True
        assert rm._follow_job["running"] is False

    def test_defaults_to_announcements_when_blank(self, app, auth_client):
        import clients.ssh_client as sshmod
        import routes.mastodon as rm
        _setup_settings(app)
        _reset_job(rm)
        captured = {}
        guest = MagicMock()
        guest.ip_address = "10.0.0.5"
        guest.credential = MagicMock()
        with patch.object(rm, "Guest") as MockGuest, \
             patch.object(rm._threading, "Thread", _ImmediateThread), \
             patch.object(sshmod.SSHClient, "from_credential", return_value=_FakeSSH(captured)):
            MockGuest.query.get.return_value = guest
            auth_client.post("/mastodon/follow-account", data={})
        assert "accounts follow announcements" in captured["cmd"]

    def test_nonzero_exit_marks_failure(self, app, auth_client):
        import clients.ssh_client as sshmod
        import routes.mastodon as rm
        _setup_settings(app)
        _reset_job(rm)
        guest = MagicMock()
        guest.ip_address = "10.0.0.5"
        guest.credential = MagicMock()
        with patch.object(rm, "Guest") as MockGuest, \
             patch.object(rm._threading, "Thread", _ImmediateThread), \
             patch.object(sshmod.SSHClient, "from_credential", return_value=_FakeSSH({}, code=1)):
            MockGuest.query.get.return_value = guest
            auth_client.post("/mastodon/follow-account", data={"account": "announcements"})
        assert rm._follow_job["success"] is False
        assert "exited with code 1" in "".join(rm._follow_job["log"])

    def test_status_endpoint_returns_joined_log(self, app, auth_client):
        import routes.mastodon as rm
        rm._follow_job.update({"running": True, "success": None, "log": ["hello\n", "world\n"]})
        try:
            resp = auth_client.get("/mastodon/follow-account/status")
            data = resp.get_json()
            assert data["running"] is True
            assert data["success"] is None
            assert data["log"] == "hello\nworld\n"
        finally:
            _reset_job(rm)

    def test_invalid_account_returns_400_not_started(self, app, auth_client):
        import routes.mastodon as rm
        _setup_settings(app)
        _reset_job(rm)
        with patch.object(rm._threading, "Thread", _ImmediateThread):
            resp = auth_client.post("/mastodon/follow-account", data={"account": "bad name!"})
        assert resp.status_code == 400
        assert rm._follow_job["running"] is False

    def test_account_with_at_and_domain_rejected(self, app, auth_client):
        import routes.mastodon as rm
        _setup_settings(app)
        _reset_job(rm)
        resp = auth_client.post("/mastodon/follow-account", data={"account": "user@example.com"})
        assert resp.status_code == 400
        assert rm._follow_job["running"] is False

    def test_already_running_returns_409(self, app, auth_client):
        import routes.mastodon as rm
        _setup_settings(app)
        rm._follow_job.update({"running": True, "success": None, "log": []})
        try:
            resp = auth_client.post("/mastodon/follow-account", data={"account": "announcements"})
            assert resp.status_code == 409
        finally:
            _reset_job(rm)

    def test_upgrade_page_renders_with_follow_modal_and_button(self, app, auth_client):
        _setup_settings(app)
        resp = auth_client.get("/mastodon/upgrade")
        assert resp.status_code == 200
        assert b'id="followModal"' in resp.data           # the live-output modal
        assert b'name="account"' in resp.data             # the account input
        assert b'startFollow(event)' in resp.data         # JS-intercepted submit

    def test_no_guest_configured_returns_400(self, app, auth_client):
        import routes.mastodon as rm
        from models import Setting
        with app.app_context():
            Setting.set("mastodon_guest_id", "")
        _reset_job(rm)
        resp = auth_client.post("/mastodon/follow-account", data={"account": "announcements"})
        assert resp.status_code == 400
        assert rm._follow_job["running"] is False
