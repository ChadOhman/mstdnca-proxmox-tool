"""Mastodon-exporter route input validation (issue #125).

The routes used to flip the job to running *before* parsing the form, so a bad
``port`` raised a 500 and wedged the job forever.  They also called
``create_app()`` inside the request-spawned thread instead of reusing the
current app object.
"""
import inspect
from unittest.mock import patch

from models import Setting, db


def _configure_guest(app):
    with app.app_context():
        Setting.set("mastodon_guest_id", "1")
        db.session.commit()


class TestMastodonExporterInputValidation:
    def _post(self, auth_client, url, data):
        with patch("apps.exporters.enable_mastodon_exporter") as enable, \
             patch("apps.exporters.reconfigure_mastodon_exporter") as reconf:
            resp = auth_client.post(url, data=data, follow_redirects=True)
            return resp, enable, reconf

    def test_bad_port_is_rejected_without_starting_a_job(self, app, auth_client):
        _configure_guest(app)
        from routes.prometheus_app import _mastodon_exporter_job

        resp, enable, _ = self._post(
            auth_client, "/prometheus/mastodon-exporter/enable",
            {"mode": "external", "host": "0.0.0.0", "port": "not-a-number"},
        )
        assert resp.status_code == 200
        assert b"Invalid exporter port" in resp.data
        enable.assert_not_called()
        # Crucially, the job is not left stuck in the running state.
        assert _mastodon_exporter_job["running"] is False

    def test_out_of_range_port_is_rejected(self, app, auth_client):
        _configure_guest(app)
        from routes.prometheus_app import _mastodon_exporter_job

        resp, enable, _ = self._post(
            auth_client, "/prometheus/mastodon-exporter/enable",
            {"mode": "external", "host": "0.0.0.0", "port": "99999"},
        )
        assert b"out of range" in resp.data
        enable.assert_not_called()
        assert _mastodon_exporter_job["running"] is False

    def test_bad_mode_is_rejected(self, app, auth_client):
        _configure_guest(app)
        resp, enable, _ = self._post(
            auth_client, "/prometheus/mastodon-exporter/enable",
            {"mode": "sideways", "host": "0.0.0.0", "port": "9394"},
        )
        assert b"Invalid exporter mode" in resp.data
        enable.assert_not_called()

    def test_bad_host_is_rejected(self, app, auth_client):
        _configure_guest(app)
        resp, enable, _ = self._post(
            auth_client, "/prometheus/mastodon-exporter/enable",
            {"mode": "external", "host": "0.0.0.0; rm -rf /", "port": "9394"},
        )
        assert b"Invalid exporter host" in resp.data
        enable.assert_not_called()

    def test_reconfigure_validates_too(self, app, auth_client):
        _configure_guest(app)
        from routes.prometheus_app import _mastodon_exporter_job

        resp, _, reconf = self._post(
            auth_client, "/prometheus/mastodon-exporter/reconfigure",
            {"mode": "external", "host": "0.0.0.0", "port": "0"},
        )
        assert b"out of range" in resp.data
        reconf.assert_not_called()
        assert _mastodon_exporter_job["running"] is False


class TestMastodonExporterConfigParser:
    def test_valid_config_round_trips(self, app):
        from routes.prometheus_app import _parse_mastodon_exporter_config

        with app.test_request_context(
            "/", method="POST",
            data={"mode": "internal", "host": "127.0.0.1", "port": "9500",
                  "web_detailed_metrics": "on"},
        ):
            config, err = _parse_mastodon_exporter_config()
        assert err is None
        assert config == {
            "web_detailed_metrics": True,
            "sidekiq_detailed_metrics": False,
            "mode": "internal",
            "host": "127.0.0.1",
            "port": 9500,
        }

    def test_defaults_apply_for_empty_fields(self, app):
        from routes.prometheus_app import _parse_mastodon_exporter_config

        with app.test_request_context("/", method="POST", data={}):
            config, err = _parse_mastodon_exporter_config()
        assert err is None
        assert config["host"] == "0.0.0.0"  # noqa: S104 — exporter bind default
        assert config["port"] == 9394
        assert config["mode"] == "external"

    def test_guest_id_parser_rejects_garbage(self):
        from routes.prometheus_app import _parse_mastodon_guest_id

        guest_id, err = _parse_mastodon_guest_id("12")
        assert (guest_id, err) == (12, None)
        guest_id, err = _parse_mastodon_guest_id("not-an-int")
        assert guest_id is None
        assert "not a valid integer" in err


class TestMastodonExporterThreadUsesCurrentApp:
    """The request-spawned thread must not build a second app with create_app()."""

    def test_routes_do_not_call_create_app(self):
        import routes.prometheus_app as mod

        for name in ("mastodon_exporter_enable", "mastodon_exporter_disable",
                     "mastodon_exporter_reconfigure"):
            source = inspect.getsource(getattr(mod, name))
            assert "create_app()" not in source, name
            assert "current_app._get_current_object()" in source, name
