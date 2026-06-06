"""Tests for the Prometheus integration (exporter, query client, routes)."""

import json
from unittest.mock import MagicMock, patch

import pytest

from models import Guest, GuestService, db

# ---------------------------------------------------------------------------
# Exporter tests
# ---------------------------------------------------------------------------

class TestPrometheusExporter:
    """Test the prometheus_exporter module."""

    def test_get_metrics_returns_bytes(self, app):
        from clients.prometheus_exporter import get_metrics
        with app.app_context():
            output = get_metrics()
            assert isinstance(output, bytes)

    def test_update_host_metrics(self, app):
        from clients.prometheus_exporter import HOST_CPU, update_host_metrics
        with app.app_context():
            update_host_metrics(1, "pve1", "pve", {
                "cpu": 0.42,
                "memory": {"used": 8_000_000_000, "total": 16_000_000_000},
                "rootfs": {"used": 5_000_000_000, "total": 50_000_000_000},
                "uptime": 86400,
            })
            # Verify the gauge was set
            val = HOST_CPU.labels("1", "pve1", "pve")._value.get()
            assert val == 42.0

    def test_update_guest_metrics(self, app):
        from clients.prometheus_exporter import GUEST_CPU, update_guest_metrics
        with app.app_context():
            update_guest_metrics(10, "myvm", "vm", "pve1", 100, {
                "cpu": 0.5,
                "maxcpu": 2,
                "mem": 2_000_000_000,
                "maxmem": 4_000_000_000,
                "status": "running",
            })
            val = GUEST_CPU.labels("10", "myvm", "vm", "pve1", "100")._value.get()
            assert val == 25.0  # 0.5 / 2 * 100

    def test_update_service_health(self, app):
        from clients.prometheus_exporter import SVC_UP, update_service_health
        with app.app_context():
            update_service_health(1, "postgresql", "db-guest", "postgresql.service", "running")
            val = SVC_UP.labels("1", "postgresql", "db-guest", "postgresql.service")._value.get()
            assert val == 1.0

    def test_update_pg_metrics(self, app):
        from clients.prometheus_exporter import PG_CONNECTIONS, update_pg_metrics
        with app.app_context():
            update_pg_metrics(1, "db-guest", {
                "total_connections": 42,
                "cache_hit_ratio": "99.5%",
                "active_queries": 3,
                "total_commits": 1000,
                "total_rollbacks": 5,
                "lock_waits": 0,
            })
            val = PG_CONNECTIONS.labels("1", "db-guest")._value.get()
            assert val == 42.0

    def test_update_redis_metrics(self, app):
        from clients.prometheus_exporter import REDIS_MEM, update_redis_metrics
        with app.app_context():
            update_redis_metrics(2, "cache-guest", {
                "used_memory": 50_000_000,
                "connected_clients": 10,
                "ops_per_sec": 500,
                "hit_ratio": "95%",
                "evicted_keys": 0,
            })
            val = REDIS_MEM.labels("2", "cache-guest")._value.get()
            assert val == 50_000_000.0

    def test_update_jitsi_metrics(self, app):
        from clients.prometheus_exporter import JITSI_CONFERENCES, update_jitsi_metrics
        with app.app_context():
            update_jitsi_metrics(3, "jitsi-guest", {
                "conferences": 5,
                "participants": 25,
                "stress_level": 0.3,
                "bit_rate_download": 1500000,
            })
            val = JITSI_CONFERENCES.labels("3", "jitsi-guest")._value.get()
            assert val == 5.0

    def test_update_prometheus_metrics(self, app):
        from clients.prometheus_exporter import PROM_HEAD_SERIES, PROM_TARGETS_UP, update_prometheus_metrics
        with app.app_context():
            update_prometheus_metrics(4, "prom-guest", {
                "targets_up": 3,
                "targets_down": 1,
                "storage_bytes": 500_000_000,
                "head_series": 12345,
            })
            val = PROM_TARGETS_UP.labels("4", "prom-guest")._value.get()
            assert val == 3.0
            val = PROM_HEAD_SERIES.labels("4", "prom-guest")._value.get()
            assert val == 12345.0

    def test_update_apt_metrics(self, app):
        from clients.prometheus_exporter import APT_PENDING, update_apt_metrics
        with app.app_context():
            update_apt_metrics(1, "web-server", 10, 2, True)
            val = APT_PENDING.labels("1", "web-server")._value.get()
            assert val == 10.0

    def test_update_app_version_info(self, app):
        from clients.prometheus_exporter import APP_UPDATE, update_app_version_info
        with app.app_context():
            update_app_version_info("mastodon", "4.2.0", "4.3.0", True)
            val = APP_UPDATE.labels("mastodon")._value.get()
            assert val == 1.0

    def test_metrics_output_contains_metric_names(self, app):
        from clients.prometheus_exporter import get_metrics, update_host_metrics
        with app.app_context():
            update_host_metrics(99, "testhost", "pve", {"cpu": 0.1, "uptime": 100})
            output = get_metrics().decode("utf-8")
            assert "mstdnca_host_cpu_usage_percent" in output
            assert "mstdnca_host_uptime_seconds" in output


# ---------------------------------------------------------------------------
# /metrics endpoint tests
# ---------------------------------------------------------------------------

class TestMetricsEndpoint:
    """Test the /metrics route."""

    def test_metrics_endpoint_requires_login_when_no_token(self, app, client):
        """Without a token configured, unauthenticated requests should get 401."""
        with app.app_context():
            from models import Setting
            Setting.set("prometheus_auth_token", "")
        resp = client.get("/metrics")
        assert resp.status_code == 401

    def test_metrics_endpoint_accessible_when_logged_in(self, app, auth_client):
        """Without a token configured, authenticated users should get 200."""
        with app.app_context():
            from models import Setting
            Setting.set("prometheus_auth_token", "")
        resp = auth_client.get("/metrics")
        assert resp.status_code == 200

    def test_metrics_endpoint_auth_required(self, app, client):
        """When auth token is set, requests without it should be rejected."""
        with app.app_context():
            from models import Setting, db
            Setting.set("prometheus_auth_token", "test-secret-token")
            db.session.commit()
        resp = client.get("/metrics")
        assert resp.status_code == 401

    def test_metrics_endpoint_auth_bearer(self, app, client):
        """Bearer token auth should work."""
        with app.app_context():
            from models import Setting, db
            Setting.set("prometheus_auth_token", "test-secret-token")
            db.session.commit()
        resp = client.get("/metrics", headers={"Authorization": "Bearer test-secret-token"})
        assert resp.status_code == 200

    def test_metrics_endpoint_auth_query_param(self, app, client):
        """Query param token auth should work."""
        with app.app_context():
            from models import Setting, db
            Setting.set("prometheus_auth_token", "test-secret-token")
            db.session.commit()
        resp = client.get("/metrics?token=test-secret-token")
        assert resp.status_code == 200

    def test_metrics_endpoint_wrong_token(self, app, client):
        """Wrong token should be rejected."""
        with app.app_context():
            from models import Setting, db
            Setting.set("prometheus_auth_token", "test-secret-token")
            db.session.commit()
        resp = client.get("/metrics", headers={"Authorization": "Bearer wrong-token"})
        assert resp.status_code == 401

        # Clean up
        with app.app_context():
            from models import Setting, db
            Setting.set("prometheus_auth_token", "")
            db.session.commit()


# ---------------------------------------------------------------------------
# Query client tests
# ---------------------------------------------------------------------------

class TestPrometheusQueryClient:
    """Test the prometheus_query module."""

    def test_init_raises_without_url(self, app):
        from clients.prometheus_query import PrometheusQueryClient
        with app.app_context():
            from models import Setting
            Setting.set("prometheus_url", "")
            with pytest.raises(ValueError, match="not configured"):
                PrometheusQueryClient()

    def test_check_connection_returns_false_on_error(self, app):
        from clients.prometheus_query import PrometheusQueryClient
        client = PrometheusQueryClient(base_url="http://localhost:99999")
        assert client.check_connection() is False

    @patch("clients.prometheus_query.requests.get")
    def test_query_range_parses_response(self, mock_get, app):
        from clients.prometheus_query import PrometheusQueryClient

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "success",
            "data": {
                "resultType": "matrix",
                "result": [{
                    "metric": {"__name__": "test_metric"},
                    "values": [[1000, "42.5"], [1060, "43.0"]],
                }],
            },
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        client = PrometheusQueryClient(base_url="http://localhost:9090")
        result = client._range_single("test_metric", 1000, 1060, 60)
        assert result["timestamps"] == [1000.0, 1060.0]
        assert result["values"] == [42.5, 43.0]

    def test_unpoller_prefix_default(self, app):
        from clients.prometheus_query import PrometheusQueryClient
        client = PrometheusQueryClient(base_url="http://localhost:9090")
        with app.app_context():
            assert client._unpoller_prefix() == "unpoller"

    def test_unpoller_prefix_custom(self, app):
        from clients.prometheus_query import PrometheusQueryClient
        client = PrometheusQueryClient(base_url="http://localhost:9090")
        with app.app_context():
            from models import Setting
            Setting.set("unpoller_metric_prefix", "myprefix")
            assert client._unpoller_prefix() == "myprefix"

    @patch("clients.prometheus_query.requests.get")
    def test_check_unpoller_available_true(self, mock_get, app):
        from clients.prometheus_query import PrometheusQueryClient
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "success",
            "data": {"result": [{"metric": {}, "value": [1000, "5"]}]},
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        client = PrometheusQueryClient(base_url="http://localhost:9090")
        with app.app_context():
            assert client.check_unpoller_available() is True

    @patch("clients.prometheus_query.requests.get")
    def test_check_unpoller_available_false(self, mock_get, app):
        from clients.prometheus_query import PrometheusQueryClient
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "success",
            "data": {"result": []},
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        client = PrometheusQueryClient(base_url="http://localhost:9090")
        with app.app_context():
            assert client.check_unpoller_available() is False

    @patch("clients.prometheus_query.requests.get")
    def test_get_unpoller_client_history(self, mock_get, app):
        from clients.prometheus_query import PrometheusQueryClient
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "success",
            "data": {
                "resultType": "matrix",
                "result": [{
                    "metric": {},
                    "values": [[1000, "-65"], [1060, "-63"]],
                }],
            },
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        client = PrometheusQueryClient(base_url="http://localhost:9090")
        with app.app_context():
            data = client.get_unpoller_client_history("aa:bb:cc:dd:ee:ff", timeframe="hour")
        assert data["source"] == "unpoller"
        assert len(data["labels"]) == 2

    @patch("clients.prometheus_query.requests.get")
    def test_get_unpoller_site_history(self, mock_get, app):
        from clients.prometheus_query import PrometheusQueryClient
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "success",
            "data": {
                "resultType": "matrix",
                "result": [{
                    "metric": {},
                    "values": [[1000, "50"], [1060, "52"]],
                }],
            },
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        client = PrometheusQueryClient(base_url="http://localhost:9090")
        with app.app_context():
            data = client.get_unpoller_site_history(timeframe="hour")
        assert data["source"] == "unpoller"
        assert len(data["labels"]) == 2

    @patch("clients.prometheus_query.requests.get")
    def test_get_unpoller_wan_history(self, mock_get, app):
        from clients.prometheus_query import PrometheusQueryClient
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "success",
            "data": {"resultType": "matrix", "result": []},
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        client = PrometheusQueryClient(base_url="http://localhost:9090")
        with app.app_context():
            data = client.get_unpoller_wan_history(timeframe="hour")
        assert data["source"] == "unpoller"
        assert data["labels"] == []


# ---------------------------------------------------------------------------
# Prometheus app management routes tests
# ---------------------------------------------------------------------------

class TestPrometheusAppRoutes:
    """Test the Prometheus management blueprint routes."""

    def test_manage_requires_login(self, client):
        resp = client.get("/prometheus/manage")
        assert resp.status_code in (302, 401)

    def test_manage_accessible_for_admin(self, auth_client):
        resp = auth_client.get("/prometheus/manage")
        assert resp.status_code == 200
        assert b"Prometheus" in resp.data

    def test_save_settings(self, auth_client, app):
        resp = auth_client.post("/prometheus/save", data={
            "prometheus_guest_id": "",
            "prometheus_url": "http://10.0.0.50:9090",
            "prometheus_auth_token": "",
            "prometheus_mstdnca_metrics_url": "10.0.0.10:5000",
            "prometheus_retention_days": "90",
            "prometheus_protection_type": "snapshot",
            "prometheus_backup_storage": "",
            "prometheus_backup_mode": "snapshot",
        }, follow_redirects=True)
        assert resp.status_code == 200

        with app.app_context():
            from models import Setting
            assert Setting.get("prometheus_url") == "http://10.0.0.50:9090"
            assert Setting.get("prometheus_mstdnca_metrics_url") == "10.0.0.10:5000"

    def test_install_status_returns_json(self, auth_client):
        resp = auth_client.get("/prometheus/install/status")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "running" in data
        assert "success" in data
        assert "log" in data

    def test_upgrade_status_returns_json(self, auth_client):
        resp = auth_client.get("/prometheus/upgrade/status")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "running" in data

    def test_preflight_requires_login(self, client):
        resp = client.post("/prometheus/preflight", follow_redirects=False)
        assert resp.status_code in (302, 401)

    def test_preflight_status_requires_login(self, client):
        resp = client.get("/prometheus/preflight/status", follow_redirects=False)
        assert resp.status_code in (302, 401)

    def test_preflight_status_returns_json(self, auth_client):
        resp = auth_client.get("/prometheus/preflight/status")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "running" in data
        assert "success" in data
        assert "log" in data

    def test_test_connection_no_url(self, auth_client, app):
        with app.app_context():
            from models import Setting, db
            Setting.set("prometheus_url", "")
            db.session.commit()
        resp = auth_client.post("/prometheus/test-connection")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["ok"] is False


# ---------------------------------------------------------------------------
# Applications page includes Prometheus
# ---------------------------------------------------------------------------

class TestApplicationsPage:
    """Test that Prometheus appears on the Applications page."""

    def test_applications_page_has_prometheus(self, auth_client):
        resp = auth_client.get("/applications/")
        assert resp.status_code == 200
        assert b"Prometheus" in resp.data
        assert b"/prometheus/manage" in resp.data


# ---------------------------------------------------------------------------
# Prometheus management route tests
# ---------------------------------------------------------------------------

@pytest.fixture()
def prom_service(app):
    """Create a Prometheus GuestService and return its ID. Cleaned up after the test."""
    with app.app_context():
        guest = Guest(name="_test-prom-mgmt", guest_type="ct", enabled=True)
        db.session.add(guest)
        db.session.flush()
        svc = GuestService(
            guest_id=guest.id,
            service_name="prometheus",
            unit_name="prometheus.service",
            port=9090,
        )
        db.session.add(svc)
        db.session.commit()
        svc_id = svc.id
        guest_id = guest.id

    yield svc_id, guest_id

    with app.app_context():
        GuestService.query.filter_by(guest_id=guest_id).delete()
        Guest.query.filter_by(id=guest_id).delete()
        db.session.commit()


@pytest.fixture()
def pg_service_for_prom(app):
    """Create a non-Prometheus (PostgreSQL) service for wrong-type validation tests."""
    with app.app_context():
        guest = Guest(name="_test-pg-wrong", guest_type="ct", enabled=True)
        db.session.add(guest)
        db.session.flush()
        svc = GuestService(
            guest_id=guest.id,
            service_name="postgresql",
            unit_name="postgresql.service",
            port=5432,
        )
        db.session.add(svc)
        db.session.commit()
        svc_id = svc.id
        guest_id = guest.id

    yield svc_id, guest_id

    with app.app_context():
        GuestService.query.filter_by(guest_id=guest_id).delete()
        Guest.query.filter_by(id=guest_id).delete()
        db.session.commit()


class TestPrometheusManagementRoutes:
    """Test the Prometheus management routes (config, flags, rules, reload, snapshot)."""

    # --- Read-only routes ---

    def test_config_requires_login(self, client, prom_service):
        svc_id, _ = prom_service
        resp = client.get(f"/services/{svc_id}/prometheus/config")
        assert resp.status_code in (302, 401)

    def test_config_wrong_service_type(self, auth_client, pg_service_for_prom):
        svc_id, _ = pg_service_for_prom
        resp = auth_client.get(f"/services/{svc_id}/prometheus/config")
        assert resp.status_code == 400

    def test_config_returns_json(self, auth_client, prom_service):
        svc_id, _ = prom_service
        resp = auth_client.get(f"/services/{svc_id}/prometheus/config")
        # SSH will fail but route validation should pass (not 400)
        assert resp.status_code != 400

    def test_flags_requires_login(self, client, prom_service):
        svc_id, _ = prom_service
        resp = client.get(f"/services/{svc_id}/prometheus/flags")
        assert resp.status_code in (302, 401)

    def test_flags_wrong_service_type(self, auth_client, pg_service_for_prom):
        svc_id, _ = pg_service_for_prom
        resp = auth_client.get(f"/services/{svc_id}/prometheus/flags")
        assert resp.status_code == 400

    def test_flags_returns_json(self, auth_client, prom_service):
        svc_id, _ = prom_service
        resp = auth_client.get(f"/services/{svc_id}/prometheus/flags")
        assert resp.status_code != 400

    def test_rules_requires_login(self, client, prom_service):
        svc_id, _ = prom_service
        resp = client.get(f"/services/{svc_id}/prometheus/rules")
        assert resp.status_code in (302, 401)

    def test_rules_wrong_service_type(self, auth_client, pg_service_for_prom):
        svc_id, _ = pg_service_for_prom
        resp = auth_client.get(f"/services/{svc_id}/prometheus/rules")
        assert resp.status_code == 400

    def test_rules_returns_json(self, auth_client, prom_service):
        svc_id, _ = prom_service
        resp = auth_client.get(f"/services/{svc_id}/prometheus/rules")
        assert resp.status_code != 400

    # --- Write routes ---

    def test_reload_requires_login(self, client, prom_service):
        svc_id, _ = prom_service
        resp = client.post(f"/services/{svc_id}/prometheus/reload")
        assert resp.status_code in (302, 401)

    def test_reload_wrong_service_type(self, auth_client, pg_service_for_prom):
        svc_id, _ = pg_service_for_prom
        resp = auth_client.post(f"/services/{svc_id}/prometheus/reload")
        assert resp.status_code == 400

    def test_reload_returns_json(self, auth_client, prom_service):
        svc_id, _ = prom_service
        resp = auth_client.post(f"/services/{svc_id}/prometheus/reload")
        data = json.loads(resp.data)
        # Will fail at SSH level but should not be a 400 validation error
        assert resp.status_code != 400
        assert "ok" in data

    def test_snapshot_requires_login(self, client, prom_service):
        svc_id, _ = prom_service
        resp = client.post(f"/services/{svc_id}/prometheus/snapshot")
        assert resp.status_code in (302, 401)

    def test_snapshot_wrong_service_type(self, auth_client, pg_service_for_prom):
        svc_id, _ = pg_service_for_prom
        resp = auth_client.post(f"/services/{svc_id}/prometheus/snapshot")
        assert resp.status_code == 400

    def test_snapshot_returns_json(self, auth_client, prom_service):
        svc_id, _ = prom_service
        resp = auth_client.post(f"/services/{svc_id}/prometheus/snapshot")
        data = json.loads(resp.data)
        assert resp.status_code != 400
        assert "ok" in data


class TestPrometheusUpgradeRoute:
    """The /prometheus/upgrade POST must return a redirect, not 500.

    Regression: upgrade() spawned the background job but had no return statement,
    so the Flask view returned None -> 'did not return a valid response' -> 500.
    """

    def test_upgrade_post_returns_redirect_not_500(self, app, auth_client):
        import routes.prometheus_app as r

        # Ensure no stale job-in-progress state from other tests.
        for job in (r._install_job, r._upgrade_job, r._preflight_job):
            job["running"] = False
        try:
            # Stub the background spawn so the job thread doesn't run during the
            # test (it has no request/login context); we only assert the view's
            # synchronous response — which is where the missing-return bug lived.
            with patch("routes.prometheus_app._threading.Thread"), \
                 patch("apps.prometheus_app.run_prometheus_upgrade", return_value=(True, "")):
                resp = auth_client.post("/prometheus/upgrade", follow_redirects=False)
            assert resp.status_code == 302
            assert resp.headers.get("Location", "").endswith("/prometheus/manage")
        finally:
            r._upgrade_job["running"] = False
