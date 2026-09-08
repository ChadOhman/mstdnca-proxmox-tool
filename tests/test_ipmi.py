"""Tests for IPMI integration (clients/ipmi_client.py, routes/ipmi.py)."""

from unittest.mock import MagicMock, patch

import pytest

from auth.credential_store import encrypt
from models import HostMetricSnapshot, ProxmoxHost, db

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def ipmi_host(app):
    """Create a ProxmoxHost with IPMI enabled."""
    with app.app_context():
        host = ProxmoxHost(
            name="test-pve",
            hostname="10.0.0.1",
            port=8006,
            host_type="pve",
            ipmi_enabled=True,
            ipmi_address="10.0.0.50",
            ipmi_username="ADMIN",
            ipmi_password=encrypt("password123"),
            ipmi_verify_ssl=False,
        )
        db.session.add(host)
        db.session.commit()
        host_id = host.id

    yield host_id

    with app.app_context():
        HostMetricSnapshot.query.filter_by(host_id=host_id).delete()
        ProxmoxHost.query.filter_by(id=host_id).delete()
        db.session.commit()


def _mock_snapshot():
    """Return a mock health snapshot dict."""
    return {
        "manufacturer": "Supermicro",
        "model": "SYS-5019C-MR",
        "serial": "SN12345",
        "bios_version": "2.1",
        "hostname": "pve-node-01",
        "uuid": "test-uuid",
        "power_state": "On",
        "health": "OK",
        "state": "Enabled",
        "total_memory_gb": 128,
        "processor_count": 2,
        "processor_model": "Intel Xeon E-2288G",
        "temperatures": [
            {"name": "CPU Temp", "reading_celsius": 42, "upper_threshold_critical": 85, "health": "OK", "state": "Enabled"},
            {"name": "System Temp", "reading_celsius": 30, "upper_threshold_critical": 70, "health": "OK", "state": "Enabled"},
        ],
        "fans": [
            {"name": "FAN1", "reading_rpm": 1200, "units": "RPM", "health": "OK", "state": "Enabled"},
        ],
        "power_supplies": [
            {"name": "PSU1", "model": "PWS-665", "serial": "PSN1", "power_output_watts": 180, "power_capacity_watts": 665, "health": "OK", "state": "Enabled"},
        ],
        "power_control": [
            {"name": "System Power", "power_consumed_watts": 180, "power_capacity_watts": 665, "min_consumed_watts": 120, "max_consumed_watts": 250, "avg_consumed_watts": 175},
        ],
        "cpu_temp": 42,
        "system_temp": 30,
        "total_watts": 180,
    }


# ---------------------------------------------------------------------------
# RedfishClient unit tests
# ---------------------------------------------------------------------------

class TestRedfishClient:
    def test_login_success(self):
        from clients.ipmi_client import RedfishClient
        client = RedfishClient("https://10.0.0.50", "ADMIN", "pass")
        with patch.object(client.session, "post") as mock_post:
            mock_post.return_value = MagicMock(
                status_code=201,
                headers={"X-Auth-Token": "token123", "Location": "/session/1"},
            )
            assert client.login() is True
            assert client._token == "token123"

    def test_login_failure(self):
        from clients.ipmi_client import RedfishClient
        client = RedfishClient("https://10.0.0.50", "ADMIN", "badpass")
        with patch.object(client.session, "post") as mock_post:
            mock_post.return_value = MagicMock(status_code=401, headers={})
            assert client.login() is False
            assert client._token is None

    def test_test_connection_success(self):
        from clients.ipmi_client import RedfishClient
        client = RedfishClient("https://10.0.0.50", "ADMIN", "pass")
        client._token = "token123"
        with patch.object(client.session, "get") as mock_get:
            mock_get.return_value = MagicMock(
                status_code=200,
                json=lambda: {"Product": "Supermicro X11SCL"},
            )
            ok, msg = client.test_connection()
            assert ok is True
            assert "Supermicro" in msg

    def test_power_action_valid(self):
        from clients.ipmi_client import RedfishClient
        client = RedfishClient("https://10.0.0.50", "ADMIN", "pass")
        client._token = "token123"
        with patch.object(client.session, "post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            ok, msg = client.power_action("on")
            assert ok is True

    def test_power_action_invalid(self):
        from clients.ipmi_client import RedfishClient
        client = RedfishClient("https://10.0.0.50", "ADMIN", "pass")
        ok, msg = client.power_action("invalid")
        assert ok is False
        assert "Unknown" in msg

    def test_get_thermal_parses_sensors(self):
        from clients.ipmi_client import RedfishClient
        client = RedfishClient("https://10.0.0.50", "ADMIN", "pass")
        client._token = "token123"
        thermal_data = {
            "Temperatures": [
                {"Name": "CPU Temp", "ReadingCelsius": 45, "UpperThresholdCritical": 85, "Status": {"Health": "OK", "State": "Enabled"}},
            ],
            "Fans": [
                {"Name": "FAN1", "Reading": 1500, "ReadingUnits": "RPM", "Status": {"Health": "OK", "State": "Enabled"}},
            ],
        }
        with patch.object(client.session, "get") as mock_get:
            mock_get.return_value = MagicMock(status_code=200, json=lambda: thermal_data)
            result = client.get_thermal()
            assert len(result["temperatures"]) == 1
            assert result["temperatures"][0]["reading_celsius"] == 45
            assert len(result["fans"]) == 1
            assert result["fans"][0]["reading_rpm"] == 1500

    def test_get_health_snapshot(self):
        from clients.ipmi_client import RedfishClient
        client = RedfishClient("https://10.0.0.50", "ADMIN", "pass")
        client._token = "token123"

        system_data = {
            "Manufacturer": "Supermicro", "Model": "X11", "SerialNumber": "SN1",
            "BiosVersion": "2.0", "HostName": "node1", "UUID": "uuid1",
            "PowerState": "On", "Status": {"Health": "OK", "State": "Enabled"},
            "MemorySummary": {"TotalSystemMemoryGiB": 64},
            "ProcessorSummary": {"Count": 1, "Model": "Xeon"},
        }
        thermal_data = {
            "Temperatures": [
                {"Name": "CPU Temp", "ReadingCelsius": 42, "Status": {"Health": "OK", "State": "Enabled"}},
            ],
            "Fans": [],
        }
        power_data = {
            "PowerSupplies": [],
            "PowerControl": [{"Name": "System", "PowerConsumedWatts": 150}],
        }

        with patch.object(client, "_get") as mock_get:
            def side_effect(path):
                if "Systems" in path:
                    return system_data
                if "Thermal" in path:
                    return thermal_data
                if "Power" in path:
                    return power_data
                return None
            mock_get.side_effect = side_effect

            snap = client.get_health_snapshot()
            assert snap is not None
            assert snap["manufacturer"] == "Supermicro"
            assert snap["cpu_temp"] == 42
            assert snap["total_watts"] == 150


# ---------------------------------------------------------------------------
# Route tests
# ---------------------------------------------------------------------------

class TestIpmiRoutes:
    def test_index_requires_login(self, client):
        resp = client.get("/ipmi/")
        assert resp.status_code in (302, 401)

    @patch("routes.ipmi._get_redfish_client")
    def test_index_shows_hosts(self, mock_client, auth_client, ipmi_host):
        mock = MagicMock()
        mock.get_health_snapshot.return_value = _mock_snapshot()
        mock_client.return_value = mock
        resp = auth_client.get("/ipmi/")
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "test-pve" in html
        assert "42" in html  # CPU temp

    @patch("routes.ipmi._get_redfish_client")
    def test_index_logs_out_bmc_session_on_success(self, mock_client, auth_client, ipmi_host):
        """A fresh RedfishClient is created per request; without an explicit logout
        each dashboard load leaks a BMC Redfish session (issue #128)."""
        mock = MagicMock()
        mock.get_health_snapshot.return_value = _mock_snapshot()
        mock_client.return_value = mock
        resp = auth_client.get("/ipmi/")
        assert resp.status_code == 200
        mock.logout.assert_called_once()

    @patch("routes.ipmi._get_redfish_client")
    def test_index_logs_out_bmc_session_on_exception(self, mock_client, auth_client, ipmi_host):
        """logout() must run even when the client raises mid-request (try/finally,
        not just a call at the end of the happy path)."""
        mock = MagicMock()
        mock.get_health_snapshot.side_effect = RuntimeError("BMC unreachable")
        mock_client.return_value = mock
        resp = auth_client.get("/ipmi/")
        assert resp.status_code == 200
        mock.logout.assert_called_once()

    @patch("routes.ipmi._get_redfish_client")
    def test_detail_page_logs_out_once_for_two_client_calls(self, mock_client, auth_client, ipmi_host):
        """detail() uses the client twice (snapshot + SEL) — logout must fire once,
        after both calls, not once per call."""
        mock = MagicMock()
        mock.get_health_snapshot.return_value = _mock_snapshot()
        mock.get_sel_entries.return_value = []
        mock_client.return_value = mock
        resp = auth_client.get(f"/ipmi/host/{ipmi_host}")
        assert resp.status_code == 200
        mock.logout.assert_called_once()

    @patch("routes.ipmi._get_redfish_client")
    def test_test_connection_logs_out(self, mock_client, auth_client, ipmi_host):
        mock = MagicMock()
        mock.test_connection.return_value = (True, "Connected")
        mock_client.return_value = mock
        # Don't follow the redirect: the detail page it lands on would create and
        # log out a second RedfishClient, which would muddy this assertion.
        auth_client.post(f"/ipmi/host/{ipmi_host}/test", follow_redirects=False)
        mock.logout.assert_called_once()

    @patch("routes.ipmi._get_redfish_client")
    def test_sel_page_logs_out(self, mock_client, auth_client, ipmi_host):
        mock = MagicMock()
        mock.get_sel_entries.return_value = []
        mock_client.return_value = mock
        auth_client.get(f"/ipmi/host/{ipmi_host}/sel")
        mock.logout.assert_called_once()

    def test_no_client_does_not_attempt_logout(self, auth_client, ipmi_host, app):
        """When IPMI isn't configured, _get_redfish_client() returns None — logout()
        must not be called on None."""
        with app.app_context():
            host = ProxmoxHost.query.get(ipmi_host)
            host.ipmi_enabled = False
            db.session.commit()
        resp = auth_client.get("/ipmi/")
        assert resp.status_code == 200

    @patch("routes.ipmi._get_redfish_client")
    def test_detail_page(self, mock_client, auth_client, ipmi_host):
        mock = MagicMock()
        mock.get_health_snapshot.return_value = _mock_snapshot()
        mock.get_sel_entries.return_value = []
        mock_client.return_value = mock
        resp = auth_client.get(f"/ipmi/host/{ipmi_host}")
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "Supermicro" in html
        assert "SYS-5019C-MR" in html

    @patch("routes.ipmi._get_redfish_client")
    def test_power_action(self, mock_client, auth_client, ipmi_host):
        mock = MagicMock()
        mock.power_action.return_value = (True, "OK")
        mock_client.return_value = mock
        resp = auth_client.post(f"/ipmi/host/{ipmi_host}/power", data={"action": "on"}, follow_redirects=False)
        assert resp.status_code == 302
        mock.power_action.assert_called_once_with("on")

    def test_power_action_invalid(self, auth_client, ipmi_host):
        resp = auth_client.post(f"/ipmi/host/{ipmi_host}/power", data={"action": "destroy"}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Invalid power action" in resp.data

    @patch("routes.ipmi._get_redfish_client")
    def test_test_connection(self, mock_client, auth_client, ipmi_host):
        mock = MagicMock()
        mock.test_connection.return_value = (True, "Connected to Supermicro X11")
        mock_client.return_value = mock
        resp = auth_client.post(f"/ipmi/host/{ipmi_host}/test", follow_redirects=True)
        assert resp.status_code == 200
        assert b"successful" in resp.data

    @patch("routes.ipmi._get_redfish_client")
    def test_sel_page(self, mock_client, auth_client, ipmi_host):
        mock = MagicMock()
        mock.get_sel_entries.return_value = [
            {"id": "1", "created": "2026-03-10T00:00:00Z", "message": "Power on", "severity": "OK", "sensor_type": "Power"},
        ]
        mock_client.return_value = mock
        resp = auth_client.get(f"/ipmi/host/{ipmi_host}/sel")
        assert resp.status_code == 200
        assert b"Power on" in resp.data

    def test_metrics_api_sqlite_fallback(self, auth_client, ipmi_host, app):
        with app.app_context():
            import json
            snap = HostMetricSnapshot(
                host_id=ipmi_host,
                data=json.dumps({"power_watts": 175, "cpu_temp": 40}),
            )
            db.session.add(snap)
            db.session.commit()

        resp = auth_client.get(f"/ipmi/api/host/{ipmi_host}/metrics?timeframe=day")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["source"] == "sqlite"
        assert len(data["snapshots"]) >= 1
        assert data["snapshots"][0]["power_watts"] == 175

    def test_configure_ipmi(self, auth_client, ipmi_host, app):
        resp = auth_client.post(
            f"/ipmi/host/{ipmi_host}/configure",
            data={
                "ipmi_enabled": "on",
                "ipmi_address": "10.0.0.99",
                "ipmi_username": "newuser",
                "ipmi_password": "newpass",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        with app.app_context():
            host = ProxmoxHost.query.get(ipmi_host)
            assert host.ipmi_address == "10.0.0.99"
            assert host.ipmi_username == "newuser"

    def test_detail_ipmi_disabled_redirects(self, auth_client, app):
        with app.app_context():
            host = ProxmoxHost(name="no-ipmi", hostname="10.0.0.2", ipmi_enabled=False)
            db.session.add(host)
            db.session.commit()
            hid = host.id

        resp = auth_client.get(f"/ipmi/host/{hid}", follow_redirects=False)
        assert resp.status_code == 302

        with app.app_context():
            ProxmoxHost.query.filter_by(id=hid).delete()
            db.session.commit()


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------

class TestIpmiModels:
    def test_role_has_ipmi_permissions(self, app):
        from models import Role
        with app.app_context():
            sa = Role.query.filter_by(name="super_admin").first()
            assert sa is not None
            assert "can_view_ipmi" in Role.PERMISSION_FIELDS
            assert "can_manage_ipmi" in Role.PERMISSION_FIELDS

    def test_proxmox_host_ipmi_fields(self, app, ipmi_host):
        with app.app_context():
            host = ProxmoxHost.query.get(ipmi_host)
            assert host.ipmi_enabled is True
            assert host.ipmi_address == "10.0.0.50"
            assert host.ipmi_username == "ADMIN"

    def test_host_metric_snapshot_creation(self, app, ipmi_host):
        import json
        with app.app_context():
            snap = HostMetricSnapshot(
                host_id=ipmi_host,
                data=json.dumps({"cpu_temp": 42, "power_watts": 180}),
            )
            db.session.add(snap)
            db.session.commit()
            assert snap.id is not None

            loaded = json.loads(snap.data)
            assert loaded["cpu_temp"] == 42

            db.session.delete(snap)
            db.session.commit()

    def test_user_can_view_ipmi(self, app):
        from models import User
        with app.app_context():
            admin = User.query.filter_by(username="admin").first()
            assert admin.can_view_ipmi is True
            assert admin.can_manage_ipmi is True


# ---------------------------------------------------------------------------
# Prometheus query tests
# ---------------------------------------------------------------------------

class TestIpmiPrometheusQuery:
    def test_get_ipmi_metrics_exporter(self, app):
        from clients.prometheus_query import PrometheusQueryClient
        with app.app_context():
            from models import Setting
            Setting.set("prometheus_url", "http://prometheus:9090")

        with app.app_context():
            client = PrometheusQueryClient()
            with patch.object(client, "_run_snapshot_queries") as mock_run:
                mock_run.return_value = {"snapshots": [{"power_consumption_watts": 200}], "source": "ipmi_exporter"}
                result = client.get_ipmi_metrics_exporter("10.0.0.50", "day")
                assert result["source"] == "ipmi_exporter"
                mock_run.assert_called_once()
                # Verify queries contain expected metric names
                queries = mock_run.call_args[0][0]
                assert "power_consumption_watts" in queries
                assert "cpu_temp" in queries


# ---------------------------------------------------------------------------
# Exporters registry test
# ---------------------------------------------------------------------------

class TestIpmiExporter:
    def test_registered_in_known_exporters(self):
        from apps.exporters import KNOWN_EXPORTERS
        assert "ipmi_exporter" in KNOWN_EXPORTERS
        info = KNOWN_EXPORTERS["ipmi_exporter"]
        assert info["default_port"] == 9290
        assert info["github_repo"] == "prometheus-community/ipmi_exporter"
        assert info["job_name"] == "ipmi"
        assert info.get("host_level") is True
