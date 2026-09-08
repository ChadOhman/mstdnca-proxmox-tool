"""Tests for UniFi routes (routes/unifi.py)."""

from unittest.mock import MagicMock, patch

import pytest

from models import Setting, db


@pytest.fixture(autouse=True)
def _enable_unifi(app):
    """Enable UniFi integration for all tests in this module."""
    with app.app_context():
        Setting.set("unifi_enabled", "true")
        Setting.set("unifi_base_url", "https://unifi.local")
        Setting.set("unifi_username", "admin")
        Setting.set("unifi_password", "encrypted_password")
        Setting.set("unifi_site", "default")
        db.session.commit()
    yield
    with app.app_context():
        Setting.set("unifi_enabled", "false")
        db.session.commit()


def _mock_unifi_client():
    """Create a mock UniFiClient with default return values."""
    mock = MagicMock()
    mock.get_devices.return_value = [
        {
            "name": "AP-01", "mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.10",
            "model": "U6-LR", "type": "uap", "state": 1, "uptime": 86400,
            "version": "6.5.28", "adopted": True, "cpu": 15.0, "mem": 42.0,
            "temperature": 55.0, "loadavg_1": 0.5, "loadavg_5": 0.3, "loadavg_15": 0.2,
            "num_sta": 5, "last_seen": 1700000000,
            "uplink": {"type": "wire", "speed": 1000, "full_duplex": True, "tx_bytes": 0, "rx_bytes": 0},
            "port_table": [], "radio_table": [
                {"name": "ra0", "channel": 36, "ht": "VHT80", "tx_power": 23, "num_sta": 5, "cu_total": 20, "radio": "na"},
            ],
        },
    ]
    mock.get_clients.return_value = [
        {
            "hostname": "laptop", "ip": "192.168.1.50", "mac": "11:22:33:44:55:66",
            "network": "LAN", "is_wired": False, "uptime": 3600, "signal": -65,
            "satisfaction": 85, "channel": 36, "radio": "na", "essid": "WiFi",
            "ap_mac": "aa:bb:cc:dd:ee:ff", "sw_mac": None,
            "last_seen": None, "tx_bytes": None, "rx_bytes": None,
            "tx_rate": None, "rx_rate": None, "blocked": False,
            "sw_port": None, "is_guest": False, "wifi_tx_attempts": None,
            "tx_retries": None, "first_seen": None, "oui": "",
        },
    ]
    mock.get_site_health.return_value = [
        {"subsystem": "wan", "status": "ok", "latency": 5, "uptime": 86400},
        {"subsystem": "lan", "status": "ok"},
        {"subsystem": "wlan", "status": "ok"},
    ]
    mock.get_wlan_conf.return_value = [
        {"id": "1", "name": "WiFi", "enabled": True, "security": "wpapsk", "is_guest": False, "wlan_band": "both"},
    ]
    mock.get_port_forward_rules.return_value = []
    mock.get_firewall_rules.return_value = []
    mock.get_dpi_stats.return_value = [{"by_cat": [{"cat": 13, "rx_bytes": 100, "tx_bytes": 50, "rx_packets": 10, "tx_packets": 5}]}]
    mock.get_daily_site_stats.return_value = [
        {"time": 1700000000000, "bytes": 1000, "wan_tx_bytes": 400, "wan_rx_bytes": 600, "num_sta": 5},
    ]
    mock.get_all_clients.return_value = mock.get_clients.return_value
    return mock


class TestUnifiIndex:
    @patch("routes.unifi._get_unifi_client")
    def test_index_with_health_cards(self, mock_get_client, auth_client):
        mock_get_client.return_value = _mock_unifi_client()
        resp = auth_client.get("/unifi/")
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "WAN Status" in html
        assert "WAN Latency" in html
        assert "AP-01" in html
        # Navigation buttons should be present
        assert "Health" in html
        assert "Traffic" in html
        assert "Client History" in html

    @patch("routes.unifi._get_unifi_client")
    def test_index_device_link(self, mock_get_client, auth_client):
        mock_get_client.return_value = _mock_unifi_client()
        resp = auth_client.get("/unifi/")
        assert resp.status_code == 200
        assert "/unifi/device/aa:bb:cc:dd:ee:ff" in resp.data.decode()

    @patch("routes.unifi._get_unifi_client")
    def test_index_cpu_mem_columns(self, mock_get_client, auth_client):
        mock_get_client.return_value = _mock_unifi_client()
        resp = auth_client.get("/unifi/")
        html = resp.data.decode()
        assert "CPU" in html
        assert "Mem" in html
        assert "15%" in html  # CPU value


class TestDeviceDetail:
    @patch("routes.unifi._get_unifi_client")
    def test_device_detail_found(self, mock_get_client, auth_client):
        mock_get_client.return_value = _mock_unifi_client()
        resp = auth_client.get("/unifi/device/aa:bb:cc:dd:ee:ff")
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "AP-01" in html
        assert "ra0" in html  # Radio name
        assert "VHT80" in html

    @patch("routes.unifi._get_unifi_client")
    def test_device_detail_not_found(self, mock_get_client, auth_client):
        mock_get_client.return_value = _mock_unifi_client()
        resp = auth_client.get("/unifi/device/00:00:00:00:00:00", follow_redirects=False)
        assert resp.status_code == 302  # Redirects to index

    def test_device_detail_invalid_mac(self, auth_client):
        resp = auth_client.get("/unifi/device/invalid", follow_redirects=False)
        assert resp.status_code == 302

    @patch("routes.unifi._get_unifi_client")
    def test_device_shows_connected_clients(self, mock_get_client, auth_client):
        mock_get_client.return_value = _mock_unifi_client()
        resp = auth_client.get("/unifi/device/aa:bb:cc:dd:ee:ff")
        html = resp.data.decode()
        assert "laptop" in html  # Connected client


class TestHealthPage:
    @patch("routes.unifi._get_unifi_client")
    def test_health_page(self, mock_get_client, auth_client):
        mock_get_client.return_value = _mock_unifi_client()
        resp = auth_client.get("/unifi/health")
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "Network Health" in html
        assert "WAN" in html
        assert "LAN" in html
        assert "WLAN" in html
        assert "WiFi" in html  # WLAN conf name

    @patch("routes.unifi._get_unifi_client")
    def test_health_not_configured(self, mock_get_client, auth_client, app):
        with app.app_context():
            Setting.set("unifi_enabled", "false")
            db.session.commit()
        resp = auth_client.get("/unifi/health", follow_redirects=False)
        assert resp.status_code == 302


class TestTrafficPage:
    @patch("routes.unifi._get_unifi_client")
    def test_traffic_page(self, mock_get_client, auth_client):
        mock_get_client.return_value = _mock_unifi_client()
        resp = auth_client.get("/unifi/traffic")
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "Traffic Analysis" in html
        assert "Traffic by Category" in html

    @patch("routes.unifi._get_unifi_client")
    def test_traffic_no_dpi(self, mock_get_client, auth_client):
        mock = _mock_unifi_client()
        mock.get_dpi_stats.return_value = []
        mock_get_client.return_value = mock
        resp = auth_client.get("/unifi/traffic")
        assert resp.status_code == 200
        assert "No DPI data available" in resp.data.decode()


class TestClientHistory:
    @patch("routes.unifi._get_unifi_client")
    def test_client_history_page(self, mock_get_client, auth_client):
        mock_get_client.return_value = _mock_unifi_client()
        resp = auth_client.get("/unifi/clients/history")
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "Client History" in html
        assert "laptop" in html

    @patch("routes.unifi._get_unifi_client")
    def test_client_history_search(self, mock_get_client, auth_client):
        mock_get_client.return_value = _mock_unifi_client()
        resp = auth_client.get("/unifi/clients/history?q=laptop")
        assert resp.status_code == 200
        assert "laptop" in resp.data.decode()

    @patch("routes.unifi._get_unifi_client")
    def test_client_history_search_no_match(self, mock_get_client, auth_client):
        mock_get_client.return_value = _mock_unifi_client()
        resp = auth_client.get("/unifi/clients/history?q=nonexistent")
        assert resp.status_code == 200
        assert "No clients found" in resp.data.decode()

    @patch("routes.unifi._get_unifi_client")
    def test_client_history_hours_param(self, mock_get_client, auth_client):
        mock = _mock_unifi_client()
        mock_get_client.return_value = mock
        resp = auth_client.get("/unifi/clients/history?hours=168")
        assert resp.status_code == 200
        mock.get_all_clients.assert_called_once_with(within=168)


class TestClientDetail:
    @patch("routes.unifi._get_unifi_client")
    def test_client_detail_requires_unpoller(self, mock_get_client, auth_client, app):
        """Redirects if unpoller not enabled."""
        with app.app_context():
            Setting.set("unpoller_enabled", "false")
            db.session.commit()
        resp = auth_client.get("/unifi/client/11:22:33:44:55:66", follow_redirects=False)
        assert resp.status_code == 302

    @patch("routes.unifi._get_unifi_client")
    def test_client_detail_found(self, mock_get_client, auth_client, app):
        with app.app_context():
            Setting.set("unpoller_enabled", "true")
            db.session.commit()
        mock_get_client.return_value = _mock_unifi_client()
        resp = auth_client.get("/unifi/client/11:22:33:44:55:66")
        assert resp.status_code == 200
        assert "laptop" in resp.data.decode()

    @patch("routes.unifi._get_unifi_client")
    def test_client_detail_not_found(self, mock_get_client, auth_client, app):
        with app.app_context():
            Setting.set("unpoller_enabled", "true")
            db.session.commit()
        mock = _mock_unifi_client()
        mock.get_all_clients.return_value = []
        mock_get_client.return_value = mock
        resp = auth_client.get("/unifi/client/00:00:00:00:00:00", follow_redirects=False)
        assert resp.status_code == 302

    def test_client_detail_invalid_mac(self, auth_client, app):
        with app.app_context():
            Setting.set("unpoller_enabled", "true")
            db.session.commit()
        resp = auth_client.get("/unifi/client/invalid", follow_redirects=False)
        assert resp.status_code == 302


class TestChartApiEndpoints:
    @patch("routes.unifi.Setting")
    def test_site_chart_prometheus_not_configured(self, mock_setting, auth_client):
        mock_setting.get.return_value = "default"
        with patch("clients.prometheus_query.Setting") as pq_setting:
            pq_setting.get.return_value = ""
            resp = auth_client.get("/unifi/api/site/chart")
        assert resp.status_code == 404

    def test_device_chart_invalid_mac(self, auth_client):
        resp = auth_client.get("/unifi/api/device/invalid/chart")
        assert resp.status_code == 400

    def test_client_chart_requires_unpoller(self, auth_client, app):
        with app.app_context():
            Setting.set("unpoller_enabled", "false")
            db.session.commit()
        resp = auth_client.get("/unifi/api/client/11:22:33:44:55:66/chart")
        assert resp.status_code == 404

    def test_client_chart_invalid_mac(self, auth_client, app):
        with app.app_context():
            Setting.set("unpoller_enabled", "true")
            db.session.commit()
        resp = auth_client.get("/unifi/api/client/invalid/chart")
        assert resp.status_code == 400

    def test_radio_chart_requires_unpoller(self, auth_client, app):
        with app.app_context():
            Setting.set("unpoller_enabled", "false")
            db.session.commit()
        resp = auth_client.get("/unifi/api/device/aa:bb:cc:dd:ee:ff/radio/ra0/chart")
        assert resp.status_code == 404

    def test_wan_chart_requires_unpoller(self, auth_client, app):
        with app.app_context():
            Setting.set("unpoller_enabled", "false")
            db.session.commit()
        resp = auth_client.get("/unifi/api/site/wan/chart")
        assert resp.status_code == 404

    def test_dpi_chart_requires_unpoller(self, auth_client, app):
        with app.app_context():
            Setting.set("unpoller_enabled", "false")
            db.session.commit()
        resp = auth_client.get("/unifi/api/site/dpi/chart")
        assert resp.status_code == 404


class TestPermissions:
    def test_unauthenticated_redirects(self, client):
        resp = client.get("/unifi/", follow_redirects=False)
        assert resp.status_code == 302

    def test_unauthenticated_health(self, client):
        resp = client.get("/unifi/health", follow_redirects=False)
        assert resp.status_code == 302

    def test_unauthenticated_traffic(self, client):
        resp = client.get("/unifi/traffic", follow_redirects=False)
        assert resp.status_code == 302

    def test_unauthenticated_device_detail(self, client):
        resp = client.get("/unifi/device/aa:bb:cc:dd:ee:ff", follow_redirects=False)
        assert resp.status_code == 302


class TestUnifiDecryptFailure:
    """A password that cannot be decrypted must not 500 the UniFi pages (#127)."""

    def test_get_unifi_client_returns_none_on_garbage_ciphertext(self, app):
        from routes.unifi import _get_unifi_client

        with app.app_context():
            Setting.set("unifi_password", "not-a-valid-fernet-token")
            client = _get_unifi_client()
        assert client is None

    def test_unifi_index_does_not_500_on_garbage_ciphertext(self, auth_client, app):
        with app.app_context():
            Setting.set("unifi_password", "not-a-valid-fernet-token")

        resp = auth_client.get("/unifi/", follow_redirects=False)
        assert resp.status_code in (200, 302)

    def test_settings_test_unifi_flashes_a_clear_message(self, auth_client, app):
        with app.app_context():
            Setting.set("unifi_base_url", "https://unifi.local")
            Setting.set("unifi_username", "admin")
            Setting.set("unifi_password", "not-a-valid-fernet-token")

        resp = auth_client.post(
            "/settings/unifi/test",
            data={"unifi_base_url": "https://unifi.local", "unifi_username": "admin",
                  "unifi_site": "default"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"could not be decrypted" in resp.data
