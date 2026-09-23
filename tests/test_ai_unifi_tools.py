"""Read-only UniFi lookup tools for the AI assistant (core/ai_tools.py).

Gated by can_view_unifi and scoped like routes/unifi.py: the site subnet filter and the
user's tag-linked network restriction apply, and clients link back to a guest by MAC.
"""
import json
from unittest.mock import MagicMock, patch

from models import Guest, Role, Setting, User, db
from tests.test_ai_live_tools import _admin

_ENABLE = {"unifi_enabled": "true", "unifi_filter_subnet": ""}


def _settings(**overrides):
    for key, value in {**_ENABLE, **overrides}.items():
        Setting.set(key, value)


def _fake_unifi(**attrs):
    client = MagicMock()
    for name, value in attrs.items():
        getattr(client, name).return_value = value
    return client


def _no_unifi_user():
    role = Role.query.filter_by(name="_ai_no_unifi").first()
    if not role:
        role = Role(name="_ai_no_unifi", display_name="AI no-unifi", level=3, is_builtin=False,
                    can_use_ai=True, can_view_guests=True, can_view_unifi=False)
        db.session.add(role)
        db.session.commit()
    user = User.query.filter_by(username="_ai_no_unifi").first()
    if not user:
        user = User(username="_ai_no_unifi", display_name="AI no-unifi", role_id=role.id)
        user.set_password("test-only-dummy")
        db.session.add(user)
        db.session.commit()
    return User.query.options(db.joinedload(User.role_obj)).get(user.id)


DEVICES = [
    {"name": "Office Switch", "mac": "aa:bb:cc:00:00:02", "ip": "10.0.0.3", "model": "USW-24-POE", "type": "usw",
     "state": 1, "uptime": 5000, "version": "7.0.50", "adopted": True, "cpu": 12.0, "mem": 40.0,
     "temperature": 51.0, "num_sta": 8, "uplink": {"type": "wire", "speed": 10000},
     "port_table": [{"up": True}, {"up": False}, {"up": True}], "radio_table": []},
    {"name": "Attic AP", "mac": "aa:bb:cc:00:00:01", "ip": "10.0.0.2", "model": "U6-LR", "type": "uap",
     "state": 6, "uptime": 100, "version": "6.6.55", "adopted": True, "cpu": 3.0, "mem": 55.0,
     "temperature": None, "num_sta": 3, "uplink": {"type": "wire", "speed": 1000}, "port_table": [],
     "radio_table": [{"radio": "na", "channel": 36, "num_sta": 3, "cu_total": 12}]},
    {"name": "Remote AP", "mac": "aa:bb:cc:00:00:09", "ip": "192.168.50.2", "model": "U6-Lite", "type": "uap",
     "state": 1, "uptime": 1, "version": "6.6.55", "adopted": True, "cpu": 1.0, "mem": 1.0,
     "temperature": None, "num_sta": 0, "uplink": {}, "port_table": [], "radio_table": []},
]

CLIENTS = [
    {"hostname": "swizzin", "ip": "10.0.0.45", "mac": "DE:AD:BE:EF:01:03", "network": "LAN", "is_wired": True,
     "uptime": 3600, "last_seen": 1_700_000_000, "blocked": False, "signal": None, "satisfaction": None,
     "essid": None, "sw_port": 7, "is_guest": False, "ap_mac": None, "sw_mac": "aa:bb:cc:00:00:02", "oui": "Proxmox"},
    {"hostname": "phone", "ip": "10.0.0.120", "mac": "de:ad:be:ef:02:00", "network": "IoT", "is_wired": False,
     "uptime": 60, "last_seen": 1_700_000_000, "blocked": False, "signal": -61, "satisfaction": 97,
     "essid": "home-iot", "sw_port": None, "is_guest": False, "ap_mac": "aa:bb:cc:00:00:01", "sw_mac": None, "oui": "Apple"},
]


class TestGatesAndOffering:

    def test_offering_by_permission(self, app):
        from core.ai_tools import execute_tool, get_tools_for_user
        with app.app_context():
            wanted = {"list_unifi_devices", "list_unifi_clients", "get_unifi_health"}
            assert wanted <= {t["name"] for t in get_tools_for_user(_admin())}
            user = _no_unifi_user()
            assert not wanted & {t["name"] for t in get_tools_for_user(user)}
            with patch("routes.unifi._get_unifi_client") as factory:
                denied = json.loads(execute_tool("list_unifi_devices", {}, user))
            assert "can_view_unifi" in denied["error"]
            factory.assert_not_called()

    def test_disabled_and_unconfigured(self, app):
        from core.ai_tools import execute_tool
        with app.app_context():
            _settings(unifi_enabled="false")
            with patch("routes.unifi._get_unifi_client") as factory:
                disabled = json.loads(execute_tool("get_unifi_health", {}, _admin()))
            factory.assert_not_called()
            _settings()
            with patch("routes.unifi._get_unifi_client", return_value=None):
                unconfigured = json.loads(execute_tool("get_unifi_health", {}, _admin()))
        assert disabled["error"] == "UniFi integration is not enabled"
        assert "not configured" in unconfigured["error"]


class TestDevices:

    def test_devices_mapped_sorted_and_subnet_filtered(self, app):
        from core.ai_tools import execute_tool
        fake = _fake_unifi(get_devices=[dict(d) for d in DEVICES])
        with app.app_context():
            _settings(unifi_filter_subnet="10.0.0.0/24")
            with patch("routes.unifi._get_unifi_client", return_value=fake):
                result = json.loads(execute_tool("list_unifi_devices", {}, _admin()))
        assert result["count"] == 2
        assert [d["name"] for d in result["devices"]] == ["Attic AP", "Office Switch"]
        ap, sw = result["devices"]
        assert ap["state"] == "heartbeat missed"
        assert ap["radios"] == [{"radio": "na", "channel": 36, "clients": 3, "utilisation_percent": 12}]
        assert sw["state"] == "online" and sw["ports_up"] == 2 and sw["temperature_c"] == 51.0
        assert sw["uplink"] == {"type": "wire", "speed_mbps": 10000}
        assert sw["connected_clients"] == 8


class TestClients:

    def test_query_links_guest_and_resolves_device(self, app):
        from core.ai_tools import execute_tool
        fake = _fake_unifi(get_clients=[dict(c) for c in CLIENTS], get_devices=[dict(d) for d in DEVICES])
        with app.app_context():
            _settings()
            guest = Guest(name="swizzin", guest_type="ct", enabled=True, mac_address="de:ad:be:ef:01:03")
            db.session.add(guest)
            db.session.commit()
            try:
                with patch("routes.unifi._get_unifi_client", return_value=fake):
                    result = json.loads(execute_tool("list_unifi_clients", {"query": "10.0.0.45"}, _admin()))
                guest_id = guest.id
            finally:
                db.session.delete(guest)
                db.session.commit()
        assert result["count"] == 1 and result["truncated"] is False
        entry = result["clients"][0]
        assert entry["mac"] == "de:ad:be:ef:01:03"
        assert entry["connection"] == "wired"
        assert entry["connected_to"] == "Office Switch" and entry["switch_port"] == 7
        assert entry["last_seen"] == "2023-11-14T22:13:20+00:00"
        assert entry["guest_id"] == guest_id and entry["guest_name"] == "swizzin"
        assert "online" not in entry
        fake.get_all_clients.assert_not_called()

    def test_network_restriction_and_offline_merge(self, app):
        from core.ai_tools import execute_tool
        offline = {"hostname": "old-laptop", "ip": "10.0.0.200", "mac": "de:ad:be:ef:03:00", "network": "LAN",
                   "is_wired": False, "last_seen": 1_699_000_000, "oui": "Dell"}
        fake = _fake_unifi(get_clients=[dict(c) for c in CLIENTS], get_devices=[],
                           get_all_clients=[dict(CLIENTS[0]), offline])
        with app.app_context():
            _settings()
            with patch("routes.unifi._get_unifi_client", return_value=fake), \
                    patch("routes.unifi._get_accessible_networks", return_value={"LAN"}):
                result = json.loads(execute_tool("list_unifi_clients", {"include_offline": True}, _admin()))
        names = [(c["hostname"], c.get("online", True)) for c in result["clients"]]
        assert names == [("swizzin", True), ("old-laptop", False)]
        assert result["count"] == 2
        assert result["clients"][0]["connected_to"] == "aa:bb:cc:00:00:02"
        fake.get_all_clients.assert_called_once_with(within=720)

    def test_result_is_capped(self, app):
        from core.ai_tools import _UNIFI_MAX_CLIENTS as cap
        from core.ai_tools import execute_tool
        many = [{"hostname": f"h{i:03d}", "ip": f"10.0.{i // 250}.{i % 250}", "mac": f"02:00:00:00:{i // 256:02x}:{i % 256:02x}",
                 "network": "LAN"} for i in range(cap + 5)]
        fake = _fake_unifi(get_clients=many, get_devices=[])
        with app.app_context():
            _settings()
            with patch("routes.unifi._get_unifi_client", return_value=fake):
                result = json.loads(execute_tool("list_unifi_clients", {}, _admin()))
        assert result["count"] == cap + 5
        assert result["truncated"] is True
        assert len(result["clients"]) == cap


class TestHealth:

    def test_health_normalises_wan_and_lists_networks(self, app):
        from core.ai_tools import execute_tool
        fake = _fake_unifi(
            get_site_health=[
                {"subsystem": "wan", "status": "ok", "num_gw": 1, "gw": "203.0.113.7", "isp_organization": "Example ISP",
                 "internet_latency": 9, "gw_system-stats": {"uptime": "86400"}, "xput_down": 940.2, "xput_up": 880.0},
                {"subsystem": "wlan", "status": "ok", "num_ap": 2, "num_user": 14, "num_guest": 1, "num_disconnected": 1},
                {"status": "ok"},
            ],
            get_networks=[{"name": "LAN", "purpose": "corporate", "vlan": None}, {"name": "IoT", "purpose": "corporate", "vlan": 20}],
            get_wlan_conf=[{"name": "home-iot", "enabled": True, "security": "wpapsk", "wlan_band": "2g", "is_guest": False}],
        )
        with app.app_context():
            _settings()
            with patch("routes.unifi._get_unifi_client", return_value=fake):
                result = json.loads(execute_tool("get_unifi_health", {}, _admin()))
        assert set(result["subsystems"]) == {"wan", "wlan"}
        assert result["subsystems"]["wan"] == {
            "status": "ok", "num_gw": 1, "wan_ip": "203.0.113.7", "isp": "Example ISP", "latency_ms": 9,
            "uptime_seconds": "86400", "speedtest_download_mbps": 940.2, "speedtest_upload_mbps": 880.0,
        }
        assert result["subsystems"]["wlan"]["num_disconnected"] == 1
        assert result["networks"][1] == {"name": "IoT", "purpose": "corporate", "vlan": 20}
        assert result["wlans"] == [{"name": "home-iot", "enabled": True, "security": "wpapsk", "band": "2g", "is_guest": False}]
