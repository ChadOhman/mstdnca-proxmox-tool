import logging
import threading

import requests
import urllib3

logger = logging.getLogger(__name__)


def _safe_float(val):
    """Convert a value to float, returning None on failure."""
    if val is None:
        return None
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


class UniFiClient:
    """Client for UniFi Controller / UniFi OS API."""

    def __init__(self, base_url, username, password, site="default", is_udm=True, verify_ssl=False):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.site = site
        self.is_udm = is_udm
        self.session = requests.Session()
        self.session.verify = verify_ssl
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self._logged_in = False
        self._login_error = None

    @property
    def _prefix(self):
        return "/proxy/network" if self.is_udm else ""

    def login(self):
        if self._logged_in:
            return True

        if self.is_udm:
            url = f"{self.base_url}/api/auth/login"
        else:
            url = f"{self.base_url}/api/login"

        try:
            resp = self.session.post(
                url,
                json={"username": self.username, "password": self.password},
                timeout=10,
            )
            if resp.status_code == 200:
                self._logged_in = True
                self._login_error = None
                return True
            self._login_error = f"HTTP {resp.status_code}"
            logger.warning("UniFi login failed: HTTP %s", resp.status_code)
            return False
        except requests.RequestException as e:
            self._login_error = str(e)
            logger.error("UniFi login error: %s", e)
            return False

    def _api_get(self, path, *path_params):
        """GET *path* and return its ``data`` list (``None`` on failure).

        *path_params* are appended to *path* as extra URL segments.  Only
        *path* is written to log lines, so per-client identifiers such as MAC
        addresses belong in *path_params* where they never reach the log.
        """
        if not self._logged_in:
            if not self.login():
                return None
        url = f"{self.base_url}{self._prefix}{path}" + "".join(f"/{p}" for p in path_params)
        try:
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 401:
                self._logged_in = False
                if not self.login():
                    return None
                resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                return resp.json().get("data", [])
            logger.warning("UniFi API GET %s: HTTP %s", path, resp.status_code)
            return None
        except requests.RequestException as e:
            logger.error("UniFi API error: %s", e)
            return None

    def _api_post(self, path, payload):
        if not self._logged_in:
            if not self.login():
                return False, "Not authenticated"
        url = f"{self.base_url}{self._prefix}{path}"
        try:
            resp = self.session.post(url, json=payload, timeout=15)
            if resp.status_code == 401:
                self._logged_in = False
                if not self.login():
                    return False, "Not authenticated"
                resp = self.session.post(url, json=payload, timeout=15)
            if resp.status_code == 200:
                return True, "OK"
            return False, f"HTTP {resp.status_code}"
        except requests.RequestException as e:
            return False, str(e)

    def _api_post_data(self, path, payload):
        """POST that returns the JSON ``data`` array (like ``_api_get``)."""
        if not self._logged_in:
            if not self.login():
                return None
        url = f"{self.base_url}{self._prefix}{path}"
        try:
            resp = self.session.post(url, json=payload, timeout=15)
            if resp.status_code == 401:
                self._logged_in = False
                if not self.login():
                    return None
                resp = self.session.post(url, json=payload, timeout=15)
            if resp.status_code == 200:
                return resp.json().get("data", [])
            logger.warning("UniFi API POST %s: HTTP %s", path, resp.status_code)
            return None
        except requests.RequestException as e:
            logger.error("UniFi API error: %s", e)
            return None

    def get_devices(self):
        raw = self._api_get(f"/api/s/{self.site}/stat/device")
        if raw is None:
            return []
        devices = []
        for d in raw:
            # System stats
            sys_stats = d.get("system-stats", {})
            # Uplink info
            uplink_raw = d.get("uplink", {})
            uplink = {
                "type": uplink_raw.get("type", ""),
                "speed": uplink_raw.get("speed", 0),
                "full_duplex": uplink_raw.get("full_duplex", False),
                "tx_bytes": uplink_raw.get("tx_bytes", 0),
                "rx_bytes": uplink_raw.get("rx_bytes", 0),
            }
            # Port table (switches/gateways)
            port_table = []
            for p in d.get("port_table", []):
                port_table.append({
                    "name": p.get("name", ""),
                    "speed": p.get("speed", 0),
                    "enabled": p.get("enable", p.get("enabled", True)),
                    "up": p.get("up", False),
                    "poe_mode": p.get("poe_mode", ""),
                    "tx_bytes": p.get("tx_bytes", 0),
                    "rx_bytes": p.get("rx_bytes", 0),
                })
            # Radio table (APs)
            radio_table = []
            for r in d.get("radio_table_stats", d.get("radio_table", [])):
                radio_table.append({
                    "name": r.get("name", ""),
                    "channel": r.get("channel", 0),
                    "ht": r.get("ht", ""),
                    "tx_power": r.get("tx_power", 0),
                    "num_sta": r.get("num_sta", 0),
                    "cu_total": r.get("cu_total", 0),
                    "radio": r.get("radio", ""),
                })

            devices.append({
                "name": d.get("name", d.get("hostname", "Unknown")),
                "mac": d.get("mac", ""),
                "ip": d.get("ip", ""),
                "model": d.get("model", ""),
                "type": d.get("type", ""),
                "state": d.get("state", 0),
                "uptime": d.get("uptime", 0),
                "version": d.get("version", ""),
                "adopted": d.get("adopted", False),
                "cpu": _safe_float(sys_stats.get("cpu")),
                "mem": _safe_float(sys_stats.get("mem")),
                "temperature": _safe_float(d.get("general_temperature")),
                "loadavg_1": _safe_float(d.get("loadavg_1", sys_stats.get("loadavg_1"))),
                "loadavg_5": _safe_float(d.get("loadavg_5", sys_stats.get("loadavg_5"))),
                "loadavg_15": _safe_float(d.get("loadavg_15", sys_stats.get("loadavg_15"))),
                "num_sta": d.get("num_sta", 0),
                "last_seen": d.get("last_seen"),
                "uplink": uplink,
                "port_table": port_table,
                "radio_table": radio_table,
            })
        return devices

    @staticmethod
    def _parse_client(c):
        return {
            "hostname": c.get("hostname", c.get("name", c.get("oui", "Unknown"))),
            "ip": c.get("ip", ""),
            "mac": c.get("mac", ""),
            "network": c.get("network", ""),
            "is_wired": c.get("is_wired", False),
            "uptime": c.get("uptime", 0),
            "last_seen": c.get("last_seen", None),
            "tx_bytes": c.get("tx_bytes", None),
            "rx_bytes": c.get("rx_bytes", None),
            "tx_rate": c.get("tx_rate", None),
            "rx_rate": c.get("rx_rate", None),
            "blocked": c.get("blocked", False),
            "signal": c.get("signal", c.get("rssi", None)),
            "satisfaction": c.get("satisfaction", None),
            "channel": c.get("channel", None),
            "radio": c.get("radio", None),
            "essid": c.get("essid", None),
            "sw_port": c.get("sw_port", None),
            "is_guest": c.get("is_guest", c.get("_is_guest_by_uap", False)),
            "ap_mac": c.get("ap_mac", None),
            "sw_mac": c.get("sw_mac", None),
            "wifi_tx_attempts": c.get("wifi_tx_attempts", None),
            "tx_retries": c.get("tx_retries", None),
            "first_seen": c.get("first_seen", None),
            "oui": c.get("oui", ""),
        }

    def get_clients(self):
        raw = self._api_get(f"/api/s/{self.site}/stat/sta")
        if raw is None:
            return []
        return [self._parse_client(c) for c in raw]

    def get_client_by_mac(self, mac):
        """Fetch live stats for a single client by MAC address."""
        raw = self._api_get(f"/api/s/{self.site}/stat/sta", mac.lower())
        if not raw:
            return None
        return self._parse_client(raw[0])

    def reconnect_client(self, mac):
        """Force reconnect a wireless client."""
        return self._api_post(
            f"/api/s/{self.site}/cmd/stamgr",
            {"cmd": "kick-sta", "mac": mac},
        )

    def block_client(self, mac):
        """Block a client from the network."""
        return self._api_post(
            f"/api/s/{self.site}/cmd/stamgr",
            {"cmd": "block-sta", "mac": mac},
        )

    def unblock_client(self, mac):
        """Unblock a client on the network."""
        return self._api_post(
            f"/api/s/{self.site}/cmd/stamgr",
            {"cmd": "unblock-sta", "mac": mac},
        )

    def restart_device(self, mac):
        return self._api_post(
            f"/api/s/{self.site}/cmd/devmgr",
            {"cmd": "restart", "mac": mac},
        )

    def get_networks(self):
        """List network configurations (VLANs/SSIDs) from the UniFi controller."""
        raw = self._api_get(f"/api/s/{self.site}/rest/networkconf")
        if raw is None:
            return []
        networks = []
        for n in raw:
            purpose = n.get("purpose", "")
            if purpose in ("wan", "wan2"):
                continue  # Skip WAN interfaces
            networks.append({
                "id": n.get("_id", ""),
                "name": n.get("name", ""),
                "purpose": purpose,
                "vlan": n.get("vlan", None),
            })
        return sorted(networks, key=lambda x: x["name"].lower())

    def get_site_health(self):
        """Fetch site health info (WAN/LAN/WLAN subsystem status)."""
        raw = self._api_get(f"/api/s/{self.site}/stat/health")
        if raw is None:
            return []
        return raw

    def get_wlan_conf(self):
        """Fetch WLAN/SSID configurations."""
        raw = self._api_get(f"/api/s/{self.site}/rest/wlanconf")
        if raw is None:
            return []
        wlans = []
        for w in raw:
            wlans.append({
                "id": w.get("_id", ""),
                "name": w.get("name", ""),
                "enabled": w.get("enabled", True),
                "security": w.get("security", ""),
                "is_guest": w.get("is_guest", False),
                "wlan_band": w.get("wlan_band", ""),
            })
        return sorted(wlans, key=lambda x: x["name"].lower())

    def get_all_clients(self, within=24):
        """Fetch all known clients (historical), not just active.

        *within* is the lookback period in hours.
        """
        raw = self._api_get(f"/api/s/{self.site}/stat/alluser?within={within}")
        if raw is None:
            return []
        return [self._parse_client(c) for c in raw]

    def get_dpi_stats(self):
        """Fetch site-level DPI (Deep Packet Inspection) category breakdown.

        UDM controllers require a POST with type parameter; legacy may accept GET.
        """
        # UDM requires POST with type
        raw = self._api_post_data(
            f"/api/s/{self.site}/stat/sitedpi",
            {"type": "by_cat"},
        )
        if raw is None:
            # Fallback to GET for legacy controllers
            raw = self._api_get(f"/api/s/{self.site}/stat/sitedpi")
        if raw is None:
            return []
        return raw

    def get_port_forward_rules(self):
        """Fetch port forwarding rules."""
        raw = self._api_get(f"/api/s/{self.site}/rest/portforward")
        if raw is None:
            return []
        rules = []
        for r in raw:
            rules.append({
                "id": r.get("_id", ""),
                "name": r.get("name", ""),
                "enabled": r.get("enabled", True),
                "src": r.get("src", "any"),
                "dst_port": r.get("dst_port", ""),
                "fwd": r.get("fwd", ""),
                "fwd_port": r.get("fwd_port", ""),
                "proto": r.get("proto", "tcp_udp"),
            })
        return rules

    def get_firewall_rules(self):
        """Fetch firewall rules."""
        raw = self._api_get(f"/api/s/{self.site}/rest/firewallrule")
        if raw is None:
            return []
        rules = []
        for r in raw:
            rules.append({
                "id": r.get("_id", ""),
                "name": r.get("name", ""),
                "enabled": r.get("enabled", True),
                "action": r.get("action", ""),
                "ruleset": r.get("ruleset", ""),
                "rule_index": r.get("rule_index", 0),
                "protocol": r.get("protocol", "all"),
                "src_firewallgroup_ids": r.get("src_firewallgroup_ids", []),
                "dst_firewallgroup_ids": r.get("dst_firewallgroup_ids", []),
            })
        return sorted(rules, key=lambda x: x.get("rule_index", 0))

    def get_daily_site_stats(self, days=7):
        """Fetch daily site bandwidth/client stats via the report endpoint."""
        import time
        end = int(time.time()) * 1000  # UniFi uses milliseconds
        start = end - (days * 86400 * 1000)
        payload = {
            "attrs": ["bytes", "wan-tx_bytes", "wan-rx_bytes", "num_sta", "time"],
            "start": start,
            "end": end,
        }
        raw = self._api_post_data(f"/api/s/{self.site}/stat/report/daily.site", payload)
        if raw is None:
            return []
        stats = []
        for s in raw:
            stats.append({
                "time": s.get("time", 0),
                "bytes": s.get("bytes", 0),
                "wan_tx_bytes": s.get("wan-tx_bytes", 0),
                "wan_rx_bytes": s.get("wan-rx_bytes", 0),
                "num_sta": s.get("num_sta", 0),
            })
        return stats

    def test_connection(self):
        if not self.login():
            return False, f"Login failed: {self._login_error}"
        devices = self.get_devices()
        if devices is None:
            return False, "Could not fetch devices"
        return True, f"Connected. {len(devices)} device(s) found."


# ---------------------------------------------------------------------------
# Module-level cached client
# ---------------------------------------------------------------------------
_cached_client: "UniFiClient | None" = None
_cached_settings_key: "tuple | None" = None
_client_lock = threading.Lock()


def get_cached_client(base_url, username, password, site="default", is_udm=True, verify_ssl=False):
    """Return a cached UniFiClient, creating a new one only if settings changed."""
    global _cached_client, _cached_settings_key
    key = (base_url, username, password, site, is_udm, verify_ssl)
    if _cached_client is not None and _cached_settings_key == key:
        return _cached_client
    with _client_lock:
        # Double-check after acquiring lock
        if _cached_client is not None and _cached_settings_key == key:
            return _cached_client
        _cached_client = UniFiClient(base_url, username, password, site=site, is_udm=is_udm, verify_ssl=verify_ssl)
        _cached_settings_key = key
        return _cached_client


def invalidate_cached_client():
    """Discard the cached client (e.g. after settings change)."""
    global _cached_client, _cached_settings_key
    with _client_lock:
        _cached_client = None
        _cached_settings_key = None
