import logging

import requests
import urllib3

from core.errors import describe_exception

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


class PBSClient:
    """Client for the Proxmox Backup Server API (port 8007)."""

    def __init__(self, host_model):
        from auth.credential_store import decrypt

        self.base_url = f"https://{host_model.hostname}:{host_model.port}/api2/json"
        self.session = requests.Session()
        self.session.verify = host_model.verify_ssl
        self._logged_in = False
        self._username = None
        self._password = None

        if host_model.auth_type == "token":
            username = host_model.username or "root@pam"
            token_id = host_model.api_token_id or ""
            token_secret = decrypt(host_model.api_token_secret) if host_model.api_token_secret else ""
            # PBS API token header: PBSAPIToken=user@realm!tokenid:secret
            self.session.headers["Authorization"] = f"PBSAPIToken={username}!{token_id}:{token_secret}"
            self._logged_in = True
        else:
            self._username = host_model.username or "root@pam"
            self._password = decrypt(host_model.encrypted_password) if host_model.encrypted_password else ""

    def _login(self):
        if self._logged_in:
            return True
        try:
            resp = self.session.post(
                f"{self.base_url}/access/ticket",
                json={"username": self._username, "password": self._password},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                ticket = data.get("ticket", "")
                csrf = data.get("CSRFPreventionToken", "")
                self.session.cookies.set("PBSAuthCookie", ticket)
                self.session.headers["CSRFPreventionToken"] = csrf
                self._logged_in = True
                return True
            logger.warning("PBS login failed: HTTP %s", resp.status_code)
            return False
        except requests.RequestException as e:
            logger.error("PBS login error: %s", e)
            return False

    def _get(self, path, params=None):
        if not self._logged_in and not self._login():
            return None
        try:
            resp = self.session.get(f"{self.base_url}{path}", params=params, timeout=15)
            if resp.status_code == 200:
                return resp.json().get("data")
            logger.warning("PBS API GET %s: HTTP %s", path, resp.status_code)
            return None
        except requests.RequestException as e:
            logger.error("PBS API error on %s: %s", path, e)
            return None

    def _post(self, path, payload=None):
        if not self._logged_in and not self._login():
            return False, "Not authenticated"
        try:
            resp = self.session.post(f"{self.base_url}{path}", json=payload or {}, timeout=15)
            if resp.status_code in (200, 201):
                return True, resp.json().get("data")
            return False, f"HTTP {resp.status_code}"
        except requests.RequestException as e:
            logger.error("PBS API error on %s: %s", path, e)
            return False, describe_exception(e)

    # ── Connection & Status ───────────────────────────────────────────────────

    def test_connection(self):
        data = self._get("/version")
        if data:
            version = data.get("version", "unknown")
            release = data.get("release", "")
            return True, f"PBS {version}-{release}" if release else f"PBS {version}"
        return False, "Could not connect to PBS API. Check credentials and network access."

    def get_node_name(self):
        nodes = self._get("/nodes")
        if nodes and len(nodes) > 0:
            return nodes[0].get("node", "pbs")
        return "pbs"

    def get_node_status(self):
        """Return normalized node status dict (same shape as ProxmoxClient.get_node_status)."""
        node = self.get_node_name()
        data = self._get(f"/nodes/{node}/status")
        if not data:
            return None

        mem = data.get("memory", {})
        swap = data.get("swap", {})
        root = data.get("root", {})
        cpuinfo = data.get("cpuinfo", {})
        return {
            "cpu_usage": round(data.get("cpu", 0) * 100, 1),
            "cpu_threads": cpuinfo.get("cpus", 0),
            "cpu_sockets": cpuinfo.get("sockets", 1),
            "cpu_cores": cpuinfo.get("cores", 1),
            "cpu_model": cpuinfo.get("model", ""),
            "memory_used": mem.get("used", 0),
            "memory_total": mem.get("total", 0),
            "swap_used": swap.get("used", 0),
            "swap_total": swap.get("total", 0),
            "rootfs_used": root.get("used", 0),
            "rootfs_total": root.get("total", 0),
            "uptime": data.get("uptime", 0),
            "loadavg": data.get("loadavg", [0, 0, 0]),
            "kversion": data.get("kversion", ""),
            "pbsversion": data.get("version", ""),
        }

    # ── Datastores ────────────────────────────────────────────────────────────

    def get_datastores(self):
        """Return list of datastore configs from /admin/datastore."""
        data = self._get("/admin/datastore")
        return data or []

    def get_datastore_status(self, store):
        """Return disk usage and GC info for a single datastore."""
        data = self._get(f"/admin/datastore/{store}/status")
        return data or {}

    def get_backup_groups(self, store):
        """Return all backup groups in a datastore (each group = one VM/CT/host)."""
        data = self._get(f"/admin/datastore/{store}/groups")
        return data or []

    def get_snapshots(self, store, backup_type=None, backup_id=None):
        """Return snapshots in a datastore, optionally filtered by type/id."""
        params = {}
        if backup_type:
            params["backup-type"] = backup_type
        if backup_id:
            params["backup-id"] = backup_id
        data = self._get(f"/admin/datastore/{store}/snapshots", params=params or None)
        return data or []

    def get_all_datastores_with_status(self):
        """Convenience: fetch all datastores and enrich each with disk usage and group count."""
        result = []
        for ds in self.get_datastores():
            store = ds.get("store") or ds.get("name", "")
            if not store:
                continue
            status = self.get_datastore_status(store)
            groups = self.get_backup_groups(store)

            used = status.get("used", 0)
            avail = status.get("avail", 0)
            total = used + avail

            # Tally type counts from groups
            vm_count = sum(1 for g in groups if g.get("backup-type") == "vm")
            ct_count = sum(1 for g in groups if g.get("backup-type") == "ct")
            host_count = sum(1 for g in groups if g.get("backup-type") == "host")

            result.append({
                "name": store,
                "path": ds.get("path", ""),
                "used": used,
                "avail": avail,
                "total": total,
                "group_count": len(groups),
                "vm_count": vm_count,
                "ct_count": ct_count,
                "host_count": host_count,
                "gc_status": status.get("gc-status", {}),
                "groups": sorted(groups, key=lambda g: g.get("last-backup", 0), reverse=True),
            })
        return result

    def run_gc(self, store):
        """Trigger garbage collection on a datastore."""
        return self._post(f"/admin/datastore/{store}/gc")

    # ── apt update management ─────────────────────────────────────────────────

    def get_apt_updates(self):
        """List pending apt packages for the PBS node."""
        node = self.get_node_name()
        return self._get(f"/nodes/{node}/apt/update") or []

    def refresh_apt_cache(self):
        """Run apt-get update on PBS node. Returns UPID string."""
        node = self.get_node_name()
        ok, data = self._post(f"/nodes/{node}/apt/update")
        if not ok:
            raise RuntimeError(data)
        return data  # UPID string

    def get_task_status(self, upid):
        """Get task status by UPID. Returns dict or None."""
        from urllib.parse import quote
        node = self.get_node_name()
        return self._get(f"/nodes/{node}/tasks/{quote(upid, safe='')}/status")

    def get_task_log(self, upid, start=0, limit=500):
        """Get task log lines by UPID. Returns list of dicts with 'n' (line no) and 't' (text)."""
        from urllib.parse import quote
        node = self.get_node_name()
        return self._get(f"/nodes/{node}/tasks/{quote(upid, safe='')}/log",
                         params={"start": start, "limit": limit}) or []
