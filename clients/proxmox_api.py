import logging
import time

from proxmoxer import ProxmoxAPI

from auth.credential_store import decrypt

logger = logging.getLogger(__name__)


class ProxmoxClient:
    """Wrapper around proxmoxer for cluster operations."""

    def __init__(self, host_model):
        self.host_model = host_model
        self._api = None

    def connect(self):
        kwargs = {
            "host": self.host_model.hostname,
            "port": self.host_model.port,
            "verify_ssl": self.host_model.verify_ssl,
        }

        if self.host_model.auth_type == "token":
            kwargs["user"] = self.host_model.username or "root@pam"
            kwargs["token_name"] = self.host_model.api_token_id
            kwargs["token_value"] = decrypt(self.host_model.api_token_secret)
        else:
            kwargs["user"] = self.host_model.username or "root@pam"
            kwargs["password"] = decrypt(self.host_model.encrypted_password)

        self._api = ProxmoxAPI(timeout=30, **kwargs)
        return self._api

    @property
    def api(self):
        if self._api is None:
            self.connect()
        return self._api

    def reconnect(self):
        """Force a fresh API connection (drops any stale TLS session)."""
        self._api = None

    def get_nodes(self):
        """Get all nodes from the Proxmox cluster. Raises on failure."""
        return self.api.nodes.get()

    def get_local_node_name(self):
        """Determine the node name of the host we're connected to."""
        try:
            # /cluster/status returns nodes with a 'local' flag
            for entry in self.api.cluster.status.get():
                if entry.get("type") == "node" and entry.get("local", 0):
                    return entry["name"]
        except Exception:
            pass
        # Fallback: if single-node or cluster/status unavailable, match by hostname
        try:
            nodes = self.get_nodes()
            if len(nodes) == 1:
                return nodes[0]["node"]
            # Try matching node name to the configured hostname
            target = self.host_model.hostname.lower()
            for node in nodes:
                if node["node"].lower() == target:
                    return node["node"]
        except Exception:
            pass
        return None

    def get_node_guests(self, node_name):
        """Get VMs and CTs on a specific node only."""
        guests = []
        errors = []
        try:
            vms = self.api.nodes(node_name).qemu.get()
            logger.info(f"Node {node_name}: found {len(vms)} VMs")
            for vm in vms:
                vm["node"] = node_name
                vm["type"] = "vm"
                guests.append(vm)
        except Exception as e:
            errors.append(f"VMs on {node_name}: {e}")
            logger.error(f"Failed to list VMs on node {node_name}: {e}")
        try:
            cts = self.api.nodes(node_name).lxc.get()
            logger.info(f"Node {node_name}: found {len(cts)} CTs")
            for ct in cts:
                ct["node"] = node_name
                ct["type"] = "ct"
                guests.append(ct)
        except Exception as e:
            errors.append(f"CTs on {node_name}: {e}")
            logger.error(f"Failed to list CTs on node {node_name}: {e}")

        if not guests and errors:
            raise RuntimeError(f"Could not list guests on {node_name}: {'; '.join(errors)}")

        return guests

    def get_replication_map(self):
        """Return a dict mapping VMID -> replication target node name."""
        repl = {}
        try:
            for job in self.api.cluster.replication.get():
                vmid = job.get("guest")
                target = job.get("target")
                if vmid and target:
                    repl[int(vmid)] = target
        except Exception as e:
            logger.debug(f"Could not fetch replication info: {e}")
        return repl

    def get_replication_jobs(self, vmid):
        """Get replication jobs for a specific VMID."""
        jobs = []
        try:
            for job in self.api.cluster.replication.get():
                if job.get("guest") == vmid:
                    jobs.append(job)
        except Exception as e:
            logger.debug(f"Could not fetch replication jobs for {vmid}: {e}")
        return jobs

    def create_replication(self, vmid, target_node, schedule="*/15", rate=None):
        """Create a replication job. Returns (success, message)."""
        try:
            job_id = f"{vmid}-0"
            params = {
                "id": job_id,
                "target": target_node,
                "schedule": schedule,
                "type": "local",
            }
            if rate:
                params["rate"] = rate
            self.api.cluster.replication.post(**params)
            return True, f"Replication to {target_node} created for VMID {vmid}"
        except Exception as e:
            return False, str(e)

    def delete_replication(self, job_id):
        """Delete a replication job. Returns (success, message)."""
        try:
            self.api.cluster.replication(job_id).delete()
            return True, f"Replication job {job_id} deleted"
        except Exception as e:
            return False, str(e)

    def get_all_guests(self):
        """Get all VMs and CTs across all nodes. Raises on connection failure."""
        nodes = self.get_nodes()
        if not nodes:
            raise RuntimeError("No nodes returned from Proxmox API. Check API token permissions (need VM.Audit or PVEAuditor role).")

        guests = []
        errors = []
        for node in nodes:
            node_name = node["node"]
            try:
                vms = self.api.nodes(node_name).qemu.get()
                logger.info(f"Node {node_name}: found {len(vms)} VMs")
                for vm in vms:
                    vm["node"] = node_name
                    vm["type"] = "vm"
                    guests.append(vm)
            except Exception as e:
                errors.append(f"VMs on {node_name}: {e}")
                logger.error(f"Failed to list VMs on node {node_name}: {e}")
            try:
                cts = self.api.nodes(node_name).lxc.get()
                logger.info(f"Node {node_name}: found {len(cts)} CTs")
                for ct in cts:
                    ct["node"] = node_name
                    ct["type"] = "ct"
                    guests.append(ct)
            except Exception as e:
                errors.append(f"CTs on {node_name}: {e}")
                logger.error(f"Failed to list CTs on node {node_name}: {e}")

        if not guests and errors:
            raise RuntimeError(f"Could not list guests: {'; '.join(errors)}")

        logger.info(f"Total guests discovered: {len(guests)} ({len(errors)} errors)")
        return guests

    def get_guest_ip(self, node, vmid, guest_type):
        """Try to get guest IP from Proxmox network info."""
        try:
            if guest_type == "vm":
                ifaces = self.api.nodes(node).qemu(vmid).agent("network-get-interfaces").get()
                for iface in ifaces.get("result", []):
                    for addr in iface.get("ip-addresses", []):
                        if addr.get("ip-address-type") == "ipv4" and not addr["ip-address"].startswith("127."):
                            return addr["ip-address"]
            else:
                config = self.api.nodes(node).lxc(vmid).config.get()
                # Parse net0 for static IP
                net0 = config.get("net0", "")
                if "ip=" in net0:
                    ip_part = net0.split("ip=")[1].split(",")[0].split("/")[0]
                    if ip_part and ip_part != "dhcp":
                        return ip_part
                # For DHCP containers, query the actual network interfaces
                try:
                    ifaces = self.api.nodes(node).lxc(vmid).interfaces.get()
                    for iface in ifaces:
                        if iface.get("name") == "lo":
                            continue
                        inet = iface.get("inet")
                        if inet:
                            # Format: "x.x.x.x/prefix"
                            return inet.split("/")[0]
                except Exception as e:
                    logger.debug(f"Could not get LXC interfaces for {vmid}: {e}")
        except Exception as e:
            logger.debug(f"Could not get IP for {guest_type}/{vmid}: {e}")
        return None

    def get_guest_mac(self, node, vmid, guest_type):
        """Get the primary MAC address of a guest from its config."""
        try:
            if guest_type == "vm":
                config = self.api.nodes(node).qemu(vmid).config.get()
            else:
                config = self.api.nodes(node).lxc(vmid).config.get()
            # Parse net0 for MAC address (format: "virtio=AA:BB:CC:DD:EE:FF,..." or "name=...,hwaddr=AA:BB:...")
            net0 = config.get("net0", "")
            if not net0:
                return None
            # VM format: "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,..."
            # CT format: "name=eth0,bridge=vmbr0,hwaddr=AA:BB:CC:DD:EE:FF,..."
            import re
            # Match hwaddr= (CT) or driver=MAC (VM)
            hwaddr_match = re.search(r"hwaddr=([0-9A-Fa-f:]{17})", net0)
            if hwaddr_match:
                return hwaddr_match.group(1).lower()
            # VM: first field is usually "virtio=MAC" or "e1000=MAC"
            mac_match = re.search(r"=([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", net0)
            if mac_match:
                return mac_match.group(1).lower()
        except Exception as e:
            logger.debug(f"Could not get MAC for {guest_type}/{vmid}: {e}")
        return None

    def exec_guest_agent(self, node, vmid, command, timeout=120):
        """Execute a command via QEMU guest agent and return output.

        Args:
            timeout: Max seconds to wait for command completion (default 120).
        """
        try:
            try:
                result = self.api.nodes(node).qemu(vmid).agent.exec.post(command=command)
            except Exception:
                # Stale TLS connection (broken pipe) — reconnect and retry once
                logger.debug("Guest agent exec failed, reconnecting and retrying")
                self._api = None
                time.sleep(1)
                result = self.api.nodes(node).qemu(vmid).agent.exec.post(command=command)

            pid = result.get("pid")
            if not pid:
                return None, "No PID returned"

            # Poll for completion
            poll_interval = 2
            max_polls = max(timeout // poll_interval, 1)
            for _ in range(max_polls):
                try:
                    status = self.api.nodes(node).qemu(vmid).agent("exec-status").get(pid=pid)
                    if status.get("exited"):
                        stdout = status.get("out-data", "")
                        stderr = status.get("err-data", "")
                        exitcode = status.get("exitcode", -1)
                        if exitcode == 0:
                            return stdout, None
                        return stdout, stderr or f"Exit code {exitcode}"
                except Exception:
                    pass
                time.sleep(poll_interval)

            return None, "Timeout waiting for command"
        except Exception as e:
            return None, str(e)

    def exec_ct_command(self, node, vmid, command):
        """Execute a command inside a CT via Proxmox API (pct exec equivalent)."""
        try:
            # Use the lxc exec endpoint
            result = self.api.nodes(node).lxc(vmid).status.current.get()
            if result.get("status") != "running":
                return None, "Container is not running"

            # For CTs, we use the exec via the API - this requires SSH to the node
            # or using the Proxmox API's built-in exec (available in newer versions)
            # Fallback: we'll use SSH to the Proxmox host and run pct exec
            return None, "CT exec via API requires SSH to Proxmox host - use SSH connection method instead"
        except Exception as e:
            return None, str(e)

    def get_guest_status(self, node, vmid, guest_type):
        """Get current power status of a guest. Returns status string or 'unknown'."""
        try:
            if guest_type == "vm":
                result = self.api.nodes(node).qemu(vmid).status.current.get()
            else:
                result = self.api.nodes(node).lxc(vmid).status.current.get()
            return result.get("status", "unknown")
        except Exception as e:
            logger.debug(f"Could not get status for {guest_type}/{vmid}: {e}")
            return "unknown"

    def start_guest(self, node, vmid, guest_type):
        """Start a VM or CT. Returns (success, message)."""
        try:
            if guest_type == "vm":
                self.api.nodes(node).qemu(vmid).status.start.post()
            else:
                self.api.nodes(node).lxc(vmid).status.start.post()
            return True, f"Start command sent for {guest_type}/{vmid}"
        except Exception as e:
            return False, str(e)

    def shutdown_guest(self, node, vmid, guest_type):
        """Gracefully shutdown a VM or CT. Returns (success, message)."""
        try:
            if guest_type == "vm":
                self.api.nodes(node).qemu(vmid).status.shutdown.post()
            else:
                self.api.nodes(node).lxc(vmid).status.shutdown.post()
            return True, f"Shutdown command sent for {guest_type}/{vmid}"
        except Exception as e:
            return False, str(e)

    def stop_guest(self, node, vmid, guest_type):
        """Force stop a VM or CT. Returns (success, message)."""
        try:
            if guest_type == "vm":
                self.api.nodes(node).qemu(vmid).status.stop.post()
            else:
                self.api.nodes(node).lxc(vmid).status.stop.post()
            return True, f"Stop command sent for {guest_type}/{vmid}"
        except Exception as e:
            return False, str(e)

    def reboot_guest(self, node, vmid, guest_type):
        """Reboot a VM or CT. Returns (success, message)."""
        try:
            if guest_type == "vm":
                self.api.nodes(node).qemu(vmid).status.reboot.post()
            else:
                self.api.nodes(node).lxc(vmid).status.reboot.post()
            return True, f"Reboot command sent for {guest_type}/{vmid}"
        except Exception as e:
            return False, str(e)

    def guest_supports_snapshot(self, node, vmid, guest_type):
        """Return True if the guest's storage supports snapshots (i.e. not plain LVM).

        Uses the Proxmox API feature-check endpoint. Defaults to True on any
        error so we don't silently block snapshot attempts.
        """
        try:
            if guest_type == "vm":
                result = self.api.nodes(node).qemu(vmid).feature.get(feature="snapshot")
            else:
                result = self.api.nodes(node).lxc(vmid).feature.get(feature="snapshot")
            return bool(result.get("hasFeature", 1))
        except Exception as e:
            logger.debug(f"Could not check snapshot feature for {guest_type}/{vmid}: {e}")
            return True  # fail open

    def create_snapshot(self, node, vmid, guest_type, snapname, description=""):
        """Create a snapshot of a VM or CT. Returns (success, upid_or_error)."""
        try:
            kwargs = {"snapname": snapname, "description": description}
            if guest_type == "vm":
                upid = self.api.nodes(node).qemu(vmid).snapshot.post(**kwargs)
            else:
                upid = self.api.nodes(node).lxc(vmid).snapshot.post(**kwargs)
            return True, upid
        except Exception as e:
            logger.error(f"Failed to create snapshot for {guest_type}/{vmid}: {e}")
            return False, str(e)

    def list_snapshots(self, node, vmid, guest_type):
        """List snapshots for a VM or CT. Returns list of dicts with name, description, snaptime."""
        try:
            if guest_type == "vm":
                data = self.api.nodes(node).qemu(vmid).snapshot.get()
            else:
                data = self.api.nodes(node).lxc(vmid).snapshot.get()
            # Filter out the virtual "current" entry that Proxmox always includes
            return [s for s in data if s.get("name") != "current"]
        except Exception as e:
            logger.error(f"Failed to list snapshots for {guest_type}/{vmid}: {e}")
            return []

    def delete_snapshot(self, node, vmid, guest_type, snapname):
        """Delete a snapshot. Returns (success, upid_or_error)."""
        try:
            if guest_type == "vm":
                upid = self.api.nodes(node).qemu(vmid).snapshot(snapname).delete()
            else:
                upid = self.api.nodes(node).lxc(vmid).snapshot(snapname).delete()
            return True, upid
        except Exception as e:
            logger.error(f"Failed to delete snapshot '{snapname}' for {guest_type}/{vmid}: {e}")
            return False, str(e)

    def rollback_snapshot(self, node, vmid, guest_type, snapname):
        """Rollback to a snapshot. Returns (success, upid_or_error)."""
        try:
            if guest_type == "vm":
                upid = self.api.nodes(node).qemu(vmid).snapshot(snapname).rollback.post()
            else:
                upid = self.api.nodes(node).lxc(vmid).snapshot(snapname).rollback.post()
            return True, upid
        except Exception as e:
            logger.error(f"Failed to rollback to snapshot '{snapname}' for {guest_type}/{vmid}: {e}")
            return False, str(e)

    # ------------------------------------------------------------------
    # Backups (vzdump)
    # ------------------------------------------------------------------

    def create_backup(self, node, vmid, storage, mode="snapshot", compress="zstd", protected=False, notes=""):
        """Create a vzdump backup. Returns (success, upid_or_error)."""
        try:
            kwargs = {
                "vmid": vmid,
                "storage": storage,
                "mode": mode,
                "compress": compress,
            }
            if protected:
                kwargs["protected"] = 1
            if notes:
                kwargs["notes-template"] = notes
            upid = self.api.nodes(node).vzdump.post(**kwargs)
            return True, upid
        except Exception as e:
            logger.error(f"Failed to create backup for VMID {vmid}: {e}")
            return False, str(e)

    def list_backups(self, node, vmid, storage):
        """List backup volumes for a VMID from a storage. Returns list of dicts."""
        try:
            data = self.api.nodes(node).storage(storage).content.get(content="backup", vmid=vmid)
            return sorted(data, key=lambda x: x.get("ctime", 0), reverse=True)
        except Exception as e:
            logger.error(f"Failed to list backups for VMID {vmid} on {storage}: {e}")
            return []

    def list_node_storages(self, node, content_type="backup"):
        """List storages available on a node, optionally filtered by content type."""
        try:
            storages = self.api.nodes(node).storage.get()
            if content_type:
                storages = [s for s in storages if content_type in s.get("content", "").split(",")]
            return storages
        except Exception as e:
            logger.error(f"Failed to list storages on {node}: {e}")
            return []

    def delete_backup(self, node, storage, volid):
        """Delete a backup volume. Returns (success, message)."""
        try:
            self.api.nodes(node).storage(storage).content(volid).delete()
            return True, f"Backup '{volid}' deleted"
        except Exception as e:
            logger.error(f"Failed to delete backup '{volid}': {e}")
            return False, str(e)

    def update_backup_protection(self, node, storage, volid, protected):
        """Set or remove protection on a backup. Returns (success, message)."""
        try:
            self.api.nodes(node).storage(storage).content(volid).put(protected=1 if protected else 0)
            state = "protected" if protected else "unprotected"
            return True, f"Backup '{volid}' is now {state}"
        except Exception as e:
            logger.error(f"Failed to update protection on '{volid}': {e}")
            return False, str(e)

    def update_backup_notes(self, node, storage, volid, notes):
        """Update the notes on a backup volume. Returns (success, message)."""
        try:
            self.api.nodes(node).storage(storage).content(volid).put(notes=notes)
            return True, f"Notes updated for '{volid}'"
        except Exception as e:
            logger.error(f"Failed to update notes on '{volid}': {e}")
            return False, str(e)

    def find_guest_node(self, vmid):
        """Find which node a guest (VM or CT) is running on. Returns node name or None."""
        try:
            for guest in self.get_all_guests():
                if guest.get("vmid") == vmid:
                    return guest.get("node")
        except Exception as e:
            logger.error(f"Failed to find guest node for vmid {vmid}: {e}")
        return None

    # ------------------------------------------------------------------
    # Clone / migrate
    # ------------------------------------------------------------------

    def list_cluster_nodes(self):
        """List cluster node names (for migrate target dropdowns). Returns a list of strings."""
        try:
            return sorted(n["node"] for n in self.get_nodes())
        except Exception as e:
            logger.error(f"Failed to list cluster nodes: {e}")
            return []

    def get_next_vmid(self):
        """Ask Proxmox for the next free VMID via /cluster/nextid. Returns int or None."""
        try:
            return int(self.api.cluster.nextid.get())
        except Exception as e:
            logger.error(f"Failed to get next VMID: {e}")
            return None

    def clone_guest(self, node, vmid, guest_type, newid, name=None, full=True, target_storage=None):
        """Clone a VM or CT to a new VMID. Returns (success, upid_or_error).

        POST /nodes/{node}/{qemu|lxc}/{vmid}/clone
          newid    — the new guest's VMID
          name     — hostname/name of the clone (optional)
          full     — 1 for a full clone, 0 for a linked clone
          storage  — optional target storage for a full clone
        """
        try:
            kwargs = {"newid": newid, "full": 1 if full else 0}
            if name:
                kwargs["name"] = name
            if full and target_storage:
                kwargs["storage"] = target_storage
            if guest_type == "vm":
                upid = self.api.nodes(node).qemu(vmid).clone.post(**kwargs)
            else:
                upid = self.api.nodes(node).lxc(vmid).clone.post(**kwargs)
            return True, upid
        except Exception as e:
            logger.error(f"Failed to clone {guest_type}/{vmid} -> {newid}: {e}")
            return False, str(e)

    def migrate_guest(self, node, vmid, guest_type, target_node, online=None):
        """Migrate a VM or CT to another node. Returns (success, upid_or_error).

        POST /nodes/{node}/{qemu|lxc}/{vmid}/migrate
        For a running QEMU VM, pass online=True to add online=1 (live migration).
        For a running LXC, pass online=True to add restart=1 (restart migration),
        since LXC does not support live migration.

        If ``online`` is None, the current power state is queried and live/restart
        migration is enabled automatically when the guest is running.
        """
        try:
            if online is None:
                online = self.get_guest_status(node, vmid, guest_type) == "running"
            kwargs = {"target": target_node}
            if online:
                if guest_type == "vm":
                    kwargs["online"] = 1
                else:
                    kwargs["restart"] = 1
            if guest_type == "vm":
                upid = self.api.nodes(node).qemu(vmid).migrate.post(**kwargs)
            else:
                upid = self.api.nodes(node).lxc(vmid).migrate.post(**kwargs)
            return True, upid
        except Exception as e:
            logger.error(f"Failed to migrate {guest_type}/{vmid} to {target_node}: {e}")
            return False, str(e)

    # ------------------------------------------------------------------
    # Node-level statistics
    # ------------------------------------------------------------------

    def get_node_status(self, node):
        """Get node-level stats: CPU, memory, rootfs, swap, uptime, loadavg, etc."""
        try:
            data = self.api.nodes(node).status.get()
            cpuinfo = data.get("cpuinfo", {})
            memory = data.get("memory", {})
            rootfs = data.get("rootfs", {})
            swap = data.get("swap", {})
            return {
                "cpu_usage": round(data.get("cpu", 0) * 100, 1),
                "cpu_cores": cpuinfo.get("cores", 0),
                "cpu_sockets": cpuinfo.get("sockets", 0),
                "cpu_threads": cpuinfo.get("cpus", 0),
                "cpu_model": cpuinfo.get("model", "Unknown"),
                "memory_used": memory.get("used", 0),
                "memory_total": memory.get("total", 0),
                "memory_free": memory.get("free", 0),
                "swap_used": swap.get("used", 0),
                "swap_total": swap.get("total", 0),
                "rootfs_used": rootfs.get("used", 0),
                "rootfs_total": rootfs.get("total", 0),
                "uptime": data.get("uptime", 0),
                "loadavg": data.get("loadavg", [0, 0, 0]),
                "kversion": data.get("kversion", ""),
                "pveversion": data.get("pveversion", ""),
            }
        except Exception as e:
            logger.error(f"Failed to get node status for {node}: {e}")
            return None

    def get_node_storage(self, node):
        """Get all storage pools on a node with usage stats."""
        try:
            storages = self.api.nodes(node).storage.get()
            result = []
            for s in storages:
                result.append({
                    "name": s.get("storage", ""),
                    "type": s.get("type", ""),
                    "total": s.get("total", 0),
                    "used": s.get("used", 0),
                    "avail": s.get("avail", 0),
                    "active": s.get("active", 0),
                    "enabled": s.get("enabled", 0),
                    "content": s.get("content", ""),
                    "shared": s.get("shared", 0),
                })
            return result
        except Exception as e:
            logger.error(f"Failed to get node storage for {node}: {e}")
            return []

    # ------------------------------------------------------------------
    # Task tracking
    # ------------------------------------------------------------------

    def get_task_status(self, node, upid):
        """Get task status. Returns dict with status, exitstatus, etc."""
        return self.api.nodes(node).tasks(upid).status.get()

    def get_task_log(self, node, upid, start=0, limit=1000):
        """Get task log lines. Returns list of dicts with n (line number), t (text)."""
        return self.api.nodes(node).tasks(upid).log.get(start=start, limit=limit)

    def cancel_task(self, node, upid):
        """Stop a running Proxmox task."""
        try:
            self.api.nodes(node).tasks(upid).delete()
        except Exception:
            pass  # Task may have already finished

    # ------------------------------------------------------------------
    # Guest configuration / hardware info
    # ------------------------------------------------------------------

    def get_guest_config(self, node, vmid, guest_type):
        """Get guest hardware config (CPUs, memory, disks). Returns a dict."""
        try:
            if guest_type == "vm":
                config = self.api.nodes(node).qemu(vmid).config.get()
            else:
                config = self.api.nodes(node).lxc(vmid).config.get()

            result = {"type": guest_type}

            # CPU
            cores = config.get("cores", 1)
            sockets = config.get("sockets", 1) if guest_type == "vm" else 1
            result["cores"] = cores
            result["sockets"] = sockets
            result["vcpus"] = cores * sockets
            result["cpu_type"] = config.get("cpu", "") if guest_type == "vm" else ""

            # Memory (Proxmox stores in MB)
            result["memory_mb"] = config.get("memory", 0)
            result["swap_mb"] = config.get("swap", 0) if guest_type == "ct" else 0
            result["balloon"] = config.get("balloon", None) if guest_type == "vm" else None

            # Disks
            disks = []
            if guest_type == "vm":
                # VM disks: scsi0, virtio0, ide0, sata0, etc.
                import re
                for key, val in config.items():
                    if re.match(r"^(scsi|virtio|ide|sata|efidisk|tpmstate)\d+$", key) and isinstance(val, str):
                        disk = {"key": key}
                        # Parse size from string like "local-lvm:vm-100-disk-0,size=32G"
                        size_match = re.search(r"size=(\d+[TGMK]?)", val)
                        if size_match:
                            disk["size"] = size_match.group(1)
                        # Parse storage
                        if ":" in val:
                            disk["storage"] = val.split(":")[0]
                        disks.append(disk)
            else:
                # CT: rootfs and mpN (mount points)
                import re
                rootfs = config.get("rootfs", "")
                if rootfs:
                    disk = {"key": "rootfs"}
                    size_match = re.search(r"size=(\d+[TGMK]?)", rootfs)
                    if size_match:
                        disk["size"] = size_match.group(1)
                    if ":" in rootfs:
                        disk["storage"] = rootfs.split(":")[0]
                    disks.append(disk)
                for key, val in config.items():
                    if re.match(r"^mp\d+$", key) and isinstance(val, str):
                        disk = {"key": key}
                        size_match = re.search(r"size=(\d+[TGMK]?)", val)
                        if size_match:
                            disk["size"] = size_match.group(1)
                        if ":" in val:
                            disk["storage"] = val.split(":")[0]
                        # Parse mount point
                        mp_match = re.search(r"mp=([^,]+)", val)
                        if mp_match:
                            disk["mountpoint"] = mp_match.group(1)
                        disks.append(disk)

            result["disks"] = sorted(disks, key=lambda d: d["key"])
            return result
        except Exception as e:
            logger.error(f"Failed to get config for {guest_type}/{vmid}: {e}")
            return None

    # ------------------------------------------------------------------
    # RRD performance data
    # ------------------------------------------------------------------

    def get_node_rrd_data(self, node, timeframe="hour"):
        """Get node-level RRD performance data. timeframe: hour, day, week, month, year.
        Returns list of dicts with keys: time, cpu, maxcpu, memused, memtotal, netin, netout, etc."""
        try:
            return self.api.nodes(node).rrddata.get(timeframe=timeframe)
        except Exception as e:
            logger.error(f"Failed to get node RRD data for {node}: {e}")
            return []

    def get_rrd_data(self, node, vmid, guest_type, timeframe="hour"):
        """Get RRD performance data. timeframe: hour, day, week, month, year.
        Returns list of dicts with keys: time, cpu, maxcpu, mem, maxmem, netin, netout, etc."""
        try:
            if guest_type == "vm":
                return self.api.nodes(node).qemu(vmid).rrddata.get(timeframe=timeframe)
            else:
                return self.api.nodes(node).lxc(vmid).rrddata.get(timeframe=timeframe)
        except Exception as e:
            logger.error(f"Failed to get RRD data for {guest_type}/{vmid}: {e}")
            return []

    # ------------------------------------------------------------------
    # apt update management
    # ------------------------------------------------------------------

    def get_apt_updates(self, node):
        """List pending apt packages. Each item has: Package, Title, Version, OldVersion, Priority."""
        try:
            return self.api.nodes(node).apt.update.get()
        except Exception as e:
            logger.error(f"Failed to get apt updates for {node}: {e}")
            return []

    def refresh_apt_cache(self, node):
        """Run apt-get update on node. Returns UPID string."""
        return self.api.nodes(node).apt.update.post()

    def test_connection(self):
        """Test API connectivity and return version info."""
        try:
            version = self.api.version.get()
            return True, f"Proxmox VE {version.get('version', 'unknown')} (release {version.get('release', '')})"
        except Exception as e:
            return False, str(e)
