import json
import logging
import re
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)


def _fmt_bytes(n):
    """Render a byte count for the model (and the user) as e.g. '1.5 GiB'."""
    try:
        n = float(n or 0)
    except (TypeError, ValueError):
        return "0 B"
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


def _pct(used, total):
    return round(used / total * 100, 1) if total else None


def _usage(used, total):
    """{used, total, percent} in bytes plus a human-readable summary string."""
    used = used or 0
    total = total or 0
    entry = {"used_bytes": used, "total_bytes": total, "percent": _pct(used, total)}
    entry["human"] = f"{_fmt_bytes(used)} of {_fmt_bytes(total)}" + (
        f" ({entry['percent']}%)" if entry["percent"] is not None else "")
    return entry


def _serialize_guest(guest):
    """Serialize a Guest model to a dict for Claude."""
    return {
        "id": guest.id,
        "name": guest.name,
        "type": guest.guest_type,
        "ip": guest.ip_address,
        "status": guest.status,
        "power_state": guest.power_state,
        "lock": guest.lock_reason,
        "host": guest.proxmox_host.name if guest.proxmox_host else None,
        "vmid": guest.vmid,
        "pending_updates": len(guest.pending_updates()),
        "security_updates": len(guest.security_updates()),
        "reboot_required": guest.reboot_required,
        "last_scan": guest.last_scan.isoformat() if guest.last_scan else None,
        "tags": [t.name for t in guest.tags],
    }


def _serialize_service(svc):
    """Serialize a GuestService model to a dict for Claude."""
    return {
        "id": svc.id,
        "guest_id": svc.guest_id,
        "service_name": svc.service_name,
        "unit_name": svc.unit_name,
        "status": svc.status,
        "port": svc.port,
        "last_checked": svc.last_checked.isoformat() if svc.last_checked else None,
    }


# ---- Tool handler functions ----

def _handle_list_guests(tool_input, user):
    from models import Guest
    # Match the UI: admin-tier roles see every guest, others their tagged guests.
    guests = Guest.query.filter_by(enabled=True).all() if user.is_admin else user.accessible_guests()
    return json.dumps([_serialize_guest(g) for g in guests])


def _handle_get_guest_details(tool_input, user):
    from models import Guest
    guest = Guest.query.get(tool_input["guest_id"])
    if not guest:
        return json.dumps({"error": "Guest not found"})
    if not user.may_access_guest(guest):
        return json.dumps({"error": "Access denied"})
    data = _serialize_guest(guest)
    # Add update details
    data["updates"] = [
        {
            "package": u.package_name,
            "current": u.current_version,
            "available": u.available_version,
            "severity": u.severity,
            "requires_reboot": u.requires_reboot,
        }
        for u in guest.pending_updates()
    ]
    data["services"] = [_serialize_service(s) for s in guest.services]
    return json.dumps(data)


def _handle_get_guest_updates(tool_input, user):
    from models import Guest
    guest = Guest.query.get(tool_input["guest_id"])
    if not guest:
        return json.dumps({"error": "Guest not found"})
    if not user.may_access_guest(guest):
        return json.dumps({"error": "Access denied"})
    updates = [
        {
            "package": u.package_name,
            "current": u.current_version,
            "available": u.available_version,
            "severity": u.severity,
            "requires_reboot": u.requires_reboot,
        }
        for u in guest.pending_updates()
    ]
    return json.dumps({"guest": guest.name, "updates": updates, "total": len(updates)})


def _handle_list_services(tool_input, user):
    from models import GuestService
    services = GuestService.query.all()
    result = []
    for svc in services:
        if svc.guest and user.may_access_guest(svc.guest):
            entry = _serialize_service(svc)
            entry["guest_name"] = svc.guest.name if svc.guest else None
            result.append(entry)
    return json.dumps(result)


def _handle_restart_service(tool_input, user):
    from auth.audit import log_action
    from models import GuestService, db

    svc = GuestService.query.get(tool_input["service_id"])
    if not svc:
        return json.dumps({"error": "Service not found"})
    guest = svc.guest
    if not guest or not user.may_access_guest(guest):
        return json.dumps({"error": "Access denied"})

    action = tool_input.get("action", "restart")
    if action not in ("start", "stop", "restart"):
        return json.dumps({"error": f"Invalid action: {action}"})

    # M2: two-phase propose-then-confirm. State-changing service control must be
    # explicitly confirmed by the caller before it actually runs. This is a
    # server-side gate — it does not rely on the model honoring the system prompt.
    if not tool_input.get("confirm"):
        return json.dumps({
            "status": "confirmation_required",
            "message": (
                f"This will {action} '{svc.service_name}' on '{guest.name}'. "
                "No action has been taken. To proceed, call control_service again "
                "with the same service_id and action plus \"confirm\": true."
            ),
            "pending_action": {
                "tool": "control_service",
                "service_id": svc.id,
                "service_name": svc.service_name,
                "guest": guest.name,
                "action": action,
            },
        })

    try:
        from core.scanner import service_action
        ok, msg = service_action(guest, svc, action)
        if ok:
            log_action("ai_service_control", "guest", resource_id=guest.id,
                       resource_name=guest.name,
                       details={"service": svc.service_name, "action": action, "via": "ai_assistant"})
            db.session.commit()
        return json.dumps({"success": ok, "message": msg})
    except Exception:
        # M3: log the full exception server-side; never leak str(e) to the model/client.
        logger.exception("AI service control error (service_id=%s, action=%s)",
                         tool_input.get("service_id"), action)
        return json.dumps({"error": "Service control failed due to an internal error."})


def _handle_list_audit_logs(tool_input, user):
    from models import AuditLog
    limit = min(tool_input.get("limit", 20), 50)
    query = AuditLog.query.order_by(AuditLog.timestamp.desc())

    action_filter = tool_input.get("action")
    if action_filter:
        query = query.filter(AuditLog.action == action_filter)

    resource_type = tool_input.get("resource_type")
    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)

    hours = tool_input.get("hours_back")
    if hours:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        query = query.filter(AuditLog.timestamp >= cutoff)

    logs = query.limit(limit).all()
    return json.dumps([
        {
            "id": log.id,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "user": log.user.username if log.user else None,
            "action": log.action,
            "resource_type": log.resource_type,
            "resource_name": log.resource_name,
            "details": log.details,
        }
        for log in logs
    ])


def _live_guest(guest, user):
    """Resolve (client, node) for a guest's live Proxmox data, or an error dict."""
    if not guest:
        return None, None, {"error": "Guest not found"}
    if not user.may_access_guest(guest):
        return None, None, {"error": "Access denied"}
    if not guest.proxmox_host or not guest.vmid:
        return None, None, {"error": "Guest is not linked to a Proxmox host, so no live data is available"}
    from clients.proxmox_api import ProxmoxClient
    client = ProxmoxClient(guest.proxmox_host)
    node = client.find_guest_node(guest.vmid)
    if not node:
        return None, None, {"error": f"Guest VMID {guest.vmid} was not found on host '{guest.proxmox_host.name}'"}
    return client, node, None


def _handle_get_guest_resource_usage(tool_input, user):
    """Live CPU / memory / disk / network figures straight from the Proxmox API."""
    from models import Guest
    guest = Guest.query.get(tool_input["guest_id"])
    client, node, err = _live_guest(guest, user)
    if err:
        return json.dumps(err)
    data = client.get_guest_current(node, guest.vmid, guest.guest_type)
    if not data:
        return json.dumps({"error": "Proxmox did not return a status record for this guest"})

    result = {
        "guest_id": guest.id,
        "name": guest.name,
        "vmid": guest.vmid,
        "type": guest.guest_type,
        "host": guest.proxmox_host.name,
        "node": node,
        "status": data.get("status", "unknown"),
        "uptime_seconds": data.get("uptime", 0),
        "cpu_percent": round((data.get("cpu") or 0) * 100, 1),
        "cpu_cores": data.get("cpus"),
        "memory": _usage(data.get("mem"), data.get("maxmem")),
        "disk": _usage(data.get("disk"), data.get("maxdisk")),
        "network_in_bytes_total": data.get("netin", 0),
        "network_out_bytes_total": data.get("netout", 0),
    }
    if data.get("maxswap"):
        result["swap"] = _usage(data.get("swap"), data.get("maxswap"))
    if data.get("lock"):
        result["lock"] = data["lock"]
    if result["status"] != "running":
        result["note"] = "Guest is not running; usage figures are zero."
    return json.dumps(result)


def _handle_get_guest_performance_history(tool_input, user):
    """Summarise Proxmox RRD history (avg / peak CPU and memory) for a guest."""
    from models import Guest
    guest = Guest.query.get(tool_input["guest_id"])
    client, node, err = _live_guest(guest, user)
    if err:
        return json.dumps(err)
    timeframe = tool_input.get("timeframe", "day")
    if timeframe not in ("hour", "day", "week", "month", "year"):
        return json.dumps({"error": f"Invalid timeframe: {timeframe}"})
    rows = [r for r in (client.get_rrd_data(node, guest.vmid, guest.guest_type, timeframe=timeframe) or [])
            if r.get("cpu") is not None or r.get("mem") is not None]
    if not rows:
        return json.dumps({"guest_id": guest.id, "name": guest.name, "timeframe": timeframe,
                           "samples": 0, "note": "No performance history available"})

    cpu = [(r.get("cpu") or 0) * 100 for r in rows]
    mem = [r.get("mem") or 0 for r in rows]
    maxmem = max((r.get("maxmem") or 0) for r in rows)
    peak_idx = max(range(len(mem)), key=mem.__getitem__)
    peak_at = rows[peak_idx].get("time")
    return json.dumps({
        "guest_id": guest.id,
        "name": guest.name,
        "timeframe": timeframe,
        "samples": len(rows),
        "cpu_percent": {"average": round(sum(cpu) / len(cpu), 1), "peak": round(max(cpu), 1)},
        "memory": {
            "total_bytes": maxmem,
            "average": _usage(sum(mem) / len(mem), maxmem),
            "peak": _usage(max(mem), maxmem),
            "peak_at": datetime.fromtimestamp(peak_at, tz=timezone.utc).isoformat() if peak_at else None,
        },
        "network_average_bytes_per_second": {
            "in": round(sum((r.get("netin") or 0) for r in rows) / len(rows)),
            "out": round(sum((r.get("netout") or 0) for r in rows) / len(rows)),
        },
    })


_POWER_ACTIONS = ("start", "shutdown", "stop", "reboot")
_SNAPSHOT_ACTIONS = ("create", "delete", "rollback")
# Proxmox snapshot names: a letter, then letters/digits/-/_ (kept short so the
# model cannot smuggle anything odd into an API path segment).
_SNAPNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,39}$")


def _confirmation_required(tool, summary, **pending):
    """Two-phase gate shared by the state-changing guest tools (see control_service)."""
    return json.dumps({
        "status": "confirmation_required",
        "message": (
            f"{summary} No action has been taken. To proceed, call {tool} again "
            "with the same arguments plus \"confirm\": true."
        ),
        "pending_action": {"tool": tool, **pending},
    })


def _linked_guest(guest, user):
    """DB-only checks shared by the guest action tools: exists, accessible, linked."""
    if not guest:
        return {"error": "Guest not found"}
    if not user.may_access_guest(guest):
        return {"error": "Access denied"}
    if not guest.proxmox_host or not guest.vmid:
        return {"error": "Guest is not linked to a Proxmox host"}
    return None


def _handle_control_guest_power(tool_input, user):
    """start / shutdown / stop / reboot a guest, mirroring routes/guests.py::power_action."""
    from auth.audit import log_action
    from models import Guest, db

    action = tool_input.get("action")
    if action not in _POWER_ACTIONS:
        return json.dumps({"error": f"Invalid action: {action}"})
    guest = Guest.query.get(tool_input["guest_id"])
    err = _linked_guest(guest, user)
    if err:
        return json.dumps(err)

    if not tool_input.get("confirm"):
        summary = (f"This will {action} '{guest.name}' ({guest.guest_type.upper()} {guest.vmid} on "
                   f"{guest.proxmox_host.name}); it is currently {guest.power_state}.")
        if guest.lock_reason:
            summary += f" WARNING: the guest is locked ({guest.lock_reason})."
        if action == "stop":
            summary += " 'stop' is a hard power-off; prefer 'shutdown' unless the guest is unresponsive."
        return _confirmation_required("control_guest_power", summary, guest_id=guest.id, guest=guest.name,
                                      action=action, current_power_state=guest.power_state)

    from clients.proxmox_api import ProxmoxClient
    client = ProxmoxClient(guest.proxmox_host)
    node = client.find_guest_node(guest.vmid) or guest.proxmox_host.name
    ok, msg = getattr(client, f"{action}_guest")(node, guest.vmid, guest.guest_type)
    if not ok:
        logger.warning("AI power %s failed for guest %s: %s", action, guest.id, msg)
        return json.dumps({"success": False,
                           "message": f"Proxmox rejected the {action} command; details are in the server log."})

    # Same optimistic state update as the human route.
    if action == "start":
        guest.power_state = "running"
    elif action in ("shutdown", "stop"):
        guest.power_state = "stopped"
    if action == "reboot":
        guest.reboot_required = False
    log_action("guest_power", "guest", resource_id=guest.id, resource_name=guest.name,
               details={"action": action, "via": "ai_assistant"})
    db.session.commit()
    return json.dumps({"success": True, "message": f"{action.capitalize()} command sent to {guest.name}."})


def _handle_list_snapshots(tool_input, user):
    from models import Guest
    guest = Guest.query.get(tool_input["guest_id"])
    client, node, err = _live_guest(guest, user)
    if err:
        return json.dumps(err)
    snapshots = client.list_snapshots(node, guest.vmid, guest.guest_type)
    return json.dumps({
        "guest_id": guest.id,
        "name": guest.name,
        "snapshots_supported": bool(client.guest_supports_snapshot(node, guest.vmid, guest.guest_type)),
        "count": len(snapshots),
        "snapshots": [
            {
                "name": s.get("name"),
                "description": s.get("description", ""),
                "created_at": (datetime.fromtimestamp(s["snaptime"], tz=timezone.utc).isoformat()
                               if s.get("snaptime") else None),
                "parent": s.get("parent"),
                "includes_ram": bool(s.get("vmstate")),
            }
            for s in snapshots
        ],
    })


def _handle_manage_snapshot(tool_input, user):
    """create / delete / rollback a snapshot, mirroring the routes/guests.py snapshot views."""
    from auth.audit import log_action
    from models import Guest, db

    action = tool_input.get("action")
    if action not in _SNAPSHOT_ACTIONS:
        return json.dumps({"error": f"Invalid action: {action}"})
    guest = Guest.query.get(tool_input["guest_id"])
    err = _linked_guest(guest, user)
    if err:
        return json.dumps(err)

    snapname = (tool_input.get("snapname") or "").strip()
    if action == "create" and not snapname:
        snapname = f"manual-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    if not snapname:
        return json.dumps({"error": "snapname is required"})
    if not _SNAPNAME_RE.match(snapname):
        return json.dumps({"error": "Invalid snapshot name: start with a letter, then letters, digits, "
                                    "'-' or '_' only, at most 40 characters"})
    description = (tool_input.get("description") or "").strip()

    if not tool_input.get("confirm"):
        summaries = {
            "create": f"This will create snapshot '{snapname}' of '{guest.name}'.",
            "delete": f"This will permanently delete snapshot '{snapname}' of '{guest.name}'. This cannot be undone.",
            "rollback": (f"This will roll '{guest.name}' back to snapshot '{snapname}', discarding every change "
                         "made since it was taken. This cannot be undone."),
        }
        pending = {"guest_id": guest.id, "guest": guest.name, "action": action, "snapname": snapname}
        if action == "create":
            pending["description"] = description
        return _confirmation_required("manage_snapshot", summaries[action], **pending)

    client, node, err = _live_guest(guest, user)
    if err:
        return json.dumps(err)
    if action == "create":
        if not client.guest_supports_snapshot(node, guest.vmid, guest.guest_type):
            return json.dumps({"error": "This guest's storage does not support snapshots"})
        ok, result = client.create_snapshot(node, guest.vmid, guest.guest_type, snapname, description)
        job_type, audit_action = "snapshot", "guest_snapshot_create"
    elif action == "delete":
        ok, result = client.delete_snapshot(node, guest.vmid, guest.guest_type, snapname)
        job_type, audit_action = "snapshot_delete", "guest_snapshot_delete"
    else:
        ok, result = client.rollback_snapshot(node, guest.vmid, guest.guest_type, snapname)
        job_type, audit_action = "rollback", "guest_snapshot_rollback"
    if not ok:
        logger.warning("AI snapshot %s failed for guest %s: %s", action, guest.id, result)
        return json.dumps({"success": False,
                           "message": f"Proxmox rejected the snapshot {action}; details are in the server log."})

    log_action(audit_action, "guest", resource_id=guest.id, resource_name=guest.name,
               details={"snapname": snapname, "via": "ai_assistant"})
    db.session.commit()
    # Register the Proxmox task so the guest page's task tracker follows it.
    from routes.api import start_proxmox_job
    start_proxmox_job(guest, job_type, result, node)
    return json.dumps({
        "success": True,
        "message": f"Snapshot {action} of '{snapname}' started on {guest.name}; Proxmox is running it as a task.",
        "task": result,
    })


def _live_host_status(host):
    """Live node status (and storage pools for PVE) for one host. Raises on failure."""
    if host.is_pbs:
        from clients.pbs_client import PBSClient
        return PBSClient(host).get_node_status(), None
    from clients.proxmox_api import ProxmoxClient
    client = ProxmoxClient(host)
    node_name = client.get_local_node_name()
    if not node_name:
        return None, None
    return client.get_node_status(node_name), client.get_node_storage(node_name)


def _handle_get_host_status(tool_input, user):
    from models import ProxmoxHost
    host_id = tool_input.get("host_id")
    hosts = ProxmoxHost.query.filter_by(id=host_id).all() if host_id else ProxmoxHost.query.all()
    if host_id and not hosts:
        return json.dumps({"error": "Host not found"})
    result = []
    for host in hosts:
        entry = {
            "id": host.id,
            "name": host.name,
            "hostname": host.hostname,
            "type": host.host_type,
            "guest_count": len(host.guests),
            "online": False,
        }
        try:
            status, storages = _live_host_status(host)
        except Exception:
            logger.warning("AI host status: live query failed for %s", host.name, exc_info=True)
            status, storages = None, None
        if status:
            entry["online"] = True
            entry["cpu_percent"] = status.get("cpu_usage")
            entry["cpu_threads"] = status.get("cpu_threads")
            entry["loadavg"] = status.get("loadavg")
            entry["memory"] = _usage(status.get("memory_used"), status.get("memory_total"))
            entry["swap"] = _usage(status.get("swap_used"), status.get("swap_total"))
            entry["rootfs"] = _usage(status.get("rootfs_used"), status.get("rootfs_total"))
            entry["uptime_seconds"] = status.get("uptime", 0)
            entry["version"] = status.get("pveversion") or status.get("pbsversion") or ""
        if storages:
            entry["storage"] = [
                {
                    "name": st["name"],
                    "type": st["type"],
                    "active": bool(st.get("active")),
                    **_usage(st.get("used"), st.get("total")),
                }
                for st in storages
            ]
        result.append(entry)
    return json.dumps(result)


# ---- UniFi lookups (read-only; scoped exactly like routes/unifi.py) ----

_UNIFI_DEVICE_STATES = {0: "offline", 1: "online", 2: "pending adoption", 4: "upgrading",
                        5: "provisioning", 6: "heartbeat missed", 7: "adopting", 9: "isolated"}
_UNIFI_MAX_CLIENTS = 100


def _unifi_client():
    """(client, None) when UniFi is enabled and configured, else (None, error dict)."""
    from models import Setting
    if Setting.get("unifi_enabled", "false") != "true":
        return None, {"error": "UniFi integration is not enabled"}
    from routes.unifi import _get_unifi_client
    client = _get_unifi_client()
    if not client:
        return None, {"error": "UniFi controller is not configured (Settings > UniFi)"}
    return client, None


def _unifi_scope(items, user):
    """Apply the site subnet filter and the user's tag-linked network restriction, as the UniFi pages do."""
    from models import Setting
    from routes.unifi import _filter_by_subnet, _get_accessible_networks
    items = _filter_by_subnet(items, "ip", Setting.get("unifi_filter_subnet", ""))
    networks = _get_accessible_networks(user)
    if networks is not None:
        items = [c for c in items if c.get("network", "") in networks]
    return items


def _iso_from_epoch(value):
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).isoformat() if value else None
    except (TypeError, ValueError, OSError):
        return None


def _serialize_unifi_device(d):
    uplink = d.get("uplink") or {}
    state = d.get("state", 0)
    return {
        "name": d.get("name"),
        "mac": d.get("mac"),
        "ip": d.get("ip"),
        "model": d.get("model"),
        "type": d.get("type"),
        "state": _UNIFI_DEVICE_STATES.get(state, f"state {state}"),
        "adopted": bool(d.get("adopted")),
        "version": d.get("version"),
        "uptime_seconds": d.get("uptime", 0),
        "cpu_percent": d.get("cpu"),
        "memory_percent": d.get("mem"),
        "temperature_c": d.get("temperature"),
        "connected_clients": d.get("num_sta", 0),
        "uplink": {"type": uplink.get("type"), "speed_mbps": uplink.get("speed")},
        "ports_up": sum(1 for p in d.get("port_table") or [] if p.get("up")),
        "radios": [{"radio": r.get("radio"), "channel": r.get("channel"), "clients": r.get("num_sta"),
                    "utilisation_percent": r.get("cu_total")} for r in d.get("radio_table") or []],
    }


def _serialize_unifi_client(c, device_names, guest_by_mac):
    mac = (c.get("mac") or "").lower()
    via_mac = ((c.get("ap_mac") or c.get("sw_mac")) or "").lower()
    guest = guest_by_mac.get(mac)
    entry = {
        "hostname": c.get("hostname"),
        "ip": c.get("ip"),
        "mac": mac,
        "network": c.get("network"),
        "connection": "wired" if c.get("is_wired") else "wireless",
        "connected_to": device_names.get(via_mac) or via_mac or None,
        "switch_port": c.get("sw_port"),
        "ssid": c.get("essid"),
        "signal_dbm": c.get("signal"),
        "satisfaction_percent": c.get("satisfaction"),
        "uptime_seconds": c.get("uptime", 0),
        "last_seen": _iso_from_epoch(c.get("last_seen")),
        "blocked": bool(c.get("blocked")),
        "is_guest": bool(c.get("is_guest")),
        "vendor": c.get("oui") or None,
    }
    if guest is not None:
        entry["guest_id"] = guest.id
        entry["guest_name"] = guest.name
    return entry


def _handle_list_unifi_devices(tool_input, user):
    client, err = _unifi_client()
    if err:
        return json.dumps(err)
    from models import Setting
    from routes.unifi import _filter_by_subnet
    devices = _filter_by_subnet(client.get_devices() or [], "ip", Setting.get("unifi_filter_subnet", ""))
    devices.sort(key=lambda d: (d.get("name") or "").lower())
    return json.dumps({"count": len(devices), "devices": [_serialize_unifi_device(d) for d in devices]})


def _handle_list_unifi_clients(tool_input, user):
    client, err = _unifi_client()
    if err:
        return json.dumps(err)
    from models import Guest

    clients = client.get_clients() or []
    if tool_input.get("include_offline"):
        seen = {(c.get("mac") or "").lower() for c in clients}
        for c in client.get_all_clients(within=720) or []:
            if (c.get("mac") or "").lower() not in seen:
                c["offline"] = True
                clients.append(c)
    clients = _unifi_scope(clients, user)

    query = (tool_input.get("query") or "").strip().lower()
    if query:
        fields = ("hostname", "ip", "mac", "network", "essid", "oui")
        clients = [c for c in clients if any(query in str(c.get(f) or "").lower() for f in fields)]

    device_names = {(d.get("mac") or "").lower(): d.get("name") for d in client.get_devices() or []}
    macs = [(c.get("mac") or "").lower() for c in clients if c.get("mac")]
    guest_by_mac = {}
    if macs:
        for g in Guest.query.filter(Guest.mac_address.isnot(None)).all():
            if g.mac_address.lower() in macs and user.may_access_guest(g):
                guest_by_mac[g.mac_address.lower()] = g

    clients.sort(key=lambda c: (bool(c.get("offline")), (c.get("hostname") or "").lower()))
    total = len(clients)
    clients = clients[:_UNIFI_MAX_CLIENTS]
    result = []
    for c in clients:
        entry = _serialize_unifi_client(c, device_names, guest_by_mac)
        if c.get("offline"):
            entry["online"] = False
        result.append(entry)
    return json.dumps({"count": total, "truncated": total > len(result), "clients": result})


def _handle_get_unifi_health(tool_input, user):
    client, err = _unifi_client()
    if err:
        return json.dumps(err)
    subsystems = {}
    for sub in client.get_site_health() or []:
        name = sub.get("subsystem")
        if not name:
            continue
        entry = {"status": sub.get("status")}
        for key in ("num_user", "num_guest", "num_iot", "num_ap", "num_sw", "num_gw", "num_adopted",
                    "num_disconnected", "num_pending"):
            if sub.get(key) is not None:
                entry[key] = sub[key]
        if name.startswith("wan"):
            gw_stats = sub.get("gw_system-stats") or sub.get("gw_system_stats") or {}
            entry["wan_ip"] = sub.get("wan_ip") or sub.get("gw") or sub.get("ip")
            entry["isp"] = sub.get("isp_name") or sub.get("isp_organization") or sub.get("ISP")
            entry["latency_ms"] = next((sub[k] for k in ("latency", "internet_latency", "wan1_latency",
                                                          "latency_average") if sub.get(k)), None)
            entry["uptime_seconds"] = sub.get("uptime") or sub.get("wan_uptime") or gw_stats.get("uptime")
            entry["speedtest_download_mbps"] = sub.get("speedtest_lastrun_download") or sub.get("xput_down")
            entry["speedtest_upload_mbps"] = sub.get("speedtest_lastrun_upload") or sub.get("xput_up")
        subsystems[name] = entry
    return json.dumps({
        "subsystems": subsystems,
        "networks": [{"name": n.get("name"), "purpose": n.get("purpose"), "vlan": n.get("vlan")}
                     for n in client.get_networks() or []],
        "wlans": [{"name": w.get("name"), "enabled": bool(w.get("enabled", True)), "security": w.get("security"),
                   "band": w.get("wlan_band"), "is_guest": bool(w.get("is_guest"))}
                  for w in client.get_wlan_conf() or []],
    })


# ---- Node apt updates (mirrors routes/hosts.py update management) ----

_HOST_UPDATE_ACTIONS = ("refresh", "apply", "cancel")
# Proxmox apt "Priority" -> the severity the scheduler stores (core/scheduler._persist_host_packages)
_APT_SEVERITY = {"important": "critical", "required": "important"}


def _host_for_tool(tool_input):
    from models import ProxmoxHost
    host = ProxmoxHost.query.get(tool_input.get("host_id") or 0)
    return host, (None if host else {"error": "Host not found"})


def _host_apt_updates(host):
    """Live pending apt packages for a PVE or PBS host, as the host page's /updates endpoint returns them."""
    from routes.hosts import _get_client_and_node
    client, node_name = _get_client_and_node(host)
    if host.is_pbs:
        return client.get_apt_updates() or [], node_name
    return (client.get_apt_updates(node_name) if node_name else []), node_name


def _apply_job_summary(host_id):
    from routes.hosts import _apply_jobs, _apply_lock
    with _apply_lock:
        job = _apply_jobs.get(host_id)
        if not job:
            return None
        log = "".join(job.get("log") or [])
        return {
            "running": bool(job.get("running")),
            "success": job.get("success"),
            "cancelled": bool(job.get("cancelled")),
            "log_tail": log[-1500:],
        }


def _handle_get_host_updates(tool_input, user):
    host, err = _host_for_tool(tool_input)
    if err:
        return json.dumps(err)
    result = {"host_id": host.id, "name": host.name, "type": host.host_type}
    try:
        updates, node = _host_apt_updates(host)
        packages = [
            {
                "package": u.get("Package"),
                "title": u.get("Title"),
                "current": u.get("OldVersion"),
                "available": u.get("Version") or u.get("NewVersion"),
                "severity": _APT_SEVERITY.get(u.get("Priority", ""), "normal"),
            }
            for u in updates
        ]
        result.update({"source": "live", "node": node, "count": len(packages),
                       "security_count": sum(1 for p in packages if p["severity"] == "critical"),
                       "packages": packages})
    except Exception:
        logger.warning("AI host updates: live apt query failed for %s; using last scan", host.name, exc_info=True)
        pending = host.pending_updates()
        result.update({
            "source": "last_scan",
            "note": "The host could not be queried live; these packages are from the last scheduled scan.",
            "count": len(pending),
            "security_count": len(host.security_updates()),
            "packages": [{"package": p.package_name, "current": p.current_version, "available": p.available_version,
                          "severity": p.severity, "discovered_at": p.discovered_at.isoformat() if p.discovered_at else None}
                         for p in pending],
        })
    job = _apply_job_summary(host.id)
    if job:
        result["apply_job"] = job
    return json.dumps(result)


def _handle_manage_host_updates(tool_input, user):
    """refresh (apt-get update via API), apply (SSH dist-upgrade job) or cancel, as routes/hosts.py does."""
    from auth.audit import log_action
    from models import db

    action = tool_input.get("action")
    if action not in _HOST_UPDATE_ACTIONS:
        return json.dumps({"error": f"Invalid action: {action}"})
    host, err = _host_for_tool(tool_input)
    if err:
        return json.dumps(err)

    if action == "refresh":
        from routes.hosts import _get_client_and_node
        client, node_name = _get_client_and_node(host)
        if host.is_pbs:
            upid = client.refresh_apt_cache()
        else:
            if not node_name:
                return json.dumps({"error": "Could not determine the node name"})
            upid = client.refresh_apt_cache(node_name)
        log_action("host_refresh_updates", "host", resource_id=host.id, resource_name=host.name,
                   details={"via": "ai_assistant"})
        db.session.commit()
        return json.dumps({"success": True, "task": upid,
                           "message": f"apt-get update started on {host.name}; call get_host_updates in a moment "
                                      "for the refreshed list."})

    from routes.hosts import _apply_jobs, _apply_lock

    if action == "cancel":
        with _apply_lock:
            job = _apply_jobs.get(host.id)
            if not job or not job.get("running"):
                return json.dumps({"success": False, "message": "No update job is running on this host."})
            job["cancelled"] = True
        log_action("host_apply_updates_cancel", "host", resource_id=host.id, resource_name=host.name,
                   details={"via": "ai_assistant"})
        db.session.commit()
        return json.dumps({"success": True, "message": f"Cancellation requested for the update job on {host.name}; "
                                                       "apt stops at the next safe point."})

    # apply
    if not host.ssh_credential:
        return json.dumps({"error": f"No SSH credential is configured for {host.name}; updates can only be applied "
                                    "over SSH. Set one on the host page."})
    with _apply_lock:
        existing = _apply_jobs.get(host.id)
        if existing and existing.get("running"):
            return json.dumps({"error": "An update job is already running for this host; check get_host_updates."})

    if not tool_input.get("confirm"):
        pending = host.pending_updates()
        kind = "PBS" if host.is_pbs else "PVE"
        summary = (f"This will run 'apt-get dist-upgrade' over SSH on {kind} host '{host.name}' "
                   f"({len(pending)} package(s) pending at the last scan, {len(host.security_updates())} security). "
                   "Kernel or Proxmox package upgrades may require a reboot afterwards; the job can be cancelled "
                   "but packages already unpacking will finish.")
        return _confirmation_required("manage_host_updates", summary, host_id=host.id, host=host.name, action="apply")

    from flask import current_app

    from routes.hosts import _run_apply, _threading
    with _apply_lock:
        existing = _apply_jobs.get(host.id)
        if existing and existing.get("running"):
            return json.dumps({"error": "An update job is already running for this host; check get_host_updates."})
        _apply_jobs[host.id] = {"log": [], "running": True, "success": None, "cancelled": False}
    _threading.Thread(target=_run_apply, args=(host.id, current_app._get_current_object()), daemon=True).start()
    log_action("host_apply_updates", "host", resource_id=host.id, resource_name=host.name,
               details={"via": "ai_assistant"})
    db.session.commit()
    return json.dumps({"success": True,
                       "message": f"Update job started on {host.name}. Call get_host_updates to follow its "
                                  "progress (apply_job.running / success / log_tail)."})


# ---- Tool registry ----

TOOL_REGISTRY = {
    "list_guests": {
        "description": "List all VMs and containers the user has access to, with their status, update counts, and tags.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
        "required_permission": None,
        "handler": _handle_list_guests,
    },
    "get_guest_details": {
        "description": "Get detailed information about a specific guest (VM/CT) including its services and pending updates.",
        "input_schema": {
            "type": "object",
            "properties": {
                "guest_id": {"type": "integer", "description": "The ID of the guest to look up"},
            },
            "required": ["guest_id"],
        },
        "required_permission": None,
        "handler": _handle_get_guest_details,
    },
    "get_guest_updates": {
        "description": "Get pending package updates for a specific guest, including severity and reboot requirements.",
        "input_schema": {
            "type": "object",
            "properties": {
                "guest_id": {"type": "integer", "description": "The ID of the guest to check updates for"},
            },
            "required": ["guest_id"],
        },
        "required_permission": None,
        "handler": _handle_get_guest_updates,
    },
    "get_guest_resource_usage": {
        "description": (
            "Get LIVE resource usage for a guest straight from Proxmox: current CPU %, memory used/total, "
            "disk used/total, swap (containers), uptime and network totals. Use this whenever the user asks "
            "how much memory, CPU or disk a VM or container is using right now."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "guest_id": {"type": "integer", "description": "The ID of the guest (from list_guests, not the VMID)"},
            },
            "required": ["guest_id"],
        },
        "required_permission": None,
        "handler": _handle_get_guest_resource_usage,
    },
    "get_guest_performance_history": {
        "description": (
            "Summarise a guest's recent performance from Proxmox history: average and peak CPU % and memory "
            "over the last hour, day, week, month or year, with when memory peaked. Use for questions like "
            "'has it been busy today' or 'did it run out of memory overnight'."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "guest_id": {"type": "integer", "description": "The ID of the guest (from list_guests, not the VMID)"},
                "timeframe": {
                    "type": "string",
                    "enum": ["hour", "day", "week", "month", "year"],
                    "description": "How far back to summarise (default: day)",
                },
            },
            "required": ["guest_id"],
        },
        "required_permission": None,
        "handler": _handle_get_guest_performance_history,
    },
    "control_guest_power": {
        "description": (
            "Start, gracefully shut down, force-stop or reboot a VM or container. State-changing: the first "
            "call returns a confirmation-required preview without doing anything; call again with "
            "\"confirm\": true after the user approves. Prefer 'shutdown' over 'stop' (hard power-off)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "guest_id": {"type": "integer", "description": "The ID of the guest (from list_guests, not the VMID)"},
                "action": {"type": "string", "enum": list(_POWER_ACTIONS), "description": "The power action"},
                "confirm": {
                    "type": "boolean",
                    "description": "Set to true only after the user has explicitly confirmed the action.",
                },
            },
            "required": ["guest_id", "action"],
        },
        "required_permission": "can_manage_guests",
        "handler": _handle_control_guest_power,
    },
    "list_snapshots": {
        "description": "List a guest's Proxmox snapshots (name, description, when taken, parent, whether RAM was included).",
        "input_schema": {
            "type": "object",
            "properties": {
                "guest_id": {"type": "integer", "description": "The ID of the guest (from list_guests, not the VMID)"},
            },
            "required": ["guest_id"],
        },
        "required_permission": None,
        "handler": _handle_list_snapshots,
    },
    "manage_snapshot": {
        "description": (
            "Create, delete or roll back to a Proxmox snapshot of a guest. State-changing: the first call returns "
            "a confirmation-required preview without doing anything; call again with \"confirm\": true after the "
            "user approves. Delete and rollback are irreversible. For create, snapname defaults to "
            "manual-<timestamp>."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "guest_id": {"type": "integer", "description": "The ID of the guest (from list_guests, not the VMID)"},
                "action": {"type": "string", "enum": list(_SNAPSHOT_ACTIONS), "description": "What to do"},
                "snapname": {
                    "type": "string",
                    "description": "Snapshot name (required for delete/rollback; optional for create)",
                },
                "description": {"type": "string", "description": "Optional description for a new snapshot"},
                "confirm": {
                    "type": "boolean",
                    "description": "Set to true only after the user has explicitly confirmed the action.",
                },
            },
            "required": ["guest_id", "action"],
        },
        "required_permission": "can_manage_guests",
        "handler": _handle_manage_snapshot,
    },
    "list_services": {
        "description": "List all monitored services across all accessible guests, with their current status.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
        "required_permission": "can_view_services",
        "handler": _handle_list_services,
    },
    "control_service": {
        "description": (
            "Start, stop, or restart a service on a guest. This is a state-changing "
            "action. The first call returns a confirmation-required result without "
            "doing anything; call again with \"confirm\": true to actually perform it."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "service_id": {"type": "integer", "description": "The ID of the service to control"},
                "action": {
                    "type": "string",
                    "enum": ["start", "stop", "restart"],
                    "description": "The action to perform",
                },
                "confirm": {
                    "type": "boolean",
                    "description": (
                        "Set to true only after the user has explicitly confirmed the action. "
                        "Omit or set false to preview the action without executing it."
                    ),
                },
            },
            "required": ["service_id", "action"],
        },
        # H1: mirror the human services.control route, which requires BOTH
        # can_view_services (services blueprint before_request) AND can_edit_services.
        "required_permission": ["can_view_services", "can_edit_services"],
        "handler": _handle_restart_service,
    },
    "list_audit_logs": {
        "description": "Search recent audit log entries with optional filters.",
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max entries to return (default 20, max 50)"},
                "action": {"type": "string", "description": "Filter by action type"},
                "resource_type": {"type": "string", "description": "Filter by resource type"},
                "hours_back": {"type": "integer", "description": "Only show entries from the last N hours"},
            },
            "required": [],
        },
        "required_permission": "can_view_audit_log",
        "handler": _handle_list_audit_logs,
    },
    "get_host_status": {
        "description": (
            "List Proxmox PVE/PBS hosts with LIVE node status: online/offline, CPU %, load average, memory, "
            "swap and root filesystem usage, uptime, version, and (PVE) every storage pool's usage and whether "
            "it is active. Pass host_id to query one host."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "host_id": {"type": "integer", "description": "Optional: only this host (from a previous listing)"},
            },
            "required": [],
        },
        "required_permission": "can_view_hosts",
        "handler": _handle_get_host_status,
    },
    "list_unifi_devices": {
        "description": (
            "List UniFi network devices (access points, switches, gateways) with online state, model, firmware, "
            "uptime, CPU/memory/temperature, connected client count, uplink and radio utilisation."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
        "required_permission": "can_view_unifi",
        "handler": _handle_list_unifi_devices,
    },
    "list_unifi_clients": {
        "description": (
            "Find devices on the network as UniFi sees them: hostname, IP, MAC, network/VLAN, wired or wireless, "
            "which AP or switch (and port) they are on, SSID, signal, last seen, blocked/guest flags, and the "
            "matching guest here when a VM/CT has that MAC. Filter with query (substring of hostname, IP, MAC, "
            "network, SSID or vendor). include_offline adds clients seen in the last 30 days."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Case-insensitive substring to match"},
                "include_offline": {"type": "boolean", "description": "Also list clients not currently connected"},
            },
            "required": [],
        },
        "required_permission": "can_view_unifi",
        "handler": _handle_list_unifi_clients,
    },
    "get_unifi_health": {
        "description": (
            "UniFi site health: per-subsystem status (wan, lan, wlan, vpn) with device and client counts, WAN IP, "
            "ISP, latency, uptime and last speedtest, plus the configured networks/VLANs and SSIDs."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
        "required_permission": "can_view_unifi",
        "handler": _handle_get_unifi_health,
    },
    "get_host_updates": {
        "description": (
            "Pending apt package updates on a Proxmox PVE or PBS host (the node itself, not its guests), queried "
            "live with severity, falling back to the last scheduled scan if the host is unreachable. Also reports "
            "the state of a running or finished update job (running, success, log tail)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "host_id": {"type": "integer", "description": "The host ID (from get_host_status)"},
            },
            "required": ["host_id"],
        },
        "required_permission": "can_view_hosts",
        "handler": _handle_get_host_updates,
    },
    "manage_host_updates": {
        "description": (
            "Node apt maintenance on a PVE/PBS host. 'refresh' runs apt-get update through the Proxmox API and "
            "needs no confirmation. 'apply' runs apt-get dist-upgrade over SSH as a background job: state-changing, "
            "so the first call returns a confirmation-required preview and only a second call with "
            "\"confirm\": true starts it. 'cancel' stops a running apply job."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "host_id": {"type": "integer", "description": "The host ID (from get_host_status)"},
                "action": {"type": "string", "enum": list(_HOST_UPDATE_ACTIONS), "description": "What to do"},
                "confirm": {
                    "type": "boolean",
                    "description": "apply only: set to true only after the user has explicitly confirmed.",
                },
            },
            "required": ["host_id", "action"],
        },
        "required_permission": "can_manage_hosts",
        "handler": _handle_manage_host_updates,
    },
}


def _required_permissions(defn):
    """Normalize a tool's required_permission into a list of permission names.

    Supports None (no permission), a single string, or a list of strings so that
    a tool can require ALL of several permissions (e.g. control_service mirrors the
    human route by requiring both can_view_services and can_edit_services).
    """
    perm = defn["required_permission"]
    if perm is None:
        return []
    if isinstance(perm, str):
        return [perm]
    return list(perm)


def _user_has_permissions(user, perms):
    """Return True only if the user has every permission in perms."""
    return all(getattr(user, p, False) for p in perms)


def get_tools_for_user(user):
    """Return Claude API tool definitions for tools the user has permission to use."""
    tools = []
    for name, defn in TOOL_REGISTRY.items():
        if _user_has_permissions(user, _required_permissions(defn)):
            tools.append({
                "name": name,
                "description": defn["description"],
                "input_schema": defn["input_schema"],
            })
    return tools


def execute_tool(tool_name, tool_input, user):
    """Execute a tool by name, enforcing permissions. Returns a JSON string result."""
    defn = TOOL_REGISTRY.get(tool_name)
    if not defn:
        return json.dumps({"error": f"Unknown tool: {tool_name}"})
    perms = _required_permissions(defn)
    if not _user_has_permissions(user, perms):
        missing = [p for p in perms if not getattr(user, p, False)]
        return json.dumps({"error": f"Permission denied: {', '.join(missing)} required"})
    try:
        return defn["handler"](tool_input, user)
    except Exception:
        # M3: log the full exception with traceback server-side; return a generic
        # message so internal details never reach the model or client.
        logger.exception("Tool execution error (%s)", tool_name)
        return json.dumps({"error": "Tool execution failed due to an internal error."})
