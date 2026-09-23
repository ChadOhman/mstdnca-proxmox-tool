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


_BACKUP_ACTIONS = ("create", "delete", "restore", "protect", "unprotect")
_BACKUP_MODES = ("snapshot", "suspend", "stop")
_BACKUP_COMPRESS = ("0", "gzip", "lzo", "zstd")


def _backup_defaults(guest):
    """Per-guest -> per-tag -> global backup defaults, exactly as routes/guests.py::create_backup."""
    from models import Setting
    from routes.guests import _get_tag_backup_defaults
    tag = _get_tag_backup_defaults(guest)
    return {
        "storage": guest.backup_storage or tag.get("storage") or Setting.get("backup_storage", ""),
        "mode": guest.backup_mode or tag.get("mode") or Setting.get("backup_mode", "snapshot"),
        "compress": guest.backup_compress or tag.get("compress") or Setting.get("backup_compress", "zstd"),
    }


def _serialize_backup(vol):
    volid = vol.get("volid") or ""
    ctime = vol.get("ctime")
    return {
        "volid": volid,
        "storage": vol.get("storage") or (volid.split(":", 1)[0] if ":" in volid else None),
        "created_at": datetime.fromtimestamp(ctime, tz=timezone.utc).isoformat() if ctime else None,
        "size": _fmt_bytes(vol.get("size", 0)),
        "size_bytes": vol.get("size", 0),
        "format": vol.get("format"),
        "protected": bool(vol.get("protected")),
        "notes": vol.get("notes", ""),
        "verified": (vol.get("verification") or {}).get("state"),
    }


def _guest_backups(guest, client, node):
    """Backups for a guest: the configured default storage, else every backup-capable storage."""
    storage = _backup_defaults(guest)["storage"]
    if storage:
        backups = client.list_backups(node, guest.vmid, storage) or []
        for vol in backups:
            vol.setdefault("storage", storage)
        return backups
    return client.list_all_backups(node, guest.vmid) or []


def _handle_list_backups(tool_input, user):
    from models import Guest
    guest = Guest.query.get(tool_input["guest_id"])
    client, node, err = _live_guest(guest, user)
    if err:
        return json.dumps(err)
    backups = _guest_backups(guest, client, node)
    storages = [s.get("storage") for s in client.list_node_storages(node, content_type="backup") or []]
    return json.dumps({
        "guest_id": guest.id,
        "name": guest.name,
        "defaults": _backup_defaults(guest),
        "backup_storages": [s for s in storages if s],
        "count": len(backups),
        "backups": [_serialize_backup(v) for v in backups],
    })


def _handle_manage_backup(tool_input, user):
    """create / delete / restore / protect / unprotect a backup, mirroring the routes/guests.py backup views."""
    from auth.audit import log_action
    from models import Guest, db

    action = tool_input.get("action")
    if action not in _BACKUP_ACTIONS:
        return json.dumps({"error": f"Invalid action: {action}"})
    guest = Guest.query.get(tool_input["guest_id"])
    err = _linked_guest(guest, user)
    if err:
        return json.dumps(err)

    volid = (tool_input.get("volid") or "").strip()
    if action != "create" and not volid:
        return json.dumps({"error": "volid is required (take it from list_backups)"})

    if action == "create":
        defaults = _backup_defaults(guest)
        storage = (tool_input.get("storage") or "").strip() or defaults["storage"]
        mode = (tool_input.get("mode") or "").strip() or defaults["mode"]
        compress = (tool_input.get("compress") or "").strip() or defaults["compress"]
        protected = bool(tool_input.get("protected"))
        notes = (tool_input.get("notes") or "").strip()
        if not storage:
            return json.dumps({"error": "No backup storage is configured for this guest. Pass storage explicitly "
                                        "(list_backups shows the backup-capable storages) or add a backup config "
                                        "for one of its tags in Settings."})
        if mode not in _BACKUP_MODES:
            return json.dumps({"error": f"Invalid mode: {mode} (use snapshot, suspend or stop)"})
        if compress not in _BACKUP_COMPRESS:
            return json.dumps({"error": f"Invalid compress: {compress} (use zstd, gzip, lzo or 0)"})

    if not tool_input.get("confirm"):
        if action == "create":
            summary = (f"This will create a {mode} backup of '{guest.name}' to storage '{storage}' "
                       f"(compression {compress}{', protected' if protected else ''}).")
            pending = {"guest_id": guest.id, "guest": guest.name, "action": action, "storage": storage,
                       "mode": mode, "compress": compress, "protected": protected, "notes": notes}
        else:
            summaries = {
                "delete": f"This will permanently delete backup '{volid}' of '{guest.name}'. This cannot be undone.",
                "restore": (f"DESTRUCTIVE: this will replace '{guest.name}' ({guest.guest_type.upper()} {guest.vmid}) "
                            f"entirely with the contents of '{volid}'; everything changed since that backup is lost. "
                            f"This cannot be undone. The confirming call must also pass "
                            f"\"confirm_name\": \"{guest.name}\"."),
                "protect": f"This will mark backup '{volid}' of '{guest.name}' as protected (kept by pruning).",
                "unprotect": f"This will remove protection from backup '{volid}' of '{guest.name}', so pruning may delete it.",
            }
            summary = summaries[action]
            pending = {"guest_id": guest.id, "guest": guest.name, "action": action, "volid": volid}
        return _confirmation_required("manage_backup", summary, **pending)

    if action == "restore" and (tool_input.get("confirm_name") or "").strip() != guest.name:
        return json.dumps({"error": f"Restore cancelled: confirm_name must exactly match the guest name '{guest.name}'."})

    client, node, err = _live_guest(guest, user)
    if err:
        return json.dumps(err)

    if action == "create":
        ok, result = client.create_backup(node, guest.vmid, storage, mode=mode, compress=compress,
                                          protected=protected, notes=notes)
        if not ok:
            logger.warning("AI backup create failed for guest %s: %s", guest.id, result)
            return json.dumps({"success": False,
                               "message": "Proxmox rejected the backup; details are in the server log."})
        log_action("guest_backup_create", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"storage": storage, "mode": mode, "via": "ai_assistant"})
        db.session.commit()
        from routes.api import start_proxmox_job
        start_proxmox_job(guest, "backup", result, node)
        return json.dumps({"success": True, "task": result,
                           "message": f"{mode} backup of {guest.name} to '{storage}' started; "
                                      "Proxmox is running it as a task."})

    # The storage API accepts any volid, so the archive must be proven to belong to this guest first.
    from routes.guests import _resolve_guest_backup
    storage = _resolve_guest_backup(guest, client, node, volid)
    if storage is None:
        return json.dumps({"error": "That backup archive does not belong to this guest (check list_backups)."})

    if action == "delete":
        ok, result = client.delete_backup(node, storage, volid)
        audit = ("guest_backup_delete", {"volid": volid})
        message, job_type = "Backup deleted.", None
    elif action in ("protect", "unprotect"):
        ok, result = client.update_backup_protection(node, storage, volid, action == "protect")
        audit = ("guest_backup_protect", {"volid": volid, "protected": action == "protect"})
        message, job_type = f"Backup is now {action}ed.", None
    else:
        ok, result = client.restore_backup(node, guest.vmid, guest.guest_type, volid, storage=storage)
        audit = ("guest_backup_restore", {"volid": volid, "storage": storage})
        message, job_type = f"Restore of {guest.name} from '{volid}' started; Proxmox is running it as a task.", "restore"
    if not ok:
        logger.warning("AI backup %s failed for guest %s: %s", action, guest.id, result)
        return json.dumps({"success": False,
                           "message": f"Proxmox rejected the backup {action}; details are in the server log."})

    log_action(audit[0], "guest", resource_id=guest.id, resource_name=guest.name,
               details={**audit[1], "via": "ai_assistant"})
    db.session.commit()
    response = {"success": True, "message": message}
    if job_type:
        from routes.api import start_proxmox_job
        start_proxmox_job(guest, job_type, result, node)
        response["task"] = result
    return json.dumps(response)


def _live_host_status(host):
    """Live node status (and storage pools / datastores) for one host. Raises on failure."""
    if host.is_pbs:
        from clients.pbs_client import PBSClient
        pbs = PBSClient(host)
        datastores = [
            {"name": d["name"], "type": "pbs-datastore", "active": True, "used": d["used"],
             "total": d["total"], "backup_groups": d["group_count"]}
            for d in pbs.get_all_datastores_with_status() or []
        ]
        return pbs.get_node_status(), datastores
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
                    **({"backup_groups": st["backup_groups"]} if "backup_groups" in st else {}),
                }
                for st in storages
            ]
        result.append(entry)
    return json.dumps(result)


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
    "list_backups": {
        "description": (
            "List a guest's backup archives (volid, storage, when taken, size, protected, notes, verification), "
            "the guest's effective backup defaults (storage, mode, compression) and the backup-capable storages "
            "on its node."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "guest_id": {"type": "integer", "description": "The ID of the guest (from list_guests, not the VMID)"},
            },
            "required": ["guest_id"],
        },
        "required_permission": None,
        "handler": _handle_list_backups,
    },
    "manage_backup": {
        "description": (
            "Create a backup of a guest, or delete / restore / protect / unprotect an existing archive. "
            "State-changing: the first call returns a confirmation-required preview without doing anything; call "
            "again with \"confirm\": true after the user approves. Restore REPLACES the guest and additionally "
            "requires confirm_name equal to the guest's exact name. Create falls back to the guest's configured "
            "storage/mode/compression when not given."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "guest_id": {"type": "integer", "description": "The ID of the guest (from list_guests, not the VMID)"},
                "action": {"type": "string", "enum": list(_BACKUP_ACTIONS), "description": "What to do"},
                "volid": {"type": "string", "description": "Archive volid from list_backups (delete/restore/protect/unprotect)"},
                "storage": {"type": "string", "description": "create: target storage (default: guest's configured storage)"},
                "mode": {"type": "string", "enum": list(_BACKUP_MODES), "description": "create: vzdump mode (default: configured)"},
                "compress": {"type": "string", "enum": list(_BACKUP_COMPRESS), "description": "create: compression (default: configured)"},
                "protected": {"type": "boolean", "description": "create: mark the new archive protected"},
                "notes": {"type": "string", "description": "create: notes for the new archive"},
                "confirm": {
                    "type": "boolean",
                    "description": "Set to true only after the user has explicitly confirmed the action.",
                },
                "confirm_name": {"type": "string", "description": "restore only: the guest's exact name, typed by the user"},
            },
            "required": ["guest_id", "action"],
        },
        "required_permission": "can_manage_guests",
        "handler": _handle_manage_backup,
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
