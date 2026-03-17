import json
import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)


def _serialize_guest(guest):
    """Serialize a Guest model to a dict for Claude."""
    return {
        "id": guest.id,
        "name": guest.name,
        "type": guest.guest_type,
        "ip": guest.ip_address,
        "status": guest.status,
        "power_state": guest.power_state,
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
    guests = user.accessible_guests()
    return json.dumps([_serialize_guest(g) for g in guests])


def _handle_get_guest_details(tool_input, user):
    from models import Guest
    guest = Guest.query.get(tool_input["guest_id"])
    if not guest:
        return json.dumps({"error": "Guest not found"})
    if not user.can_access_guest(guest):
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
    if not user.can_access_guest(guest):
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
        if svc.guest and user.can_access_guest(svc.guest):
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
    if not guest or not user.can_access_guest(guest):
        return json.dumps({"error": "Access denied"})

    action = tool_input.get("action", "restart")
    if action not in ("start", "stop", "restart"):
        return json.dumps({"error": f"Invalid action: {action}"})

    try:
        from core.scanner import service_action
        ok, msg = service_action(guest, svc, action)
        if ok:
            log_action("ai_service_control", "guest", resource_id=guest.id,
                       resource_name=guest.name,
                       details={"service": svc.service_name, "action": action, "via": "ai_assistant"})
            db.session.commit()
        return json.dumps({"success": ok, "message": msg})
    except Exception as e:
        logger.error("AI service control error: %s", e)
        return json.dumps({"error": str(e)})


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


def _handle_get_host_status(tool_input, user):
    from models import ProxmoxHost
    hosts = ProxmoxHost.query.all()
    result = []
    for host in hosts:
        result.append({
            "id": host.id,
            "name": host.name,
            "hostname": host.hostname,
            "type": host.host_type,
            "guest_count": len(host.guests),
        })
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
        "description": "Start, stop, or restart a service on a guest.",
        "input_schema": {
            "type": "object",
            "properties": {
                "service_id": {"type": "integer", "description": "The ID of the service to control"},
                "action": {
                    "type": "string",
                    "enum": ["start", "stop", "restart"],
                    "description": "The action to perform",
                },
            },
            "required": ["service_id", "action"],
        },
        "required_permission": "can_edit_services",
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
        "description": "List all Proxmox hosts with their type and guest counts.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
        "required_permission": "can_view_hosts",
        "handler": _handle_get_host_status,
    },
}


def get_tools_for_user(user):
    """Return Claude API tool definitions for tools the user has permission to use."""
    tools = []
    for name, defn in TOOL_REGISTRY.items():
        perm = defn["required_permission"]
        if perm is None or getattr(user, perm, False):
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
    perm = defn["required_permission"]
    if perm and not getattr(user, perm, False):
        return json.dumps({"error": f"Permission denied: {perm} required"})
    try:
        return defn["handler"](tool_input, user)
    except Exception as e:
        logger.error("Tool execution error (%s): %s", tool_name, e)
        return json.dumps({"error": f"Tool execution failed: {e}"})
