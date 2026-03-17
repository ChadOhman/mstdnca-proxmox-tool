"""Mobile API v1 blueprint.

Versioned REST API for the iOS/Android mobile app.  All endpoints return JSON
with a consistent envelope.  Authentication uses JWT tokens issued by the
``/api/v1/auth/login`` endpoint.
"""

import hashlib
import json
import logging

from flask import Blueprint, jsonify, request
from flask_login import current_user

from auth.audit import log_action
from auth.jwt_auth import (
    check_api_rate_limit,
    create_access_token,
    create_refresh_token,
    decode_token,
    is_token_revoked,
    jwt_required,
    record_api_failed_login,
    revoke_token,
)
from auth.local_network import _get_client_ip
from models import Guest, ProxmoxHost, PushWebhook, Tag, db

logger = logging.getLogger(__name__)

bp = Blueprint("api_v1", __name__)

_MAX_PER_PAGE = 100
_DEFAULT_PER_PAGE = 50

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _error(code, message, status=400):
    return jsonify({"error": {"code": code, "message": message}}), status


def _paginate(query, page, per_page):
    """Apply offset/limit pagination and return (items, total)."""
    per_page = min(per_page, _MAX_PER_PAGE)
    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()
    return items, total


def _serialize_guest(guest):
    return {
        "id": guest.id,
        "name": guest.name,
        "vmid": guest.vmid,
        "guest_type": guest.guest_type,
        "status": guest.status,
        "power_state": guest.power_state,
        "ip_address": guest.ip_address,
        "reboot_required": guest.reboot_required,
        "auto_update": guest.auto_update,
        "last_scan": guest.last_scan.isoformat() if guest.last_scan else None,
        "pending_updates_count": len(guest.pending_updates()),
        "security_updates_count": len(guest.security_updates()),
        "tags": [{"id": t.id, "name": t.name, "color": t.color} for t in guest.tags],
        "host": {"id": guest.proxmox_host.id, "name": guest.proxmox_host.name} if guest.proxmox_host else None,
        "services": [
            {"name": s.service_name, "unit_name": s.unit_name, "status": s.status}
            for s in guest.services
        ],
    }


def _serialize_guest_detail(guest):
    """Extended serialization including updates and snapshot/backup info."""
    base = _serialize_guest(guest)
    base["updates"] = [
        {
            "package_name": u.package_name,
            "current_version": u.current_version,
            "available_version": u.available_version,
            "severity": u.severity,
        }
        for u in guest.pending_updates()
    ]
    return base


def _make_etag_response(data):
    """Create a JSON response with ETag support for conditional polling."""
    body = json.dumps(data, sort_keys=True, default=str)
    etag = hashlib.sha256(body.encode()).hexdigest()[:16]

    if_none_match = request.headers.get("If-None-Match", "").strip('" ')
    if if_none_match == etag:
        return "", 304

    resp = jsonify(data)
    resp.headers["ETag"] = f'"{etag}"'
    return resp


# ============================================================================
# Auth endpoints (no @jwt_required)
# ============================================================================


@bp.route("/auth/login", methods=["POST"])
def login():
    """Authenticate with username/password, receive JWT tokens."""
    ip = _get_client_ip()
    if check_api_rate_limit(ip):
        return _error("RATE_LIMITED", "Too many login attempts. Try again later.", 429)

    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return _error("BAD_REQUEST", "username and password are required.", 400)

    from models import User
    user = User.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        record_api_failed_login(ip)
        return _error("UNAUTHORIZED", "Invalid username or password.", 401)

    if not user.is_active:
        return _error("UNAUTHORIZED", "Account is disabled.", 401)

    access_token = create_access_token(user)
    refresh_token, _jti = create_refresh_token(user)

    log_action("api_login", "user", resource_id=user.id, resource_name=user.username)
    db.session.commit()

    return jsonify({
        "data": {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": {
                "id": user.id,
                "username": user.username,
                "display_name": user.display_name,
                "role": user.role,
                "timezone": user.timezone,
            },
        }
    })


@bp.route("/auth/refresh", methods=["POST"])
def refresh():
    """Exchange a valid refresh token for a new access token."""
    data = request.get_json(silent=True) or {}
    refresh_token = data.get("refresh_token", "")

    if not refresh_token:
        return _error("BAD_REQUEST", "refresh_token is required.", 400)

    import jwt as pyjwt
    try:
        payload = decode_token(refresh_token)
    except pyjwt.ExpiredSignatureError:
        return _error("TOKEN_EXPIRED", "Refresh token has expired.", 401)
    except pyjwt.InvalidTokenError:
        return _error("INVALID_TOKEN", "Invalid refresh token.", 401)

    if payload.get("type") != "refresh":
        return _error("INVALID_TOKEN", "Not a refresh token.", 401)

    jti = payload.get("jti")
    if not jti or is_token_revoked(jti):
        return _error("TOKEN_REVOKED", "Refresh token has been revoked.", 401)

    from models import User
    user = db.session.get(User, int(payload["sub"]))
    if not user or not user.is_active:
        return _error("UNAUTHORIZED", "User not found or inactive.", 401)

    access_token = create_access_token(user)
    return jsonify({"data": {"access_token": access_token}})


@bp.route("/auth/logout", methods=["POST"])
def logout():
    """Revoke a refresh token."""
    data = request.get_json(silent=True) or {}
    refresh_token = data.get("refresh_token", "")

    if not refresh_token:
        return _error("BAD_REQUEST", "refresh_token is required.", 400)

    from datetime import datetime
    from datetime import timezone as tz

    import jwt as pyjwt
    try:
        payload = decode_token(refresh_token)
    except (pyjwt.ExpiredSignatureError, pyjwt.InvalidTokenError):
        # Already expired or invalid — nothing to revoke
        return jsonify({"data": {"ok": True}})

    jti = payload.get("jti")
    if jti:
        exp = datetime.fromtimestamp(payload["exp"], tz=tz.utc)
        revoke_token(jti, exp)

    return jsonify({"data": {"ok": True}})


# ============================================================================
# User profile
# ============================================================================


@bp.route("/me")
@jwt_required
def me():
    """Return the authenticated user's profile and permissions."""
    from models import Role
    perms = {field: getattr(current_user, field) for field in Role.PERMISSION_FIELDS}
    return jsonify({
        "data": {
            "id": current_user.id,
            "username": current_user.username,
            "display_name": current_user.display_name,
            "role": current_user.role,
            "role_display": current_user.role_display,
            "timezone": current_user.timezone,
            "permissions": perms,
            "allowed_tags": [
                {"id": t.id, "name": t.name, "color": t.color}
                for t in current_user.allowed_tags
            ],
        }
    })


# ============================================================================
# Dashboard
# ============================================================================


@bp.route("/dashboard/summary")
@jwt_required
def dashboard_summary():
    """Aggregated dashboard stats with ETag support for efficient polling."""
    from core.dashboard_stats import get_dashboard_stats

    tag_filter = request.args.get("tag", None)
    result = get_dashboard_stats(current_user, tag_filter=tag_filter)

    return _make_etag_response({"data": result["stats"]})


@bp.route("/dashboard/alerts")
@jwt_required
def dashboard_alerts():
    """Actionable alerts: security updates, failed services, reboots needed."""
    guests = current_user.accessible_guests()

    security_updates = []
    reboots_required = []
    guests_with_errors = []
    failed_services = []

    for guest in guests:
        sec_count = len(guest.security_updates())
        if sec_count > 0:
            security_updates.append({"guest_id": guest.id, "guest_name": guest.name, "count": sec_count})

        if guest.reboot_required:
            reboots_required.append({"guest_id": guest.id, "guest_name": guest.name})

        if guest.status == "error":
            guests_with_errors.append({"guest_id": guest.id, "guest_name": guest.name})

        for svc in guest.services:
            if svc.status == "failed":
                failed_services.append({
                    "guest_id": guest.id,
                    "guest_name": guest.name,
                    "service": svc.service_name,
                    "unit_name": svc.unit_name,
                })

    return jsonify({
        "data": {
            "security_updates": security_updates,
            "failed_services": failed_services,
            "reboots_required": reboots_required,
            "guests_with_errors": guests_with_errors,
        }
    })


# ============================================================================
# Guests
# ============================================================================


@bp.route("/guests")
@jwt_required
def guest_list():
    """Paginated guest listing with filtering and access control."""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", _DEFAULT_PER_PAGE, type=int)
    tag_name = request.args.get("tag")
    status = request.args.get("status")
    power_state = request.args.get("power_state")
    search = request.args.get("search", "").strip()

    # Build query with access control
    if current_user.is_admin:
        query = Guest.query.filter_by(enabled=True)
    else:
        user_tag_ids = [t.id for t in current_user.allowed_tags]
        if not user_tag_ids:
            return jsonify({"data": [], "meta": {"page": page, "per_page": per_page, "total": 0}})
        query = Guest.query.filter_by(enabled=True).filter(
            Guest.tags.any(Tag.id.in_(user_tag_ids))
        )

    # Apply filters
    if tag_name:
        query = query.filter(Guest.tags.any(Tag.name == tag_name))
    if status:
        query = query.filter(Guest.status == status)
    if power_state:
        query = query.filter(Guest.power_state == power_state)
    if search:
        query = query.filter(Guest.name.ilike(f"%{search}%"))

    query = query.order_by(Guest.name)
    items, total = _paginate(query, page, per_page)

    return jsonify({
        "data": [_serialize_guest(g) for g in items],
        "meta": {"page": page, "per_page": per_page, "total": total},
    })


@bp.route("/guests/<int:guest_id>")
@jwt_required
def guest_detail(guest_id):
    """Detailed guest information including services and pending updates."""
    guest = db.session.get(Guest, guest_id)
    if not guest or not guest.enabled:
        return _error("NOT_FOUND", "Guest not found.", 404)

    if not current_user.can_access_guest(guest):
        return _error("FORBIDDEN", "Access denied.", 403)

    return jsonify({"data": _serialize_guest_detail(guest)})


@bp.route("/guests/<int:guest_id>/power", methods=["POST"])
@jwt_required
def guest_power(guest_id):
    """Execute a power action on a guest (start/stop/shutdown/reboot)."""
    if not current_user.can_manage_guests:
        return _error("FORBIDDEN", "Insufficient permissions.", 403)

    data = request.get_json(silent=True) or {}
    action = data.get("action", "")
    if action not in ("start", "shutdown", "stop", "reboot"):
        return _error("BAD_REQUEST", "action must be one of: start, shutdown, stop, reboot.", 400)

    guest = db.session.get(Guest, guest_id)
    if not guest or not guest.enabled:
        return _error("NOT_FOUND", "Guest not found.", 404)

    if not current_user.can_access_guest(guest):
        return _error("FORBIDDEN", "Access denied.", 403)

    if not guest.proxmox_host or not guest.vmid:
        return _error("BAD_REQUEST", "Guest is not linked to a Proxmox host.", 400)

    from clients.proxmox_api import ProxmoxClient
    client = ProxmoxClient(guest.proxmox_host)
    node = guest.proxmox_host.name

    found_node = client.find_guest_node(guest.vmid)
    if found_node:
        node = found_node

    if action == "start":
        ok, msg = client.start_guest(node, guest.vmid, guest.guest_type)
    elif action == "shutdown":
        ok, msg = client.shutdown_guest(node, guest.vmid, guest.guest_type)
    elif action == "stop":
        ok, msg = client.stop_guest(node, guest.vmid, guest.guest_type)
    else:
        ok, msg = client.reboot_guest(node, guest.vmid, guest.guest_type)

    if ok:
        if action == "start":
            guest.power_state = "running"
        elif action in ("shutdown", "stop"):
            guest.power_state = "stopped"
        log_action("guest_power", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"action": action, "source": "api"})
        db.session.commit()
        return jsonify({"data": {"ok": True, "message": f"{action.capitalize()} command sent."}})

    logger.warning("Power %s failed for guest %s (vmid %s): %s", action, guest.name, guest.vmid, msg)
    return _error("POWER_FAILED", f"Power {action} failed.", 500)


# ============================================================================
# Hosts
# ============================================================================


@bp.route("/hosts")
@jwt_required
def host_list():
    """List all Proxmox hosts with guest counts."""
    if not current_user.can_view_hosts:
        return _error("FORBIDDEN", "Insufficient permissions.", 403)

    hosts = ProxmoxHost.query.order_by(ProxmoxHost.name).all()
    data = []
    for h in hosts:
        guest_count = Guest.query.filter_by(proxmox_host_id=h.id, enabled=True).count()
        data.append({
            "id": h.id,
            "name": h.name,
            "hostname": h.hostname,
            "port": h.port,
            "host_type": h.host_type,
            "guest_count": guest_count,
        })

    return jsonify({"data": data})


@bp.route("/hosts/<int:host_id>")
@jwt_required
def host_detail(host_id):
    """Host detail with live stats from Proxmox."""
    if not current_user.can_view_hosts:
        return _error("FORBIDDEN", "Insufficient permissions.", 403)

    host = db.session.get(ProxmoxHost, host_id)
    if not host:
        return _error("NOT_FOUND", "Host not found.", 404)

    data = {
        "id": host.id,
        "name": host.name,
        "hostname": host.hostname,
        "port": host.port,
        "host_type": host.host_type,
        "verify_ssl": host.verify_ssl,
    }

    # Try to fetch live stats from Proxmox
    if not host.is_pbs:
        try:
            from clients.proxmox_api import ProxmoxClient
            client = ProxmoxClient(host)
            nodes = client.get_nodes()
            for node in nodes:
                if node.get("node") == host.name:
                    data["live_stats"] = {
                        "cpu": node.get("cpu"),
                        "maxcpu": node.get("maxcpu"),
                        "mem": node.get("mem"),
                        "maxmem": node.get("maxmem"),
                        "uptime": node.get("uptime"),
                        "status": node.get("status"),
                    }
                    break
        except Exception as e:
            logger.debug("Failed to fetch live stats for host %s: %s", host.name, e)

    return jsonify({"data": data})


# ============================================================================
# Services
# ============================================================================


@bp.route("/services")
@jwt_required
def service_list():
    """All monitored services grouped by guest."""
    if not current_user.can_view_services:
        return _error("FORBIDDEN", "Insufficient permissions.", 403)

    guests = current_user.accessible_guests()
    data = []
    for guest in guests:
        if not guest.services:
            continue
        data.append({
            "guest_id": guest.id,
            "guest_name": guest.name,
            "services": [
                {
                    "id": s.id,
                    "name": s.service_name,
                    "unit_name": s.unit_name,
                    "port": s.port,
                    "status": s.status,
                    "last_checked": s.last_checked.isoformat() if s.last_checked else None,
                }
                for s in guest.services
            ],
        })

    return jsonify({"data": data})


# ============================================================================
# Push Webhook Management
# ============================================================================


@bp.route("/push")
@jwt_required
def push_list():
    """List the authenticated user's push webhook registrations."""
    webhooks = PushWebhook.query.filter_by(user_id=current_user.id).all()
    return jsonify({
        "data": [
            {
                "id": wh.id,
                "url": wh.url,
                "device_token": wh.device_token[:8] + "...",  # redact
                "platform": wh.platform,
                "events": json.loads(wh.events),
                "created_at": wh.created_at.isoformat() if wh.created_at else None,
            }
            for wh in webhooks
        ]
    })


@bp.route("/push/register", methods=["POST"])
@jwt_required
def push_register():
    """Register a device for push notifications."""
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    device_token = (data.get("device_token") or "").strip()
    platform = (data.get("platform") or "").strip().lower()
    events = data.get("events", [])

    if not url or not device_token or not platform:
        return _error("BAD_REQUEST", "url, device_token, and platform are required.", 400)

    if platform not in ("ios", "android"):
        return _error("BAD_REQUEST", "platform must be 'ios' or 'android'.", 400)

    if not isinstance(events, list) or not events:
        return _error("BAD_REQUEST", "events must be a non-empty list.", 400)

    invalid = set(events) - PushWebhook.VALID_EVENTS
    if invalid:
        return _error("BAD_REQUEST", f"Invalid events: {', '.join(sorted(invalid))}", 400)

    # Upsert: replace existing registration for same device_token + user
    existing = PushWebhook.query.filter_by(
        user_id=current_user.id, device_token=device_token,
    ).first()

    if existing:
        existing.url = url
        existing.platform = platform
        existing.events = json.dumps(sorted(events))
    else:
        wh = PushWebhook(
            user_id=current_user.id,
            url=url,
            device_token=device_token,
            platform=platform,
            events=json.dumps(sorted(events)),
        )
        db.session.add(wh)

    db.session.commit()
    return jsonify({"data": {"ok": True}}), 201


@bp.route("/push/<int:webhook_id>", methods=["DELETE"])
@jwt_required
def push_delete(webhook_id):
    """Unregister a push webhook (own registrations only)."""
    wh = db.session.get(PushWebhook, webhook_id)
    if not wh:
        return _error("NOT_FOUND", "Webhook not found.", 404)

    if wh.user_id != current_user.id:
        return _error("FORBIDDEN", "Access denied.", 403)

    db.session.delete(wh)
    db.session.commit()
    return jsonify({"data": {"ok": True}})
