import ipaddress
import logging
import re
from datetime import datetime, timedelta, timezone

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import or_

from auth.audit import log_action
from auth.credential_store import decrypt
from models import Setting, UnifiLogEntry, db

logger = logging.getLogger(__name__)

bp = Blueprint("unifi", __name__)

_LOGS_PER_PAGE = 50


@bp.before_request
@login_required
def _require_login():
    if not current_user.can_view_unifi:
        flash("You don't have permission to view network devices.", "error")
        return redirect(url_for("dashboard.index"))


def _get_unifi_client():
    """Return a cached UniFi client from saved settings."""
    from clients.unifi_client import get_cached_client

    base_url = Setting.get("unifi_base_url", "")
    username = Setting.get("unifi_username", "")
    encrypted_pw = Setting.get("unifi_password", "")
    site = Setting.get("unifi_site", "default")
    is_udm = Setting.get("unifi_is_udm", "true") == "true"
    verify_ssl = Setting.get("unifi_verify_ssl", "false") == "true"

    if not base_url or not username or not encrypted_pw:
        return None

    try:
        password = decrypt(encrypted_pw)
    except Exception:
        logger.warning(
            "Stored UniFi password could not be decrypted (was the secret key rotated?)",
            exc_info=True,
        )
        return None
    if not password:
        return None

    return get_cached_client(base_url, username, password, site=site, is_udm=is_udm, verify_ssl=verify_ssl)


def _filter_by_subnet(items, ip_key, subnet_str):
    """Filter a list of dicts by subnet on the given IP key."""
    if not subnet_str:
        return items
    try:
        network = ipaddress.ip_network(subnet_str, strict=False)
    except ValueError:
        return items
    filtered = []
    for item in items:
        ip = item.get(ip_key, "")
        if not ip:
            continue
        try:
            if ipaddress.ip_address(ip) in network:
                filtered.append(item)
        except ValueError:
            continue
    return filtered


def _get_accessible_ips(user):
    """Return a set of IP addresses for all guests this user can access."""
    guests = user.accessible_guests()
    return {g.ip_address for g in guests if g.ip_address}


def _get_accessible_networks(user):
    """Return set of UniFi network names accessible to user, or None if unrestricted.

    Returns None for super admins and for users whose tags have no network links
    configured (backwards compatible — no filtering until links are set up).
    Returns a set (possibly empty) once any tag-network links exist for the user.
    """
    if user.is_super_admin:
        return None
    networks = set()
    has_links = False
    for tag in user.allowed_tags:
        for n in tag.unifi_networks:
            networks.add(n.network_name)
            has_links = True
    if not has_links:
        return None  # No links configured yet: don't filter (backwards compatible)
    return networks


@bp.route("/")
def index():
    enabled = Setting.get("unifi_enabled", "false") == "true"
    if not enabled:
        return render_template("unifi.html", enabled=False, devices=[], clients=[], subnet_filter="",
                               chart_direction=[], chart_blocked=[])

    client = _get_unifi_client()
    if not client:
        flash("UniFi controller is not configured. Ask a super admin to set it up in Settings.", "warning")
        return render_template("unifi.html", enabled=False, devices=[], clients=[], subnet_filter="",
                               chart_direction=[], chart_blocked=[])

    devices = client.get_devices() or []
    clients = client.get_clients() or []
    health = client.get_site_health() or []
    Setting.set("unifi_last_polled", datetime.now(timezone.utc).isoformat())

    subnet_filter = Setting.get("unifi_filter_subnet", "")
    if subnet_filter:
        devices = _filter_by_subnet(devices, "ip", subnet_filter)
        clients = _filter_by_subnet(clients, "ip", subnet_filter)

    # Network-based access control: filter clients to networks linked to user's tags
    accessible_networks = _get_accessible_networks(current_user)
    network_restricted = accessible_networks is not None
    if accessible_networks is not None:
        clients = [c for c in clients if c.get("network", "") in accessible_networks]

    # Sort
    devices.sort(key=lambda d: d.get("name", "").lower())
    clients.sort(key=lambda c: c.get("hostname", "").lower())

    # Build chart data from recent log entries (last 24h)
    chart_direction = []
    chart_blocked = []
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    base_q = UnifiLogEntry.query.filter(UnifiLogEntry.timestamp >= since)
    if not current_user.is_super_admin:
        ips = _get_accessible_ips(current_user)
        if ips:
            base_q = base_q.filter(or_(
                UnifiLogEntry.src_ip.in_(ips),
                UnifiLogEntry.dst_ip.in_(ips),
            ))
        else:
            base_q = base_q.filter(False)

    from sqlalchemy import func
    direction_rows = (
        base_q.with_entities(UnifiLogEntry.direction, func.count().label("cnt"))
        .group_by(UnifiLogEntry.direction)
        .all()
    )
    chart_direction = [{"label": r.direction or "unknown", "count": r.cnt} for r in direction_rows]

    blocked_rows = (
        base_q.filter(UnifiLogEntry.action == "block", UnifiLogEntry.src_ip.isnot(None))
        .with_entities(UnifiLogEntry.src_ip, func.count().label("cnt"))
        .group_by(UnifiLogEntry.src_ip)
        .order_by(func.count().desc())
        .limit(10)
        .all()
    )
    chart_blocked = [{"ip": r.src_ip, "count": r.cnt} for r in blocked_rows]

    # Extract WAN health summary for status cards
    wan_health = {}
    for sub in health:
        if sub.get("subsystem") == "wan":
            wan_health = sub

    return render_template(
        "unifi.html",
        enabled=True,
        devices=devices,
        clients=clients,
        subnet_filter=subnet_filter,
        chart_direction=chart_direction,
        chart_blocked=chart_blocked,
        network_restricted=network_restricted,
        accessible_networks=sorted(accessible_networks) if accessible_networks is not None else None,
        health=health,
        wan_health=wan_health,
        unpoller_enabled=Setting.get("unpoller_enabled", "false") == "true",
    )


@bp.route("/logs")
def logs():
    # Filter parameters
    log_type = request.args.get("type", "")
    action = request.args.get("action", "")
    direction = request.args.get("direction", "")
    search = request.args.get("q", "").strip()
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1

    # Time range
    hours_str = request.args.get("hours", "24")
    try:
        hours = int(hours_str)
        if hours not in (1, 6, 24, 48, 168):
            hours = 24
    except ValueError:
        hours = 24

    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    q = UnifiLogEntry.query.filter(UnifiLogEntry.timestamp >= since)

    # Tag-based IP access control: non-super-admins see only traffic for their VMs
    access_restricted = False
    if not current_user.is_super_admin:
        ips = _get_accessible_ips(current_user)
        access_restricted = True
        if ips:
            q = q.filter(or_(
                UnifiLogEntry.src_ip.in_(ips),
                UnifiLogEntry.dst_ip.in_(ips),
            ))
        else:
            q = q.filter(False)

    if log_type:
        q = q.filter(UnifiLogEntry.log_type == log_type)
    if action:
        q = q.filter(UnifiLogEntry.action == action)
    if direction:
        q = q.filter(UnifiLogEntry.direction == direction)
    if search:
        like = f"%{search}%"
        q = q.filter(or_(
            UnifiLogEntry.src_ip.like(like),
            UnifiLogEntry.dst_ip.like(like),
            UnifiLogEntry.msg.like(like),
            UnifiLogEntry.rule_id.like(like),
            UnifiLogEntry.mac.like(like),
            UnifiLogEntry.country.like(like),
        ))

    total = q.count()
    entries = q.order_by(UnifiLogEntry.timestamp.desc()).paginate(
        page=page, per_page=_LOGS_PER_PAGE, error_out=False
    )

    return render_template(
        "unifi_logs.html",
        entries=entries,
        total=total,
        log_type=log_type,
        action=action,
        direction=direction,
        search=search,
        hours=hours,
        page=page,
        access_restricted=access_restricted,
    )


@bp.route("/restart/<mac>", methods=["POST"])
def restart(mac):
    if not current_user.can_restart_unifi:
        flash("You don't have permission to restart devices.", "error")
        return redirect(url_for("unifi.index"))

    client = _get_unifi_client()
    if not client:
        flash("UniFi controller not configured.", "error")
        return redirect(url_for("unifi.index"))

    ok, msg = client.restart_device(mac)
    if ok:
        log_action("unifi_device_restart", "unifi", resource_name=mac)
        db.session.commit()
        flash(f"Restart command sent to device {mac}.", "success")
    else:
        flash(f"Failed to restart device: {msg}", "error")

    return redirect(url_for("unifi.index"))


@bp.route("/refresh", methods=["POST"])
def refresh():
    return redirect(url_for("unifi.index"))


_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", re.IGNORECASE)


@bp.route("/device/<mac>")
def device_detail(mac):
    """Show detailed info for a single UniFi device."""
    if not _MAC_RE.match(mac):
        flash("Invalid MAC address format.", "error")
        return redirect(url_for("unifi.index"))

    client = _get_unifi_client()
    if not client:
        flash("UniFi controller not configured.", "error")
        return redirect(url_for("unifi.index"))

    devices = client.get_devices() or []
    device = next((d for d in devices if d.get("mac", "").lower() == mac.lower()), None)
    if not device:
        flash("Device not found.", "error")
        return redirect(url_for("unifi.index"))

    # Get clients connected to this device
    all_clients = client.get_clients() or []
    device_clients = [
        c for c in all_clients
        if (c.get("ap_mac") or "").lower() == mac.lower()
        or (c.get("sw_mac") or "").lower() == mac.lower()
    ]

    # Network access control
    accessible_networks = _get_accessible_networks(current_user)
    if accessible_networks is not None:
        device_clients = [c for c in device_clients if c.get("network", "") in accessible_networks]

    device_clients.sort(key=lambda c: c.get("hostname", "").lower())

    return render_template(
        "unifi_device.html",
        device=device,
        clients=device_clients,
        unpoller_enabled=Setting.get("unpoller_enabled", "false") == "true",
    )


@bp.route("/health")
def health():
    """Network health overview with WAN/LAN/WLAN status."""
    enabled = Setting.get("unifi_enabled", "false") == "true"
    if not enabled:
        flash("UniFi integration is not enabled.", "warning")
        return redirect(url_for("unifi.index"))

    client = _get_unifi_client()
    if not client:
        flash("UniFi controller not configured.", "error")
        return redirect(url_for("unifi.index"))

    health_data = client.get_site_health() or []
    wlan_conf = client.get_wlan_conf() or []
    port_fwd = client.get_port_forward_rules() or []
    firewall_rules = client.get_firewall_rules() or []

    # Separate subsystems for template
    subsystems = {}
    for sub in health_data:
        name = sub.get("subsystem", "")
        if name:
            subsystems[name] = sub

    # Normalize WAN fields — UDM uses different keys than legacy controllers
    # Multi-WAN setups may also have wan2 subsystem
    if "wan" in subsystems:
        wan = subsystems["wan"]
        logger.info("WAN health raw data: %s", {k: v for k, v in wan.items() if k != "subsystem"})
        # Latency: try multiple known key variants
        if not wan.get("latency"):
            for key in ("internet_latency", "wan1_latency", "latency_average"):
                if wan.get(key):
                    wan["latency"] = wan[key]
                    break
        # Uptime: try variants
        if not wan.get("uptime"):
            for key in ("wan_uptime", "gw_system-stats.uptime"):
                if wan.get(key):
                    wan["uptime"] = wan[key]
                    break
            # Nested gw_system_stats
            gw_stats = wan.get("gw_system-stats") or wan.get("gw_system_stats") or {}
            if not wan.get("uptime") and gw_stats.get("uptime"):
                wan["uptime"] = int(gw_stats["uptime"])
        # Speedtest: may use different naming
        if not wan.get("speedtest_lastrun_download"):
            wan["speedtest_lastrun_download"] = wan.get("xput_down")
        if not wan.get("speedtest_lastrun_upload"):
            wan["speedtest_lastrun_upload"] = wan.get("xput_up")
        # WAN IP
        if not wan.get("wan_ip"):
            wan["wan_ip"] = wan.get("gw") or wan.get("ip")
        # ISP
        if not wan.get("isp_name"):
            wan["isp_name"] = wan.get("isp_organization") or wan.get("ISP")

    return render_template(
        "unifi_health.html",
        subsystems=subsystems,
        health_data=health_data,
        wlan_conf=wlan_conf,
        port_fwd=port_fwd,
        firewall_rules=firewall_rules,
        unpoller_enabled=Setting.get("unpoller_enabled", "false") == "true",
    )


@bp.route("/traffic")
def traffic():
    """Traffic analysis page with DPI breakdown and daily bandwidth."""
    enabled = Setting.get("unifi_enabled", "false") == "true"
    if not enabled:
        flash("UniFi integration is not enabled.", "warning")
        return redirect(url_for("unifi.index"))

    client = _get_unifi_client()
    if not client:
        flash("UniFi controller not configured.", "error")
        return redirect(url_for("unifi.index"))

    dpi_raw = client.get_dpi_stats() or []
    daily_stats = client.get_daily_site_stats(days=7) or []

    # Parse DPI data — the API returns a list with one element containing by_cat/by_app
    dpi_categories = []
    if dpi_raw:
        by_cat = dpi_raw[0].get("by_cat", []) if dpi_raw else []
        for cat in by_cat:
            dpi_categories.append({
                "cat": cat.get("cat", 0),
                "app": cat.get("app", 0),
                "rx_bytes": cat.get("rx_bytes", 0),
                "tx_bytes": cat.get("tx_bytes", 0),
                "rx_packets": cat.get("rx_packets", 0),
                "tx_packets": cat.get("tx_packets", 0),
            })
        dpi_categories.sort(key=lambda x: x["rx_bytes"] + x["tx_bytes"], reverse=True)

    return render_template(
        "unifi_traffic.html",
        dpi_categories=dpi_categories,
        daily_stats=daily_stats,
        unpoller_enabled=Setting.get("unpoller_enabled", "false") == "true",
    )


@bp.route("/clients/history")
def client_history():
    """Show all known clients (historical), not just active."""
    enabled = Setting.get("unifi_enabled", "false") == "true"
    if not enabled:
        flash("UniFi integration is not enabled.", "warning")
        return redirect(url_for("unifi.index"))

    client = _get_unifi_client()
    if not client:
        flash("UniFi controller not configured.", "error")
        return redirect(url_for("unifi.index"))

    # Time window
    hours_str = request.args.get("hours", "24")
    try:
        hours = int(hours_str)
        if hours not in (24, 168, 720):
            hours = 24
    except ValueError:
        hours = 24

    search = request.args.get("q", "").strip().lower()

    all_clients = client.get_all_clients(within=hours) or []

    # Network access control
    accessible_networks = _get_accessible_networks(current_user)
    if accessible_networks is not None:
        all_clients = [c for c in all_clients if c.get("network", "") in accessible_networks]

    # Search filter
    if search:
        all_clients = [
            c for c in all_clients
            if search in (c.get("hostname", "") or "").lower()
            or search in (c.get("ip", "") or "").lower()
            or search in (c.get("mac", "") or "").lower()
            or search in (c.get("oui", "") or "").lower()
        ]

    all_clients.sort(key=lambda c: c.get("last_seen") or 0, reverse=True)

    return render_template(
        "unifi_clients_history.html",
        clients=all_clients,
        hours=hours,
        search=request.args.get("q", ""),
    )


@bp.route("/client/<mac>")
def client_detail(mac):
    """Per-client detail page with signal/satisfaction charts (requires unpoller)."""
    if not _MAC_RE.match(mac):
        flash("Invalid MAC address.", "error")
        return redirect(url_for("unifi.index"))

    unpoller_enabled = Setting.get("unpoller_enabled", "false") == "true"
    if not unpoller_enabled:
        flash("Per-client charts require Unpoller integration.", "warning")
        return redirect(url_for("unifi.index"))

    enabled = Setting.get("unifi_enabled", "false") == "true"
    if not enabled:
        flash("UniFi integration is not enabled.", "warning")
        return redirect(url_for("unifi.index"))

    client = _get_unifi_client()
    if not client:
        flash("UniFi controller not configured.", "error")
        return redirect(url_for("unifi.index"))

    # Find the client in the active client list
    all_clients = client.get_clients() or []
    target_client = None
    for c in all_clients:
        if (c.get("mac") or "").lower() == mac.lower():
            target_client = c
            break

    if not target_client:
        # Try historical clients
        history = client.get_all_clients(within=720) or []
        for c in history:
            if (c.get("mac") or "").lower() == mac.lower():
                target_client = c
                break

    if not target_client:
        flash("Client not found.", "warning")
        return redirect(url_for("unifi.index"))

    # Network access control
    accessible_networks = _get_accessible_networks(current_user)
    if accessible_networks is not None and target_client.get("network", "") not in accessible_networks:
        flash("You don't have access to this client's network.", "error")
        return redirect(url_for("unifi.index"))

    return render_template(
        "unifi_client_detail.html",
        client=target_client,
    )


@bp.route("/api/device/<mac>/chart")
def device_chart_data(mac):
    """Return Chart.js-ready JSON for device performance metrics from Prometheus.

    When unpoller is enabled, queries unpoller metrics first (richer data),
    falling back to mstdnca_unifi_* metrics.
    """
    if not _MAC_RE.match(mac):
        return jsonify({"error": "Invalid MAC"}), 400

    timeframe = request.args.get("timeframe", "day")
    device_name = request.args.get("name", "")
    try:
        from clients.prometheus_query import PrometheusQueryClient
        prom = PrometheusQueryClient()

        # Try unpoller first if enabled and device name provided
        if Setting.get("unpoller_enabled", "false") == "true" and device_name:
            data = prom.get_unpoller_device_history(device_name, timeframe=timeframe)
            if data.get("labels"):
                return jsonify(data)

        data = prom.get_unifi_device_history(mac, timeframe=timeframe)
        return jsonify(data)
    except ValueError:
        return jsonify({"error": "Prometheus not configured"}), 404
    except Exception as e:
        logger.debug("Device chart query failed: %s", e, exc_info=True)
        return jsonify({"error": "Query failed"}), 500


@bp.route("/api/site/chart")
def site_chart_data():
    """Return Chart.js-ready JSON for site-level metrics from Prometheus.

    When unpoller is enabled, queries unpoller metrics first (richer data).
    """
    site = Setting.get("unifi_site", "default")
    timeframe = request.args.get("timeframe", "day")
    try:
        from clients.prometheus_query import PrometheusQueryClient
        prom = PrometheusQueryClient()

        if Setting.get("unpoller_enabled", "false") == "true":
            data = prom.get_unpoller_site_history(timeframe=timeframe)
            if data.get("labels"):
                return jsonify(data)

        data = prom.get_unifi_site_history(site, timeframe=timeframe)
        return jsonify(data)
    except ValueError:
        return jsonify({"error": "Prometheus not configured"}), 404
    except Exception as e:
        logger.debug("Site chart query failed: %s", e, exc_info=True)
        return jsonify({"error": "Query failed"}), 500


@bp.route("/api/client/<mac>/chart")
def client_chart_data(mac):
    """Return Chart.js-ready JSON for per-client metrics from unpoller."""
    if not _MAC_RE.match(mac):
        return jsonify({"error": "Invalid MAC"}), 400
    if Setting.get("unpoller_enabled", "false") != "true":
        return jsonify({"error": "Unpoller not configured"}), 404

    timeframe = request.args.get("timeframe", "day")
    try:
        from clients.prometheus_query import PrometheusQueryClient
        prom = PrometheusQueryClient()
        data = prom.get_unpoller_client_history(mac, timeframe=timeframe)
        return jsonify(data)
    except ValueError:
        return jsonify({"error": "Prometheus not configured"}), 404
    except Exception as e:
        logger.debug("Client chart query failed: %s", e, exc_info=True)
        return jsonify({"error": "Query failed"}), 500


@bp.route("/api/device/<mac>/radio/<radio_name>/chart")
def radio_chart_data(mac, radio_name):
    """Return Chart.js-ready JSON for per-radio metrics from unpoller."""
    if not _MAC_RE.match(mac):
        return jsonify({"error": "Invalid MAC"}), 400
    if Setting.get("unpoller_enabled", "false") != "true":
        return jsonify({"error": "Unpoller not configured"}), 404

    device_name = request.args.get("name", "")
    if not device_name:
        return jsonify({"error": "Device name required"}), 400

    timeframe = request.args.get("timeframe", "day")
    try:
        from clients.prometheus_query import PrometheusQueryClient
        prom = PrometheusQueryClient()
        data = prom.get_unpoller_radio_history(device_name, radio_name, timeframe=timeframe)
        return jsonify(data)
    except ValueError:
        return jsonify({"error": "Prometheus not configured"}), 404
    except Exception as e:
        logger.debug("Radio chart query failed: %s", e, exc_info=True)
        return jsonify({"error": "Query failed"}), 500


@bp.route("/api/site/wan/chart")
def wan_chart_data():
    """Return Chart.js-ready JSON for WAN metrics from unpoller."""
    if Setting.get("unpoller_enabled", "false") != "true":
        return jsonify({"error": "Unpoller not configured"}), 404

    timeframe = request.args.get("timeframe", "day")
    try:
        from clients.prometheus_query import PrometheusQueryClient
        prom = PrometheusQueryClient()
        data = prom.get_unpoller_wan_history(timeframe=timeframe)
        return jsonify(data)
    except ValueError:
        return jsonify({"error": "Prometheus not configured"}), 404
    except Exception as e:
        logger.debug("WAN chart query failed: %s", e, exc_info=True)
        return jsonify({"error": "Query failed"}), 500


@bp.route("/api/site/dpi/chart")
def dpi_chart_data():
    """Return Chart.js-ready JSON for DPI category breakdown from unpoller."""
    if Setting.get("unpoller_enabled", "false") != "true":
        return jsonify({"error": "Unpoller not configured"}), 404

    timeframe = request.args.get("timeframe", "day")
    try:
        from clients.prometheus_query import PrometheusQueryClient
        prom = PrometheusQueryClient()
        data = prom.get_unpoller_dpi_history(timeframe=timeframe)
        return jsonify(data)
    except ValueError:
        return jsonify({"error": "Prometheus not configured"}), 404
    except Exception as e:
        logger.debug("DPI chart query failed: %s", e, exc_info=True)
        return jsonify({"error": "Query failed"}), 500
