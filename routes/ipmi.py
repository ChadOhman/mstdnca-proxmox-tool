import json
import logging
from contextlib import contextmanager

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from auth.audit import log_action
from auth.credential_store import decrypt, encrypt
from models import HostMetricSnapshot, ProxmoxHost, Setting, db

logger = logging.getLogger(__name__)

bp = Blueprint("ipmi", __name__)

_VALID_POWER_ACTIONS = ("on", "off", "reset", "cycle", "graceful_shutdown")


@bp.before_request
@login_required
def _require_login():
    if not current_user.can_view_ipmi:
        flash("You don't have permission to view IPMI data.", "error")
        return redirect(url_for("dashboard.index"))


def _get_redfish_client(host):
    """Create a RedfishClient from a ProxmoxHost's IPMI config."""
    from clients.ipmi_client import RedfishClient

    if not host.ipmi_enabled or not host.ipmi_address:
        return None

    password = decrypt(host.ipmi_password) if host.ipmi_password else ""
    if not password:
        return None

    return RedfishClient(
        base_url=f"https://{host.ipmi_address}",
        username=host.ipmi_username or "",
        password=password,
        verify_ssl=host.ipmi_verify_ssl,
    )


@contextmanager
def _redfish_session(host):
    """Yield a RedfishClient for `host` (or None if IPMI isn't configured).

    Always logs the BMC session out on exit — a fresh RedfishClient is created per
    request, and without an explicit logout each request leaks a Redfish session on
    the BMC, eventually exhausting its (typically very small) session table.
    """
    client = _get_redfish_client(host)
    try:
        yield client
    finally:
        if client is not None:
            try:
                client.logout()
            except Exception:
                logger.debug("Failed to log out IPMI session for %s", host.name, exc_info=True)


@bp.route("/")
def index():
    """IPMI dashboard showing all IPMI-enabled hosts."""
    hosts = ProxmoxHost.query.filter_by(ipmi_enabled=True).all()

    host_data = []
    for host in hosts:
        snapshot = None
        with _redfish_session(host) as client:
            if client:
                try:
                    snapshot = client.get_health_snapshot()
                except Exception:
                    logger.debug("Failed to fetch IPMI data for %s", host.name, exc_info=True)

        host_data.append({
            "host": host,
            "snapshot": snapshot,
        })

    return render_template("ipmi.html", host_data=host_data)


@bp.route("/host/<int:host_id>")
def detail(host_id):
    """IPMI detail page for a single host."""
    host = ProxmoxHost.query.get_or_404(host_id)
    if not host.ipmi_enabled:
        flash("IPMI is not enabled for this host.", "warning")
        return redirect(url_for("ipmi.index"))

    snapshot = None
    sel_entries = []
    with _redfish_session(host) as client:
        if client:
            try:
                snapshot = client.get_health_snapshot()
            except Exception:
                logger.debug("Failed to fetch IPMI data for %s", host.name, exc_info=True)
            try:
                sel_entries = client.get_sel_entries()
            except Exception:
                logger.debug("Failed to fetch SEL for %s", host.name, exc_info=True)

    return render_template("ipmi_detail.html", host=host, snapshot=snapshot, sel_entries=sel_entries)


@bp.route("/host/<int:host_id>/power", methods=["POST"])
def power_action(host_id):
    """Execute a power action on a host via IPMI."""
    if not current_user.can_manage_ipmi:
        flash("You don't have permission to manage IPMI power.", "error")
        return redirect(url_for("ipmi.index"))

    host = ProxmoxHost.query.get_or_404(host_id)
    action = request.form.get("action", "").strip()

    if action not in _VALID_POWER_ACTIONS:
        flash(f"Invalid power action: {action}", "error")
        return redirect(url_for("ipmi.detail", host_id=host_id))

    with _redfish_session(host) as client:
        if not client:
            flash("IPMI is not configured for this host.", "error")
            return redirect(url_for("ipmi.detail", host_id=host_id))

        ok, msg = client.power_action(action)

    if ok:
        log_action(f"ipmi_power_{action}", "host", resource_id=host.id,
                   resource_name=host.name, details={"ipmi_address": host.ipmi_address})
        db.session.commit()
        flash(f"Power {action} command sent to {host.name}.", "success")
    else:
        flash(f"Power {action} failed for {host.name}: {msg}", "error")

    return redirect(url_for("ipmi.detail", host_id=host_id))


@bp.route("/host/<int:host_id>/test", methods=["POST"])
def test_connection(host_id):
    """Test IPMI connection to a host."""
    host = ProxmoxHost.query.get_or_404(host_id)
    with _redfish_session(host) as client:
        if not client:
            flash("IPMI is not configured for this host.", "error")
            return redirect(request.referrer or url_for("ipmi.index"))

        ok, msg = client.test_connection()

    if ok:
        flash(f"IPMI connection to {host.name} successful: {msg}", "success")
    else:
        flash(f"IPMI connection to {host.name} failed: {msg}", "error")

    return redirect(request.referrer or url_for("ipmi.index"))


@bp.route("/host/<int:host_id>/sel")
def sel(host_id):
    """System Event Log viewer for a host."""
    host = ProxmoxHost.query.get_or_404(host_id)
    if not host.ipmi_enabled:
        flash("IPMI is not enabled for this host.", "warning")
        return redirect(url_for("ipmi.index"))

    try:
        limit = min(int(request.args.get("limit", 500)), 2000)
    except (ValueError, TypeError):
        limit = 500

    entries = []
    with _redfish_session(host) as client:
        if client:
            try:
                entries = client.get_sel_entries(limit=limit)
            except Exception:
                logger.debug("Failed to fetch SEL for %s", host.name, exc_info=True)
                flash("Failed to fetch System Event Log.", "error")

    return render_template("ipmi_sel.html", host=host, entries=entries, limit=limit)


@bp.route("/api/host/<int:host_id>/metrics")
def metrics_api(host_id):
    """JSON endpoint for IPMI metrics (Prometheus first, SQLite fallback)."""
    host = ProxmoxHost.query.get_or_404(host_id)
    timeframe = request.args.get("timeframe", "day")

    # Try Prometheus IPMI exporter first
    if Setting.get("prometheus_enabled", "false") == "true":
        try:
            from clients.prometheus_query import PrometheusQueryClient
            prom = PrometheusQueryClient()
            # Multi-target exporter: instance label is the BMC IP
            target = host.ipmi_address or host.hostname
            data = prom.get_ipmi_metrics_exporter(target, timeframe)
            if data and data.get("snapshots"):
                return jsonify(data)
        except Exception:
            logger.debug("Prometheus IPMI query failed for host %s", host_id, exc_info=True)

    # Fallback to SQLite snapshots
    from datetime import datetime, timedelta, timezone

    _DURATIONS = {
        "hour": timedelta(hours=1),
        "day": timedelta(days=1),
        "3d": timedelta(days=3),
        "week": timedelta(weeks=1),
        "month": timedelta(days=30),
    }
    duration = _DURATIONS.get(timeframe, timedelta(days=1))
    since = datetime.now(timezone.utc) - duration

    rows = (
        HostMetricSnapshot.query
        .filter_by(host_id=host_id)
        .filter(HostMetricSnapshot.captured_at >= since)
        .order_by(HostMetricSnapshot.captured_at.asc())
        .all()
    )

    snapshots = []
    for row in rows:
        snap = {"captured_at": row.captured_at.isoformat()}
        if row.data:
            try:
                snap.update(json.loads(row.data))
            except (json.JSONDecodeError, TypeError):
                pass
        snapshots.append(snap)

    return jsonify({"snapshots": snapshots, "source": "sqlite"})


@bp.route("/api/host/<int:host_id>/prom-debug")
def prom_debug(host_id):
    """Return all IPMI metric names/labels from Prometheus for this host (debug)."""
    if not current_user.can_manage_hosts:
        return jsonify({"error": "forbidden"}), 403
    host = ProxmoxHost.query.get_or_404(host_id)
    if Setting.get("prometheus_enabled", "false") != "true":
        return jsonify({"error": "Prometheus not enabled"})
    try:
        from clients.prometheus_query import PrometheusQueryClient
        prom = PrometheusQueryClient()
        target = host.ipmi_address or host.hostname
        inst = f'instance="{target}"'
        # Query all ipmi_ metrics for this instance
        results = prom.query(f'{{__name__=~"ipmi_.*",{inst}}}')
        metrics = {}
        for r in results:
            name = r.get("metric", {}).get("__name__", "?")
            labels = {k: v for k, v in r.get("metric", {}).items() if k != "__name__"}
            value = r.get("value", [None, None])[1]
            metrics.setdefault(name, []).append({"labels": labels, "value": value})
        return jsonify({"target": target, "metrics": metrics})
    except Exception as e:
        return jsonify({"error": str(e)})


@bp.route("/host/<int:host_id>/configure", methods=["POST"])
def configure(host_id):
    """Update IPMI configuration for a host."""
    if not current_user.can_manage_hosts:
        flash("You don't have permission to manage hosts.", "error")
        return redirect(url_for("ipmi.index"))

    host = ProxmoxHost.query.get_or_404(host_id)

    host.ipmi_enabled = "ipmi_enabled" in request.form
    host.ipmi_address = request.form.get("ipmi_address", "").strip()
    host.ipmi_username = request.form.get("ipmi_username", "").strip()
    host.ipmi_verify_ssl = "ipmi_verify_ssl" in request.form

    new_password = request.form.get("ipmi_password", "").strip()
    if new_password:
        host.ipmi_password = encrypt(new_password)

    log_action("ipmi_configure", "host", resource_id=host.id,
               resource_name=host.name, details={"ipmi_address": host.ipmi_address})
    db.session.commit()

    flash(f"IPMI configuration updated for {host.name}.", "success")
    return redirect(request.referrer or url_for("ipmi.detail", host_id=host_id))
