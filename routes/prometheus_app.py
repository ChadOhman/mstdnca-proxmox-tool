"""
Prometheus application management blueprint.

Provides settings, install, upgrade, and connection test routes following the
same pattern as routes/jitsi.py.
"""

import logging
import threading as _threading
from datetime import datetime, timezone

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from auth.audit import log_action
from models import ExporterInstance, Guest, HostExporterInstance, ProxmoxHost, Setting, db


def _parse_iso(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


_install_job = {"running": False, "success": None, "log": []}
_upgrade_job = {"running": False, "success": None, "log": []}
_preflight_job = {"running": False, "success": None, "log": []}
_exporter_install_job = {"running": False, "success": None, "log": [], "instance_id": None}
_exporter_uninstall_job = {"running": False, "success": None, "log": [], "instance_id": None}
_host_exporter_install_job = {"running": False, "success": None, "log": [], "instance_id": None}
_host_exporter_uninstall_job = {"running": False, "success": None, "log": [], "instance_id": None}

logger = logging.getLogger(__name__)

bp = Blueprint("prometheus_app", __name__)


@bp.before_request
@login_required
def _require_login():
    if not current_user.can_update:
        flash("'Apply Updates' permission required.", "error")
        return redirect(url_for("dashboard.index"))


def _get_settings():
    return {
        "guest_id": Setting.get("prometheus_guest_id", ""),
        "url": Setting.get("prometheus_url", ""),
        "auth_token": Setting.get("prometheus_auth_token", ""),
        "enabled": Setting.get("prometheus_enabled", "false") == "true",
        "auto_upgrade": Setting.get("prometheus_auto_upgrade", "false"),
        "current_version": Setting.get("prometheus_current_version", ""),
        "latest_version": Setting.get("prometheus_latest_version", ""),
        "update_available": Setting.get("prometheus_update_available", "") == "true",
        "installed": Setting.get("prometheus_installed", "") == "true",
        "retention_days": Setting.get("prometheus_retention_days", "365"),
        "protection_type": Setting.get("prometheus_protection_type", "snapshot"),
        "backup_storage": Setting.get("prometheus_backup_storage", ""),
        "backup_mode": Setting.get("prometheus_backup_mode", "snapshot"),
        "mstdnca_metrics_url": Setting.get("prometheus_mstdnca_metrics_url", ""),
        "last_install_at": _parse_iso(Setting.get("prometheus_last_install_at", "")),
        "last_install_status": Setting.get("prometheus_last_install_status", ""),
        "last_install_log": Setting.get("prometheus_last_install_log", ""),
        "last_upgrade_at": _parse_iso(Setting.get("prometheus_last_upgrade_at", "")),
        "last_upgrade_status": Setting.get("prometheus_last_upgrade_status", ""),
        "last_upgrade_log": Setting.get("prometheus_last_upgrade_log", ""),
    }


@bp.route("/manage")
def manage():
    settings = _get_settings()
    guests = Guest.query.filter_by(enabled=True).order_by(Guest.name).all()

    backup_storages = []
    snapshots_supported = True

    guest_id = settings.get("guest_id", "")
    if guest_id:
        try:
            g = Guest.query.get(int(guest_id))
            if g and g.proxmox_host and not g.proxmox_host.is_pbs:
                from clients.proxmox_api import ProxmoxClient
                client = ProxmoxClient(g.proxmox_host)
                node = client.find_guest_node(g.vmid)
                if node:
                    backup_storages = client.list_node_storages(node, content_type="backup")
                    if not client.guest_supports_snapshot(node, g.vmid, g.guest_type):
                        snapshots_supported = False
        except Exception as e:
            logger.warning("Could not check snapshot/backup support: %s", e)

    from apps.exporters import BUILTIN_EXPORTERS, KNOWN_EXPORTERS
    exporter_instances = ExporterInstance.query.join(Guest).order_by(Guest.name).all()
    hosts = ProxmoxHost.query.order_by(ProxmoxHost.name).all()
    host_exporter_instances = HostExporterInstance.query.join(ProxmoxHost).order_by(ProxmoxHost.name).all()

    # Check Mastodon built-in exporter status and current config
    mastodon_guest_id = Setting.get("mastodon_guest_id", "")
    mastodon_exporter_status = "not_configured"
    mastodon_exporter_config = {}
    if mastodon_guest_id:
        masto_exp = ExporterInstance.query.filter_by(
            guest_id=int(mastodon_guest_id), exporter_type="mastodon", status="installed"
        ).first()
        mastodon_exporter_status = "enabled" if masto_exp else "disabled"
        if masto_exp and masto_exp.config:
            mastodon_exporter_config = masto_exp.config

    return render_template(
        "prometheus.html",
        settings=settings,
        guests=guests,
        backup_storages=backup_storages,
        snapshots_supported=snapshots_supported,
        exporter_instances=exporter_instances,
        known_exporters=KNOWN_EXPORTERS,
        builtin_exporters=BUILTIN_EXPORTERS,
        mastodon_exporter_status=mastodon_exporter_status,
        mastodon_exporter_config=mastodon_exporter_config,
        hosts=hosts,
        host_exporter_instances=host_exporter_instances,
    )


@bp.route("/save", methods=["POST"])
def save():
    Setting.set("prometheus_guest_id", request.form.get("prometheus_guest_id", "").strip())
    Setting.set("prometheus_url", request.form.get("prometheus_url", "").strip())
    Setting.set("prometheus_auth_token", request.form.get("prometheus_auth_token", "").strip())
    Setting.set("prometheus_enabled",
                "true" if "prometheus_enabled" in request.form else "false")
    Setting.set("prometheus_auto_upgrade",
                "true" if "prometheus_auto_upgrade" in request.form else "false")
    Setting.set("prometheus_mstdnca_metrics_url",
                request.form.get("prometheus_mstdnca_metrics_url", "").strip())

    retention = request.form.get("prometheus_retention_days", "365").strip()
    try:
        retention = str(max(1, int(retention)))
    except (ValueError, TypeError):
        retention = "365"
    Setting.set("prometheus_retention_days", retention)

    protection_type = request.form.get("prometheus_protection_type", "snapshot")
    Setting.set("prometheus_protection_type",
                protection_type if protection_type in ("snapshot", "backup") else "snapshot")
    Setting.set("prometheus_backup_storage",
                request.form.get("prometheus_backup_storage", "").strip())
    backup_mode = request.form.get("prometheus_backup_mode", "snapshot")
    Setting.set("prometheus_backup_mode",
                backup_mode if backup_mode in ("snapshot", "suspend", "stop") else "snapshot")

    log_action("prometheus_config_save", "settings", resource_name="prometheus")
    db.session.commit()
    flash("Prometheus settings saved.", "success")
    return redirect(url_for("prometheus_app.manage"))


@bp.route("/check", methods=["POST"])
def check():
    from apps.prometheus_app import check_prometheus_release

    update_available, latest, release_url = check_prometheus_release()
    current = Setting.get("prometheus_current_version", "")

    if not latest:
        flash("Could not fetch latest Prometheus version.", "error")
    elif update_available:
        flash(f"Prometheus update available: v{current} \u2192 v{latest}", "warning")
    elif current:
        flash(f"Prometheus is up to date (v{current}).", "success")
    else:
        flash(f"Latest Prometheus version: v{latest}. Set your current version to enable update detection.", "info")

    db.session.commit()
    return redirect(url_for("prometheus_app.manage"))


@bp.route("/test-connection", methods=["POST"])
def test_connection():
    prom_url = Setting.get("prometheus_url", "")
    if not prom_url:
        return jsonify({"ok": False, "error": "Prometheus URL is not configured"})

    try:
        from clients.prometheus_query import PrometheusQueryClient
        client = PrometheusQueryClient(base_url=prom_url)
        ok = client.check_connection()
        if ok:
            return jsonify({"ok": True, "message": "Connection successful"})
        return jsonify({"ok": False, "error": "Prometheus is not reachable"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@bp.route("/detect-versions", methods=["POST"])
def detect_versions():
    from apps.prometheus_app import detect_prometheus_version

    guest_id = Setting.get("prometheus_guest_id", "")
    if not guest_id:
        flash("Prometheus guest is not configured.", "warning")
        return redirect(url_for("prometheus_app.manage"))

    try:
        guest = Guest.query.get(int(guest_id))
    except (TypeError, ValueError):
        flash("Invalid guest ID.", "error")
        return redirect(url_for("prometheus_app.manage"))

    if not guest:
        flash("Guest not found.", "error")
        return redirect(url_for("prometheus_app.manage"))

    version, error = detect_prometheus_version(guest)
    if version:
        Setting.set("prometheus_current_version", version)
        if Setting.get("prometheus_installed") != "true":
            Setting.set("prometheus_installed", "true")
        db.session.commit()
        flash(f"Detected Prometheus version: {version}", "success")
    else:
        if Setting.get("prometheus_installed") == "true":
            Setting.set("prometheus_installed", "false")
            Setting.set("prometheus_current_version", "")
            db.session.commit()
            flash(f"Prometheus not found on guest: {error}. Marked as not installed.", "warning")
        else:
            flash(f"Could not detect Prometheus version: {error}", "warning")

    return redirect(url_for("prometheus_app.manage"))


@bp.route("/install/status")
def install_status():
    return jsonify({
        "running": _install_job["running"],
        "success": _install_job["success"],
        "log": _install_job["log"],
    })


@bp.route("/upgrade/status")
def upgrade_status():
    return jsonify({
        "running": _upgrade_job["running"],
        "success": _upgrade_job["success"],
        "log": _upgrade_job["log"],
    })


@bp.route("/preflight/status")
def preflight_status():
    return jsonify({
        "running": _preflight_job["running"],
        "success": _preflight_job["success"],
        "log": _preflight_job["log"],
    })


@bp.route("/preflight", methods=["POST"])
def preflight():
    from flask import current_app

    from apps.prometheus_app import run_prometheus_preflight

    if _install_job["running"] or _upgrade_job["running"]:
        return jsonify({"error": "An operation is already in progress"}), 409
    if _preflight_job["running"]:
        return jsonify({"error": "A pre-flight check is already in progress"}), 409

    _preflight_job.update({"running": True, "success": None, "log": []})

    def _cb(msg):
        _preflight_job["log"].append(msg)

    _app = current_app._get_current_object()

    def _bg():
        ok = False
        try:
            with _app.app_context():
                ok, _ = run_prometheus_preflight(log_callback=_cb)
        except Exception as e:
            _cb(f"FATAL ERROR: {e}")
            ok = False
        _preflight_job["running"] = False
        _preflight_job["success"] = ok

    try:
        import gevent as _gevent
        _gevent.spawn(_bg)
    except ImportError:
        _threading.Thread(target=_bg, daemon=True).start()

    return jsonify({"started": True})


@bp.route("/install", methods=["POST"])
def install():
    from flask import current_app

    from apps.prometheus_app import run_prometheus_install

    if _install_job["running"] or _upgrade_job["running"] or _preflight_job["running"]:
        flash("An operation is already in progress.", "warning")
        return redirect(url_for("prometheus_app.manage"))

    _install_job.update({"running": True, "success": None, "log": []})

    def _cb(msg):
        _install_job["log"].append(msg)

    _app = current_app._get_current_object()

    def _bg():
        from core.notifier import send_upgrade_result_notification, send_upgrade_started_notification
        ok = False
        try:
            with _app.app_context():
                send_upgrade_started_notification("prometheus", "", "manual")
                ok, _ = run_prometheus_install(log_callback=_cb)
        except Exception as e:
            _cb(f"FATAL ERROR: {e}")
            ok = False
        _install_job["running"] = False
        _install_job["success"] = ok
        with _app.app_context():
            send_upgrade_result_notification("prometheus", "", ok, "manual")
            now = datetime.now(timezone.utc).isoformat()
            Setting.set("prometheus_last_install_at", now)
            Setting.set("prometheus_last_install_status", "success" if ok else "error")
            Setting.set("prometheus_last_install_log", "\n".join(_install_job["log"]))
            if ok:
                Setting.set("prometheus_installed", "true")
            log_action("prometheus_install", "settings", resource_name="prometheus",
                       details={"status": "success" if ok else "error"})
            db.session.commit()

    try:
        import gevent as _gevent
        _gevent.spawn(_bg)
    except ImportError:
        _threading.Thread(target=_bg, daemon=True).start()

    return redirect(url_for("prometheus_app.manage"))


@bp.route("/upgrade", methods=["POST"])
def upgrade():
    from flask import current_app

    from apps.prometheus_app import run_prometheus_upgrade

    if _install_job["running"] or _upgrade_job["running"] or _preflight_job["running"]:
        flash("An operation is already in progress.", "warning")
        return redirect(url_for("prometheus_app.manage"))

    _upgrade_job.update({"running": True, "success": None, "log": []})

    def _cb(msg):
        _upgrade_job["log"].append(msg)

    _app = current_app._get_current_object()

    def _bg():
        from core.notifier import send_upgrade_result_notification, send_upgrade_started_notification
        ok = False
        try:
            with _app.app_context():
                send_upgrade_started_notification("prometheus", "", "manual")
                ok, _ = run_prometheus_upgrade(log_callback=_cb)
        except Exception as e:
            _cb(f"FATAL ERROR: {e}")
            ok = False
        _upgrade_job["running"] = False
        _upgrade_job["success"] = ok
        with _app.app_context():
            send_upgrade_result_notification("prometheus", "", ok, "manual")
            now = datetime.now(timezone.utc).isoformat()
            Setting.set("prometheus_last_upgrade_at", now)
            Setting.set("prometheus_last_upgrade_status", "success" if ok else "error")
            Setting.set("prometheus_last_upgrade_log", "\n".join(_upgrade_job["log"]))
            log_action("prometheus_upgrade", "settings", resource_name="prometheus",
                       details={"status": "success" if ok else "error"})
            db.session.commit()

    try:
        import gevent as _gevent
        _gevent.spawn(_bg)
    except ImportError:
        _threading.Thread(target=_bg, daemon=True).start()

    return redirect(url_for("prometheus_app.manage"))


# ---------------------------------------------------------------------------
# Exporter management routes
# ---------------------------------------------------------------------------

@bp.route("/exporters")
def exporters_list():
    from apps.exporters import KNOWN_EXPORTERS
    instances = ExporterInstance.query.join(Guest).order_by(Guest.name).all()
    return jsonify({"exporters": [
        {
            "id": e.id,
            "guest_id": e.guest_id,
            "guest_name": e.guest.name,
            "exporter_type": e.exporter_type,
            "display_name": KNOWN_EXPORTERS.get(e.exporter_type, {}).get("display_name", e.exporter_type),
            "port": e.port,
            "version": e.version,
            "status": e.status,
        }
        for e in instances
    ]})


@bp.route("/exporters/add", methods=["POST"])
def exporter_add():
    from apps.exporters import KNOWN_EXPORTERS

    data = request.form if request.form else (request.get_json(silent=True) or {})
    guest_id = data.get("guest_id", "")
    exporter_type = data.get("exporter_type", "")
    port = data.get("port", "")

    if exporter_type not in KNOWN_EXPORTERS or KNOWN_EXPORTERS[exporter_type].get("builtin"):
        flash("Invalid exporter type.", "error")
        return redirect(url_for("prometheus_app.manage"))

    if not guest_id:
        flash("Please select a guest.", "error")
        return redirect(url_for("prometheus_app.manage"))

    try:
        guest = Guest.query.get(int(guest_id))
    except (TypeError, ValueError):
        flash("Invalid guest ID.", "error")
        return redirect(url_for("prometheus_app.manage"))

    if not guest:
        flash("Guest not found.", "error")
        return redirect(url_for("prometheus_app.manage"))

    info = KNOWN_EXPORTERS[exporter_type]
    try:
        port_int = int(port) if port else info["default_port"]
    except (TypeError, ValueError):
        port_int = info["default_port"]

    # Check for duplicate
    existing = ExporterInstance.query.filter_by(
        guest_id=guest.id, exporter_type=exporter_type
    ).filter(ExporterInstance.status != "removed").first()
    if existing:
        flash(f"{info['display_name']} already exists on {guest.name}.", "warning")
        return redirect(url_for("prometheus_app.manage"))

    # Parse env var config for exporters that require it
    config = None
    if info.get("requires_config") and info.get("env_vars"):
        config = {}
        for var in info["env_vars"]:
            val = data.get(f"config_{var}", "").strip()
            if val:
                config[var] = val
        if not config:
            config = None

    instance = ExporterInstance(
        guest_id=guest.id,
        exporter_type=exporter_type,
        port=port_int,
        config=config,
        status="pending",
    )
    db.session.add(instance)
    log_action("exporter_add", "guest", resource_id=guest.id, resource_name=guest.name,
               details={"exporter_type": exporter_type, "port": port_int})
    db.session.commit()

    flash(f"{info['display_name']} added for {guest.name}. Click Install to deploy.", "success")
    return redirect(url_for("prometheus_app.manage"))


@bp.route("/exporters/<int:instance_id>/install", methods=["POST"])
def exporter_install(instance_id):
    if _exporter_install_job["running"] or _exporter_uninstall_job["running"]:
        return jsonify({"error": "Another exporter operation is already running."}), 409

    instance = ExporterInstance.query.get_or_404(instance_id)

    _exporter_install_job["running"] = True
    _exporter_install_job["success"] = None
    _exporter_install_job["log"] = []
    _exporter_install_job["instance_id"] = instance_id

    from flask import current_app
    _app = current_app._get_current_object()
    _guest_id = instance.guest_id
    _guest_name = instance.guest.name
    _etype = instance.exporter_type

    def _bg():
        from apps.exporters import run_exporter_install
        from core.notifier import send_exporter_notification
        def _cb(msg):
            _exporter_install_job["log"].append(msg)
        try:
            with _app.app_context():
                ok, _ = run_exporter_install(instance_id, log_callback=_cb)
        except Exception as e:
            _cb(f"FATAL ERROR: {e}")
            ok = False
        _exporter_install_job["running"] = False
        _exporter_install_job["success"] = ok
        with _app.app_context():
            send_exporter_notification("install", _etype, _guest_name, ok)
            log_action("exporter_install", "guest", resource_id=_guest_id,
                       resource_name=_guest_name,
                       details={"exporter_type": _etype, "status": "success" if ok else "error"})
            db.session.commit()

    _threading.Thread(target=_bg, daemon=True).start()
    return jsonify({"started": True})


@bp.route("/exporters/install/status")
def exporter_install_status():
    return jsonify({
        "running": _exporter_install_job["running"],
        "success": _exporter_install_job["success"],
        "log": _exporter_install_job["log"],
        "instance_id": _exporter_install_job["instance_id"],
    })


@bp.route("/exporters/<int:instance_id>/uninstall", methods=["POST"])
def exporter_uninstall(instance_id):
    if _exporter_install_job["running"] or _exporter_uninstall_job["running"]:
        return jsonify({"error": "Another exporter operation is already running."}), 409

    instance = ExporterInstance.query.get_or_404(instance_id)

    _exporter_uninstall_job["running"] = True
    _exporter_uninstall_job["success"] = None
    _exporter_uninstall_job["log"] = []
    _exporter_uninstall_job["instance_id"] = instance_id

    from flask import current_app
    _app = current_app._get_current_object()
    _guest_id = instance.guest_id
    _guest_name = instance.guest.name
    _etype = instance.exporter_type

    def _bg():
        from apps.exporters import run_exporter_uninstall
        from core.notifier import send_exporter_notification
        def _cb(msg):
            _exporter_uninstall_job["log"].append(msg)
        try:
            with _app.app_context():
                ok, _ = run_exporter_uninstall(instance_id, log_callback=_cb)
        except Exception as e:
            _cb(f"FATAL ERROR: {e}")
            ok = False
        _exporter_uninstall_job["running"] = False
        _exporter_uninstall_job["success"] = ok
        with _app.app_context():
            send_exporter_notification("uninstall", _etype, _guest_name, ok)
            log_action("exporter_uninstall", "guest", resource_id=_guest_id,
                       resource_name=_guest_name,
                       details={"exporter_type": _etype, "status": "success" if ok else "error"})
            db.session.commit()

    _threading.Thread(target=_bg, daemon=True).start()
    return jsonify({"started": True})


@bp.route("/exporters/uninstall/status")
def exporter_uninstall_status():
    return jsonify({
        "running": _exporter_uninstall_job["running"],
        "success": _exporter_uninstall_job["success"],
        "log": _exporter_uninstall_job["log"],
        "instance_id": _exporter_uninstall_job["instance_id"],
    })


@bp.route("/exporters/<int:instance_id>/delete", methods=["POST"])
def exporter_delete(instance_id):
    instance = ExporterInstance.query.get_or_404(instance_id)
    if instance.status == "installed":
        flash("Uninstall the exporter before deleting.", "error")
        return redirect(url_for("prometheus_app.manage"))

    guest_name = instance.guest.name
    etype = instance.exporter_type
    log_action("exporter_delete", "guest", resource_id=instance.guest_id, resource_name=guest_name,
               details={"exporter_type": etype})
    db.session.delete(instance)
    db.session.commit()
    flash(f"Exporter entry removed for {guest_name}.", "success")
    return redirect(url_for("prometheus_app.manage"))


@bp.route("/exporters/<int:instance_id>/config", methods=["POST"])
def exporter_update_config(instance_id):
    from apps.exporters import KNOWN_EXPORTERS

    instance = ExporterInstance.query.get_or_404(instance_id)
    if instance.status == "installed":
        flash("Uninstall the exporter before changing its configuration.", "error")
        return redirect(url_for("prometheus_app.manage"))

    info = KNOWN_EXPORTERS.get(instance.exporter_type, {})
    env_vars = info.get("env_vars", [])
    if not env_vars:
        flash("This exporter does not require configuration.", "warning")
        return redirect(url_for("prometheus_app.manage"))

    data = request.form if request.form else (request.get_json(silent=True) or {})
    config = {}
    for var in env_vars:
        val = data.get(f"config_{var}", "").strip()
        if val:
            config[var] = val

    instance.config = config if config else None
    log_action("exporter_config", "guest", resource_id=instance.guest_id,
               resource_name=instance.guest.name,
               details={"exporter_type": instance.exporter_type, "config_set": bool(config)})
    db.session.commit()
    flash(f"Configuration updated for {info.get('display_name', instance.exporter_type)}.", "success")
    return redirect(url_for("prometheus_app.manage"))


# ---------------------------------------------------------------------------
# Host-level exporter routes
# ---------------------------------------------------------------------------


@bp.route("/host-exporters/add", methods=["POST"])
def host_exporter_add():
    from apps.exporters import KNOWN_EXPORTERS

    data = request.form if request.form else (request.get_json(silent=True) or {})
    host_id = data.get("host_id", "")
    exporter_type = data.get("exporter_type", "")
    port = data.get("port", "")

    if exporter_type not in KNOWN_EXPORTERS or not KNOWN_EXPORTERS[exporter_type].get("host_level"):
        flash("Invalid host-level exporter type.", "error")
        return redirect(url_for("prometheus_app.manage"))

    if not host_id:
        flash("Please select a host.", "error")
        return redirect(url_for("prometheus_app.manage"))

    try:
        host = ProxmoxHost.query.get(int(host_id))
    except (TypeError, ValueError):
        flash("Invalid host ID.", "error")
        return redirect(url_for("prometheus_app.manage"))

    if not host:
        flash("Host not found.", "error")
        return redirect(url_for("prometheus_app.manage"))

    info = KNOWN_EXPORTERS[exporter_type]
    try:
        port_int = int(port) if port else info["default_port"]
    except (TypeError, ValueError):
        port_int = info["default_port"]

    existing = HostExporterInstance.query.filter_by(
        host_id=host.id, exporter_type=exporter_type
    ).filter(HostExporterInstance.status != "removed").first()
    if existing:
        flash(f"{info['display_name']} already exists on {host.name}.", "warning")
        return redirect(url_for("prometheus_app.manage"))

    config = None
    if info.get("requires_config") and info.get("env_vars"):
        config = {}
        for var in info["env_vars"]:
            val = data.get(f"config_{var}", "").strip()
            if val:
                config[var] = val
        if not config:
            config = None

    instance = HostExporterInstance(
        host_id=host.id,
        exporter_type=exporter_type,
        port=port_int,
        config=config,
        status="pending",
    )
    db.session.add(instance)
    log_action("host_exporter_add", "host", resource_id=host.id, resource_name=host.name,
               details={"exporter_type": exporter_type, "port": port_int})
    db.session.commit()

    flash(f"{info['display_name']} added for {host.name}. Click Install to deploy.", "success")
    return redirect(url_for("prometheus_app.manage"))


@bp.route("/host-exporters/<int:instance_id>/install", methods=["POST"])
def host_exporter_install(instance_id):
    if _host_exporter_install_job["running"] or _host_exporter_uninstall_job["running"]:
        return jsonify({"error": "Another host exporter operation is already running."}), 409

    instance = HostExporterInstance.query.get_or_404(instance_id)

    _host_exporter_install_job["running"] = True
    _host_exporter_install_job["success"] = None
    _host_exporter_install_job["log"] = []
    _host_exporter_install_job["instance_id"] = instance_id

    from flask import current_app
    _app = current_app._get_current_object()
    _host_id = instance.host_id
    _host_name = instance.host.name
    _etype = instance.exporter_type

    def _bg():
        from apps.exporters import run_host_exporter_install
        from core.notifier import send_exporter_notification
        def _cb(msg):
            _host_exporter_install_job["log"].append(msg)
        try:
            with _app.app_context():
                ok, _ = run_host_exporter_install(instance_id, log_callback=_cb)
        except Exception as e:
            _cb(f"FATAL ERROR: {e}")
            ok = False
        _host_exporter_install_job["running"] = False
        _host_exporter_install_job["success"] = ok
        with _app.app_context():
            send_exporter_notification("install", _etype, _host_name, ok)
            log_action("host_exporter_install", "host", resource_id=_host_id,
                       resource_name=_host_name,
                       details={"exporter_type": _etype, "status": "success" if ok else "error"})
            db.session.commit()

    _threading.Thread(target=_bg, daemon=True).start()
    return jsonify({"started": True})


@bp.route("/host-exporters/install/status")
def host_exporter_install_status():
    return jsonify({
        "running": _host_exporter_install_job["running"],
        "success": _host_exporter_install_job["success"],
        "log": _host_exporter_install_job["log"],
        "instance_id": _host_exporter_install_job["instance_id"],
    })


@bp.route("/host-exporters/<int:instance_id>/uninstall", methods=["POST"])
def host_exporter_uninstall(instance_id):
    if _host_exporter_install_job["running"] or _host_exporter_uninstall_job["running"]:
        return jsonify({"error": "Another host exporter operation is already running."}), 409

    instance = HostExporterInstance.query.get_or_404(instance_id)

    _host_exporter_uninstall_job["running"] = True
    _host_exporter_uninstall_job["success"] = None
    _host_exporter_uninstall_job["log"] = []
    _host_exporter_uninstall_job["instance_id"] = instance_id

    from flask import current_app
    _app = current_app._get_current_object()
    _host_id = instance.host_id
    _host_name = instance.host.name
    _etype = instance.exporter_type

    def _bg():
        from apps.exporters import run_host_exporter_uninstall
        from core.notifier import send_exporter_notification
        def _cb(msg):
            _host_exporter_uninstall_job["log"].append(msg)
        try:
            with _app.app_context():
                ok, _ = run_host_exporter_uninstall(instance_id, log_callback=_cb)
        except Exception as e:
            _cb(f"FATAL ERROR: {e}")
            ok = False
        _host_exporter_uninstall_job["running"] = False
        _host_exporter_uninstall_job["success"] = ok
        with _app.app_context():
            send_exporter_notification("uninstall", _etype, _host_name, ok)
            log_action("host_exporter_uninstall", "host", resource_id=_host_id,
                       resource_name=_host_name,
                       details={"exporter_type": _etype, "status": "success" if ok else "error"})
            db.session.commit()

    _threading.Thread(target=_bg, daemon=True).start()
    return jsonify({"started": True})


@bp.route("/host-exporters/uninstall/status")
def host_exporter_uninstall_status():
    return jsonify({
        "running": _host_exporter_uninstall_job["running"],
        "success": _host_exporter_uninstall_job["success"],
        "log": _host_exporter_uninstall_job["log"],
        "instance_id": _host_exporter_uninstall_job["instance_id"],
    })


@bp.route("/host-exporters/<int:instance_id>/delete", methods=["POST"])
def host_exporter_delete(instance_id):
    instance = HostExporterInstance.query.get_or_404(instance_id)
    if instance.status == "installed":
        flash("Uninstall the exporter before deleting.", "error")
        return redirect(url_for("prometheus_app.manage"))

    host_name = instance.host.name
    etype = instance.exporter_type
    log_action("host_exporter_delete", "host", resource_id=instance.host_id, resource_name=host_name,
               details={"exporter_type": etype})
    db.session.delete(instance)
    db.session.commit()
    flash(f"Exporter entry removed for {host_name}.", "success")
    return redirect(url_for("prometheus_app.manage"))


@bp.route("/host-exporters/<int:instance_id>/config", methods=["POST"])
def host_exporter_update_config(instance_id):
    from apps.exporters import KNOWN_EXPORTERS

    instance = HostExporterInstance.query.get_or_404(instance_id)
    if instance.status == "installed":
        flash("Uninstall the exporter before changing its configuration.", "error")
        return redirect(url_for("prometheus_app.manage"))

    info = KNOWN_EXPORTERS.get(instance.exporter_type, {})
    env_vars = info.get("env_vars", [])
    if not env_vars:
        flash("This exporter does not require configuration.", "warning")
        return redirect(url_for("prometheus_app.manage"))

    data = request.form if request.form else (request.get_json(silent=True) or {})
    config = {}
    for var in env_vars:
        val = data.get(f"config_{var}", "").strip()
        if val:
            config[var] = val

    instance.config = config if config else None
    log_action("host_exporter_config", "host", resource_id=instance.host_id,
               resource_name=instance.host.name,
               details={"exporter_type": instance.exporter_type, "config_set": bool(config)})
    db.session.commit()
    flash(f"Configuration updated for {info.get('display_name', instance.exporter_type)}.", "success")
    return redirect(url_for("prometheus_app.manage"))


# ---------------------------------------------------------------------------
# Mastodon built-in exporter
# ---------------------------------------------------------------------------

_mastodon_exporter_job = {"running": False, "success": None, "log": []}


def _parse_mastodon_exporter_config():
    """Parse Mastodon exporter configuration from form data."""
    return {
        "web_detailed_metrics": request.form.get("web_detailed_metrics") == "on",
        "sidekiq_detailed_metrics": request.form.get("sidekiq_detailed_metrics") == "on",
        "mode": request.form.get("mode", "external"),
        "host": (request.form.get("host", "0.0.0.0").strip() or "0.0.0.0"),
        "port": int(request.form.get("port", 9394) or 9394),
    }


@bp.route("/mastodon-exporter/enable", methods=["POST"])
def mastodon_exporter_enable():
    from apps.exporters import enable_mastodon_exporter

    mastodon_guest_id = Setting.get("mastodon_guest_id", "")
    if not mastodon_guest_id:
        flash("Mastodon guest not configured. Set it in the Mastodon management page first.", "error")
        return redirect(url_for("prometheus_app.manage"))

    if _mastodon_exporter_job["running"]:
        flash("A Mastodon exporter operation is already in progress.", "warning")
        return redirect(url_for("prometheus_app.manage"))

    _mastodon_exporter_job["running"] = True
    _mastodon_exporter_job["success"] = None
    _mastodon_exporter_job["log"] = []

    guest_id = int(mastodon_guest_id)
    config = _parse_mastodon_exporter_config()

    def _run():
        from app import create_app
        app = create_app()
        with app.app_context():
            def _log(msg):
                _mastodon_exporter_job["log"].append(msg)

            try:
                ok = enable_mastodon_exporter(guest_id, config=config, log_callback=_log)
                _mastodon_exporter_job["success"] = ok
            except Exception as e:
                _mastodon_exporter_job["log"].append(f"ERROR: {e}")
                _mastodon_exporter_job["success"] = False
            finally:
                _mastodon_exporter_job["running"] = False

    _threading.Thread(target=_run, daemon=True).start()
    log_action("mastodon_exporter_enable", "guest", resource_id=guest_id,
               details={"config": config})
    db.session.commit()
    return redirect(url_for("prometheus_app.manage"))


@bp.route("/mastodon-exporter/disable", methods=["POST"])
def mastodon_exporter_disable():
    from apps.exporters import disable_mastodon_exporter

    mastodon_guest_id = Setting.get("mastodon_guest_id", "")
    if not mastodon_guest_id:
        flash("Mastodon guest not configured.", "error")
        return redirect(url_for("prometheus_app.manage"))

    if _mastodon_exporter_job["running"]:
        flash("A Mastodon exporter operation is already in progress.", "warning")
        return redirect(url_for("prometheus_app.manage"))

    _mastodon_exporter_job["running"] = True
    _mastodon_exporter_job["success"] = None
    _mastodon_exporter_job["log"] = []

    guest_id = int(mastodon_guest_id)

    def _run():
        from app import create_app
        app = create_app()
        with app.app_context():
            def _log(msg):
                _mastodon_exporter_job["log"].append(msg)

            try:
                ok = disable_mastodon_exporter(guest_id, _log)
                _mastodon_exporter_job["success"] = ok
            except Exception as e:
                _mastodon_exporter_job["log"].append(f"ERROR: {e}")
                _mastodon_exporter_job["success"] = False
            finally:
                _mastodon_exporter_job["running"] = False

    _threading.Thread(target=_run, daemon=True).start()
    log_action("mastodon_exporter_disable", "guest", resource_id=guest_id)
    db.session.commit()
    return redirect(url_for("prometheus_app.manage"))


@bp.route("/mastodon-exporter/reconfigure", methods=["POST"])
def mastodon_exporter_reconfigure():
    from apps.exporters import reconfigure_mastodon_exporter

    mastodon_guest_id = Setting.get("mastodon_guest_id", "")
    if not mastodon_guest_id:
        flash("Mastodon guest not configured.", "error")
        return redirect(url_for("prometheus_app.manage"))

    if _mastodon_exporter_job["running"]:
        flash("A Mastodon exporter operation is already in progress.", "warning")
        return redirect(url_for("prometheus_app.manage"))

    _mastodon_exporter_job["running"] = True
    _mastodon_exporter_job["success"] = None
    _mastodon_exporter_job["log"] = []

    guest_id = int(mastodon_guest_id)
    config = _parse_mastodon_exporter_config()

    def _run():
        from app import create_app
        app = create_app()
        with app.app_context():
            def _log(msg):
                _mastodon_exporter_job["log"].append(msg)

            try:
                ok = reconfigure_mastodon_exporter(guest_id, config, _log)
                _mastodon_exporter_job["success"] = ok
            except Exception as e:
                _mastodon_exporter_job["log"].append(f"ERROR: {e}")
                _mastodon_exporter_job["success"] = False
            finally:
                _mastodon_exporter_job["running"] = False

    _threading.Thread(target=_run, daemon=True).start()
    log_action("mastodon_exporter_reconfigure", "guest", resource_id=guest_id,
               details={"config": config})
    db.session.commit()
    return redirect(url_for("prometheus_app.manage"))


@bp.route("/mastodon-exporter/status")
def mastodon_exporter_status():
    return jsonify({
        "running": _mastodon_exporter_job["running"],
        "success": _mastodon_exporter_job["success"],
        "log": _mastodon_exporter_job["log"],
    })
