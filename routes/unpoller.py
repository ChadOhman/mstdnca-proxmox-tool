"""
Unpoller management blueprint.

Provides install, upgrade, preflight, and reconfigure routes
for the unpoller service (installed on the Prometheus guest).
"""

import logging
import threading as _threading
from datetime import datetime, timezone

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from apps.utils import _validate_no_control_chars, _validate_shell_param
from auth.audit import log_action
from models import Guest, Setting, db

_install_job = {"running": False, "success": None, "log": []}
_upgrade_job = {"running": False, "success": None, "log": []}
_preflight_job = {"running": False, "success": None, "log": []}
_reconfig_job = {"running": False, "success": None, "log": []}

logger = logging.getLogger(__name__)

bp = Blueprint("unpoller", __name__)


@bp.before_request
@login_required
def _require_login():
    if not current_user.can_update:
        flash("'Apply Updates' permission required.", "error")
        return redirect(url_for("dashboard.index"))


def _parse_iso(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


def _get_settings():
    return {
        "enabled": Setting.get("unpoller_enabled", "false") == "true",
        "installed": Setting.get("unpoller_installed", "") == "true",
        "auto_upgrade": Setting.get("unpoller_auto_upgrade", "false"),
        "current_version": Setting.get("unpoller_current_version", ""),
        "latest_version": Setting.get("unpoller_latest_version", ""),
        "update_available": Setting.get("unpoller_update_available", "") == "true",
        "metric_prefix": Setting.get("unpoller_metric_prefix", "unpoller"),
        "site_name": Setting.get("unpoller_site_name", "default"),
        "listen_port": Setting.get("unpoller_listen_port", "9130"),
        "last_install_at": _parse_iso(Setting.get("unpoller_last_install_at", "")),
        "last_install_status": Setting.get("unpoller_last_install_status", ""),
        "last_install_log": Setting.get("unpoller_last_install_log", ""),
        "last_upgrade_at": _parse_iso(Setting.get("unpoller_last_upgrade_at", "")),
        "last_upgrade_status": Setting.get("unpoller_last_upgrade_status", ""),
        "last_upgrade_log": Setting.get("unpoller_last_upgrade_log", ""),
        # Prometheus guest info for context
        "prometheus_guest_id": Setting.get("prometheus_guest_id", ""),
        "prometheus_installed": Setting.get("prometheus_installed", "") == "true",
    }


@bp.route("/manage")
def manage():
    settings = _get_settings()

    # Get the Prometheus guest for display
    prom_guest = None
    guest_id = settings.get("prometheus_guest_id", "")
    if guest_id:
        try:
            prom_guest = Guest.query.get(int(guest_id))
        except (TypeError, ValueError):
            pass

    # Check if UniFi controller is configured
    unifi_configured = bool(
        Setting.get("unifi_base_url", "")
        and Setting.get("unifi_username", "")
        and Setting.get("unifi_password", "")
    )

    return render_template(
        "unpoller.html",
        settings=settings,
        prom_guest=prom_guest,
        unifi_configured=unifi_configured,
    )


@bp.route("/save", methods=["POST"])
def save():
    # Both of these are written into up.conf on the Prometheus guest.  The TOML
    # writer escapes them, but a newline or control character has no legitimate
    # use in either and is rejected outright rather than escaped.
    metric_prefix = request.form.get("unpoller_metric_prefix", "unpoller").strip() or "unpoller"
    site_name = request.form.get("unpoller_site_name", "default").strip() or "default"
    try:
        _validate_shell_param(metric_prefix, "Metric prefix")
        _validate_no_control_chars(site_name, "Site name")
        if len(site_name) > 128:
            raise ValueError("Site name is too long")
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("unpoller.manage"))

    Setting.set("unpoller_auto_upgrade",
                "true" if "unpoller_auto_upgrade" in request.form else "false")
    Setting.set("unpoller_metric_prefix", metric_prefix)
    Setting.set("unpoller_site_name", site_name)

    port = request.form.get("unpoller_listen_port", "9130").strip()
    try:
        port = str(max(1, min(65535, int(port))))
    except (TypeError, ValueError):
        port = "9130"
    Setting.set("unpoller_listen_port", port)

    log_action("unpoller_config_save", "settings", resource_name="unpoller")
    db.session.commit()
    flash("Unpoller settings saved.", "success")
    return redirect(url_for("unpoller.manage"))


@bp.route("/check", methods=["POST"])
def check():
    from apps.unpoller import check_unpoller_release

    update_available, latest, release_url = check_unpoller_release()
    current = Setting.get("unpoller_current_version", "")

    if not latest:
        flash("Could not fetch latest unpoller version.", "error")
    elif update_available:
        flash(f"Unpoller update available: v{current} → v{latest}", "warning")
    elif current:
        flash(f"Unpoller is up to date (v{current}).", "success")
    else:
        flash(f"Latest unpoller version: v{latest}.", "info")

    db.session.commit()
    return redirect(url_for("unpoller.manage"))


@bp.route("/detect-version", methods=["POST"])
def detect_version():
    from apps.unpoller import detect_unpoller_version

    guest_id = Setting.get("prometheus_guest_id", "")
    if not guest_id:
        flash("Prometheus guest is not configured.", "warning")
        return redirect(url_for("unpoller.manage"))

    try:
        guest = Guest.query.get(int(guest_id))
    except (TypeError, ValueError):
        flash("Invalid guest ID.", "error")
        return redirect(url_for("unpoller.manage"))

    if not guest:
        flash("Guest not found.", "error")
        return redirect(url_for("unpoller.manage"))

    version, error = detect_unpoller_version(guest)
    if version:
        Setting.set("unpoller_current_version", version)
        if Setting.get("unpoller_installed") != "true":
            Setting.set("unpoller_installed", "true")
        db.session.commit()
        flash(f"Detected unpoller version: {version}", "success")
    else:
        if Setting.get("unpoller_installed") == "true":
            Setting.set("unpoller_installed", "false")
            Setting.set("unpoller_current_version", "")
            db.session.commit()
            flash(f"Unpoller not found on guest: {error}. Marked as not installed.", "warning")
        else:
            flash(f"Could not detect unpoller version: {error}", "warning")

    return redirect(url_for("unpoller.manage"))


# ---------------------------------------------------------------------------
# Status endpoints
# ---------------------------------------------------------------------------

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


@bp.route("/reconfig/status")
def reconfig_status():
    return jsonify({
        "running": _reconfig_job["running"],
        "success": _reconfig_job["success"],
        "log": _reconfig_job["log"],
    })


# ---------------------------------------------------------------------------
# Action endpoints
# ---------------------------------------------------------------------------

@bp.route("/preflight", methods=["POST"])
def preflight():
    from flask import current_app

    from apps.unpoller import run_unpoller_preflight

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
                ok, _ = run_unpoller_preflight(log_callback=_cb)
        except Exception as e:
            _cb(f"FATAL ERROR: {e}")
            ok = False
        _preflight_job["running"] = False
        _preflight_job["success"] = ok

    _threading.Thread(target=_bg, daemon=True).start()
    return jsonify({"started": True})


@bp.route("/install", methods=["POST"])
def install():
    from flask import current_app

    from apps.unpoller import run_unpoller_install

    if _install_job["running"] or _upgrade_job["running"] or _preflight_job["running"]:
        flash("An operation is already in progress.", "warning")
        return redirect(url_for("unpoller.manage"))

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
                ok, _ = run_unpoller_install(log_callback=_cb)
        except Exception as e:
            _cb(f"FATAL ERROR: {e}")
            ok = False
        _install_job["running"] = False
        _install_job["success"] = ok
        with _app.app_context():
            send_upgrade_result_notification("prometheus", "", ok, "manual")
            now = datetime.now(timezone.utc).isoformat()
            Setting.set("unpoller_last_install_at", now)
            Setting.set("unpoller_last_install_status", "success" if ok else "error")
            Setting.set("unpoller_last_install_log", "\n".join(_install_job["log"]))
            if ok:
                Setting.set("unpoller_installed", "true")
                Setting.set("unpoller_enabled", "true")
            log_action("unpoller_install", "settings", resource_name="unpoller",
                       details={"status": "success" if ok else "error"})
            db.session.commit()

    _threading.Thread(target=_bg, daemon=True).start()
    return redirect(url_for("unpoller.manage"))


@bp.route("/upgrade", methods=["POST"])
def upgrade():
    from flask import current_app

    from apps.unpoller import run_unpoller_upgrade

    if _install_job["running"] or _upgrade_job["running"] or _preflight_job["running"]:
        flash("An operation is already in progress.", "warning")
        return redirect(url_for("unpoller.manage"))

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
                ok, _ = run_unpoller_upgrade(log_callback=_cb)
        except Exception as e:
            _cb(f"FATAL ERROR: {e}")
            ok = False
        _upgrade_job["running"] = False
        _upgrade_job["success"] = ok
        with _app.app_context():
            send_upgrade_result_notification("prometheus", "", ok, "manual")
            now = datetime.now(timezone.utc).isoformat()
            Setting.set("unpoller_last_upgrade_at", now)
            Setting.set("unpoller_last_upgrade_status", "success" if ok else "error")
            Setting.set("unpoller_last_upgrade_log", "\n".join(_upgrade_job["log"]))
            log_action("unpoller_upgrade", "settings", resource_name="unpoller",
                       details={"status": "success" if ok else "error"})
            db.session.commit()

    _threading.Thread(target=_bg, daemon=True).start()
    return redirect(url_for("unpoller.manage"))


@bp.route("/reconfig", methods=["POST"])
def reconfig():
    from flask import current_app

    from apps.unpoller import run_unpoller_reconfig

    if _install_job["running"] or _upgrade_job["running"] or _reconfig_job["running"]:
        flash("An operation is already in progress.", "warning")
        return redirect(url_for("unpoller.manage"))

    _reconfig_job.update({"running": True, "success": None, "log": []})

    def _cb(msg):
        _reconfig_job["log"].append(msg)

    _app = current_app._get_current_object()

    def _bg():
        ok = False
        try:
            with _app.app_context():
                ok, _ = run_unpoller_reconfig(log_callback=_cb)
        except Exception as e:
            _cb(f"FATAL ERROR: {e}")
            ok = False
        _reconfig_job["running"] = False
        _reconfig_job["success"] = ok
        with _app.app_context():
            log_action("unpoller_reconfig", "settings", resource_name="unpoller",
                       details={"status": "success" if ok else "error"})
            db.session.commit()

    _threading.Thread(target=_bg, daemon=True).start()
    return redirect(url_for("unpoller.manage"))
