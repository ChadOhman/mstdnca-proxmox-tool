import logging
import threading as _threading
from datetime import datetime

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import login_required

from apps.utils import JobTracker
from auth.audit import log_action
from models import Guest, Setting, db


def _parse_iso(value):
    """Parse an ISO 8601 string into a timezone-aware datetime, or return None."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None

# ---------------------------------------------------------------------------
# In-memory job state — mirrors the pattern from routes/ghost.py
# ---------------------------------------------------------------------------
_upgrade_job = JobTracker()
_preflight_job = JobTracker()
_install_job = JobTracker()

logger = logging.getLogger(__name__)

bp = Blueprint("peertube", __name__)


@bp.before_request
@login_required
def _require_login():
    from flask_login import current_user
    if not current_user.can_update:
        flash("'Apply Updates' permission required.", "error")
        return redirect(url_for("dashboard.index"))


def _get_peertube_settings():
    return {
        "guest_id": Setting.get("peertube_guest_id", ""),
        "db_guest_id": Setting.get("peertube_db_guest_id", ""),
        "user": Setting.get("peertube_user", "peertube"),
        "db_name": Setting.get("peertube_db_name", "peertube"),
        "peertube_dir": Setting.get("peertube_dir", "/var/www/peertube"),
        "url": Setting.get("peertube_url", ""),
        "db_host": Setting.get("peertube_db_host", ""),
        "db_password": Setting.get("peertube_db_password", ""),
        "auto_upgrade": Setting.get("peertube_auto_upgrade", "false"),
        "current_version": Setting.get("peertube_current_version", ""),
        "latest_version": Setting.get("peertube_latest_version", ""),
        "latest_release_url": Setting.get("peertube_latest_release_url", ""),
        "update_available": Setting.get("peertube_update_available", "") == "true",
        "installed": Setting.get("peertube_installed", "") == "true",
        "last_upgrade_at": _parse_iso(Setting.get("peertube_last_upgrade_at", "")),
        "last_upgrade_status": Setting.get("peertube_last_upgrade_status", ""),
        "last_upgrade_log": Setting.get("peertube_last_upgrade_log", ""),
        "last_install_at": _parse_iso(Setting.get("peertube_last_install_at", "")),
        "last_install_status": Setting.get("peertube_last_install_status", ""),
        "last_install_log": Setting.get("peertube_last_install_log", ""),
        "protection_type": Setting.get("peertube_protection_type", "snapshot"),
        "backup_storage": Setting.get("peertube_backup_storage", ""),
        "backup_mode": Setting.get("peertube_backup_mode", "snapshot"),
    }


@bp.route("/upgrade")
def upgrade_page():
    settings = _get_peertube_settings()
    guests = Guest.query.filter_by(enabled=True).order_by(Guest.name).all()

    backup_storages = []
    snapshots_supported = True
    snapshot_blockers = []

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
                        snapshot_blockers.append(g.name)
        except Exception as e:
            logger.warning("Could not check snapshot/backup support: %s", e)

    return render_template(
        "peertube.html",
        settings=settings,
        guests=guests,
        backup_storages=backup_storages,
        snapshots_supported=snapshots_supported,
        snapshot_blockers=snapshot_blockers,
    )


@bp.route("/save", methods=["POST"])
def save():
    Setting.set("peertube_guest_id", request.form.get("peertube_guest_id", "").strip())
    Setting.set("peertube_db_guest_id", request.form.get("peertube_db_guest_id", "").strip())
    Setting.set("peertube_user", request.form.get("peertube_user", "peertube").strip() or "peertube")
    Setting.set("peertube_db_name", request.form.get("peertube_db_name", "peertube").strip() or "peertube")
    Setting.set("peertube_dir", request.form.get("peertube_dir", "/var/www/peertube").strip() or "/var/www/peertube")
    Setting.set("peertube_url", request.form.get("peertube_url", "").strip())
    Setting.set("peertube_db_host", request.form.get("peertube_db_host", "").strip())

    # Encrypt DB password if provided; keep existing if blank
    db_password_raw = request.form.get("peertube_db_password", "").strip()
    if db_password_raw:
        from auth.credential_store import encrypt
        Setting.set("peertube_db_password", encrypt(db_password_raw))

    Setting.set("peertube_current_version", request.form.get("peertube_current_version", "").strip())
    Setting.set("peertube_auto_upgrade", "true" if "peertube_auto_upgrade" in request.form else "false")
    protection_type = request.form.get("peertube_protection_type", "snapshot")
    Setting.set("peertube_protection_type",
                protection_type if protection_type in ("snapshot", "backup") else "snapshot")
    Setting.set("peertube_backup_storage", request.form.get("peertube_backup_storage", "").strip())
    backup_mode = request.form.get("peertube_backup_mode", "snapshot")
    Setting.set("peertube_backup_mode",
                backup_mode if backup_mode in ("snapshot", "suspend", "stop") else "snapshot")

    log_action("peertube_config_save", "settings", resource_name="peertube")
    db.session.commit()
    flash("PeerTube settings saved.", "success")
    return redirect(url_for("peertube.upgrade_page"))


@bp.route("/check", methods=["POST"])
def check():
    from apps.peertube import check_peertube_release

    update_available, latest, release_url = check_peertube_release()
    current = Setting.get("peertube_current_version", "")

    if not latest:
        flash("Could not fetch latest PeerTube release from GitHub.", "error")
    elif update_available:
        flash(f"PeerTube update available: v{current} \u2192 v{latest}", "warning")
    elif current:
        flash(f"PeerTube is up to date (v{current}).", "success")
    else:
        flash(
            f"Latest PeerTube release: v{latest}. "
            "Set your current version to enable update detection.",
            "info",
        )

    return redirect(url_for("peertube.upgrade_page"))


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


@bp.route("/install/status")
def install_status():
    return jsonify({
        "running": _install_job["running"],
        "success": _install_job["success"],
        "log": _install_job["log"],
    })


@bp.route("/preflight", methods=["POST"])
def preflight():
    from flask import current_app

    from apps.peertube import run_peertube_preflight

    if _upgrade_job["running"] or _install_job["running"]:
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
                ok, _ = run_peertube_preflight(log_callback=_cb)
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


@bp.route("/upgrade", methods=["POST"])
def upgrade():
    from flask import current_app
    from flask_login import current_user

    from apps.peertube import run_peertube_upgrade
    from apps.utils import acquire_upgrade_lock, release_upgrade_lock

    if _install_job["running"]:
        flash("An operation is already in progress.", "warning")
        return redirect(url_for("peertube.upgrade_page"))
    # Atomic check-and-set, shared with the scheduler's auto-upgrade job so a
    # cron upgrade and a manual one can never run against the same host at once.
    if not acquire_upgrade_lock("peertube"):
        flash("An operation is already in progress.", "warning")
        return redirect(url_for("peertube.upgrade_page"))

    skip_protection = (
        current_user.is_super_admin
        and request.form.get("skip_protection") == "1"
    )

    _upgrade_job.update({"running": True, "success": None, "log": []})
    target_version = Setting.get("peertube_latest_version", "")

    def _cb(msg):
        _upgrade_job["log"].append(msg)

    _app = current_app._get_current_object()

    def _bg():
        ok = False
        try:
            with _app.app_context():
                from core.notifier import send_upgrade_started_notification
                send_upgrade_started_notification("peertube", target_version, "manual")
                ok, _ = run_peertube_upgrade(log_callback=_cb, skip_protection=skip_protection)
        except Exception as e:
            _cb(f"FATAL ERROR: {e}")
            ok = False
        _upgrade_job["running"] = False
        _upgrade_job["success"] = ok
        from datetime import datetime, timezone
        with _app.app_context():
            now = datetime.now(timezone.utc).isoformat()
            Setting.set("peertube_last_upgrade_at", now)
            Setting.set("peertube_last_upgrade_status", "success" if ok else "error")
            Setting.set("peertube_last_upgrade_log", "\n".join(_upgrade_job["log"]))
            log_action("peertube_upgrade", "settings", resource_name="peertube",
                       details={"status": "success" if ok else "error"})
            db.session.commit()
            from core.notifier import send_upgrade_result_notification
            send_upgrade_result_notification("peertube", target_version, ok, "manual")

    def _bg_locked():
        try:
            _bg()
        finally:
            _upgrade_job["running"] = False
            release_upgrade_lock("peertube")

    try:
        import gevent as _gevent
        _gevent.spawn(_bg_locked)
    except ImportError:
        _threading.Thread(target=_bg_locked, daemon=True).start()

    return redirect(url_for("peertube.upgrade_page"))


@bp.route("/install", methods=["POST"])
def install():
    from flask import current_app

    from apps.peertube import run_peertube_install

    if _upgrade_job["running"] or _install_job["running"]:
        flash("An operation is already in progress.", "warning")
        return redirect(url_for("peertube.upgrade_page"))

    _install_job.update({"running": True, "success": None, "log": []})

    def _cb(msg):
        _install_job["log"].append(msg)

    _app = current_app._get_current_object()

    def _bg():
        ok = False
        try:
            with _app.app_context():
                ok, _ = run_peertube_install(log_callback=_cb)
        except Exception as e:
            _cb(f"FATAL ERROR: {e}")
            ok = False
        _install_job["running"] = False
        _install_job["success"] = ok
        from datetime import datetime, timezone
        with _app.app_context():
            now = datetime.now(timezone.utc).isoformat()
            Setting.set("peertube_last_install_at", now)
            Setting.set("peertube_last_install_status", "success" if ok else "error")
            Setting.set("peertube_last_install_log", "\n".join(_install_job["log"]))
            if ok:
                Setting.set("peertube_installed", "true")
            log_action("peertube_install", "settings", resource_name="peertube",
                       details={"status": "success" if ok else "error"})
            db.session.commit()

    try:
        import gevent as _gevent
        _gevent.spawn(_bg)
    except ImportError:
        _threading.Thread(target=_bg, daemon=True).start()

    return redirect(url_for("peertube.upgrade_page"))


@bp.route("/detect-versions", methods=["POST"])
def detect_versions():
    from apps.peertube import detect_peertube_version

    guest_id = Setting.get("peertube_guest_id", "")
    peertube_dir = Setting.get("peertube_dir", "/var/www/peertube")
    peertube_user = Setting.get("peertube_user", "peertube")

    if not guest_id:
        flash("PeerTube guest is not configured.", "warning")
        return redirect(url_for("peertube.upgrade_page"))

    try:
        guest = Guest.query.get(int(guest_id))
    except (TypeError, ValueError):
        flash("Invalid PeerTube guest ID.", "error")
        return redirect(url_for("peertube.upgrade_page"))

    if not guest:
        flash("PeerTube guest not found.", "error")
        return redirect(url_for("peertube.upgrade_page"))

    version, error = detect_peertube_version(guest, peertube_dir, user=peertube_user)
    if version:
        Setting.set("peertube_current_version", version)
        if Setting.get("peertube_installed") != "true":
            Setting.set("peertube_installed", "true")
        db.session.commit()
        flash(f"Detected PeerTube version: {version}", "success")
    else:
        if Setting.get("peertube_installed") == "true":
            Setting.set("peertube_installed", "false")
            Setting.set("peertube_current_version", "")
            db.session.commit()
            flash(f"PeerTube not found on guest: {error}. Marked as not installed.", "warning")
        else:
            flash(f"Could not detect PeerTube version: {error}", "warning")

    return redirect(url_for("peertube.upgrade_page"))
