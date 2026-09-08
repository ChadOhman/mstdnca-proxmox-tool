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
# In-memory job state — mirrors the pattern from routes/mastodon.py
# ---------------------------------------------------------------------------
_upgrade_job = JobTracker()
_preflight_job = JobTracker()

logger = logging.getLogger(__name__)

bp = Blueprint("ghost", __name__)


@bp.before_request
@login_required
def _require_login():
    from flask_login import current_user
    if not current_user.can_update:
        flash("'Apply Updates' permission required.", "error")
        return redirect(url_for("dashboard.index"))


def _get_ghost_settings():
    return {
        "guest_id": Setting.get("ghost_guest_id", ""),
        "user": Setting.get("ghost_user", "ghost_user"),
        "ghost_dir": Setting.get("ghost_dir", "/opt/ghost"),
        "url": Setting.get("ghost_url", ""),
        "auto_upgrade": Setting.get("ghost_auto_upgrade", "false"),
        "current_version": Setting.get("ghost_current_version", ""),
        "latest_version": Setting.get("ghost_latest_version", ""),
        "latest_release_url": Setting.get("ghost_latest_release_url", ""),
        "update_available": Setting.get("ghost_update_available", "") == "true",
        "last_upgrade_at": _parse_iso(Setting.get("ghost_last_upgrade_at", "")),
        "last_upgrade_status": Setting.get("ghost_last_upgrade_status", ""),
        "last_upgrade_log": Setting.get("ghost_last_upgrade_log", ""),
        "protection_type": Setting.get("ghost_protection_type", "snapshot"),
        "backup_storage": Setting.get("ghost_backup_storage", ""),
        "backup_mode": Setting.get("ghost_backup_mode", "snapshot"),
    }


@bp.route("/")
def overview():
    settings = _get_ghost_settings()
    guest_id = settings.get("guest_id", "")

    ghost_services = []
    ghost_guest = None
    from models import GuestService
    try:
        if guest_id:
            ghost_services = GuestService.query.filter_by(guest_id=int(guest_id)).all()
            ghost_guest = Guest.query.get(int(guest_id))
    except (TypeError, ValueError):
        logger.warning("Ghost guest_id setting is not a valid integer")

    return render_template(
        "ghost_overview.html",
        settings=settings,
        ghost_services=ghost_services,
        ghost_guest=ghost_guest,
    )


@bp.route("/upgrade")
def upgrade_page():
    settings = _get_ghost_settings()
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
        "ghost.html",
        settings=settings,
        guests=guests,
        backup_storages=backup_storages,
        snapshots_supported=snapshots_supported,
        snapshot_blockers=snapshot_blockers,
    )


@bp.route("/save", methods=["POST"])
def save():
    Setting.set("ghost_guest_id", request.form.get("ghost_guest_id", "").strip())
    Setting.set("ghost_user", request.form.get("ghost_user", "ghost_user").strip() or "ghost_user")
    Setting.set("ghost_dir", request.form.get("ghost_dir", "/opt/ghost").strip() or "/opt/ghost")
    Setting.set("ghost_url", request.form.get("ghost_url", "").strip())
    Setting.set("ghost_current_version", request.form.get("ghost_current_version", "").strip())
    Setting.set("ghost_auto_upgrade", "true" if "ghost_auto_upgrade" in request.form else "false")
    protection_type = request.form.get("ghost_protection_type", "snapshot")
    Setting.set("ghost_protection_type",
                protection_type if protection_type in ("snapshot", "backup") else "snapshot")
    Setting.set("ghost_backup_storage", request.form.get("ghost_backup_storage", "").strip())
    backup_mode = request.form.get("ghost_backup_mode", "snapshot")
    Setting.set("ghost_backup_mode",
                backup_mode if backup_mode in ("snapshot", "suspend", "stop") else "snapshot")

    log_action("ghost_config_save", "settings", resource_name="ghost")
    db.session.commit()
    flash("Ghost settings saved.", "success")
    return redirect(url_for("ghost.upgrade_page"))


@bp.route("/check", methods=["POST"])
def check():
    from apps.ghost import check_ghost_release

    update_available, latest, release_url = check_ghost_release()
    current = Setting.get("ghost_current_version", "")

    if not latest:
        flash("Could not fetch latest Ghost release from npm.", "error")
    elif update_available:
        flash(f"Ghost update available: v{current} \u2192 v{latest}", "warning")
    elif current:
        flash(f"Ghost is up to date (v{current}).", "success")
    else:
        flash(
            f"Latest Ghost release: v{latest}. "
            "Set your current version to enable update detection.",
            "info",
        )

    return redirect(url_for("ghost.upgrade_page"))


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

    from apps.ghost import run_ghost_preflight

    if _upgrade_job["running"]:
        return jsonify({"error": "An upgrade is already in progress"}), 409
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
                ok, _ = run_ghost_preflight(log_callback=_cb)
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

    from apps.ghost import run_ghost_upgrade
    from apps.utils import acquire_upgrade_lock, release_upgrade_lock

    # Atomic check-and-set, shared with the scheduler's auto-upgrade job so a
    # cron upgrade and a manual one can never run against the same host at once.
    if not acquire_upgrade_lock("ghost"):
        flash("An upgrade is already in progress.", "warning")
        return redirect(url_for("ghost.upgrade_page"))

    skip_protection = (
        current_user.is_super_admin
        and request.form.get("skip_protection") == "1"
    )

    _upgrade_job.update({"running": True, "success": None, "log": []})
    target_version = Setting.get("ghost_latest_version", "")

    def _cb(msg):
        _upgrade_job["log"].append(msg)

    _app = current_app._get_current_object()

    def _bg():
        ok = False
        try:
            with _app.app_context():
                from core.notifier import send_upgrade_started_notification
                send_upgrade_started_notification("ghost", target_version, "manual")
                ok, _ = run_ghost_upgrade(log_callback=_cb, skip_protection=skip_protection)
        except Exception as e:
            _cb(f"FATAL ERROR: {e}")
            ok = False
        _upgrade_job["running"] = False
        _upgrade_job["success"] = ok
        from datetime import datetime, timezone
        with _app.app_context():
            now = datetime.now(timezone.utc).isoformat()
            Setting.set("ghost_last_upgrade_at", now)
            Setting.set("ghost_last_upgrade_status", "success" if ok else "error")
            Setting.set("ghost_last_upgrade_log", "\n".join(_upgrade_job["log"]))
            log_action("ghost_upgrade", "settings", resource_name="ghost",
                       details={"status": "success" if ok else "error"})
            db.session.commit()
            from core.notifier import send_upgrade_result_notification
            send_upgrade_result_notification("ghost", target_version, ok, "manual")

    def _bg_locked():
        try:
            _bg()
        finally:
            _upgrade_job["running"] = False
            release_upgrade_lock("ghost")

    try:
        import gevent as _gevent
        _gevent.spawn(_bg_locked)
    except ImportError:
        _threading.Thread(target=_bg_locked, daemon=True).start()

    return redirect(url_for("ghost.upgrade_page"))


@bp.route("/detect-versions", methods=["POST"])
def detect_versions():
    from apps.ghost import detect_ghost_version

    guest_id = Setting.get("ghost_guest_id", "")
    ghost_dir = Setting.get("ghost_dir", "/opt/ghost")
    ghost_user = Setting.get("ghost_user", "ghost_user")

    if not guest_id:
        flash("Ghost guest is not configured.", "warning")
        return redirect(url_for("ghost.upgrade_page"))

    try:
        guest = Guest.query.get(int(guest_id))
    except (TypeError, ValueError):
        flash("Invalid Ghost guest ID.", "error")
        return redirect(url_for("ghost.upgrade_page"))

    if not guest:
        flash("Ghost guest not found.", "error")
        return redirect(url_for("ghost.upgrade_page"))

    version, error = detect_ghost_version(guest, ghost_dir, user=ghost_user)
    if version:
        Setting.set("ghost_current_version", version)
        db.session.commit()
        flash(f"Detected Ghost version: {version}", "success")
    else:
        flash(f"Could not detect Ghost version: {error}", "warning")

    return redirect(url_for("ghost.upgrade_page"))
