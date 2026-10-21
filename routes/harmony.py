import logging
import threading as _threading
from datetime import datetime

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import login_required

from apps.utils import JobTracker, _validate_abs_path
from auth.audit import log_action
from core.errors import describe_exception
from core.guest_scope import resolve_guest_selection
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
# In-memory job state — mirrors the pattern from routes/peertube.py
# ---------------------------------------------------------------------------
_upgrade_job = JobTracker()
_preflight_job = JobTracker()
_health_job = JobTracker()

logger = logging.getLogger(__name__)

bp = Blueprint("harmony", __name__)


@bp.before_request
@login_required
def _require_login():
    from flask_login import current_user
    if not current_user.can_update:
        flash("'Apply Updates' permission required.", "error")
        return redirect(url_for("dashboard.index"))


@bp.before_request
def _require_configured_guest_scope():
    """Refuse state-changing requests when the configured guest is outside the user's tags."""
    from core.guest_scope import require_configured_guest_scope
    return require_configured_guest_scope(("harmony_guest_id",), "harmony.upgrade_page")


def _get_harmony_settings():
    return {
        "guest_id": Setting.get("harmony_guest_id", ""),
        "harmony_dir": Setting.get("harmony_dir", "/opt/harmony"),
        "auto_upgrade": Setting.get("harmony_auto_upgrade", "false"),
        "current_version": Setting.get("harmony_current_version", ""),
        "latest_version": Setting.get("harmony_latest_version", ""),
        "latest_release_url": Setting.get("harmony_latest_release_url", ""),
        "update_available": Setting.get("harmony_update_available", "") == "true",
        "installed": Setting.get("harmony_installed", "") == "true",
        "last_upgrade_at": _parse_iso(Setting.get("harmony_last_upgrade_at", "")),
        "last_upgrade_status": Setting.get("harmony_last_upgrade_status", ""),
        "last_upgrade_log": Setting.get("harmony_last_upgrade_log", ""),
        "last_health_at": _parse_iso(Setting.get("harmony_last_health_at", "")),
        "last_health_status": Setting.get("harmony_last_health_status", ""),
        "protection_type": Setting.get("harmony_protection_type", "snapshot"),
        "backup_storage": Setting.get("harmony_backup_storage", ""),
        "backup_mode": Setting.get("harmony_backup_mode", "snapshot"),
    }


def _any_running():
    return _upgrade_job["running"] or _preflight_job["running"] or _health_job["running"]


def _spawn(fn):
    try:
        import gevent as _gevent
        _gevent.spawn(fn)
    except ImportError:
        _threading.Thread(target=fn, daemon=True).start()


@bp.route("/upgrade")
def upgrade_page():
    settings = _get_harmony_settings()
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
        "harmony.html",
        settings=settings,
        guests=guests,
        backup_storages=backup_storages,
        snapshots_supported=snapshots_supported,
        snapshot_blockers=snapshot_blockers,
    )


@bp.route("/save", methods=["POST"])
def save():
    # The directory reaches a root shell on the Harmony guest — allow-list it
    # before anything is persisted.
    harmony_dir = request.form.get("harmony_dir", "/opt/harmony").strip() or "/opt/harmony"
    try:
        _validate_abs_path(harmony_dir, "Harmony directory")
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("harmony.upgrade_page"))

    harmony_guest_id, err = resolve_guest_selection(
        request.form.get("harmony_guest_id", ""), "harmony_guest_id", "Harmony guest"
    )
    if err:
        flash(err, "error")
        return redirect(url_for("harmony.upgrade_page"))

    Setting.set("harmony_guest_id", harmony_guest_id)
    Setting.set("harmony_dir", harmony_dir)
    Setting.set("harmony_auto_upgrade", "true" if "harmony_auto_upgrade" in request.form else "false")
    protection_type = request.form.get("harmony_protection_type", "snapshot")
    Setting.set("harmony_protection_type",
                protection_type if protection_type in ("snapshot", "backup") else "snapshot")
    Setting.set("harmony_backup_storage", request.form.get("harmony_backup_storage", "").strip())
    backup_mode = request.form.get("harmony_backup_mode", "snapshot")
    Setting.set("harmony_backup_mode",
                backup_mode if backup_mode in ("snapshot", "suspend", "stop") else "snapshot")

    log_action("harmony_config_save", "settings", resource_name="harmony")
    db.session.commit()
    flash("Harmony settings saved.", "success")
    return redirect(url_for("harmony.upgrade_page"))


@bp.route("/check", methods=["POST"])
def check():
    from apps.harmony import check_harmony_release

    update_available, latest, _release_url = check_harmony_release()
    current = Setting.get("harmony_current_version", "")

    if not latest:
        flash("Could not fetch the latest Harmony release from GitHub.", "error")
    elif update_available:
        flash(f"Harmony update available: v{current} → v{latest}", "warning")
    elif current:
        flash(f"Harmony is up to date (v{current}).", "success")
    else:
        flash(
            f"Latest Harmony release: v{latest}. "
            "Use 'Detect Version' to enable update detection.",
            "info",
        )

    return redirect(url_for("harmony.upgrade_page"))


@bp.route("/detect-versions", methods=["POST"])
def detect_versions():
    from apps.harmony import detect_harmony_version

    guest_id = Setting.get("harmony_guest_id", "")
    harmony_dir = Setting.get("harmony_dir", "/opt/harmony")

    if not guest_id:
        flash("Harmony guest is not configured.", "warning")
        return redirect(url_for("harmony.upgrade_page"))

    try:
        guest = Guest.query.get(int(guest_id))
    except (TypeError, ValueError):
        flash("Invalid Harmony guest ID.", "error")
        return redirect(url_for("harmony.upgrade_page"))

    if not guest:
        flash("Harmony guest not found.", "error")
        return redirect(url_for("harmony.upgrade_page"))

    version, error = detect_harmony_version(guest, harmony_dir)
    if version:
        from apps.utils import _version_gt
        Setting.set("harmony_current_version", version)
        Setting.set("harmony_installed", "true")
        latest = Setting.get("harmony_latest_version", "")
        Setting.set("harmony_update_available",
                    "true" if latest and _version_gt(latest, version) else "false")
        db.session.commit()
        flash(f"Detected Harmony version: {version}", "success")
    else:
        flash(f"Could not detect the Harmony version: {error}", "warning")

    return redirect(url_for("harmony.upgrade_page"))


def _status(job):
    return jsonify({"running": job["running"], "success": job["success"], "log": job["log"]})


@bp.route("/upgrade/status")
def upgrade_status():
    return _status(_upgrade_job)


@bp.route("/preflight/status")
def preflight_status():
    return _status(_preflight_job)


@bp.route("/health/status")
def health_status():
    return _status(_health_job)


def _start_readonly_job(job, runner, label, after=None):
    """Start a read-only background job (pre-flight / health check)."""
    from flask import current_app

    if _any_running():
        return jsonify({"error": "An operation is already in progress"}), 409

    job.update({"running": True, "success": None, "log": []})

    def _cb(msg):
        job["log"].append(msg)

    _app = current_app._get_current_object()

    def _bg():
        ok = False
        try:
            with _app.app_context():
                ok, _ = runner(log_callback=_cb)
        except Exception as e:
            logger.exception("Harmony %s crashed", label)
            _cb(f"FATAL ERROR: {describe_exception(e)}")
            ok = False
        job["running"] = False
        job["success"] = ok
        if after:
            with _app.app_context():
                after(ok)

    _spawn(_bg)
    return jsonify({"started": True})


@bp.route("/preflight", methods=["POST"])
def preflight():
    from apps.harmony import run_harmony_preflight
    return _start_readonly_job(_preflight_job, run_harmony_preflight, "pre-flight")


@bp.route("/health", methods=["POST"])
def health():
    from apps.harmony import run_harmony_health_check

    def _record(ok):
        from datetime import timezone
        Setting.set("harmony_last_health_at", datetime.now(timezone.utc).isoformat())
        Setting.set("harmony_last_health_status", "healthy" if ok else "unhealthy")
        db.session.commit()

    return _start_readonly_job(_health_job, run_harmony_health_check, "health check", after=_record)


@bp.route("/upgrade", methods=["POST"])
def upgrade():
    from flask import current_app
    from flask_login import current_user

    from apps.harmony import run_harmony_upgrade
    from apps.utils import acquire_upgrade_lock, release_upgrade_lock

    if _preflight_job["running"] or _health_job["running"]:
        flash("An operation is already in progress.", "warning")
        return redirect(url_for("harmony.upgrade_page"))
    # Atomic check-and-set, shared with the scheduler's auto-upgrade job so a
    # cron upgrade and a manual one can never run against the same host at once.
    if not acquire_upgrade_lock("harmony"):
        flash("An operation is already in progress.", "warning")
        return redirect(url_for("harmony.upgrade_page"))

    skip_protection = (
        current_user.is_super_admin
        and request.form.get("skip_protection") == "1"
    )

    _upgrade_job.update({"running": True, "success": None, "log": []})
    target_version = Setting.get("harmony_latest_version", "")

    def _cb(msg):
        _upgrade_job["log"].append(msg)

    _app = current_app._get_current_object()

    def _bg():
        ok = False
        try:
            with _app.app_context():
                from core.notifier import send_upgrade_started_notification
                send_upgrade_started_notification("harmony", target_version, "manual")
                ok, log_output = run_harmony_upgrade(log_callback=_cb, skip_protection=skip_protection)
                # Early refusals (bad config, nothing to upgrade) return their
                # reason without streaming it; surface it in the live log.
                if not ok and not _upgrade_job["log"] and log_output:
                    _cb(f"ERROR: {log_output}")
        except Exception as e:
            logger.exception("Harmony upgrade crashed")
            _cb(f"FATAL ERROR: {describe_exception(e)}")
            ok = False
        _upgrade_job["running"] = False
        _upgrade_job["success"] = ok
        from datetime import timezone
        with _app.app_context():
            now = datetime.now(timezone.utc).isoformat()
            Setting.set("harmony_last_upgrade_at", now)
            Setting.set("harmony_last_upgrade_status", "success" if ok else "error")
            Setting.set("harmony_last_upgrade_log", "\n".join(_upgrade_job["log"]))
            log_action("harmony_upgrade", "settings", resource_name="harmony",
                       details={"status": "success" if ok else "error"})
            db.session.commit()
            from core.notifier import send_upgrade_result_notification
            send_upgrade_result_notification("harmony", target_version, ok, "manual")

    def _bg_locked():
        try:
            _bg()
        finally:
            _upgrade_job["running"] = False
            release_upgrade_lock("harmony")

    _spawn(_bg_locked)

    return redirect(url_for("harmony.upgrade_page"))
