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
# In-memory job state
# ---------------------------------------------------------------------------
_preflight_job = JobTracker()
_install_job = JobTracker()
_configure_job = JobTracker()
_smb_job = JobTracker()

logger = logging.getLogger(__name__)

bp = Blueprint("jibri", __name__)


@bp.before_request
@login_required
def _require_login():
    from flask_login import current_user
    if not current_user.can_update:
        flash("'Apply Updates' permission required.", "error")
        return redirect(url_for("dashboard.index"))


def _get_jibri_settings():
    return {
        "guest_id": Setting.get("jibri_guest_id", ""),
        "installed": Setting.get("jibri_installed", "") == "true",
        "enabled": Setting.get("jibri_enabled", "") == "true",
        "recording_dir": Setting.get("jibri_recording_dir", "/srv/recordings"),
        "smb_share": Setting.get("jibri_smb_share", ""),
        "smb_username": Setting.get("jibri_smb_username", ""),
        "smb_configured": Setting.get("jibri_smb_configured", "") == "true",
        "protection_type": Setting.get("jibri_protection_type", "snapshot"),
        "backup_storage": Setting.get("jibri_backup_storage", ""),
        "backup_mode": Setting.get("jibri_backup_mode", "snapshot"),
        "last_install_at": _parse_iso(Setting.get("jibri_last_install_at", "")),
        "last_install_status": Setting.get("jibri_last_install_status", ""),
        "last_install_log": Setting.get("jibri_last_install_log", ""),
        "last_configure_at": _parse_iso(Setting.get("jibri_last_configure_at", "")),
        "last_configure_status": Setting.get("jibri_last_configure_status", ""),
        # Jitsi dependency info
        "jitsi_installed": Setting.get("jitsi_installed", "") == "true",
        "jitsi_hostname": Setting.get("jitsi_hostname", ""),
    }


@bp.route("/manage")
def manage_page():
    settings = _get_jibri_settings()
    # Only show VMs (not LXC) since Jibri requires snd-aloop
    guests = Guest.query.filter_by(enabled=True, guest_type="vm").order_by(Guest.name).all()

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
        "jibri.html",
        settings=settings,
        guests=guests,
        backup_storages=backup_storages,
        snapshots_supported=snapshots_supported,
        snapshot_blockers=snapshot_blockers,
    )


@bp.route("/save", methods=["POST"])
def save():
    Setting.set("jibri_guest_id", request.form.get("jibri_guest_id", "").strip())
    Setting.set("jibri_recording_dir",
                request.form.get("jibri_recording_dir", "/srv/recordings").strip() or "/srv/recordings")

    protection_type = request.form.get("jibri_protection_type", "snapshot")
    Setting.set("jibri_protection_type",
                protection_type if protection_type in ("snapshot", "backup") else "snapshot")
    Setting.set("jibri_backup_storage", request.form.get("jibri_backup_storage", "").strip())
    backup_mode = request.form.get("jibri_backup_mode", "snapshot")
    Setting.set("jibri_backup_mode",
                backup_mode if backup_mode in ("snapshot", "suspend", "stop") else "snapshot")

    # SMB settings
    Setting.set("jibri_smb_share", request.form.get("jibri_smb_share", "").strip())
    Setting.set("jibri_smb_username", request.form.get("jibri_smb_username", "").strip())
    smb_password = request.form.get("jibri_smb_password", "")
    if smb_password:  # Only update if a new password is provided
        Setting.set("jibri_smb_password", smb_password)

    log_action("jibri_config_save", "settings", resource_name="jibri")
    db.session.commit()

    flash("Jibri settings saved.", "success")
    return redirect(url_for("jibri.manage_page"))


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

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

    from apps.jibri import run_jibri_preflight

    if _install_job["running"] or _configure_job["running"]:
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
                ok, _ = run_jibri_preflight(log_callback=_cb)
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


# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

@bp.route("/install/status")
def install_status():
    return jsonify({
        "running": _install_job["running"],
        "success": _install_job["success"],
        "log": _install_job["log"],
    })


@bp.route("/install", methods=["POST"])
def install():
    from flask import current_app

    from apps.jibri import run_jibri_install

    if _install_job["running"] or _configure_job["running"]:
        flash("An operation is already in progress.", "warning")
        return redirect(url_for("jibri.manage_page"))

    _install_job.update({"running": True, "success": None, "log": []})

    def _cb(msg):
        _install_job["log"].append(msg)

    _app = current_app._get_current_object()

    def _bg():
        ok = False
        try:
            with _app.app_context():
                ok, _ = run_jibri_install(log_callback=_cb)
        except Exception as e:
            _cb(f"FATAL ERROR: {e}")
            ok = False
        _install_job["running"] = False
        _install_job["success"] = ok
        from datetime import datetime, timezone
        with _app.app_context():
            now = datetime.now(timezone.utc).isoformat()
            Setting.set("jibri_last_install_at", now)
            Setting.set("jibri_last_install_status", "success" if ok else "error")
            Setting.set("jibri_last_install_log", "\n".join(_install_job["log"]))
            if ok:
                Setting.set("jibri_installed", "true")
            log_action("jibri_install", "settings", resource_name="jibri",
                       details={"status": "success" if ok else "error"})
            db.session.commit()

    try:
        import gevent as _gevent
        _gevent.spawn(_bg)
    except ImportError:
        _threading.Thread(target=_bg, daemon=True).start()

    return redirect(url_for("jibri.manage_page"))


# ---------------------------------------------------------------------------
# Configure Jitsi server for Jibri
# ---------------------------------------------------------------------------

@bp.route("/configure-jitsi/status")
def configure_status():
    return jsonify({
        "running": _configure_job["running"],
        "success": _configure_job["success"],
        "log": _configure_job["log"],
    })


@bp.route("/configure-jitsi", methods=["POST"])
def configure_jitsi():
    from flask import current_app

    from apps.jibri import run_jibri_jitsi_configure

    if Setting.get("jibri_installed", "") != "true":
        flash("Jibri must be installed before configuring the Jitsi server.", "warning")
        return redirect(url_for("jibri.manage_page"))

    if _install_job["running"] or _configure_job["running"]:
        flash("An operation is already in progress.", "warning")
        return redirect(url_for("jibri.manage_page"))

    _configure_job.update({"running": True, "success": None, "log": []})

    def _cb(msg):
        _configure_job["log"].append(msg)

    _app = current_app._get_current_object()

    def _bg():
        ok = False
        try:
            with _app.app_context():
                ok, _ = run_jibri_jitsi_configure(log_callback=_cb)
        except Exception as e:
            _cb(f"FATAL ERROR: {e}")
            ok = False
        _configure_job["running"] = False
        _configure_job["success"] = ok
        from datetime import datetime, timezone
        with _app.app_context():
            now = datetime.now(timezone.utc).isoformat()
            Setting.set("jibri_last_configure_at", now)
            Setting.set("jibri_last_configure_status", "success" if ok else "error")
            Setting.set("jibri_last_configure_log", "\n".join(_configure_job["log"]))
            log_action("jibri_configure_jitsi", "settings", resource_name="jibri",
                       details={"status": "success" if ok else "error"})
            db.session.commit()

    try:
        import gevent as _gevent
        _gevent.spawn(_bg)
    except ImportError:
        _threading.Thread(target=_bg, daemon=True).start()

    return redirect(url_for("jibri.manage_page"))


# ---------------------------------------------------------------------------
# Configure SMB mount
# ---------------------------------------------------------------------------

@bp.route("/configure-smb/status")
def smb_status():
    return jsonify({
        "running": _smb_job["running"],
        "success": _smb_job["success"],
        "log": _smb_job["log"],
    })


@bp.route("/configure-smb", methods=["POST"])
def configure_smb():
    from flask import current_app

    from apps.jibri import configure_smb_mount

    if Setting.get("jibri_installed", "") != "true":
        flash("Jibri must be installed before configuring SMB.", "warning")
        return redirect(url_for("jibri.manage_page"))

    if _install_job["running"] or _smb_job["running"]:
        flash("An operation is already in progress.", "warning")
        return redirect(url_for("jibri.manage_page"))

    _smb_job.update({"running": True, "success": None, "log": []})

    def _cb(msg):
        _smb_job["log"].append(msg)

    _app = current_app._get_current_object()

    def _bg():
        ok = False
        try:
            with _app.app_context():
                ok, _ = configure_smb_mount(log_callback=_cb)
        except Exception as e:
            _cb(f"FATAL ERROR: {e}")
            ok = False
        _smb_job["running"] = False
        _smb_job["success"] = ok
        with _app.app_context():
            if ok:
                Setting.set("jibri_smb_configured", "true")
            log_action("jibri_configure_smb", "settings", resource_name="jibri",
                       details={"status": "success" if ok else "error"})
            db.session.commit()

    try:
        import gevent as _gevent
        _gevent.spawn(_bg)
    except ImportError:
        _threading.Thread(target=_bg, daemon=True).start()

    return redirect(url_for("jibri.manage_page"))


# ---------------------------------------------------------------------------
# Status endpoint
# ---------------------------------------------------------------------------

@bp.route("/status")
def jibri_status():
    from apps.jibri import check_jibri_status

    status = check_jibri_status()
    return jsonify(status)


# ---------------------------------------------------------------------------
# Recording control
# ---------------------------------------------------------------------------

@bp.route("/record/start", methods=["POST"])
def record_start():
    from apps.jibri import start_recording

    room_name = request.form.get("room_name", "").strip()
    if not room_name:
        flash("Room name is required.", "warning")
        return redirect(url_for("jibri.manage_page"))

    ok, msg = start_recording(room_name)
    flash(msg, "success" if ok else "error")
    log_action("jibri_record_start", "settings", resource_name="jibri",
               details={"room": room_name, "success": ok})
    db.session.commit()
    return redirect(url_for("jibri.manage_page"))


@bp.route("/record/stop", methods=["POST"])
def record_stop():
    from apps.jibri import stop_recording

    ok, msg = stop_recording()
    flash(msg, "success" if ok else "error")
    log_action("jibri_record_stop", "settings", resource_name="jibri",
               details={"success": ok})
    db.session.commit()
    return redirect(url_for("jibri.manage_page"))


# ---------------------------------------------------------------------------
# Streaming control
# ---------------------------------------------------------------------------

@bp.route("/stream/start", methods=["POST"])
def stream_start():
    from apps.jibri import start_streaming

    room_name = request.form.get("room_name", "").strip()
    rtmp_url = request.form.get("rtmp_url", "").strip()
    stream_key = request.form.get("stream_key", "").strip()

    if not room_name:
        flash("Room name is required.", "warning")
        return redirect(url_for("jibri.manage_page"))
    if not rtmp_url:
        flash("RTMP URL is required.", "warning")
        return redirect(url_for("jibri.manage_page"))

    ok, msg = start_streaming(room_name, rtmp_url, stream_key)
    flash(msg, "success" if ok else "error")
    log_action("jibri_stream_start", "settings", resource_name="jibri",
               details={"room": room_name, "success": ok})
    db.session.commit()
    return redirect(url_for("jibri.manage_page"))


@bp.route("/stream/stop", methods=["POST"])
def stream_stop():
    from apps.jibri import stop_streaming

    ok, msg = stop_streaming()
    flash(msg, "success" if ok else "error")
    log_action("jibri_stream_stop", "settings", resource_name="jibri",
               details={"success": ok})
    db.session.commit()
    return redirect(url_for("jibri.manage_page"))


# ---------------------------------------------------------------------------
# Recordings management
# ---------------------------------------------------------------------------

@bp.route("/recordings")
def recordings_list():
    from apps.jibri import list_recordings

    recordings, error = list_recordings()
    # Sanitize error to avoid exposing internal details (stack traces, paths)
    if error:
        logger.warning("Recordings list error: %s", error)
        error = "Could not retrieve recordings. Check the operation log for details."
    return jsonify({"recordings": recordings, "error": error})


@bp.route("/recordings/delete", methods=["POST"])
def recordings_delete():
    from apps.jibri import delete_recording

    filename = request.form.get("filename", "").strip()
    if not filename:
        flash("Filename is required.", "warning")
        return redirect(url_for("jibri.manage_page"))

    ok, msg = delete_recording(filename)
    flash(msg, "success" if ok else "error")
    log_action("jibri_recording_delete", "settings", resource_name="jibri",
               details={"filename": filename, "success": ok})
    db.session.commit()
    return redirect(url_for("jibri.manage_page"))
