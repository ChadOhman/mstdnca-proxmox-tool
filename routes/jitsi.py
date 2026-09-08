import logging
import threading as _threading
from datetime import datetime

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import login_required

from apps.utils import (
    JobTracker,
    _validate_email,
    _validate_hostname,
    _validate_http_url,
    _validate_ipv4,
)
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
# In-memory job state — five jobs: upgrade, preflight, install, CF configure, SD configure
# ---------------------------------------------------------------------------
_upgrade_job = JobTracker()
_preflight_job = JobTracker()
_install_job = JobTracker()
_cf_configure_job = JobTracker()
_sd_configure_job = JobTracker()

logger = logging.getLogger(__name__)

bp = Blueprint("jitsi", __name__)


@bp.before_request
@login_required
def _require_login():
    from flask_login import current_user
    if not current_user.can_update:
        flash("'Apply Updates' permission required.", "error")
        return redirect(url_for("dashboard.index"))


def _get_jitsi_settings():
    return {
        "guest_id": Setting.get("jitsi_guest_id", ""),
        "hostname": Setting.get("jitsi_hostname", ""),
        "cert_type": Setting.get("jitsi_cert_type", "self-signed"),
        "letsencrypt_email": Setting.get("jitsi_letsencrypt_email", ""),
        "url": Setting.get("jitsi_url", ""),
        "auto_upgrade": Setting.get("jitsi_auto_upgrade", "false"),
        "current_version": Setting.get("jitsi_current_version", ""),
        "latest_version": Setting.get("jitsi_latest_version", ""),
        "latest_release_url": "",
        "update_available": Setting.get("jitsi_update_available", "") == "true",
        "installed": Setting.get("jitsi_installed", "") == "true",
        "last_upgrade_at": _parse_iso(Setting.get("jitsi_last_upgrade_at", "")),
        "last_upgrade_status": Setting.get("jitsi_last_upgrade_status", ""),
        "last_upgrade_log": Setting.get("jitsi_last_upgrade_log", ""),
        "last_install_at": _parse_iso(Setting.get("jitsi_last_install_at", "")),
        "last_install_status": Setting.get("jitsi_last_install_status", ""),
        "last_install_log": Setting.get("jitsi_last_install_log", ""),
        "protection_type": Setting.get("jitsi_protection_type", "snapshot"),
        "backup_storage": Setting.get("jitsi_backup_storage", ""),
        "backup_mode": Setting.get("jitsi_backup_mode", "snapshot"),
        "cf_mode": Setting.get("jitsi_cf_mode", "none"),
        "public_ip": Setting.get("jitsi_public_ip", ""),
        "last_cf_configure_at": _parse_iso(Setting.get("jitsi_last_cf_configure_at", "")),
        "last_cf_configure_status": Setting.get("jitsi_last_cf_configure_status", ""),
        "secure_domain": Setting.get("jitsi_secure_domain", "false"),
        "last_sd_configure_at": _parse_iso(Setting.get("jitsi_last_sd_configure_at", "")),
        "last_sd_configure_status": Setting.get("jitsi_last_sd_configure_status", ""),
        "prometheus_scrape": Setting.get("jitsi_prometheus_scrape", "false"),
    }


@bp.route("/upgrade")
def upgrade_page():
    settings = _get_jitsi_settings()
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
        "jitsi.html",
        settings=settings,
        guests=guests,
        backup_storages=backup_storages,
        snapshots_supported=snapshots_supported,
        snapshot_blockers=snapshot_blockers,
    )


@bp.route("/save", methods=["POST"])
def save():
    # The hostname is interpolated into config-file paths and shell arguments on
    # the Jitsi guest, and the public IP into JVB's NAT harvester config — both
    # are allow-listed here so a hostile value is never stored in the first place.
    hostname = request.form.get("jitsi_hostname", "").strip()
    letsencrypt_email = request.form.get("jitsi_letsencrypt_email", "").strip()
    jitsi_url = request.form.get("jitsi_url", "").strip()
    public_ip = request.form.get("jitsi_public_ip", "").strip()
    try:
        if hostname:
            _validate_hostname(hostname, "Jitsi hostname")
        if letsencrypt_email:
            _validate_email(letsencrypt_email, "Let's Encrypt email")
        if jitsi_url:
            _validate_http_url(jitsi_url, "Jitsi URL")
        if public_ip:
            _validate_ipv4(public_ip, "Public IP")
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("jitsi.upgrade_page"))

    Setting.set("jitsi_guest_id", request.form.get("jitsi_guest_id", "").strip())
    Setting.set("jitsi_hostname", hostname)
    cert_type = request.form.get("jitsi_cert_type", "self-signed")
    Setting.set("jitsi_cert_type",
                cert_type if cert_type in ("letsencrypt", "self-signed", "custom") else "self-signed")
    Setting.set("jitsi_letsencrypt_email", letsencrypt_email)
    Setting.set("jitsi_url", jitsi_url)
    Setting.set("jitsi_current_version", request.form.get("jitsi_current_version", "").strip())
    Setting.set("jitsi_auto_upgrade",
                "true" if "jitsi_auto_upgrade" in request.form else "false")
    protection_type = request.form.get("jitsi_protection_type", "snapshot")
    Setting.set("jitsi_protection_type",
                protection_type if protection_type in ("snapshot", "backup") else "snapshot")
    Setting.set("jitsi_backup_storage", request.form.get("jitsi_backup_storage", "").strip())
    backup_mode = request.form.get("jitsi_backup_mode", "snapshot")
    Setting.set("jitsi_backup_mode",
                backup_mode if backup_mode in ("snapshot", "suspend", "stop") else "snapshot")

    cf_mode = request.form.get("jitsi_cf_mode", "none")
    Setting.set("jitsi_cf_mode", cf_mode if cf_mode in ("none", "tcp_only", "hybrid") else "none")
    Setting.set("jitsi_public_ip", public_ip)

    Setting.set("jitsi_secure_domain",
                "true" if "jitsi_secure_domain" in request.form else "false")

    new_scrape = "true" if "jitsi_prometheus_scrape" in request.form else "false"
    old_scrape = Setting.get("jitsi_prometheus_scrape", "false")
    Setting.set("jitsi_prometheus_scrape", new_scrape)

    log_action("jitsi_config_save", "settings", resource_name="jitsi")
    db.session.commit()

    # Regenerate Prometheus config and update JVB REST API binding when scrape toggle changes
    if new_scrape != old_scrape:
        try:
            from apps.exporters import _regenerate_prometheus_config
            _regenerate_prometheus_config()
        except Exception:
            logger.warning("Failed to regenerate Prometheus config after JVB scrape toggle", exc_info=True)
        # Configure JVB REST API to listen on 0.0.0.0 (or revert to 127.0.0.1)
        try:
            from apps.jitsi import configure_jvb_rest_binding
            ok, msg = configure_jvb_rest_binding(bind_all=(new_scrape == "true"))
            if ok:
                logger.info("JVB REST binding: %s", msg)
            else:
                logger.warning("JVB REST binding failed: %s", msg)
                flash(f"Warning: Could not configure JVB REST API binding: {msg}", "warning")
        except Exception:
            logger.warning("Failed to configure JVB REST API binding", exc_info=True)
    flash("Jitsi settings saved.", "success")
    return redirect(url_for("jitsi.upgrade_page"))


@bp.route("/check", methods=["POST"])
def check():
    from apps.jitsi import check_jitsi_release

    guest_id = Setting.get("jitsi_guest_id", "")
    if not guest_id:
        flash("Jitsi guest is not configured. Cannot check for updates.", "warning")
        return redirect(url_for("jitsi.upgrade_page"))

    update_available, latest, release_url = check_jitsi_release()
    current = Setting.get("jitsi_current_version", "")

    if not latest:
        flash("Could not fetch latest Jitsi version. Check that the guest is reachable via SSH or guest agent "
              "and that the Jitsi apt repository is configured.", "error")
    elif update_available:
        flash(f"Jitsi update available: v{current} \u2192 v{latest}", "warning")
    elif current:
        flash(f"Jitsi is up to date (v{current}).", "success")
    else:
        flash(
            f"Latest Jitsi version: v{latest}. "
            "Set your current version to enable update detection.",
            "info",
        )

    return redirect(url_for("jitsi.upgrade_page"))


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

    from apps.jitsi import run_jitsi_preflight

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
                ok, _ = run_jitsi_preflight(log_callback=_cb)
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

    from apps.jitsi import run_jitsi_upgrade
    from apps.utils import acquire_upgrade_lock, release_upgrade_lock

    if _install_job["running"]:
        flash("An operation is already in progress.", "warning")
        return redirect(url_for("jitsi.upgrade_page"))
    # Atomic check-and-set, shared with the scheduler's auto-upgrade job so a
    # cron upgrade and a manual one can never run against the same host at once.
    if not acquire_upgrade_lock("jitsi"):
        flash("An operation is already in progress.", "warning")
        return redirect(url_for("jitsi.upgrade_page"))

    skip_protection = (
        current_user.is_super_admin
        and request.form.get("skip_protection") == "1"
    )

    _upgrade_job.update({"running": True, "success": None, "log": []})
    target_version = Setting.get("jitsi_latest_version", "")

    def _cb(msg):
        _upgrade_job["log"].append(msg)

    _app = current_app._get_current_object()

    def _bg():
        ok = False
        try:
            with _app.app_context():
                from core.notifier import send_upgrade_started_notification
                send_upgrade_started_notification("jitsi", target_version, "manual")
                ok, _ = run_jitsi_upgrade(log_callback=_cb, skip_protection=skip_protection)
        except Exception as e:
            _cb(f"FATAL ERROR: {e}")
            ok = False
        _upgrade_job["running"] = False
        _upgrade_job["success"] = ok
        from datetime import datetime, timezone
        with _app.app_context():
            now = datetime.now(timezone.utc).isoformat()
            Setting.set("jitsi_last_upgrade_at", now)
            Setting.set("jitsi_last_upgrade_status", "success" if ok else "error")
            Setting.set("jitsi_last_upgrade_log", "\n".join(_upgrade_job["log"]))
            log_action("jitsi_upgrade", "settings", resource_name="jitsi",
                       details={"status": "success" if ok else "error"})
            db.session.commit()
            from core.notifier import send_upgrade_result_notification
            send_upgrade_result_notification("jitsi", target_version, ok, "manual")

    def _bg_locked():
        try:
            _bg()
        finally:
            _upgrade_job["running"] = False
            release_upgrade_lock("jitsi")

    try:
        import gevent as _gevent
        _gevent.spawn(_bg_locked)
    except ImportError:
        _threading.Thread(target=_bg_locked, daemon=True).start()

    return redirect(url_for("jitsi.upgrade_page"))


@bp.route("/install", methods=["POST"])
def install():
    from flask import current_app

    from apps.jitsi import run_jitsi_install

    if _upgrade_job["running"] or _install_job["running"]:
        flash("An operation is already in progress.", "warning")
        return redirect(url_for("jitsi.upgrade_page"))

    _install_job.update({"running": True, "success": None, "log": []})

    def _cb(msg):
        _install_job["log"].append(msg)

    _app = current_app._get_current_object()

    def _bg():
        ok = False
        try:
            with _app.app_context():
                ok, _ = run_jitsi_install(log_callback=_cb)
        except Exception as e:
            _cb(f"FATAL ERROR: {e}")
            ok = False
        _install_job["running"] = False
        _install_job["success"] = ok
        from datetime import datetime, timezone
        with _app.app_context():
            now = datetime.now(timezone.utc).isoformat()
            Setting.set("jitsi_last_install_at", now)
            Setting.set("jitsi_last_install_status", "success" if ok else "error")
            Setting.set("jitsi_last_install_log", "\n".join(_install_job["log"]))
            if ok:
                Setting.set("jitsi_installed", "true")
            log_action("jitsi_install", "settings", resource_name="jitsi",
                       details={"status": "success" if ok else "error"})
            db.session.commit()

    try:
        import gevent as _gevent
        _gevent.spawn(_bg)
    except ImportError:
        _threading.Thread(target=_bg, daemon=True).start()

    return redirect(url_for("jitsi.upgrade_page"))


@bp.route("/detect-versions", methods=["POST"])
def detect_versions():
    from apps.jitsi import detect_jitsi_version

    guest_id = Setting.get("jitsi_guest_id", "")

    if not guest_id:
        flash("Jitsi guest is not configured.", "warning")
        return redirect(url_for("jitsi.upgrade_page"))

    try:
        guest = Guest.query.get(int(guest_id))
    except (TypeError, ValueError):
        flash("Invalid Jitsi guest ID.", "error")
        return redirect(url_for("jitsi.upgrade_page"))

    if not guest:
        flash("Jitsi guest not found.", "error")
        return redirect(url_for("jitsi.upgrade_page"))

    version, error = detect_jitsi_version(guest)
    if version:
        Setting.set("jitsi_current_version", version)
        if Setting.get("jitsi_installed") != "true":
            Setting.set("jitsi_installed", "true")
        db.session.commit()
        flash(f"Detected Jitsi version: {version}", "success")
    else:
        # Jitsi not found on guest — reset installed state
        if Setting.get("jitsi_installed") == "true":
            Setting.set("jitsi_installed", "false")
            Setting.set("jitsi_current_version", "")
            db.session.commit()
            flash(f"Jitsi not found on guest: {error}. Marked as not installed.", "warning")
        else:
            flash(f"Could not detect Jitsi version: {error}", "warning")

    return redirect(url_for("jitsi.upgrade_page"))


# ---------------------------------------------------------------------------
# Cloudflare Zero Trust configuration
# ---------------------------------------------------------------------------

@bp.route("/configure-cloudflare/status")
def cf_configure_status():
    return jsonify({
        "running": _cf_configure_job["running"],
        "success": _cf_configure_job["success"],
        "log": _cf_configure_job["log"],
    })


@bp.route("/configure-cloudflare", methods=["POST"])
def cf_configure():
    from flask import current_app

    from apps.jitsi import run_cloudflare_configure

    if Setting.get("jitsi_installed", "") != "true":
        flash("Jitsi must be installed before configuring Cloudflare.", "warning")
        return redirect(url_for("jitsi.upgrade_page"))

    if (_cf_configure_job["running"] or _upgrade_job["running"]
            or _install_job["running"] or _sd_configure_job["running"]):
        flash("An operation is already in progress.", "warning")
        return redirect(url_for("jitsi.upgrade_page"))

    _cf_configure_job.update({"running": True, "success": None, "log": []})

    def _cb(msg):
        _cf_configure_job["log"].append(msg)

    _app = current_app._get_current_object()

    def _bg():
        ok = False
        try:
            with _app.app_context():
                ok, _ = run_cloudflare_configure(log_callback=_cb)
        except Exception as e:
            _cb(f"FATAL ERROR: {e}")
            ok = False
        _cf_configure_job["running"] = False
        _cf_configure_job["success"] = ok
        from datetime import datetime, timezone
        with _app.app_context():
            now = datetime.now(timezone.utc).isoformat()
            Setting.set("jitsi_last_cf_configure_at", now)
            Setting.set("jitsi_last_cf_configure_status", "success" if ok else "error")
            Setting.set("jitsi_last_cf_configure_log", "\n".join(_cf_configure_job["log"]))
            log_action("jitsi_cf_configure", "settings", resource_name="jitsi",
                       details={"status": "success" if ok else "error",
                                "mode": Setting.get("jitsi_cf_mode", "none")})
            db.session.commit()

    try:
        import gevent as _gevent
        _gevent.spawn(_bg)
    except ImportError:
        _threading.Thread(target=_bg, daemon=True).start()

    return redirect(url_for("jitsi.upgrade_page"))


# ---------------------------------------------------------------------------
# Secure Domain configuration
# ---------------------------------------------------------------------------

@bp.route("/configure-secure-domain/status")
def sd_configure_status():
    return jsonify({
        "running": _sd_configure_job["running"],
        "success": _sd_configure_job["success"],
        "log": _sd_configure_job["log"],
    })


@bp.route("/configure-secure-domain", methods=["POST"])
def sd_configure():
    from flask import current_app

    from apps.jitsi import run_secure_domain_configure

    if Setting.get("jitsi_installed", "") != "true":
        flash("Jitsi must be installed before configuring Secure Domain.", "warning")
        return redirect(url_for("jitsi.upgrade_page"))

    if (_sd_configure_job["running"] or _cf_configure_job["running"]
            or _upgrade_job["running"] or _install_job["running"]):
        flash("An operation is already in progress.", "warning")
        return redirect(url_for("jitsi.upgrade_page"))

    # Persist the checkbox state so the background job reads the correct value
    sd_enabled = request.form.get("secure_domain_enabled") == "1"
    Setting.set("jitsi_secure_domain", "true" if sd_enabled else "false")
    db.session.commit()

    _sd_configure_job.update({"running": True, "success": None, "log": []})

    def _cb(msg):
        _sd_configure_job["log"].append(msg)

    _app = current_app._get_current_object()

    def _bg():
        ok = False
        try:
            with _app.app_context():
                ok, _ = run_secure_domain_configure(log_callback=_cb)
        except Exception as e:
            _cb(f"FATAL ERROR: {e}")
            ok = False
        _sd_configure_job["running"] = False
        _sd_configure_job["success"] = ok
        from datetime import datetime, timezone
        with _app.app_context():
            now = datetime.now(timezone.utc).isoformat()
            Setting.set("jitsi_last_sd_configure_at", now)
            Setting.set("jitsi_last_sd_configure_status", "success" if ok else "error")
            Setting.set("jitsi_last_sd_configure_log", "\n".join(_sd_configure_job["log"]))
            log_action("jitsi_sd_configure", "settings", resource_name="jitsi",
                       details={"status": "success" if ok else "error",
                                "enabled": Setting.get("jitsi_secure_domain", "false")})
            db.session.commit()

    try:
        import gevent as _gevent
        _gevent.spawn(_bg)
    except ImportError:
        _threading.Thread(target=_bg, daemon=True).start()

    return redirect(url_for("jitsi.upgrade_page"))


@bp.route("/secure-domain/users")
def sd_list_users_route():
    from apps.jitsi import sd_list_users

    if Setting.get("jitsi_installed", "") != "true":
        return jsonify({"users": [], "error": "Jitsi not installed"})

    users, error = sd_list_users()
    return jsonify({"users": users, "error": error})


@bp.route("/secure-domain/add-user", methods=["POST"])
def sd_add_user_route():
    from apps.jitsi import sd_add_user

    if Setting.get("jitsi_installed", "") != "true":
        flash("Jitsi must be installed first.", "warning")
        return redirect(url_for("jitsi.upgrade_page"))

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    ok, msg = sd_add_user(username, password)
    flash(msg, "success" if ok else "error")
    log_action("jitsi_sd_add_user", "settings", resource_name="jitsi",
               details={"username": username, "success": ok})
    db.session.commit()
    return redirect(url_for("jitsi.upgrade_page"))


@bp.route("/secure-domain/remove-user", methods=["POST"])
def sd_remove_user_route():
    from apps.jitsi import sd_remove_user

    if Setting.get("jitsi_installed", "") != "true":
        flash("Jitsi must be installed first.", "warning")
        return redirect(url_for("jitsi.upgrade_page"))

    username = request.form.get("username", "").strip()

    ok, msg = sd_remove_user(username)
    flash(msg, "success" if ok else "error")
    log_action("jitsi_sd_remove_user", "settings", resource_name="jitsi",
               details={"username": username, "success": ok})
    db.session.commit()
    return redirect(url_for("jitsi.upgrade_page"))
