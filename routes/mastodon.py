import logging
import re
import threading as _threading
from datetime import datetime

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import login_required

from apps.utils import _SHELL_SAFE_RE, JobTracker
from auth.audit import log_action
from models import Guest, Setting, db

# ---------------------------------------------------------------------------
# In-memory upgrade job state — tracks the currently-running upgrade so the
# frontend can poll for real-time log output.
# ---------------------------------------------------------------------------
_upgrade_job = JobTracker()
_preflight_job = JobTracker()

logger = logging.getLogger(__name__)

bp = Blueprint("mastodon", __name__)


@bp.before_request
@login_required
def _require_login():
    from flask_login import current_user
    if not current_user.can_update:
        flash("'Apply Updates' permission required.", "error")
        return redirect(url_for("dashboard.index"))


def _parse_iso(value):
    """Parse an ISO 8601 string into a timezone-aware datetime, or return None."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


def _get_mastodon_settings():
    return {
        "guest_id": Setting.get("mastodon_guest_id", ""),
        "db_guest_id": Setting.get("mastodon_db_guest_id", ""),
        "user": Setting.get("mastodon_user", "mastodon"),
        "app_dir": Setting.get("mastodon_app_dir", "/home/mastodon/live"),
        "repo": Setting.get("mastodon_repo", "mastodon/mastodon"),
        "branch": Setting.get("mastodon_branch", ""),
        "pgbouncer_host": Setting.get("mastodon_pgbouncer_host", ""),
        "pgbouncer_port": Setting.get("mastodon_pgbouncer_port", ""),
        "direct_db_host": Setting.get("mastodon_direct_db_host", ""),
        "direct_db_port": Setting.get("mastodon_direct_db_port", "5432"),
        "auto_upgrade": Setting.get("mastodon_auto_upgrade", "false"),
        "current_version": Setting.get("mastodon_current_version", ""),
        "pg_version": Setting.get("mastodon_pg_version", ""),
        "latest_version": Setting.get("mastodon_latest_version", ""),
        "latest_release_url": Setting.get("mastodon_latest_release_url", ""),
        "update_available": Setting.get("mastodon_update_available", "") == "true",
        "pg_latest_version": Setting.get("mastodon_pg_latest_version", ""),
        "last_upgrade_at": _parse_iso(Setting.get("mastodon_last_upgrade_at", "")),
        "last_upgrade_status": Setting.get("mastodon_last_upgrade_status", ""),
        "last_upgrade_log": Setting.get("mastodon_last_upgrade_log", ""),
        "protection_type": Setting.get("mastodon_protection_type", "snapshot"),
        "backup_storage": Setting.get("mastodon_backup_storage", ""),
        "backup_mode": Setting.get("mastodon_backup_mode", "snapshot"),
        "guest_id_2": Setting.get("mastodon_guest_id_2", ""),
    }


@bp.route("/upgrade")
def upgrade_page():
    settings = _get_mastodon_settings()
    guests = Guest.query.filter_by(enabled=True).order_by(Guest.name).all()

    backup_storages = []
    snapshots_supported = True  # assume True until proven otherwise
    snapshot_blockers = []  # guest names that don't support snapshots

    guest_id = settings.get("guest_id", "")
    guest_id_2 = settings.get("guest_id_2", "")
    db_guest_id = settings.get("db_guest_id", "")

    guests_to_check = []
    for gid in (guest_id, guest_id_2, db_guest_id):
        if gid:
            g = Guest.query.get(int(gid))
            if g:
                guests_to_check.append(g)

    if guests_to_check:
        primary = guests_to_check[0]
        if primary.proxmox_host and not primary.proxmox_host.is_pbs:
            try:
                from clients.proxmox_api import ProxmoxClient
                client = ProxmoxClient(primary.proxmox_host)

                # Backup storages (from primary app guest's host)
                node = client.find_guest_node(primary.vmid)
                if node:
                    backup_storages = client.list_node_storages(node, content_type="backup")

                # Snapshot capability check for all configured guests
                for g in guests_to_check:
                    g_node = client.find_guest_node(g.vmid)
                    if g_node and not client.guest_supports_snapshot(g_node, g.vmid, g.guest_type):
                        snapshots_supported = False
                        snapshot_blockers.append(g.name)
            except Exception as e:
                logger.warning(f"Could not check snapshot/backup support: {e}")

    return render_template(
        "mastodon.html",
        settings=settings,
        guests=guests,
        backup_storages=backup_storages,
        snapshots_supported=snapshots_supported,
        snapshot_blockers=snapshot_blockers,
    )


@bp.route("/save", methods=["POST"])
def save():
    Setting.set("mastodon_guest_id", request.form.get("mastodon_guest_id", "").strip())
    Setting.set("mastodon_guest_id_2", request.form.get("mastodon_guest_id_2", "").strip())
    Setting.set("mastodon_db_guest_id", request.form.get("mastodon_db_guest_id", "").strip())
    Setting.set("mastodon_db_name", request.form.get("mastodon_db_name", "mastodon_production").strip() or "mastodon_production")
    Setting.set("mastodon_user", request.form.get("mastodon_user", "mastodon").strip())
    Setting.set("mastodon_app_dir", request.form.get("mastodon_app_dir", "/home/mastodon/live").strip())
    Setting.set("mastodon_repo", request.form.get("mastodon_repo", "mastodon/mastodon").strip())
    Setting.set("mastodon_branch", request.form.get("mastodon_branch", "").strip())
    pgbouncer_host = request.form.get("mastodon_pgbouncer_host", "").strip()
    pgbouncer_port = request.form.get("mastodon_pgbouncer_port", "").strip()
    direct_db_host = request.form.get("mastodon_direct_db_host", "").strip()
    direct_db_port = request.form.get("mastodon_direct_db_port", "5432").strip()

    for label, val in [("PGBouncer host", pgbouncer_host), ("Direct DB host", direct_db_host)]:
        if val and not _SHELL_SAFE_RE.match(val):
            flash(f"Invalid {label}: only alphanumeric, dots, hyphens, colons, and slashes are allowed.", "error")
            return redirect(url_for("mastodon.upgrade_page"))
    for label, val in [("PGBouncer port", pgbouncer_port), ("Direct DB port", direct_db_port)]:
        if val and not re.match(r'^\d+$', val):
            flash(f"Invalid {label}: must be numeric.", "error")
            return redirect(url_for("mastodon.upgrade_page"))

    Setting.set("mastodon_pgbouncer_host", pgbouncer_host)
    Setting.set("mastodon_pgbouncer_port", pgbouncer_port)
    Setting.set("mastodon_direct_db_host", direct_db_host)
    Setting.set("mastodon_direct_db_port", direct_db_port)
    Setting.set("mastodon_auto_upgrade", "true" if "mastodon_auto_upgrade" in request.form else "false")
    Setting.set("mastodon_current_version", request.form.get("mastodon_current_version", "").strip())
    protection_type = request.form.get("mastodon_protection_type", "snapshot")
    Setting.set("mastodon_protection_type", protection_type if protection_type in ("snapshot", "backup") else "snapshot")
    Setting.set("mastodon_backup_storage", request.form.get("mastodon_backup_storage", "").strip())
    backup_mode = request.form.get("mastodon_backup_mode", "snapshot")
    Setting.set("mastodon_backup_mode", backup_mode if backup_mode in ("snapshot", "suspend", "stop") else "snapshot")

    log_action("mastodon_config_save", "settings", resource_name="mastodon")
    db.session.commit()
    flash("Mastodon settings saved.", "success")
    return redirect(url_for("mastodon.upgrade_page"))


@bp.route("/check", methods=["POST"])
def check():
    from apps.mastodon import check_mastodon_release

    update_available, latest, release_url = check_mastodon_release()
    current = Setting.get("mastodon_current_version", "")

    if not latest:
        flash("Could not fetch latest Mastodon release from GitHub.", "error")
    elif update_available:
        flash(f"Mastodon update available: v{current} -> v{latest}", "warning")
    elif current:
        flash(f"Mastodon is up to date (v{current}).", "success")
    else:
        flash(f"Latest Mastodon release: v{latest}. Set your current version to enable update detection.", "info")

    return redirect(url_for("mastodon.upgrade_page"))


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

    from apps.mastodon import run_mastodon_preflight

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
                ok, _ = run_mastodon_preflight(log_callback=_cb)
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

    from apps.mastodon import run_mastodon_upgrade

    if _upgrade_job["running"]:
        flash("An upgrade is already in progress.", "warning")
        return redirect(url_for("mastodon.upgrade_page"))

    # Only super-admins may skip the snapshot/backup step
    skip_protection = (
        current_user.is_super_admin
        and request.form.get("skip_protection") == "1"
    )

    _upgrade_job.update({"running": True, "success": None, "log": []})
    target_version = Setting.get("mastodon_latest_version", "")

    def _cb(msg):
        _upgrade_job["log"].append(msg)

    _app = current_app._get_current_object()

    def _bg():
        ok = False
        try:
            with _app.app_context():
                from core.notifier import send_upgrade_started_notification
                send_upgrade_started_notification("mastodon", target_version, "manual")
                ok, _ = run_mastodon_upgrade(log_callback=_cb, skip_protection=skip_protection)
        except Exception as e:
            _cb(f"FATAL ERROR: {e}")
            ok = False
        _upgrade_job["running"] = False
        _upgrade_job["success"] = ok
        from datetime import datetime, timezone
        with _app.app_context():
            now = datetime.now(timezone.utc).isoformat()
            Setting.set("mastodon_last_upgrade_at", now)
            Setting.set("mastodon_last_upgrade_status", "success" if ok else "error")
            Setting.set("mastodon_last_upgrade_log", "\n".join(_upgrade_job["log"]))
            log_action("mastodon_upgrade", "settings", resource_name="mastodon",
                       details={"status": "success" if ok else "error"})
            db.session.commit()
            from core.notifier import send_upgrade_result_notification
            send_upgrade_result_notification("mastodon", target_version, ok, "manual")

    try:
        import gevent as _gevent
        _gevent.spawn(_bg)
    except ImportError:
        _threading.Thread(target=_bg, daemon=True).start()

    return redirect(url_for("mastodon.upgrade_page"))


@bp.route("/detect-versions", methods=["POST"])
def detect_versions():
    from apps.mastodon import _validate_shell_param
    from core.scanner import _execute_command

    guest_id = Setting.get("mastodon_guest_id", "")
    db_guest_id = Setting.get("mastodon_db_guest_id", "")
    user = Setting.get("mastodon_user", "mastodon")
    app_dir = Setting.get("mastodon_app_dir", "/home/mastodon/live")

    try:
        _validate_shell_param(user, "Mastodon user")
        _validate_shell_param(app_dir, "Mastodon app_dir")
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("mastodon.upgrade_page"))

    detected = []

    # Detect Mastodon version
    if guest_id:
        mastodon_guest = Guest.query.get(int(guest_id))
        if mastodon_guest:
            # Read lib/mastodon/version.rb and reconstruct the version string.
            # Supports two formats:
            #   - Constant-style:  MAJOR = 4  (older Mastodon)
            #   - Method-style:    def major\n  4\nend  (newer Mastodon/glitch-soc)
            # build_metadata may be a literal in version.rb (constant-style) or read
            # from Rails config at runtime (method-style).  When it is not in version.rb,
            # fall back to grepping the config directory.
            import re as _re

            def _find_first(patterns, text):
                for pat in patterns:
                    m = _re.search(pat, text)
                    if m:
                        return m.group(1)
                return None

            stdout, error = _execute_command(
                mastodon_guest,
                f"su - {user} -c 'cat {app_dir}/lib/mastodon/version.rb 2>/dev/null'",
                timeout=15,
                sudo=True,
            )
            version = None
            if stdout and not error:
                major = _find_first([r'MAJOR\s*=\s*(\d+)', r'def major\s+(\d+)'], stdout)
                minor = _find_first([r'MINOR\s*=\s*(\d+)', r'def minor\s+(\d+)'], stdout)
                patch = _find_first([r'PATCH\s*=\s*(\d+)', r'def patch\s+(\d+)'], stdout)
                pre   = _find_first([r"PRE\s*=\s*['\"]([^'\"]+)['\"]",
                                     r"def default_prerelease\s+['\"]([^'\"]+)['\"]"], stdout)
                build = _find_first([r"BUILD_METADATA\s*=\s*['\"]([^'\"]+)['\"]"], stdout)

                if major and minor and patch:
                    version = f"{major}.{minor}.{patch}"
                    if pre:
                        version += f"-{pre}"
                    if build:
                        version += f"+{build}"

            # build_metadata is not a literal in method-style version.rb (it reads from
            # Rails config).  Search config files for the metadata value.
            if version and '+' not in version:
                meta_out, _ = _execute_command(
                    mastodon_guest,
                    f"su - {user} -c 'grep -rh \"metadata\" {app_dir}/config/ 2>/dev/null"
                    r" | grep -v \"^\s*#\"'",
                    timeout=10,
                    sudo=True,
                )
                if meta_out:
                    m = _re.search(
                        r":metadata\s*=>\s*['\"]([^'\"]+)['\"]"
                        r"|metadata:\s*['\"]([^'\"]+)['\"]",
                        meta_out,
                    )
                    if m:
                        build_val = m.group(1) or m.group(2)
                        if build_val:
                            version += f"+{build_val}"

            if version:
                Setting.set("mastodon_current_version", version)
                detected.append(f"Mastodon: v{version}")
            else:
                logger.warning(f"Mastodon version detection failed: {error or 'could not parse version.rb'}")
                flash(f"Could not detect Mastodon version: {error or 'could not parse lib/mastodon/version.rb'}", "warning")
        else:
            flash("Mastodon app guest not found.", "error")
    else:
        flash("Mastodon app guest not configured.", "warning")

    # Detect PostgreSQL version
    if db_guest_id:
        db_guest = Guest.query.get(int(db_guest_id))
        if db_guest:
            stdout, error = _execute_command(
                db_guest,
                "psql --version 2>/dev/null || postgres --version 2>/dev/null",
                timeout=15,
            )
            if stdout and not error:
                import re
                match = re.search(r"(\d+[\.\d]*)", stdout.strip())
                if match:
                    pg_version = match.group(1)
                    Setting.set("mastodon_pg_version", pg_version)
                    detected.append(f"PostgreSQL: {pg_version}")

                    # Check apt for a newer patch version of this major release
                    pg_major = pg_version.split(".")[0]
                    upg_out, _ = _execute_command(
                        db_guest,
                        f"apt list --upgradable 2>/dev/null | grep -i 'postgresql-{pg_major}/'",
                        timeout=15,
                    )
                    if upg_out and upg_out.strip():
                        # e.g. "postgresql-18/focal-pgdg 18.4-1.pgdg22.04+1 amd64 [upgradable from: 18.3-...]"
                        upg_match = re.search(r"postgresql-\d+/\S+\s+([\d.]+)", upg_out.strip())
                        if upg_match:
                            Setting.set("mastodon_pg_latest_version", upg_match.group(1))
                        else:
                            Setting.set("mastodon_pg_latest_version", "")
                    else:
                        Setting.set("mastodon_pg_latest_version", "")
            elif error:
                logger.warning(f"PostgreSQL version detection failed: {error}")
                flash(f"Could not detect PostgreSQL version: {error}", "warning")
        else:
            flash("PostgreSQL guest not found.", "error")
    else:
        flash("PostgreSQL guest not configured.", "warning")

    if detected:
        flash(f"Detected: {', '.join(detected)}", "success")

    return redirect(url_for("mastodon.upgrade_page"))


@bp.route("/follow-account", methods=["POST"])
def follow_account():
    """Make every local account follow a given local account via tootctl.

    Runs, on the Mastodon app guest:
        sudo su - <user> -c '<rbenv PATH>; cd <app_dir> &&
            RAILS_ENV=production bin/tootctl accounts follow <account>'
    The rbenv PATH + cd are required so ruby and bin/tootctl resolve in the
    non-login `su -c` shell (same form the upgrade uses for `tootctl cache clear`).
    """
    from apps.mastodon import _RBENV_PATH, _validate_shell_param
    from core.scanner import _execute_command

    account = (request.form.get("account") or "announcements").strip()
    if not re.match(r'^[A-Za-z0-9_]{1,30}$', account):
        flash("Invalid account username — use letters, numbers, or underscore only.", "error")
        return redirect(url_for("mastodon.upgrade_page"))

    guest_id = Setting.get("mastodon_guest_id", "")
    user = Setting.get("mastodon_user", "mastodon")
    app_dir = Setting.get("mastodon_app_dir", "/home/mastodon/live")

    if not guest_id:
        flash("Mastodon app guest not configured.", "warning")
        return redirect(url_for("mastodon.upgrade_page"))

    try:
        _validate_shell_param(user, "Mastodon user")
        _validate_shell_param(app_dir, "Mastodon app_dir")
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("mastodon.upgrade_page"))

    mastodon_guest = Guest.query.get(int(guest_id))
    if not mastodon_guest:
        flash("Mastodon app guest not found.", "error")
        return redirect(url_for("mastodon.upgrade_page"))

    command = (
        f"su - {user} -c '{_RBENV_PATH}; cd {app_dir} && "
        f"RAILS_ENV=production bin/tootctl accounts follow {account}'"
    )
    stdout, error = _execute_command(mastodon_guest, command, timeout=300, sudo=True)

    log_action("mastodon_follow_account", "settings", resource_name="mastodon",
               details={"account": account, "ok": not error})
    db.session.commit()

    if error:
        flash(f"Failed to make accounts follow @{account}: {error}", "error")
    else:
        tail = (stdout or "").strip()
        tail = tail[-500:] if len(tail) > 500 else tail
        flash(f"All local accounts now follow @{account}." + (f"\n{tail}" if tail else ""), "success")

    return redirect(url_for("mastodon.upgrade_page"))
