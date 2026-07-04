import logging
import queue
import threading
import time
import zoneinfo
from datetime import datetime, timezone

from flask import Blueprint, Response, flash, jsonify, redirect, render_template, request, stream_with_context, url_for
from flask_login import current_user, login_required

from auth.audit import log_action
from core.notifier import send_update_notification
from core.scanner import scan_all_guests, scan_guest
from models import Guest, ProxmoxHost, Setting, Tag, db

logger = logging.getLogger(__name__)


def _user_tz():
    """Return the current user's ZoneInfo or UTC as fallback."""
    try:
        if current_user.is_authenticated and current_user.timezone:
            return zoneinfo.ZoneInfo(current_user.timezone)
    except Exception:
        pass
    return timezone.utc

bp = Blueprint("api", __name__)

# In-memory store for running update jobs keyed by guest_id
_update_jobs = {}
_jobs_lock = threading.Lock()

# In-memory state for a single "update all guests" run. One run at a time;
# each guest is updated sequentially by a single orchestrator thread that
# reuses the per-guest _run_update_background worker.
_bulk_update = {
    "running": False,
    "started_at": None,
    "total": 0,
    "done": 0,
    "items": [],   # list of {"guest_id", "name", "state", "reason"}
}
_bulk_update_lock = threading.Lock()


class UpdateJob:
    """Tracks a background guest update."""

    def __init__(self, guest_id, guest_name):
        self.guest_id = guest_id
        self.guest_name = guest_name
        self.log = ""
        self.running = True
        self.success = None  # None=in progress, True=success, False=failed
        self.cancel_requested = False
        self.cancelled = False
        self.reboot_required = False
        self.started_at = datetime.now(timezone.utc)
        self._lock = threading.Lock()

    def append(self, text):
        with self._lock:
            self.log += text

    def finish(self, success):
        with self._lock:
            self.running = False
            self.success = success
            if not success and self.cancel_requested:
                self.cancelled = True

    def to_dict(self):
        with self._lock:
            return {
                "guest_id": self.guest_id,
                "guest_name": self.guest_name,
                "log": self.log,
                "running": self.running,
                "success": self.success,
                "cancelled": self.cancelled,
                "reboot_required": self.reboot_required,
                "started_at": self.started_at.isoformat(),
            }


def _run_update_background(app, guest_id, dist_upgrade=False):
    """Run apt upgrade in a background thread with streaming output."""
    from clients.proxmox_api import ProxmoxClient
    from clients.ssh_client import SSHClient

    with app.app_context():
        job = _update_jobs.get(guest_id)
        if not job:
            return

        guest = Guest.query.get(guest_id)
        if not guest:
            job.append("[Error] Guest not found.\n")
            job.finish(False)
            return

        cmd = (
            "DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y"
            if dist_upgrade
            else "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"
        )

        try:
            # SSH path — preferred for updates (streaming output, long timeout support).
            # Try SSH even for "agent" connection method if the guest has a usable IP.
            has_usable_ip = guest.ip_address and guest.ip_address.lower() not in ("dhcp", "dhcp6", "auto")
            if has_usable_ip:
                credential = guest.credential
                if not credential:
                    from models import Credential
                    credential = Credential.query.filter_by(is_default=True).first()

                if credential:
                    job.append(f"Connecting to {guest.name} ({guest.ip_address}) via SSH...\n")
                    try:
                        with SSHClient.from_credential(guest.ip_address, credential) as ssh:
                            job.append("$ apt-get update\n")
                            update_code = ssh.execute_sudo_streaming(
                                "apt-get update", job.append, timeout=120,
                                stop_fn=lambda: job.cancel_requested,
                            )
                            if job.cancel_requested:
                                job.append("\n[Cancelled by user]\n")
                                job.finish(False)
                                return
                            if update_code != 0:
                                job.append(f"\napt-get update exited with code {update_code}.\n")

                            job.append(f"\n$ {cmd}\n")
                            exit_code = ssh.execute_sudo_streaming(
                                cmd, job.append, timeout=600,
                                stop_fn=lambda: job.cancel_requested,
                            )
                            if job.cancel_requested:
                                job.append("\n[Cancelled by user]\n")
                                job.finish(False)
                                return

                            if exit_code == 0:
                                job.append("\n\nUpdates applied successfully.\n")
                                # Check reboot-required while SSH connection is still open
                                rb_out, _, _ = ssh.execute_sudo(
                                    "[ -f /var/run/reboot-required ] && echo yes || echo no",
                                    timeout=10,
                                )
                                reboot_needed = bool(rb_out) and rb_out.strip() == "yes"
                                guest.reboot_required = reboot_needed
                                job.reboot_required = reboot_needed
                                now = datetime.now(timezone.utc)
                                # Count applied packages from the pending list BEFORE
                                # commit: applied_at is a naive column, so a post-commit
                                # `applied_at == now` (tz-aware) match always fails and
                                # would report "0 update(s) applied".
                                from core.notifier import (
                                    send_updates_applied_notification,
                                    summarize_applied_packages,
                                )
                                applied_pkgs = list(guest.pending_updates())
                                applied_count, security_count = summarize_applied_packages(applied_pkgs)
                                for pkg in applied_pkgs:
                                    pkg.status = "applied"
                                    pkg.applied_at = now
                                guest.status = "up-to-date"
                                db.session.commit()
                                try:
                                    send_updates_applied_notification([{
                                        "name": guest.name,
                                        "type": guest.guest_type.upper(),
                                        "applied": applied_count,
                                        "security": security_count,
                                    }])
                                except Exception:
                                    pass
                                job.finish(True)
                                return
                            else:
                                job.append(f"\n\napt exited with code {exit_code}.\n")
                                job.finish(False)
                                return
                    except Exception as e:
                        if guest.connection_method == "ssh":
                            job.append(f"\n[SSH Error] {e}\n")
                            job.finish(False)
                            return
                        job.append("SSH failed, trying guest agent...\n")

            # Guest agent path (non-streaming fallback)
            if guest.connection_method in ("agent", "auto") and guest.proxmox_host and guest.guest_type == "vm":
                job.append(f"Connecting to {guest.name} via QEMU guest agent...\n")
                try:
                    client = ProxmoxClient(guest.proxmox_host)
                    all_guests = client.get_all_guests()
                    node = None
                    for g in all_guests:
                        if g.get("vmid") == guest.vmid:
                            node = g.get("node")
                            break

                    if node:
                        # Run update + upgrade as a single command to avoid guest agent
                        # channel issues (broken pipe) between sequential exec calls
                        combined = f"sh -c 'apt-get update && {cmd}'"
                        job.append(f"$ apt-get update && {cmd}\n")
                        stdout, err = client.exec_guest_agent(node, guest.vmid, combined, timeout=600)
                        if err is None:
                            if stdout:
                                job.append(stdout)
                            job.append("\n\nUpdates applied successfully.\n")
                            # Check reboot-required via guest agent
                            from core.scanner import check_reboot_required
                            check_reboot_required(guest)
                            job.reboot_required = guest.reboot_required
                            now = datetime.now(timezone.utc)
                            # Count applied packages before commit (applied_at is a
                            # naive column; a post-commit tz-aware equality match
                            # always fails -> "0 update(s) applied").
                            from core.notifier import (
                                send_updates_applied_notification,
                                summarize_applied_packages,
                            )
                            applied_pkgs = list(guest.pending_updates())
                            applied_count, security_count = summarize_applied_packages(applied_pkgs)
                            for pkg in applied_pkgs:
                                pkg.status = "applied"
                                pkg.applied_at = now
                            guest.status = "up-to-date"
                            db.session.commit()
                            try:
                                send_updates_applied_notification([{
                                    "name": guest.name,
                                    "type": guest.guest_type.upper(),
                                    "applied": applied_count,
                                    "security": security_count,
                                }])
                            except Exception:
                                pass
                            job.finish(True)
                            return
                        else:
                            job.append(f"\n[Agent Error] {err}\n")
                            job.finish(False)
                            return
                    else:
                        job.append(f"[Error] Could not find VM {guest.vmid} on any node.\n")
                        job.finish(False)
                        return
                except Exception as e:
                    job.append(f"\n[Agent Error] {e}\n")
                    job.finish(False)
                    return

            job.append("[Error] No viable connection method available.\n")
            job.finish(False)

        except Exception as e:
            logger.error(f"Background update error for guest {guest_id}: {e}", exc_info=True)
            job.append(f"\n[Unexpected Error] {e}\n")
            job.finish(False)


@bp.route("/scan/<int:guest_id>", methods=["POST"])
@login_required
def scan_single(guest_id):
    guest = Guest.query.get_or_404(guest_id)

    # Check permission
    if not current_user.is_admin and not current_user.can_access_guest(guest):
        flash("You don't have permission to scan this guest.", "error")
        return redirect(url_for("guests.index"))

    result = scan_guest(guest)
    if result.status == "success":
        log_action("guest_scan", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"updates_found": result.total_updates})
        db.session.commit()
        flash(f"Scan complete for '{guest.name}': {result.total_updates} update(s) found.", "success")
    else:
        flash(f"Scan failed for '{guest.name}': {result.error_message}", "error")

    referrer = request.referrer
    if referrer and f"/guests/{guest_id}" in referrer:
        return redirect(url_for("guests.detail", guest_id=guest_id))
    return redirect(url_for("dashboard.index"))


@bp.route("/scan-all", methods=["POST"])
@login_required
def scan_all():
    if not current_user.can_manage_guests:
        flash("Only admins can scan all guests.", "error")
        return redirect(url_for("dashboard.index"))

    results = scan_all_guests()
    total = len(results)
    errors = sum(1 for r in results if r.status == "error")

    send_update_notification(results)

    log_action("guest_scan_all", "system", resource_name="all guests",
               details={"total": total, "errors": errors})
    db.session.commit()

    if errors:
        flash(f"Scan complete: {total} guest(s) scanned, {errors} error(s).", "warning")
    else:
        flash(f"Scan complete: {total} guest(s) scanned successfully.", "success")

    return redirect(url_for("dashboard.index"))


@bp.route("/apply/<int:guest_id>", methods=["POST"])
@login_required
def apply(guest_id):
    guest = Guest.query.get_or_404(guest_id)

    if not current_user.is_admin and not current_user.can_access_guest(guest):
        flash("You don't have permission to update this guest.", "error")
        return redirect(url_for("guests.index"))

    # Applying updates requires the "Apply Updates" permission, consistent with
    # every app-upgrade blueprint (mastodon/ghost/peertube/... gate on
    # can_update in before_request). can_access_guest alone is read-only access.
    if not current_user.can_update:
        flash("You don't have permission to apply updates.", "error")
        return redirect(url_for("guests.detail", guest_id=guest_id))

    # Snapshot gating for non-admin users
    if not current_user.is_admin:
        from routes.guests import auto_snapshot_if_needed, guest_requires_snapshot
        if guest_requires_snapshot(guest):
            ok, msg = auto_snapshot_if_needed(guest)
            if not ok:
                flash(f"Cannot apply updates: snapshot required but failed — {msg}", "error")
                referrer = request.referrer
                if referrer and f"/guests/{guest_id}" in referrer:
                    return redirect(url_for("guests.detail", guest_id=guest_id))
                return redirect(url_for("dashboard.index"))

    # Check if an update is already running for this guest
    with _jobs_lock:
        existing = _update_jobs.get(guest_id)
        if existing and existing.running:
            flash(f"Updates are already being applied to '{guest.name}'.", "warning")
            return redirect(url_for("api.update_progress", guest_id=guest_id))

    dist_upgrade = request.form.get("dist_upgrade") == "1"

    log_action("guest_update", "guest", resource_id=guest.id, resource_name=guest.name,
               details={"dist_upgrade": dist_upgrade})
    db.session.commit()

    # Create the job and start the background thread
    from flask import current_app
    app = current_app._get_current_object()

    job = UpdateJob(guest_id, guest.name)
    with _jobs_lock:
        _update_jobs[guest_id] = job

    thread = threading.Thread(
        target=_run_update_background,
        args=(app, guest_id, dist_upgrade),
        daemon=True,
    )
    thread.start()

    return redirect(url_for("api.update_progress", guest_id=guest_id))


@bp.route("/apply/<int:guest_id>/progress")
@login_required
def update_progress(guest_id):
    guest = Guest.query.get_or_404(guest_id)

    if not current_user.is_admin and not current_user.can_access_guest(guest):
        flash("You don't have permission to view this guest.", "error")
        return redirect(url_for("guests.index"))

    job = _update_jobs.get(guest_id)
    if not job:
        flash("No update in progress for this guest.", "info")
        return redirect(url_for("guests.detail", guest_id=guest_id))

    return render_template("guest_update_progress.html", guest=guest, job=job)


@bp.route("/apply/<int:guest_id>/status")
@login_required
def update_status(guest_id):
    guest = Guest.query.get_or_404(guest_id)
    if not current_user.is_admin and not current_user.can_access_guest(guest):
        return jsonify({"error": "forbidden"}), 403

    job = _update_jobs.get(guest_id)
    if not job:
        return jsonify({"running": False, "log": "", "success": None})
    return jsonify(job.to_dict())


@bp.route("/apply/<int:guest_id>/cancel", methods=["POST"])
@login_required
def update_cancel(guest_id):
    guest = Guest.query.get_or_404(guest_id)
    if not current_user.is_admin and not current_user.can_access_guest(guest):
        return jsonify({"ok": False, "error": "forbidden"}), 403

    with _jobs_lock:
        job = _update_jobs.get(guest_id)
    if not job or not job.running:
        return jsonify({"ok": False, "error": "No active job"})
    job.cancel_requested = True
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Bulk update — apply pending updates to every eligible guest, one at a time
# ---------------------------------------------------------------------------

def _run_bulk_update(app, guest_ids, dist_upgrade, enforce_snapshot):
    """Orchestrator thread: update each guest sequentially.

    Reuses the per-guest _run_update_background worker so the existing per-guest
    /apply/<id>/status endpoint keeps reflecting live output for the guest
    currently being updated. One guest failing does not abort the batch.
    """
    with app.app_context():
        from routes.guests import auto_snapshot_if_needed, guest_requires_snapshot

        for guest_id in guest_ids:
            with _bulk_update_lock:
                item = next((i for i in _bulk_update["items"] if i["guest_id"] == guest_id), None)
                if item:
                    item["state"] = "running"

            guest = Guest.query.get(guest_id)
            if not guest:
                with _bulk_update_lock:
                    if item:
                        item["state"] = "skipped"
                        item["reason"] = "Guest not found"
                    _bulk_update["done"] += 1
                continue

            # Snapshot gating for non-admins, mirroring the single-guest apply().
            if enforce_snapshot and guest_requires_snapshot(guest):
                try:
                    ok, msg = auto_snapshot_if_needed(guest)
                except Exception as e:
                    ok, msg = False, str(e)
                if not ok:
                    with _bulk_update_lock:
                        if item:
                            item["state"] = "skipped"
                            item["reason"] = f"Snapshot required but failed: {msg}"
                        _bulk_update["done"] += 1
                    continue

            # Dedupe against any in-flight single-guest job.
            with _jobs_lock:
                existing = _update_jobs.get(guest_id)
                if existing and existing.running:
                    with _bulk_update_lock:
                        if item:
                            item["state"] = "skipped"
                            item["reason"] = "An update is already running for this guest"
                        _bulk_update["done"] += 1
                    continue
                _update_jobs[guest_id] = UpdateJob(guest_id, guest.name)

            try:
                _run_update_background(app, guest_id, dist_upgrade)
                job = _update_jobs.get(guest_id)
                success = bool(job.success) if job else False
            except Exception as e:
                logger.error("Bulk guest update error for guest %s: %s", guest_id, e)
                success = False
                job = _update_jobs.get(guest_id)
                if job and job.running:
                    job.finish(False)

            with _bulk_update_lock:
                if item:
                    item["state"] = "success" if success else "failed"
                _bulk_update["done"] += 1

        with _bulk_update_lock:
            _bulk_update["running"] = False


@bp.route("/apply-all", methods=["POST"])
@login_required
def apply_all():
    """Start a sequential bulk update across all guests with updates available."""
    if not current_user.can_update:
        flash("You don't have permission to apply updates.", "error")
        return redirect(url_for("dashboard.index"))

    with _bulk_update_lock:
        if _bulk_update.get("running"):
            flash("A bulk guest update is already running.", "warning")
            return redirect(url_for("api.apply_all_progress"))

    dist_upgrade = request.form.get("dist_upgrade") == "1"

    # Only enabled, running guests flagged with updates available.
    candidates = (Guest.query
                  .filter_by(enabled=True, status="updates-available", power_state="running")
                  .order_by(Guest.name)
                  .all())

    targets = []
    for guest in candidates:
        # Tag scoping: non-admins only act on guests they can access.
        if not current_user.is_admin and not current_user.can_access_guest(guest):
            continue
        if not guest.pending_updates():
            continue
        targets.append(guest)

    if not targets:
        flash("No guests with pending updates are available to update.", "info")
        return redirect(url_for("guests.index"))

    # Per-guest audit rows (parity with single apply) plus one bulk summary row.
    for guest in targets:
        log_action("guest_update", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"dist_upgrade": dist_upgrade, "bulk": True})
    log_action("guest_update_all", "system", resource_name="all guests",
               details={"targets": len(targets), "dist_upgrade": dist_upgrade})
    db.session.commit()

    items = [{"guest_id": g.id, "name": g.name, "state": "pending", "reason": None} for g in targets]
    guest_ids = [g.id for g in targets]
    with _bulk_update_lock:
        _bulk_update["running"] = True
        _bulk_update["started_at"] = datetime.now(timezone.utc).isoformat()
        _bulk_update["total"] = len(items)
        _bulk_update["done"] = 0
        _bulk_update["items"] = items

    from flask import current_app
    app = current_app._get_current_object()
    enforce_snapshot = not current_user.is_admin
    thread = threading.Thread(
        target=_run_bulk_update,
        args=(app, guest_ids, dist_upgrade, enforce_snapshot),
        daemon=True,
    )
    thread.start()

    flash(f"Started updates on {len(targets)} guest(s).", "info")
    return redirect(url_for("api.apply_all_progress"))


@bp.route("/apply-all/progress")
@login_required
def apply_all_progress():
    """Render the aggregate bulk-update progress page for guests."""
    if not current_user.can_update:
        flash("You don't have permission to view this page.", "error")
        return redirect(url_for("guests.index"))
    return render_template(
        "bulk_update_progress.html",
        page_title="Updating All Guests",
        heading="Updating All Guests",
        status_url=url_for("api.apply_all_status"),
        back_url=url_for("guests.index"),
        back_label="Back to Guests",
    )


@bp.route("/apply-all/status")
@login_required
def apply_all_status():
    """JSON: aggregate state of the bulk guest update, with live log per guest."""
    if not current_user.can_update:
        return jsonify({"error": "forbidden"}), 403

    with _bulk_update_lock:
        running = _bulk_update.get("running", False)
        total = _bulk_update.get("total", 0)
        done = _bulk_update.get("done", 0)
        snapshot = [(i["guest_id"], i["name"], i["state"], i.get("reason")) for i in _bulk_update["items"]]

    items_out = []
    for guest_id, name, state, reason in snapshot:
        log = ""
        if state in ("running", "success", "failed"):
            job = _update_jobs.get(guest_id)
            if job:
                log = job.to_dict().get("log", "")
        items_out.append({"id": guest_id, "name": name, "state": state, "reason": reason, "log": log})

    return jsonify({"running": running, "total": total, "done": done, "items": items_out})


# ---------------------------------------------------------------------------
# Proxmox task tracking (backups, snapshots, rollbacks)
# ---------------------------------------------------------------------------

_proxmox_jobs = {}  # keyed by f"{job_type}:{guest_id}"
_proxmox_jobs_lock = threading.Lock()

JOB_TYPE_LABELS = {
    "backup": "Creating Backup",
    "snapshot": "Creating Snapshot",
    "snapshot_delete": "Deleting Snapshot",
    "rollback": "Rolling Back",
    "clone": "Cloning Guest",
    "migrate": "Migrating Guest",
}


class ProxmoxJob:
    """Tracks a background Proxmox task (backup, snapshot, etc.)."""

    def __init__(self, guest_id, guest_name, job_type, upid, node, host_model):
        self.guest_id = guest_id
        self.guest_name = guest_name
        self.job_type = job_type
        self.upid = upid
        self.node = node
        self.host_model = host_model
        self.log = ""
        self.running = True
        self.success = None
        self.cancel_requested = False
        self.cancelled = False
        self.started_at = datetime.now(timezone.utc)
        self._lock = threading.Lock()
        self._last_log_line = 0

    @property
    def label(self):
        return JOB_TYPE_LABELS.get(self.job_type, self.job_type)

    def append(self, text):
        with self._lock:
            self.log += text

    def finish(self, success):
        with self._lock:
            self.running = False
            self.success = success
            if not success and self.cancel_requested:
                self.cancelled = True

    def to_dict(self):
        with self._lock:
            return {
                "guest_id": self.guest_id,
                "guest_name": self.guest_name,
                "job_type": self.job_type,
                "label": self.label,
                "log": self.log,
                "running": self.running,
                "success": self.success,
                "cancelled": self.cancelled,
                "started_at": self.started_at.isoformat(),
            }


def _poll_proxmox_task(app, job_key):
    """Poll Proxmox task status and accumulate log output."""
    from clients.proxmox_api import ProxmoxClient

    with app.app_context():
        job = _proxmox_jobs.get(job_key)
        if not job:
            return

        try:
            client = ProxmoxClient(job.host_model)

            while True:
                time.sleep(2)

                try:
                    log_lines = client.get_task_log(job.node, job.upid, start=job._last_log_line)
                    for line in log_lines:
                        text = line.get("t", "")
                        if text:
                            job.append(text + "\n")
                        line_num = line.get("n", 0)
                        if line_num >= job._last_log_line:
                            job._last_log_line = line_num + 1
                except Exception as e:
                    logger.debug(f"Error fetching task log: {e}")

                try:
                    status = client.get_task_status(job.node, job.upid)
                    if status.get("status") == "stopped":
                        exit_status = status.get("exitstatus", "")
                        if exit_status == "OK":
                            job.finish(True)
                        else:
                            if job.cancel_requested:
                                job.append("\n[Cancelled by user]\n")
                            else:
                                job.append(f"\nTask failed: {exit_status}\n")
                            job.finish(False)
                        return
                except Exception as e:
                    logger.debug(f"Error fetching task status: {e}")

        except Exception as e:
            logger.error(f"Proxmox task polling error for {job_key}: {e}", exc_info=True)
            job.append(f"\n[Error] {e}\n")
            job.finish(False)


def start_proxmox_job(guest, job_type, upid, node):
    """Create a ProxmoxJob, start the polling thread, and return the job key."""
    from flask import current_app
    app = current_app._get_current_object()

    job_key = f"{job_type}:{guest.id}"

    job = ProxmoxJob(guest.id, guest.name, job_type, upid, node, guest.proxmox_host)
    with _proxmox_jobs_lock:
        _proxmox_jobs[job_key] = job

    thread = threading.Thread(
        target=_poll_proxmox_task,
        args=(app, job_key),
        daemon=True,
    )
    thread.start()

    return job_key


@bp.route("/task/<int:guest_id>/<job_type>/progress")
@login_required
def task_progress(guest_id, job_type):
    guest = Guest.query.get_or_404(guest_id)

    if not current_user.can_manage_guests and not current_user.can_access_guest(guest):
        flash("You don't have permission to view this guest.", "error")
        return redirect(url_for("guests.index"))

    job_key = f"{job_type}:{guest_id}"
    job = _proxmox_jobs.get(job_key)
    if not job:
        flash("No task in progress for this guest.", "info")
        return redirect(url_for("guests.detail", guest_id=guest_id))

    return render_template("proxmox_task_progress.html", guest=guest, job=job)


@bp.route("/task/<int:guest_id>/<job_type>/status")
@login_required
def task_status(guest_id, job_type):
    guest = Guest.query.get_or_404(guest_id)
    if not current_user.can_manage_guests and not current_user.can_access_guest(guest):
        return jsonify({"error": "forbidden"}), 403

    job_key = f"{job_type}:{guest_id}"
    job = _proxmox_jobs.get(job_key)
    if not job:
        return jsonify({"running": False, "log": "", "success": None})
    return jsonify(job.to_dict())


@bp.route("/task/<int:guest_id>/<job_type>/cancel", methods=["POST"])
@login_required
def task_cancel(guest_id, job_type):
    guest = Guest.query.get_or_404(guest_id)
    if not current_user.can_manage_guests and not current_user.can_access_guest(guest):
        return jsonify({"ok": False, "error": "forbidden"}), 403

    job_key = f"{job_type}:{guest_id}"
    with _proxmox_jobs_lock:
        job = _proxmox_jobs.get(job_key)
    if not job or not job.running:
        return jsonify({"ok": False, "error": "No active job"})
    job.cancel_requested = True
    try:
        from clients.proxmox_api import ProxmoxClient
        client = ProxmoxClient(job.host_model)
        client.cancel_task(job.node, job.upid)
    except Exception:
        logger.exception("Error cancelling task for guest %s", guest_id)
        return jsonify({"ok": False, "error": "Failed to cancel task."})
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# RRD performance data
# ---------------------------------------------------------------------------

@bp.route("/guests/<int:guest_id>/rrd")
@login_required
def guest_rrd(guest_id):
    """Return RRD performance data as JSON for Chart.js."""
    from clients.proxmox_api import ProxmoxClient

    guest = Guest.query.get_or_404(guest_id)

    if not current_user.is_admin and not current_user.can_access_guest(guest):
        return jsonify({"error": "Permission denied"}), 403

    if not guest.proxmox_host or not guest.vmid:
        return jsonify({"error": "Guest has no Proxmox host configured"}), 400

    timeframe = request.args.get("timeframe", "day")
    if timeframe not in ("hour", "day", "3d", "week", "month", "3mo", "year", "365d"):
        timeframe = "day"

    # Try Prometheus first if enabled
    if Setting.get("prometheus_enabled", "false") == "true" and Setting.get("prometheus_url", ""):
        try:
            from clients.prometheus_query import PrometheusQueryClient
            prom = PrometheusQueryClient()
            data = prom.get_guest_rrd(guest.vmid, timeframe, guest_id=guest.id)
            if data and data.get("labels"):
                return jsonify(data)
        except Exception:
            logger.debug("Prometheus query failed for guest %s, falling back to RRD", guest_id)

    # Extended timeframes only available with Prometheus — fall back to closest RRD equivalent
    if timeframe in ("3d", "3mo", "365d"):
        _fallback = {"3d": "week", "3mo": "month", "365d": "year"}
        timeframe = _fallback.get(timeframe, "month")

    try:
        client = ProxmoxClient(guest.proxmox_host)
        node = client.find_guest_node(guest.vmid)
        if not node:
            return jsonify({"error": "Guest not found on any node"}), 404

        raw = client.get_rrd_data(node, guest.vmid, guest.guest_type, timeframe=timeframe)
    except Exception:
        logger.exception("RRD fetch error for guest %s", guest_id)
        return jsonify({"error": "Failed to fetch performance data."}), 500

    if not raw:
        return jsonify({"labels": [], "cpu": [], "mem_percent": [], "mem_used_mb": [],
                        "mem_total_mb": 0, "netin": [], "netout": [], "net_unit": "KB/s"})

    labels = []
    cpu = []
    mem_percent = []
    mem_used_mb = []
    netin = []
    netout = []
    mem_total_mb = 0

    for point in raw:
        ts = point.get("time")
        if ts is None:
            continue

        labels.append(datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(_user_tz()).strftime("%Y-%m-%d %H:%M"))

        # CPU: fraction (0.0–N where N = num cores) → percentage of allocated cores
        cpu_val = point.get("cpu")
        maxcpu = point.get("maxcpu", 1) or 1
        if cpu_val is not None:
            cpu.append(round(cpu_val / maxcpu * 100, 2))
        else:
            cpu.append(None)

        # Memory: bytes → percentage + MB
        mem_val = point.get("mem")
        maxmem = point.get("maxmem", 1) or 1
        if mem_val is not None:
            mem_used_mb.append(round(mem_val / 1048576, 1))
            mem_percent.append(round(mem_val / maxmem * 100, 2))
        else:
            mem_used_mb.append(None)
            mem_percent.append(None)
        mem_total_mb = round(maxmem / 1048576, 1)

        # Network: bytes/sec
        ni = point.get("netin")
        no = point.get("netout")
        netin.append(round(ni, 2) if ni is not None else None)
        netout.append(round(no, 2) if no is not None else None)

    # Pick a sensible unit for network values
    max_net = max((v for v in netin + netout if v is not None), default=0)
    if max_net > 1_000_000:
        net_unit = "Mbps"
        divisor = 125_000  # bytes/sec → Mbps
    elif max_net > 1_000:
        net_unit = "KB/s"
        divisor = 1024
    else:
        net_unit = "B/s"
        divisor = 1

    if divisor != 1:
        netin = [round(v / divisor, 2) if v is not None else None for v in netin]
        netout = [round(v / divisor, 2) if v is not None else None for v in netout]

    return jsonify({
        "labels": labels,
        "cpu": cpu,
        "mem_percent": mem_percent,
        "mem_used_mb": mem_used_mb,
        "mem_total_mb": mem_total_mb,
        "netin": netin,
        "netout": netout,
        "net_unit": net_unit,
        "source": "proxmox_rrd",
    })


@bp.route("/hosts/<int:host_id>/rrd")
@login_required
def host_rrd(host_id):
    """Return node-level RRD performance data as JSON for Chart.js."""
    from clients.proxmox_api import ProxmoxClient

    if not current_user.can_view_hosts and not current_user.can_manage_hosts:
        return jsonify({"error": "Permission denied"}), 403

    host = ProxmoxHost.query.get_or_404(host_id)

    timeframe = request.args.get("timeframe", "day")
    if timeframe not in ("hour", "day", "3d", "week", "month", "3mo", "year", "365d"):
        timeframe = "day"

    # Try Prometheus first if enabled
    if Setting.get("prometheus_enabled", "false") == "true" and Setting.get("prometheus_url", ""):
        try:
            from clients.prometheus_query import PrometheusQueryClient
            prom = PrometheusQueryClient()
            data = prom.get_host_rrd(host.id, timeframe)
            if data and data.get("labels"):
                return jsonify(data)
        except Exception:
            logger.debug("Prometheus query failed for host %s, falling back to RRD", host_id)

    # Extended timeframes only available with Prometheus — fall back to closest RRD equivalent
    if timeframe in ("3d", "3mo", "365d"):
        _fallback = {"3d": "week", "3mo": "month", "365d": "year"}
        timeframe = _fallback.get(timeframe, "month")

    try:
        client = ProxmoxClient(host)
        node_name = client.get_local_node_name()
        if not node_name:
            return jsonify({"error": "Could not determine node name"}), 404

        raw = client.get_node_rrd_data(node_name, timeframe=timeframe)
    except Exception:
        logger.exception("RRD fetch error for host %s", host_id)
        return jsonify({"error": "Failed to fetch performance data."}), 500

    if not raw:
        return jsonify({"labels": [], "cpu": [], "mem_percent": [], "mem_used_mb": [],
                        "mem_total_mb": 0, "netin": [], "netout": [], "net_unit": "KB/s",
                        "iowait": [], "rootfs_percent": []})

    labels = []
    cpu = []
    iowait = []
    mem_percent = []
    mem_used_mb = []
    netin = []
    netout = []
    rootfs_percent = []
    mem_total_mb = 0

    for point in raw:
        ts = point.get("time")
        if ts is None:
            continue

        labels.append(datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(_user_tz()).strftime("%Y-%m-%d %H:%M"))

        # CPU: fraction (0.0–1.0) → percentage
        cpu_val = point.get("cpu")
        if cpu_val is not None:
            cpu.append(round(cpu_val * 100, 2))
        else:
            cpu.append(None)

        # IO wait: fraction → percentage
        iow = point.get("iowait")
        if iow is not None:
            iowait.append(round(iow * 100, 2))
        else:
            iowait.append(None)

        # Memory: bytes → percentage + MB
        mem_val = point.get("memused")
        maxmem = point.get("memtotal", 1) or 1
        if mem_val is not None:
            mem_used_mb.append(round(mem_val / 1048576, 1))
            mem_percent.append(round(mem_val / maxmem * 100, 2))
        else:
            mem_used_mb.append(None)
            mem_percent.append(None)
        mem_total_mb = round(maxmem / 1048576, 1)

        # Root filesystem usage
        rootfs_used = point.get("rootused")
        rootfs_total = point.get("roottotal", 1) or 1
        if rootfs_used is not None:
            rootfs_percent.append(round(rootfs_used / rootfs_total * 100, 2))
        else:
            rootfs_percent.append(None)

        # Network: bytes/sec
        ni = point.get("netin")
        no = point.get("netout")
        netin.append(round(ni, 2) if ni is not None else None)
        netout.append(round(no, 2) if no is not None else None)

    # Pick a sensible unit for network values
    max_net = max((v for v in netin + netout if v is not None), default=0)
    if max_net > 1_000_000:
        net_unit = "Mbps"
        divisor = 125_000
    elif max_net > 1_000:
        net_unit = "KB/s"
        divisor = 1024
    else:
        net_unit = "B/s"
        divisor = 1

    if divisor != 1:
        netin = [round(v / divisor, 2) if v is not None else None for v in netin]
        netout = [round(v / divisor, 2) if v is not None else None for v in netout]

    return jsonify({
        "labels": labels,
        "cpu": cpu,
        "iowait": iowait,
        "mem_percent": mem_percent,
        "mem_used_mb": mem_used_mb,
        "mem_total_mb": mem_total_mb,
        "netin": netin,
        "netout": netout,
        "net_unit": net_unit,
        "rootfs_percent": rootfs_percent,
        "source": "proxmox_rrd",
    })


@bp.route("/dashboard/host-stats")
@login_required
def dashboard_host_stats():
    """Return aggregated live stats from all Proxmox hosts for the dashboard."""
    from clients.proxmox_api import ProxmoxClient

    if not current_user.can_view_hosts and not current_user.can_manage_hosts:
        return jsonify({"error": "Permission denied"}), 403

    hosts = ProxmoxHost.query.all()
    if not hosts:
        return jsonify({"hosts": []})

    results = []
    for host in hosts:
        entry = {"id": host.id, "name": host.name, "online": False, "is_pbs": host.is_pbs}
        try:
            if host.is_pbs:
                from clients.pbs_client import PBSClient
                status = PBSClient(host).get_node_status()
            else:
                client = ProxmoxClient(host)
                node_name = client.get_local_node_name()
                if not node_name:
                    results.append(entry)
                    continue
                status = client.get_node_status(node_name)

            if not status:
                results.append(entry)
                continue

            entry["online"] = True
            entry["cpu_usage"] = status["cpu_usage"]
            entry["cpu_threads"] = status["cpu_threads"]
            entry["memory_used"] = status["memory_used"]
            entry["memory_total"] = status["memory_total"]
            entry["swap_used"] = status["swap_used"]
            entry["swap_total"] = status["swap_total"]
            entry["rootfs_used"] = status["rootfs_used"]
            entry["rootfs_total"] = status["rootfs_total"]
            entry["uptime"] = status["uptime"]
            entry["loadavg"] = status["loadavg"]
        except Exception as e:
            logger.error(f"Dashboard host stats error for {host.name}: {e}")

        results.append(entry)

    # Compute aggregates across all online hosts
    online = [h for h in results if h.get("online")]
    agg = {}
    if online:
        agg["total_cpu_threads"] = sum(h.get("cpu_threads", 0) for h in online)
        agg["avg_cpu"] = round(sum(h.get("cpu_usage", 0) for h in online) / len(online), 1)
        agg["max_cpu"] = max(h.get("cpu_usage", 0) for h in online)
        agg["total_memory_used"] = sum(h.get("memory_used", 0) for h in online)
        agg["total_memory"] = sum(h.get("memory_total", 0) for h in online)
        agg["total_swap_used"] = sum(h.get("swap_used", 0) for h in online)
        agg["total_swap"] = sum(h.get("swap_total", 0) for h in online)
        agg["total_rootfs_used"] = sum(h.get("rootfs_used", 0) for h in online)
        agg["total_rootfs"] = sum(h.get("rootfs_total", 0) for h in online)
        agg["hosts_online"] = len(online)
        agg["hosts_offline"] = len(results) - len(online)

    return jsonify({"hosts": results, "aggregate": agg})


@bp.route("/dashboard/guest-stats")
@login_required
def dashboard_guest_stats():
    """Return live CPU/memory/disk usage for all running guests across all Proxmox hosts."""
    from clients.proxmox_api import ProxmoxClient

    if not current_user.can_view_hosts and not current_user.can_manage_hosts:
        return jsonify({"error": "Permission denied"}), 403

    tag_filter = request.args.get("tag", "")

    hosts = ProxmoxHost.query.all()
    if not hosts:
        return jsonify({"guests": []})

    # Build lookup: (host_id, vmid) -> db guest (for links).
    # Apply the active tag filter so the panel matches the dashboard view.
    guest_query = Guest.query.filter_by(enabled=True)
    if tag_filter == "__my_tags__":
        user_tag_names = [t.name for t in current_user.allowed_tags]
        if user_tag_names:
            guest_query = guest_query.filter(Guest.tags.any(Tag.name.in_(user_tag_names)))
    elif tag_filter:
        guest_query = guest_query.filter(Guest.tags.any(Tag.name == tag_filter))

    db_lookup = {}
    for g in guest_query.all():
        if g.proxmox_host_id and g.vmid:
            db_lookup[(g.proxmox_host_id, g.vmid)] = g

    results = []
    for host in hosts:
        if host.is_pbs:
            continue  # PBS has no VMs/CTs to report
        try:
            client = ProxmoxClient(host)
            raw_guests = client.get_all_guests()
        except Exception as e:
            logger.error(f"Dashboard guest stats error for {host.name}: {e}")
            continue

        for g in raw_guests:
            if g.get("status") != "running":
                continue

            vmid = g.get("vmid")
            db_guest = db_lookup.get((host.id, vmid))
            # When a tag filter is active, skip guests not in the filtered set.
            if tag_filter and db_guest is None:
                continue
            mem_used = g.get("mem", 0)
            mem_total = g.get("maxmem", 0) or 1
            disk_used = g.get("disk", 0)
            disk_total = g.get("maxdisk", 0) or 1
            cpu_pct = round(g.get("cpu", 0) * 100, 1)
            mem_pct = round(mem_used / mem_total * 100, 1)
            disk_pct = round(disk_used / disk_total * 100, 1)

            results.append({
                "vmid": vmid,
                "name": g.get("name", f"VMID {vmid}"),
                "type": g.get("type", "vm"),
                "node": g.get("node", ""),
                "host_name": host.name,
                "cpu_pct": cpu_pct,
                "mem_used": mem_used,
                "mem_total": mem_total,
                "mem_pct": mem_pct,
                "disk_used": disk_used,
                "disk_total": disk_total,
                "disk_pct": disk_pct,
                "uptime": g.get("uptime", 0),
                "guest_id": db_guest.id if db_guest else None,
            })

    results.sort(key=lambda x: x["cpu_pct"], reverse=True)
    return jsonify({"guests": results})


@bp.route("/hosts/<int:host_id>/guest-stats")
@login_required
def host_guest_stats(host_id):
    """Return live CPU/memory/disk keyed by VMID for all guests on one PVE host."""
    from clients.proxmox_api import ProxmoxClient

    host = ProxmoxHost.query.get_or_404(host_id)

    if not current_user.can_view_hosts and not current_user.can_manage_hosts:
        return jsonify({"error": "Permission denied"}), 403

    if host.is_pbs:
        return jsonify({"error": "Not a PVE host"}), 400

    try:
        client = ProxmoxClient(host)
        node_name = client.get_local_node_name()
        raw = client.get_node_guests(node_name) if node_name else client.get_all_guests()
    except Exception:
        logger.exception("Host guest stats error for host %s", host_id)
        return jsonify({"error": "Failed to fetch host guest statistics."}), 500

    stats = {}
    for g in raw:
        vmid = g.get("vmid")
        if vmid is None:
            continue
        mem_used = g.get("mem", 0)
        mem_total = g.get("maxmem", 0) or 1
        disk_used = g.get("disk", 0)
        disk_total = g.get("maxdisk", 0) or 1
        stats[vmid] = {
            "status": g.get("status", ""),
            "cpu_pct": round(g.get("cpu", 0) * 100, 1),
            "mem_used": mem_used,
            "mem_total": mem_total,
            "mem_pct": round(mem_used / mem_total * 100, 1),
            "disk_used": disk_used,
            "disk_total": disk_total,
            "disk_pct": round(disk_used / disk_total * 100, 1) if disk_used > 0 else 0,
        }

    return jsonify({"stats": stats})


@bp.route("/guests/<int:guest_id>/unifi-stats")
@login_required
def guest_unifi_stats(guest_id):
    """Return fresh UniFi stats for a guest as JSON (used for live polling)."""
    guest = Guest.query.get_or_404(guest_id)
    if not current_user.is_admin and not current_user.can_access_guest(guest):
        return jsonify({"error": "forbidden"}), 403

    if not guest.mac_address:
        return jsonify({"error": "no_mac"}), 404

    from models import Setting
    if Setting.get("unifi_enabled", "false") != "true":
        return jsonify({"error": "unifi_disabled"}), 404

    try:
        from routes.unifi import _get_unifi_client
        client = _get_unifi_client()
        if not client:
            return jsonify({"error": "not_configured"}), 404

        stats = client.get_client_by_mac(guest.mac_address)
        if not stats:
            return jsonify({"error": "not_found"}), 404

        Setting.set("unifi_last_polled", datetime.now(timezone.utc).isoformat())
        return jsonify({"stats": stats})
    except Exception as e:
        logger.error(f"UniFi stats fetch failed for guest {guest_id}: {e}")
        return jsonify({"error": "fetch_failed"}), 500


# ---------------------------------------------------------------------------
# Real-time collaboration
# ---------------------------------------------------------------------------

@bp.route("/collab/stream")
@login_required
def collab_stream():
    """Long-lived SSE stream that pushes presence and activity events.

    Each authenticated browser tab opens this connection on page load.
    Requires threaded or single-worker gunicorn deployment (one thread per
    active connection).  For multi-process deployments, replace the in-process
    CollaborationHub with a Redis pub/sub backend.
    """
    from core.collaboration import collab_hub

    user_id = current_user.id
    username = current_user.username
    display_name = current_user.display_name or username

    page = request.args.get("page", "/")
    event_queue = collab_hub.connect(user_id, username, display_name, page=page)

    @stream_with_context
    def generate():
        try:
            # Immediately send the current presence snapshot
            import json as _json
            yield f"data: {_json.dumps({'type': 'presence', 'users': collab_hub.get_online_users()})}\n\n"
            while True:
                try:
                    event = event_queue.get(timeout=25)
                    if event is None:   # sentinel — shut down this stream
                        break
                    yield f"data: {_json.dumps(event)}\n\n"
                except queue.Empty:
                    yield ": keepalive\n\n"   # prevent proxy timeouts
        except GeneratorExit:
            pass
        finally:
            collab_hub.disconnect(user_id, event_queue=event_queue)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # disable nginx / gunicorn buffering
        },
    )


@bp.route("/collab/presence", methods=["POST"])
@login_required
def collab_presence():
    """Heartbeat + page update sent by every tab every 30 seconds."""
    from core.collaboration import collab_hub
    data = request.get_json(silent=True) or {}
    page = data.get("page", "/")
    following = data.get("following") or None  # username string or null
    collab_hub.update_presence(current_user.id, page, following=following)
    return jsonify({"ok": True})


@bp.route("/collab/terminal-sessions")
@login_required
def collab_terminal_sessions():
    """List active terminal sessions the current user is permitted to follow."""
    from core.collaboration import terminal_registry
    sessions = []
    for s in terminal_registry.get_all():
        guest = Guest.query.get(s.guest_id)
        if not guest:
            continue
        if not current_user.is_admin and not current_user.can_access_guest(guest):
            continue
        sessions.append({
            "session_id": s.session_id,
            "guest_id": s.guest_id,
            "guest_name": s.guest_name,
            "owner_username": s.owner_username,
            "started_at": s.started_at.isoformat(),
            "follower_count": s.follower_count(),
        })
    return jsonify({"sessions": sessions})


@bp.route("/collab/cursor")
@login_required
def collab_cursor_update():
    """Receive and store the current user's cursor position (GET with query params)."""
    from core.collaboration import cursor_hub
    try:
        x_pct = float(request.args["x_pct"])
        y_pct = float(request.args["y_pct"])
    except (KeyError, TypeError, ValueError):
        return jsonify(ok=False), 400
    cursor_hub.update(
        current_user.username,
        current_user.display_name or current_user.username,
        request.args.get("page", "/"),
        x_pct, y_pct,
        request.args.get("color", "#3b82f6"),
    )
    return jsonify(ok=True)


@bp.route("/collab/cursors")
@login_required
def collab_cursors():
    """Return cursor positions of all co-viewers on the given page."""
    from core.collaboration import cursor_hub
    page = request.args.get("page", "/")
    return jsonify(cursors=cursor_hub.get_for_page(
        page, exclude_username=current_user.username
    ))
