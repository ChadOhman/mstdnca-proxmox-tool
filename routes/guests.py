import json
import logging
from datetime import datetime

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required

from auth.audit import log_action
from clients.proxmox_api import ProxmoxClient
from models import AuditLog, Credential, Guest, GuestService, ProxmoxHost, Setting, Tag, UpdatePackage, db

logger = logging.getLogger(__name__)


def _parse_iso(value):
    """Parse an ISO 8601 string into a timezone-aware datetime, or return None."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


def _get_tag_backup_defaults(guest):
    """Return backup defaults for the first matching tag override, or empty dict."""
    raw = Setting.get("backup_tag_defaults", "")
    if not raw:
        return {}
    try:
        overrides = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}
    for tag in guest.tags:
        if tag.name in overrides:
            return overrides[tag.name]
    return {}

bp = Blueprint("guests", __name__)


def _get_unifi_mac_map():
    """Fetch UniFi clients and return a MAC -> client dict. Returns empty dict if UniFi is disabled."""
    if Setting.get("unifi_enabled", "false") != "true":
        return {}
    try:
        from datetime import datetime, timezone

        from routes.unifi import _get_unifi_client
        client = _get_unifi_client()
        if not client:
            return {}
        clients = client.get_clients() or []
        Setting.set("unifi_last_polled", datetime.now(timezone.utc).isoformat())
        db.session.commit()
        return {c["mac"].lower(): c for c in clients if c.get("mac")}
    except Exception as e:
        logger.debug(f"Could not fetch UniFi clients: {e}")
        return {}


_VALID_FILTERS = {"updates", "security", "reboot", "never_scanned", "error", "up_to_date"}

_FILTER_LABELS = {
    "updates": "Pending Updates",
    "security": "Security Updates",
    "reboot": "Reboots Required",
    "never_scanned": "Never Scanned",
    "error": "Scan Errors",
    "up_to_date": "Up to Date",
}


@bp.route("/")
@login_required
def index():
    tag_filter = request.args.get("tag", None)
    user_tag_names = [t.name for t in current_user.allowed_tags]

    if tag_filter is not None:
        # User explicitly chose a filter — save it
        session["guest_tag_filter"] = tag_filter
    elif "guest_tag_filter" in session:
        # Restore previous filter
        tag_filter = session["guest_tag_filter"]
    elif user_tag_names:
        # First visit, default to user's tags
        tag_filter = "__my_tags__"
    else:
        tag_filter = ""

    # Status filter from dashboard cards — not persisted to session
    status_filter = request.args.get("filter", None)
    if status_filter not in _VALID_FILTERS:
        status_filter = None

    if current_user.is_admin:
        query = Guest.query
    else:
        user_tag_ids = [t.id for t in current_user.allowed_tags]
        if not user_tag_ids:
            query = Guest.query.filter(False)
        else:
            query = Guest.query.filter_by(enabled=True).filter(
                Guest.tags.any(Tag.id.in_(user_tag_ids))
            )

    # Apply tag filter
    if tag_filter == "__my_tags__":
        query = query.filter(Guest.tags.any(Tag.name.in_(user_tag_names)))
    elif tag_filter:
        query = query.filter(Guest.tags.any(Tag.name == tag_filter))

    # Apply status filter
    if status_filter == "updates":
        query = query.filter(Guest.status == "updates-available")
    elif status_filter == "security":
        query = query.filter(
            Guest.updates.any(db.and_(
                UpdatePackage.status == "pending",
                UpdatePackage.severity == "critical",
            ))
        )
    elif status_filter == "reboot":
        query = query.filter(Guest.reboot_required == True)  # noqa: E712
    elif status_filter == "never_scanned":
        query = query.filter(Guest.last_scan.is_(None))
    elif status_filter == "error":
        query = query.filter(Guest.status == "error")
    elif status_filter == "up_to_date":
        query = query.filter(Guest.status == "up-to-date")

    guests = query.order_by(Guest.name).all()

    hosts = ProxmoxHost.query.all()
    credentials = Credential.query.all()
    tags = Tag.query.order_by(Tag.name).all()

    # Fetch UniFi clients for MAC-based IP enrichment
    unifi_map = _get_unifi_mac_map()

    return render_template(
        "guests.html",
        guests=guests,
        hosts=hosts,
        credentials=credentials,
        tags=tags,
        current_tag=tag_filter,
        user_tag_names=user_tag_names,
        unifi_map=unifi_map,
        current_filter=status_filter,
        filter_label=_FILTER_LABELS.get(status_filter),
    )


@bp.route("/add", methods=["POST"])
@login_required
def add():
    if not current_user.can_manage_guests:
        flash("Permission denied.", "error")
        return redirect(url_for("guests.index"))

    name = request.form.get("name", "").strip()
    guest_type = request.form.get("guest_type", "vm")
    ip_address = request.form.get("ip_address", "").strip()
    connection_method = request.form.get("connection_method", "ssh")

    if not name:
        flash("Name is required.", "error")
        return redirect(url_for("guests.index"))

    guest = Guest(
        name=name,
        guest_type=guest_type,
        ip_address=ip_address or None,
        connection_method=connection_method,
    )

    host_id = request.form.get("proxmox_host_id")
    if host_id:
        try:
            guest.proxmox_host_id = int(host_id)
        except (TypeError, ValueError):
            flash("Invalid host selection.", "error")
            return redirect(url_for("guests.index"))

    vmid = request.form.get("vmid")
    if vmid:
        try:
            guest.vmid = int(vmid)
        except (TypeError, ValueError):
            flash("Invalid VM ID.", "error")
            return redirect(url_for("guests.index"))

    cred_id = request.form.get("credential_id")
    if cred_id:
        try:
            guest.credential_id = int(cred_id)
        except (TypeError, ValueError):
            flash("Invalid credential selection.", "error")
            return redirect(url_for("guests.index"))

    # Assign tags
    tag_ids = request.form.getlist("tag_ids")
    if tag_ids:
        try:
            tag_id_ints = [int(t) for t in tag_ids]
        except (TypeError, ValueError):
            flash("Invalid tag selection.", "error")
            return redirect(url_for("guests.index"))
        tags = Tag.query.filter(Tag.id.in_(tag_id_ints)).all()
        guest.tags = tags

    db.session.add(guest)
    db.session.flush()  # populate guest.id before logging
    log_action("guest_add", "guest", resource_id=guest.id, resource_name=guest.name)
    db.session.commit()

    flash(f"Guest '{name}' added.", "success")
    return redirect(url_for("guests.index"))


@bp.route("/<int:guest_id>")
@login_required
def detail(guest_id):
    guest = Guest.query.get_or_404(guest_id)

    if not current_user.is_admin and not current_user.can_access_guest(guest):
        flash("You don't have permission to view this guest.", "error")
        return redirect(url_for("guests.index"))

    credentials = Credential.query.all()
    tags = Tag.query.order_by(Tag.name).all()

    # Fetch replication info, snapshots, backups, and available nodes if guest has a Proxmox host
    repl_jobs = []
    cluster_nodes = []
    snapshots = []
    backups = []
    backup_storages = []
    hardware = None
    suggested_vmid = None
    if guest.proxmox_host and guest.vmid:
        try:
            client = ProxmoxClient(guest.proxmox_host)
            node = client.find_guest_node(guest.vmid)
            if node:
                repl_jobs = client.get_replication_jobs(guest.vmid)
                cluster_nodes = [n["node"] for n in client.get_nodes()]
                suggested_vmid = client.get_next_vmid()
                snapshots = client.list_snapshots(node, guest.vmid, guest.guest_type)
                backup_storages = client.list_node_storages(node, content_type="backup")
                hardware = client.get_guest_config(node, guest.vmid, guest.guest_type)
                # List backups from per-guest/tag/legacy default storage (or all backup-capable storages)
                tag_cfg = _get_tag_backup_defaults(guest)
                default_storage = guest.backup_storage or tag_cfg.get("storage") or Setting.get("backup_storage", "")
                if default_storage:
                    backups = client.list_backups(node, guest.vmid, default_storage)
                else:
                    # Try each backup-capable storage
                    for st in backup_storages:
                        backups.extend(client.list_backups(node, guest.vmid, st.get("storage", "")))
                    backups.sort(key=lambda x: x.get("ctime", 0), reverse=True)
        except Exception as e:
            logger.warning(f"Could not fetch Proxmox detail data for guest {guest.name}: {e}")

    # Fetch UniFi client info by MAC address
    unifi_client = None
    unifi_last_polled = None
    if guest.mac_address:
        unifi_map = _get_unifi_mac_map()
        unifi_client = unifi_map.get(guest.mac_address)
        unifi_last_polled = _parse_iso(Setting.get("unifi_last_polled", ""))

    # Recent audit activity for this guest (last 7 days)
    from datetime import datetime, timedelta, timezone
    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    recent_logs = (AuditLog.query
                   .filter(AuditLog.resource_type == "guest",
                           AuditLog.resource_id == guest.id,
                           AuditLog.timestamp >= cutoff)
                   .order_by(AuditLog.timestamp.desc())
                   .limit(25).all())

    return render_template("guest_detail.html", guest=guest, credentials=credentials, tags=tags,
                           repl_jobs=repl_jobs, cluster_nodes=cluster_nodes,
                           snapshots=snapshots, backups=backups,
                           backup_storages=backup_storages,
                           hardware=hardware,
                           suggested_vmid=suggested_vmid,
                           unifi_client=unifi_client,
                           unifi_last_polled=unifi_last_polled,
                           known_services=GuestService.KNOWN_SERVICES,
                           recent_logs=recent_logs)


@bp.route("/<int:guest_id>/edit", methods=["POST"])
@login_required
def edit(guest_id):
    guest = Guest.query.get_or_404(guest_id)

    if not current_user.can_manage_guests:
        flash("Permission denied.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    guest.connection_method = request.form.get("connection_method", "ssh")
    guest.auto_update = "auto_update" in request.form
    guest.require_snapshot = request.form.get("require_snapshot", "inherit")

    cred_id = request.form.get("credential_id")
    try:
        guest.credential_id = int(cred_id) if cred_id else None
    except (TypeError, ValueError):
        flash("Invalid credential selection.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    # Update tags
    tag_ids = request.form.getlist("tag_ids")
    if tag_ids:
        try:
            parsed_tag_ids = [int(t) for t in tag_ids]
        except (TypeError, ValueError):
            flash("Invalid tag selection.", "error")
            return redirect(url_for("guests.detail", guest_id=guest.id))
        tags = Tag.query.filter(Tag.id.in_(parsed_tag_ids)).all()
        guest.tags = tags
    else:
        guest.tags = []

    log_action("guest_edit", "guest", resource_id=guest.id, resource_name=guest.name)
    db.session.commit()
    flash(f"Guest '{guest.name}' updated.", "success")
    return redirect(url_for("guests.detail", guest_id=guest.id))


@bp.route("/<int:guest_id>/reset", methods=["POST"])
@login_required
def reset(guest_id):
    """Clear stale scan results, packages, and services for a guest."""
    guest = Guest.query.get_or_404(guest_id)

    if not current_user.can_manage_guests:
        flash("Permission denied.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    guest.clear_stale_data()
    log_action("guest_reset", "guest", resource_id=guest.id, resource_name=guest.name)
    db.session.commit()
    flash(f"Guest '{guest.name}' has been reset. Scan results, packages, and services cleared.", "success")
    return redirect(url_for("guests.detail", guest_id=guest.id))


@bp.route("/<int:guest_id>/replication", methods=["POST"])
@login_required
def create_replication(guest_id):
    if not current_user.can_manage_guests:
        flash("Permission denied.", "error")
        return redirect(url_for("guests.detail", guest_id=guest_id))

    guest = Guest.query.get_or_404(guest_id)
    if not guest.proxmox_host or not guest.vmid:
        flash("Guest must be linked to a Proxmox host with a VMID.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    target_node = request.form.get("target_node", "").strip()
    schedule = request.form.get("schedule", "*/15").strip()

    if not target_node:
        flash("Target node is required.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    client = ProxmoxClient(guest.proxmox_host)
    ok, msg = client.create_replication(guest.vmid, target_node, schedule=schedule)
    if ok:
        guest.replication_target = target_node
        log_action("guest_replication_save", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"target_node": target_node, "schedule": schedule})
        db.session.commit()
        flash(msg, "success")
    else:
        flash(f"Failed to create replication: {msg}", "error")

    return redirect(url_for("guests.detail", guest_id=guest.id))


@bp.route("/<int:guest_id>/replication/<job_id>/delete", methods=["POST"])
@login_required
def delete_replication(guest_id, job_id):
    if not current_user.can_manage_guests:
        flash("Permission denied.", "error")
        return redirect(url_for("guests.detail", guest_id=guest_id))

    guest = Guest.query.get_or_404(guest_id)
    if not guest.proxmox_host:
        flash("Guest must be linked to a Proxmox host.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    client = ProxmoxClient(guest.proxmox_host)
    ok, msg = client.delete_replication(job_id)
    if ok:
        guest.replication_target = None
        log_action("guest_replication_delete", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"job_id": job_id})
        db.session.commit()
        flash(msg, "success")
    else:
        flash(f"Failed to delete replication: {msg}", "error")

    return redirect(url_for("guests.detail", guest_id=guest.id))


@bp.route("/<int:guest_id>/unifi/reconnect", methods=["POST"])
@login_required
def unifi_reconnect(guest_id):
    if not current_user.can_manage_guests:
        flash("Permission denied.", "error")
        return redirect(url_for("guests.detail", guest_id=guest_id))

    guest = Guest.query.get_or_404(guest_id)
    if not guest.mac_address:
        flash("No MAC address available for this guest.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    from routes.unifi import _get_unifi_client
    client = _get_unifi_client()
    if not client:
        flash("UniFi controller not configured.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    ok, msg = client.reconnect_client(guest.mac_address)
    if ok:
        log_action("guest_unifi_reconnect", "guest", resource_id=guest.id, resource_name=guest.name)
        db.session.commit()
        flash(f"Reconnect command sent to {guest.name}.", "success")
    else:
        flash(f"Failed to reconnect: {msg}", "error")

    return redirect(url_for("guests.detail", guest_id=guest.id))


@bp.route("/<int:guest_id>/unifi/block", methods=["POST"])
@login_required
def unifi_block(guest_id):
    if not current_user.can_manage_guests:
        flash("Permission denied.", "error")
        return redirect(url_for("guests.detail", guest_id=guest_id))

    guest = Guest.query.get_or_404(guest_id)
    if not guest.mac_address:
        flash("No MAC address available for this guest.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    from routes.unifi import _get_unifi_client
    client = _get_unifi_client()
    if not client:
        flash("UniFi controller not configured.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    ok, msg = client.block_client(guest.mac_address)
    if ok:
        log_action("guest_unifi_block", "guest", resource_id=guest.id, resource_name=guest.name)
        db.session.commit()
        flash(f"Block command sent for {guest.name}.", "warning")
    else:
        flash(f"Failed to block: {msg}", "error")

    return redirect(url_for("guests.detail", guest_id=guest.id))


@bp.route("/<int:guest_id>/unifi/unblock", methods=["POST"])
@login_required
def unifi_unblock(guest_id):
    if not current_user.can_manage_guests:
        flash("Permission denied.", "error")
        return redirect(url_for("guests.detail", guest_id=guest_id))

    guest = Guest.query.get_or_404(guest_id)
    if not guest.mac_address:
        flash("No MAC address available for this guest.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    from routes.unifi import _get_unifi_client
    client = _get_unifi_client()
    if not client:
        flash("UniFi controller not configured.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    ok, msg = client.unblock_client(guest.mac_address)
    if ok:
        log_action("guest_unifi_unblock", "guest", resource_id=guest.id, resource_name=guest.name)
        db.session.commit()
        flash(f"Unblock command sent for {guest.name}.", "success")
    else:
        flash(f"Failed to unblock: {msg}", "error")

    return redirect(url_for("guests.detail", guest_id=guest.id))


@bp.route("/<int:guest_id>/power/<action>", methods=["POST"])
@login_required
def power_action(guest_id, action):
    if not current_user.can_manage_guests:
        flash("Permission denied.", "error")
        return redirect(url_for("guests.detail", guest_id=guest_id))

    if action not in ("start", "shutdown", "stop", "reboot"):
        flash("Invalid power action.", "error")
        return redirect(url_for("guests.detail", guest_id=guest_id))

    guest = Guest.query.get_or_404(guest_id)
    if not guest.proxmox_host or not guest.vmid:
        flash("Guest must be linked to a Proxmox host with a VMID.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    client = ProxmoxClient(guest.proxmox_host)
    node = guest.proxmox_host.name

    # Find the actual node the guest is on
    found_node = client.find_guest_node(guest.vmid)
    if found_node:
        node = found_node

    if action == "start":
        ok, msg = client.start_guest(node, guest.vmid, guest.guest_type)
    elif action == "shutdown":
        ok, msg = client.shutdown_guest(node, guest.vmid, guest.guest_type)
    elif action == "stop":
        ok, msg = client.stop_guest(node, guest.vmid, guest.guest_type)
    else:
        ok, msg = client.reboot_guest(node, guest.vmid, guest.guest_type)

    if ok:
        # Update power state optimistically
        if action == "start":
            guest.power_state = "running"
        elif action in ("shutdown", "stop"):
            guest.power_state = "stopped"
        if action == "reboot":
            guest.reboot_required = False
        log_action("guest_power", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"action": action})
        db.session.commit()
        flash(f"{action.capitalize()} command sent to {guest.name}.", "success")
    else:
        flash(f"Power {action} failed: {msg}", "error")

    return redirect(url_for("guests.detail", guest_id=guest.id))


@bp.route("/<int:guest_id>/clone", methods=["POST"])
@login_required
def clone_guest(guest_id):
    if not current_user.can_manage_guests:
        flash("Permission denied.", "error")
        return redirect(url_for("guests.detail", guest_id=guest_id))

    guest = Guest.query.get_or_404(guest_id)
    if not guest.proxmox_host or not guest.vmid:
        flash("Guest must be linked to a Proxmox host with a VMID.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    newid_raw = request.form.get("newid", "").strip()
    try:
        newid = int(newid_raw)
    except (TypeError, ValueError):
        flash("New VMID must be a number.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))
    if newid <= 0:
        flash("New VMID must be a positive number.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))
    if newid == guest.vmid:
        flash("New VMID must differ from the source VMID.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    name = request.form.get("name", "").strip() or None
    full = request.form.get("clone_type", "full") != "linked"
    target_storage = request.form.get("target_storage", "").strip() or None

    client = ProxmoxClient(guest.proxmox_host)
    node = client.find_guest_node(guest.vmid)
    if not node:
        flash(f"Could not find {guest.guest_type}/{guest.vmid} on any node.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    ok, upid = client.clone_guest(node, guest.vmid, guest.guest_type, newid,
                                  name=name, full=full, target_storage=target_storage)
    if ok:
        # The clone appears as a new guest on the next host scan/discovery — no row is
        # hand-inserted here (matches how created guests are picked up).
        log_action("guest_clone", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"source_vmid": guest.vmid, "new_vmid": newid, "name": name,
                            "full": full, "node": node})
        db.session.commit()
        from routes.api import start_proxmox_job
        start_proxmox_job(guest, "clone", upid, node)
        return redirect(url_for("api.task_progress", guest_id=guest.id, job_type="clone"))
    else:
        flash(f"Failed to clone: {upid}", "error")

    return redirect(url_for("guests.detail", guest_id=guest.id))


@bp.route("/<int:guest_id>/migrate", methods=["POST"])
@login_required
def migrate_guest(guest_id):
    if not current_user.can_manage_guests:
        flash("Permission denied.", "error")
        return redirect(url_for("guests.detail", guest_id=guest_id))

    guest = Guest.query.get_or_404(guest_id)
    if not guest.proxmox_host or not guest.vmid:
        flash("Guest must be linked to a Proxmox host with a VMID.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    target_node = request.form.get("target_node", "").strip()
    if not target_node:
        flash("Target node is required.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    client = ProxmoxClient(guest.proxmox_host)
    node = client.find_guest_node(guest.vmid)
    if not node:
        flash(f"Could not find {guest.guest_type}/{guest.vmid} on any node.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    if target_node == node:
        flash("Target node must differ from the current node.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    valid_nodes = client.list_cluster_nodes()
    if valid_nodes and target_node not in valid_nodes:
        flash(f"Unknown target node '{target_node}'.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    # online=None lets the client decide (online=1 for running QEMU, restart=1 for running LXC).
    ok, upid = client.migrate_guest(node, guest.vmid, guest.guest_type, target_node)
    if ok:
        log_action("guest_migrate", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"source_node": node, "target_node": target_node})
        db.session.commit()
        from routes.api import start_proxmox_job
        start_proxmox_job(guest, "migrate", upid, node)
        return redirect(url_for("api.task_progress", guest_id=guest.id, job_type="migrate"))
    else:
        flash(f"Failed to migrate: {upid}", "error")

    return redirect(url_for("guests.detail", guest_id=guest.id))


@bp.route("/<int:guest_id>/snapshot/create", methods=["POST"])
@login_required
def create_snapshot(guest_id):
    if not current_user.can_manage_guests:
        flash("Permission denied.", "error")
        return redirect(url_for("guests.detail", guest_id=guest_id))

    guest = Guest.query.get_or_404(guest_id)
    if not guest.proxmox_host or not guest.vmid:
        flash("Guest must be linked to a Proxmox host with a VMID.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    snapname = request.form.get("snapname", "").strip()
    description = request.form.get("description", "").strip()

    if not snapname:
        from datetime import datetime
        snapname = f"manual-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

    client = ProxmoxClient(guest.proxmox_host)
    node = client.find_guest_node(guest.vmid)
    if not node:
        flash(f"Could not find {guest.guest_type}/{guest.vmid} on any node.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    ok, upid = client.create_snapshot(node, guest.vmid, guest.guest_type, snapname, description)
    if ok:
        log_action("guest_snapshot_create", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"snapname": snapname})
        db.session.commit()
        from routes.api import start_proxmox_job
        start_proxmox_job(guest, "snapshot", upid, node)
        return redirect(url_for("api.task_progress", guest_id=guest.id, job_type="snapshot"))
    else:
        flash(f"Failed to create snapshot: {upid}", "error")

    return redirect(url_for("guests.detail", guest_id=guest.id))


@bp.route("/<int:guest_id>/snapshot/<snapname>/delete", methods=["POST"])
@login_required
def delete_snapshot(guest_id, snapname):
    if not current_user.can_manage_guests:
        flash("Permission denied.", "error")
        return redirect(url_for("guests.detail", guest_id=guest_id))

    guest = Guest.query.get_or_404(guest_id)
    if not guest.proxmox_host or not guest.vmid:
        flash("Guest must be linked to a Proxmox host with a VMID.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    client = ProxmoxClient(guest.proxmox_host)
    node = client.find_guest_node(guest.vmid)
    if not node:
        flash(f"Could not find {guest.guest_type}/{guest.vmid} on any node.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    ok, upid = client.delete_snapshot(node, guest.vmid, guest.guest_type, snapname)
    if ok:
        log_action("guest_snapshot_delete", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"snapname": snapname})
        db.session.commit()
        from routes.api import start_proxmox_job
        start_proxmox_job(guest, "snapshot_delete", upid, node)
        return redirect(url_for("api.task_progress", guest_id=guest.id, job_type="snapshot_delete"))
    else:
        flash(f"Failed to delete snapshot: {upid}", "error")

    return redirect(url_for("guests.detail", guest_id=guest.id))


@bp.route("/<int:guest_id>/snapshot/<snapname>/rollback", methods=["POST"])
@login_required
def rollback_snapshot(guest_id, snapname):
    if not current_user.can_manage_guests:
        flash("Permission denied.", "error")
        return redirect(url_for("guests.detail", guest_id=guest_id))

    guest = Guest.query.get_or_404(guest_id)
    if not guest.proxmox_host or not guest.vmid:
        flash("Guest must be linked to a Proxmox host with a VMID.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    client = ProxmoxClient(guest.proxmox_host)
    node = client.find_guest_node(guest.vmid)
    if not node:
        flash(f"Could not find {guest.guest_type}/{guest.vmid} on any node.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    ok, upid = client.rollback_snapshot(node, guest.vmid, guest.guest_type, snapname)
    if ok:
        log_action("guest_snapshot_rollback", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"snapname": snapname})
        db.session.commit()
        from routes.api import start_proxmox_job
        start_proxmox_job(guest, "rollback", upid, node)
        return redirect(url_for("api.task_progress", guest_id=guest.id, job_type="rollback"))
    else:
        flash(f"Failed to rollback: {upid}", "error")

    return redirect(url_for("guests.detail", guest_id=guest.id))


@bp.route("/<int:guest_id>/backup-defaults", methods=["POST"])
@login_required
def save_backup_defaults(guest_id):
    if not current_user.can_manage_guests:
        flash("Permission denied.", "error")
        return redirect(url_for("guests.detail", guest_id=guest_id))

    guest = Guest.query.get_or_404(guest_id)
    guest.backup_storage = request.form.get("backup_storage", "").strip() or None
    guest.backup_mode = request.form.get("backup_mode", "").strip() or None
    guest.backup_compress = request.form.get("backup_compress", "").strip() or None
    db.session.commit()

    log_action("guest_backup_defaults_save", "guest", resource_id=guest.id, resource_name=guest.name,
               details={"storage": guest.backup_storage, "mode": guest.backup_mode, "compress": guest.backup_compress})
    db.session.commit()
    flash("Backup defaults saved.", "success")
    return redirect(url_for("guests.detail", guest_id=guest.id))


@bp.route("/<int:guest_id>/backup/create", methods=["POST"])
@login_required
def create_backup(guest_id):
    if not current_user.can_manage_guests:
        flash("Permission denied.", "error")
        return redirect(url_for("guests.detail", guest_id=guest_id))

    guest = Guest.query.get_or_404(guest_id)
    if not guest.proxmox_host or not guest.vmid:
        flash("Guest must be linked to a Proxmox host with a VMID.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    storage = request.form.get("storage", "").strip()
    mode = request.form.get("mode", "").strip()
    compress = request.form.get("compress", "").strip()
    protected = "protected" in request.form
    notes = request.form.get("notes", "").strip()

    # Fall back: per-guest → per-tag → legacy global defaults (grandfather clause)
    if not storage or not mode or not compress:
        tag_defaults = _get_tag_backup_defaults(guest)
        if not storage:
            storage = guest.backup_storage or tag_defaults.get("storage") or Setting.get("backup_storage", "")
        if not mode:
            mode = guest.backup_mode or tag_defaults.get("mode") or Setting.get("backup_mode", "snapshot")
        if not compress:
            compress = guest.backup_compress or tag_defaults.get("compress") or Setting.get("backup_compress", "zstd")

    if not storage:
        flash("No backup storage configured. Add a backup config for one of this guest's tags in Settings.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    client = ProxmoxClient(guest.proxmox_host)
    node = client.find_guest_node(guest.vmid)
    if not node:
        flash(f"Could not find {guest.guest_type}/{guest.vmid} on any node.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    ok, upid = client.create_backup(node, guest.vmid, storage, mode=mode, compress=compress, protected=protected, notes=notes)
    if ok:
        log_action("guest_backup_create", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"storage": storage, "mode": mode})
        db.session.commit()
        from routes.api import start_proxmox_job
        start_proxmox_job(guest, "backup", upid, node)
        return redirect(url_for("api.task_progress", guest_id=guest.id, job_type="backup"))
    else:
        flash(f"Failed to create backup: {upid}", "error")

    return redirect(url_for("guests.detail", guest_id=guest.id))


@bp.route("/<int:guest_id>/backup/<path:volid>/delete", methods=["POST"])
@login_required
def delete_backup(guest_id, volid):
    if not current_user.can_manage_guests:
        flash("Permission denied.", "error")
        return redirect(url_for("guests.detail", guest_id=guest_id))

    guest = Guest.query.get_or_404(guest_id)
    if not guest.proxmox_host or not guest.vmid:
        flash("Guest must be linked to a Proxmox host with a VMID.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    storage = volid.split(":")[0] if ":" in volid else (guest.backup_storage or _get_tag_backup_defaults(guest).get("storage") or Setting.get("backup_storage", ""))

    client = ProxmoxClient(guest.proxmox_host)
    node = client.find_guest_node(guest.vmid)
    if not node:
        flash(f"Could not find {guest.guest_type}/{guest.vmid} on any node.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    ok, msg = client.delete_backup(node, storage, volid)
    if ok:
        log_action("guest_backup_delete", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"volid": volid})
        db.session.commit()
        flash("Backup deleted.", "warning")
    else:
        flash(f"Failed to delete backup: {msg}", "error")

    return redirect(url_for("guests.detail", guest_id=guest.id))


@bp.route("/<int:guest_id>/backup/<path:volid>/protect", methods=["POST"])
@login_required
def toggle_backup_protection(guest_id, volid):
    if not current_user.can_manage_guests:
        flash("Permission denied.", "error")
        return redirect(url_for("guests.detail", guest_id=guest_id))

    guest = Guest.query.get_or_404(guest_id)
    if not guest.proxmox_host or not guest.vmid:
        flash("Guest must be linked to a Proxmox host with a VMID.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    storage = volid.split(":")[0] if ":" in volid else (guest.backup_storage or _get_tag_backup_defaults(guest).get("storage") or Setting.get("backup_storage", ""))
    protect = request.form.get("protected", "1") == "1"

    client = ProxmoxClient(guest.proxmox_host)
    node = client.find_guest_node(guest.vmid)
    if not node:
        flash(f"Could not find {guest.guest_type}/{guest.vmid} on any node.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    ok, msg = client.update_backup_protection(node, storage, volid, protect)
    if ok:
        log_action("guest_backup_protect", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"volid": volid, "protected": protect})
        db.session.commit()
        flash(msg, "success")
    else:
        flash(f"Failed to update protection: {msg}", "error")

    return redirect(url_for("guests.detail", guest_id=guest.id))


@bp.route("/<int:guest_id>/backup/<path:volid>/notes", methods=["POST"])
@login_required
def update_backup_notes(guest_id, volid):
    if not current_user.can_manage_guests:
        flash("Permission denied.", "error")
        return redirect(url_for("guests.detail", guest_id=guest_id))

    guest = Guest.query.get_or_404(guest_id)
    if not guest.proxmox_host or not guest.vmid:
        flash("Guest must be linked to a Proxmox host with a VMID.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    storage = volid.split(":")[0] if ":" in volid else (guest.backup_storage or _get_tag_backup_defaults(guest).get("storage") or Setting.get("backup_storage", ""))
    notes = request.form.get("notes", "").strip()

    client = ProxmoxClient(guest.proxmox_host)
    node = client.find_guest_node(guest.vmid)
    if not node:
        flash(f"Could not find {guest.guest_type}/{guest.vmid} on any node.", "error")
        return redirect(url_for("guests.detail", guest_id=guest.id))

    ok, msg = client.update_backup_notes(node, storage, volid, notes)
    if ok:
        log_action("guest_backup_notes", "guest", resource_id=guest.id, resource_name=guest.name,
                   details={"volid": volid})
        db.session.commit()
        flash("Backup notes updated.", "success")
    else:
        flash(f"Failed to update notes: {msg}", "error")

    return redirect(url_for("guests.detail", guest_id=guest.id))


@bp.route("/<int:guest_id>/delete", methods=["POST"])
@login_required
def delete(guest_id):
    if not current_user.can_manage_guests:
        flash("Permission denied.", "error")
        return redirect(url_for("guests.index"))

    guest = Guest.query.get_or_404(guest_id)
    name = guest.name
    log_action("guest_delete", "guest", resource_id=guest.id, resource_name=name)
    db.session.delete(guest)
    db.session.commit()
    flash(f"Guest '{name}' deleted.", "warning")
    return redirect(url_for("guests.index"))


def guest_requires_snapshot(guest):
    """Check if a snapshot is required before action on this guest."""
    if guest.require_snapshot == "yes":
        return True
    if guest.require_snapshot == "no":
        return False
    # inherit — check global setting
    return Setting.get("require_snapshot_before_action", "false") == "true"


def auto_snapshot_if_needed(guest):
    """Create an auto-snapshot if gating requires it and no recent snapshot exists.

    Returns (ok, message) — ok is True if snapshot was created or not needed,
    False if snapshot was required but creation failed.
    """
    import time
    from datetime import datetime

    if not guest.proxmox_host or not guest.vmid:
        # Can't create snapshots without Proxmox — skip gating
        return True, "No Proxmox host configured, skipping snapshot"

    client = ProxmoxClient(guest.proxmox_host)
    node = client.find_guest_node(guest.vmid)
    if not node:
        return False, f"Could not find {guest.guest_type}/{guest.vmid} on any node"

    # Check if a snapshot was taken within the last hour
    snapshots = client.list_snapshots(node, guest.vmid, guest.guest_type)
    now = time.time()
    one_hour_ago = now - 3600
    for snap in snapshots:
        snap_time = snap.get("snaptime", 0)
        if snap_time >= one_hour_ago:
            return True, f"Recent snapshot '{snap.get('name')}' exists, skipping"

    # Create auto-snapshot
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    snapname = f"auto-{timestamp}"
    description = f"Auto-snapshot before user action at {timestamp}"
    ok, msg = client.create_snapshot(node, guest.vmid, guest.guest_type, snapname, description)
    return ok, msg
