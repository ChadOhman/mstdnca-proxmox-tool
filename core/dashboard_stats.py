"""Shared dashboard statistics computation.

Used by both the web dashboard route and the mobile API.
"""

from collections import Counter

from models import Guest, GuestService, ProxmoxHost, Tag, UpdatePackage, db


def get_dashboard_stats(user, tag_filter=None):
    """Compute dashboard statistics respecting user's access control.

    Args:
        user: The authenticated User instance.
        tag_filter: Optional tag name to filter guests.  Use ``"__my_tags__"``
            to restrict to the user's own tags.

    Returns:
        A dict with aggregate stats, the list of guests with updates, and
        the list of guests needing a reboot.
    """
    user_tags = user.allowed_tags
    user_tag_names = [t.name for t in user_tags]

    # Build base guest query with access control
    if user.is_admin:
        base_query = Guest.query.filter_by(enabled=True)
    else:
        user_tag_ids = [t.id for t in user_tags]
        if not user_tag_ids:
            base_query = Guest.query.filter(False)
        else:
            base_query = Guest.query.filter_by(enabled=True).filter(
                Guest.tags.any(Tag.id.in_(user_tag_ids))
            )

    # Apply tag filter
    if tag_filter == "__my_tags__":
        base_query = base_query.filter(Guest.tags.any(Tag.name.in_(user_tag_names)))
    elif tag_filter:
        base_query = base_query.filter(Guest.tags.any(Tag.name == tag_filter))

    filtered_guests = base_query.all()
    filtered_guest_ids = [g.id for g in filtered_guests]

    total_guests = len(filtered_guests)
    guests_with_updates = [g for g in filtered_guests if g.status == "updates-available"]

    total_hosts = ProxmoxHost.query.count()

    if filtered_guest_ids:
        total_updates = UpdatePackage.query.filter(
            UpdatePackage.status == "pending",
            UpdatePackage.guest_id.in_(filtered_guest_ids),
        ).count()
        security_updates = UpdatePackage.query.filter(
            UpdatePackage.status == "pending",
            UpdatePackage.severity == "critical",
            UpdatePackage.guest_id.in_(filtered_guest_ids),
        ).count()
    else:
        total_updates = 0
        security_updates = 0

    reboot_required = [g for g in filtered_guests if g.reboot_required]

    # Power state breakdown
    power_states = Counter(g.power_state for g in filtered_guests)

    # Guest type breakdown
    guest_types = Counter(g.guest_type for g in filtered_guests)

    # Update status breakdown
    status_counts = Counter(g.status for g in filtered_guests)
    guests_never_scanned = sum(1 for g in filtered_guests if g.last_scan is None)

    # Auto-update coverage
    auto_update_enabled = sum(1 for g in filtered_guests if g.auto_update)

    # Service health
    total_services = 0
    services_running = 0
    services_failed = 0
    if filtered_guest_ids:
        svc_statuses = db.session.query(GuestService.status, db.func.count()).filter(
            GuestService.guest_id.in_(filtered_guest_ids)
        ).group_by(GuestService.status).all()
        for svc_status, count in svc_statuses:
            total_services += count
            if svc_status == "running":
                services_running += count
            elif svc_status == "failed":
                services_failed += count

    stats = {
        "total_hosts": total_hosts,
        "total_guests": total_guests,
        "total_updates": total_updates,
        "security_updates": security_updates,
        "reboot_required": len(reboot_required),
        "guests_running": power_states.get("running", 0),
        "guests_stopped": power_states.get("stopped", 0),
        "vms": guest_types.get("vm", 0),
        "containers": guest_types.get("ct", 0),
        "guests_up_to_date": status_counts.get("up-to-date", 0),
        "guests_error": status_counts.get("error", 0),
        "guests_never_scanned": guests_never_scanned,
        "auto_update_enabled": auto_update_enabled,
        "total_services": total_services,
        "services_running": services_running,
        "services_failed": services_failed,
    }

    return {
        "stats": stats,
        "guests_with_updates": guests_with_updates,
        "guests_needing_reboot": reboot_required,
    }
