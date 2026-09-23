import logging

logger = logging.getLogger(__name__)


def build_system_prompt(user, page_context=None):
    """Build a system prompt for Claude with infrastructure context.

    Args:
        user: The current User model instance.
        page_context: Optional dict with keys: page_url, page_type, entity_id.

    Returns:
        A system prompt string.
    """
    parts = [
        "You are an AI assistant integrated into a Proxmox datacenter administration tool. "
        "You help administrators manage their virtual machines, containers, services, and infrastructure.",
        "",
        f"The current user is '{user.username}' with the '{user.role}' role.",
        "",
        "You have access to tools that let you query and control the infrastructure. "
        "Always use the appropriate tool when the user asks about guests, services, updates, or hosts. "
        "Do not make up information — use tools to look up real data.",
        "",
        "State-changing tools (control_service, control_guest_power, manage_snapshot, manage_backup) are protected by a "
        "server-side two-phase confirmation: your first call returns a 'confirmation_required' result and "
        "does NOT perform the action. Relay that proposed action to the user in plain language, including "
        "any warning it carries (a hard stop, a lock, an irreversible delete or rollback), and wait for "
        "their explicit approval. Only after the user approves should you call the tool again with "
        "\"confirm\": true. Never set confirm=true on your own initiative, and never chain several "
        "state-changing actions on one approval. A backup restore also needs confirm_name equal to the "
        "guest's exact name, which the user must have typed themselves.",
        "",
        "Guests have two identifiers: the tool's own guest ID (used by every guest_id parameter) and the "
        "Proxmox VMID (what 'CT 103' or 'VM 133' refers to). Resolve names and VMIDs with list_guests first. "
        "list_guests and get_guest_details report the last package scan stored in the database; for live "
        "CPU, memory, disk or uptime call get_guest_resource_usage (now) or get_guest_performance_history "
        "(averages and peaks), and get_host_status for a host's own resources and storage pools. Byte values "
        "come with a ready-made 'human' string; quote that rather than raw bytes.",
        "",
        "Keep responses concise and actionable. The chat panel renders only headings, bold, italics, inline "
        "code, fenced code blocks and '- ' bullet lists; it does not render tables, so use bullets instead.",
    ]

    # Add permission context
    permissions = []
    if user.can_view_services:
        permissions.append("view and monitor services")
    if user.can_edit_services:
        permissions.append("control services (start/stop/restart)")
    if user.can_manage_guests:
        permissions.append("manage guests (power control, snapshots, backups)")
    if user.can_update:
        permissions.append("scan and apply updates")
    if user.can_view_hosts:
        permissions.append("view host status")
    if user.can_view_audit_log:
        permissions.append("search audit logs")
    if user.can_view_unifi:
        permissions.append("view network devices and clients")

    if permissions:
        parts.append("")
        parts.append(f"Your capabilities for this user: {', '.join(permissions)}.")

    # Add page context
    if page_context:
        context_str = _build_page_context(page_context, user)
        if context_str:
            parts.append("")
            parts.append("## Current Page Context")
            parts.append(context_str)

    return "\n".join(parts)


def _build_page_context(page_context, user):
    """Build context string based on the current page."""
    page_type = page_context.get("page_type", "")
    entity_id = page_context.get("entity_id")

    if not page_type:
        return ""

    try:
        if page_type == "guests" and entity_id:
            return _guest_context(int(entity_id), user)
        if page_type == "services":
            return "The user is viewing the Services monitoring page."
        if page_type == "hosts":
            return "The user is viewing the Hosts overview page."
        if page_type == "dashboard":
            return "The user is on the main Dashboard."
        if page_type == "unifi":
            return "The user is viewing the UniFi network overview."
        if page_type in ("mastodon", "ghost", "peertube", "jitsi", "elk"):
            return f"The user is viewing the {page_type.capitalize()} application management page."
        return f"The user is on the {page_type} page."
    except Exception as e:
        logger.debug("Error building page context: %s", e)
        return ""


def _guest_context(guest_id, user):
    """Build context for a specific guest detail page."""
    from models import Guest

    guest = Guest.query.get(guest_id)
    if not guest or not user.can_access_guest(guest):
        return ""

    lines = [
        f"The user is viewing guest '{guest.name}' (ID: {guest.id}).",
        f"- Type: {guest.guest_type}, VMID: {guest.vmid}",
        f"- IP: {guest.ip_address or 'unknown'}",
        f"- Status: {guest.status}, Power: {guest.power_state}",
        f"- Host: {guest.proxmox_host.name if guest.proxmox_host else 'unknown'}",
    ]

    pending = guest.pending_updates()
    if pending:
        security = guest.security_updates()
        lines.append(f"- Pending updates: {len(pending)} ({len(security)} security)")
        if guest.reboot_required:
            lines.append("- Reboot required after updates")

    if guest.services:
        svc_summary = ", ".join(f"{s.service_name}({s.status})" for s in guest.services)
        lines.append(f"- Services: {svc_summary}")

    if guest.tags:
        lines.append(f"- Tags: {', '.join(t.name for t in guest.tags)}")

    return "\n".join(lines)
