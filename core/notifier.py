import hashlib
import json
import logging
import urllib.error
import urllib.request

from models import Setting

logger = logging.getLogger(__name__)

# Discord embed color constants (decimal integers)
_COLOR_GREEN = 8505220   # #81c784
_COLOR_CYAN = 5227511    # #4fc3f7
_COLOR_YELLOW = 16761095  # #ffc107
_COLOR_RED = 14431557    # #dc3545


def _get_discord_config():
    webhook_url = Setting.get("discord_webhook_url")
    enabled = Setting.get("discord_enabled", "false") == "true"
    return {"webhook_url": webhook_url, "enabled": enabled}


def _send_discord(embeds):
    """POST embeds to the configured Discord webhook. Returns (ok, message)."""
    config = _get_discord_config()

    if not config["enabled"]:
        return False, "Discord notifications are disabled"

    if not config["webhook_url"]:
        return False, "Discord webhook URL not configured"

    payload = json.dumps({"embeds": embeds}).encode()
    req = urllib.request.Request(
        config["webhook_url"],
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "MCAT/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status in (200, 204):
                return True, "Notification sent successfully"
            return False, f"Discord returned HTTP {resp.status}"
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode())
            detail = body.get("message", "")
        except Exception:
            detail = ""
        msg = f"Discord HTTP {e.code}: {detail or e.reason}"
        logger.error(f"Discord webhook error: {msg}")
        return False, msg
    except Exception as e:
        logger.error(f"Discord send failed: {e}")
        return False, str(e)


def send_test_notification():
    embeds = [{
        "title": "Mastodon Canada Administration Tool",
        "description": "Discord notifications are working correctly!",
        "color": _COLOR_GREEN,
    }]
    return _send_discord(embeds)


def send_update_notification(scan_results):
    """Send notification about available updates after a scan."""
    if Setting.get("discord_notify_updates", "true") != "true":
        return

    security_only = Setting.get("discord_notify_updates_security_only", "false") == "true"

    guests_with_updates = []
    total_updates = 0
    total_security = 0

    for result in scan_results:
        if result.status == "success" and result.total_updates > 0:
            if security_only and result.security_updates == 0:
                continue
            guests_with_updates.append(result)
            total_updates += result.total_updates
            total_security += result.security_updates

    if not guests_with_updates:
        return

    # Dedup: skip if the same set of updates was already notified
    fingerprint_parts = sorted(
        f"{r.guest.name}:{r.total_updates}:{r.security_updates}"
        for r in guests_with_updates
    )
    fingerprint = hashlib.sha256("|".join(fingerprint_parts).encode()).hexdigest()
    if fingerprint == Setting.get("guest_updates_last_notified_hash", ""):
        logger.debug("Guest update notification skipped (no change since last notification)")
        return

    color = _COLOR_RED if total_security > 0 else _COLOR_YELLOW

    fields = []
    for result in guests_with_updates:
        guest = result.guest
        sec_label = f"{result.security_updates} \U0001f534" if result.security_updates > 0 else str(result.security_updates)
        fields.append({
            "name": f"{guest.name} ({guest.guest_type.upper()})",
            "value": f"Updates: **{result.total_updates}** | Security: **{sec_label}**",
            "inline": False,
        })

    title = (
        f"\U0001f6a8 CRITICAL: {total_security} security update(s) available"
        if total_security > 0
        else f"\U0001f4e6 {total_updates} update(s) available"
    )

    embeds = [{
        "title": title,
        "description": f"**{total_updates}** update(s) across **{len(guests_with_updates)}** guest(s).",
        "color": color,
        "fields": fields,
        "footer": {"text": "Log in to MCAT to review and apply updates."},
    }]

    ok, msg = _send_discord(embeds)
    if ok:
        Setting.set("guest_updates_last_notified_hash", fingerprint)
        logger.info(f"Update notification sent for {len(guests_with_updates)} guest(s)")
    else:
        logger.error(f"Failed to send update notification: {msg}")


def send_host_update_notification(host_results):
    """Send notification about Proxmox host APT updates.

    host_results: list of dicts with keys name, host_type, update_count.
    """
    if Setting.get("discord_notify_updates", "true") != "true":
        return

    hosts_with_updates = [h for h in host_results if h["update_count"] > 0]
    if not hosts_with_updates:
        return

    # Dedup: skip if the same set of host updates was already notified
    fingerprint_parts = sorted(
        f"{h['name']}:{h['update_count']}" for h in hosts_with_updates
    )
    fingerprint = hashlib.sha256("|".join(fingerprint_parts).encode()).hexdigest()
    if fingerprint == Setting.get("host_updates_last_notified_hash", ""):
        logger.debug("Host update notification skipped (no change since last notification)")
        return

    total = sum(h["update_count"] for h in hosts_with_updates)

    fields = []
    for h in hosts_with_updates:
        type_label = "PBS" if h["host_type"] == "pbs" else "PVE"
        fields.append({
            "name": f"{h['name']} ({type_label})",
            "value": f"**{h['update_count']}** package(s) available",
            "inline": False,
        })

    embeds = [{
        "title": f"\U0001f4e6 {total} host update(s) available",
        "description": f"**{total}** package update(s) across **{len(hosts_with_updates)}** Proxmox host(s).",
        "color": _COLOR_YELLOW,
        "fields": fields,
        "footer": {"text": "Log in to MCAT to review and apply updates."},
    }]

    ok, msg = _send_discord(embeds)
    if ok:
        Setting.set("host_updates_last_notified_hash", fingerprint)
        logger.info(f"Host update notification sent for {len(hosts_with_updates)} host(s)")
    else:
        logger.error(f"Failed to send host update notification: {msg}")


def send_mastodon_update_notification(current_version, new_version, release_url):
    """Send notification about a new Mastodon release."""
    if Setting.get("discord_notify_mastodon", "true") != "true":
        return False, "Mastodon notifications disabled"

    auto_upgrade = Setting.get("mastodon_auto_upgrade", "false") == "true"
    note = "Auto-upgrade is enabled and will run shortly." if auto_upgrade else "Log in to MCAT to upgrade."

    fields = [
        {"name": "Current Version", "value": f"v{current_version or 'unknown'}", "inline": True},
        {"name": "New Version", "value": f"v{new_version}", "inline": True},
    ]
    if release_url:
        fields.append({"name": "Release Notes", "value": f"[View on GitHub]({release_url})", "inline": False})

    embeds = [{
        "title": f"\U0001f43b Mastodon update available: v{new_version}",
        "description": note,
        "color": _COLOR_YELLOW,
        "fields": fields,
        "footer": {"text": "Sent by Mastodon Canada Administration Tool"},
    }]

    ok, msg = _send_discord(embeds)
    if ok:
        logger.info(f"Mastodon update notification sent for v{new_version}")
    else:
        logger.error(f"Failed to send Mastodon update notification: {msg}")
    return ok, msg


def send_ghost_update_notification(current_version, new_version, release_url):
    """Send notification about a new Ghost release."""
    if Setting.get("discord_notify_ghost", "true") != "true":
        return False, "Ghost notifications disabled"

    auto_upgrade = Setting.get("ghost_auto_upgrade", "false") == "true"
    note = "Auto-upgrade is enabled and will run shortly." if auto_upgrade else "Log in to MCAT to upgrade."

    fields = [
        {"name": "Current Version", "value": f"v{current_version or 'unknown'}", "inline": True},
        {"name": "New Version", "value": f"v{new_version}", "inline": True},
    ]
    if release_url:
        fields.append({"name": "Release Notes", "value": f"[View on GitHub]({release_url})", "inline": False})

    embeds = [{
        "title": f"\U0001f47b Ghost update available: v{new_version}",
        "description": note,
        "color": _COLOR_YELLOW,
        "fields": fields,
        "footer": {"text": "Sent by Mastodon Canada Administration Tool"},
    }]

    ok, msg = _send_discord(embeds)
    if ok:
        logger.info(f"Ghost update notification sent for v{new_version}")
    else:
        logger.error(f"Failed to send Ghost update notification: {msg}")
    return ok, msg


def send_peertube_update_notification(current_version, new_version, release_url):
    """Send notification about a new PeerTube release."""
    if Setting.get("discord_notify_peertube", "true") != "true":
        return False, "PeerTube notifications disabled"

    auto_upgrade = Setting.get("peertube_auto_upgrade", "false") == "true"
    note = "Auto-upgrade is enabled and will run shortly." if auto_upgrade else "Log in to MCAT to upgrade."

    fields = [
        {"name": "Current Version", "value": f"v{current_version or 'unknown'}", "inline": True},
        {"name": "New Version", "value": f"v{new_version}", "inline": True},
    ]
    if release_url:
        fields.append({"name": "Release Notes", "value": f"[View on GitHub]({release_url})", "inline": False})

    embeds = [{
        "title": f"\U0001f3ac PeerTube update available: v{new_version}",
        "description": note,
        "color": _COLOR_YELLOW,
        "fields": fields,
        "footer": {"text": "Sent by Mastodon Canada Administration Tool"},
    }]

    ok, msg = _send_discord(embeds)
    if ok:
        logger.info(f"PeerTube update notification sent for v{new_version}")
    else:
        logger.error(f"Failed to send PeerTube update notification: {msg}")
    return ok, msg


def send_elk_update_notification(current_version, new_version, release_url):
    """Send notification about a new Elk release."""
    if Setting.get("discord_notify_elk", "true") != "true":
        return False, "Elk notifications disabled"

    auto_upgrade = Setting.get("elk_auto_upgrade", "false") == "true"
    note = "Auto-upgrade is enabled and will run shortly." if auto_upgrade else "Log in to MCAT to upgrade."

    fields = [
        {"name": "Current Version", "value": f"v{current_version or 'unknown'}", "inline": True},
        {"name": "New Version", "value": f"v{new_version}", "inline": True},
    ]
    if release_url:
        fields.append({"name": "Release Notes", "value": f"[View on GitHub]({release_url})", "inline": False})

    embeds = [{
        "title": f"\U0001f98c Elk update available: v{new_version}",
        "description": note,
        "color": _COLOR_YELLOW,
        "fields": fields,
        "footer": {"text": "Sent by Mastodon Canada Administration Tool"},
    }]

    ok, msg = _send_discord(embeds)
    if ok:
        logger.info(f"Elk update notification sent for v{new_version}")
    else:
        logger.error(f"Failed to send Elk update notification: {msg}")
    return ok, msg


def send_jitsi_update_notification(current_version, new_version, release_url):
    """Send notification about a new Jitsi Meet release."""
    if Setting.get("discord_notify_jitsi", "true") != "true":
        return False, "Jitsi notifications disabled"

    auto_upgrade = Setting.get("jitsi_auto_upgrade", "false") == "true"
    note = "Auto-upgrade is enabled and will run shortly." if auto_upgrade else "Log in to MCAT to upgrade."

    fields = [
        {"name": "Current Version", "value": f"v{current_version or 'unknown'}", "inline": True},
        {"name": "New Version", "value": f"v{new_version}", "inline": True},
    ]

    embeds = [{
        "title": f"\U0001f4f9 Jitsi Meet update available: v{new_version}",
        "description": note,
        "color": _COLOR_YELLOW,
        "fields": fields,
        "footer": {"text": "Sent by Mastodon Canada Administration Tool"},
    }]

    ok, msg = _send_discord(embeds)
    if ok:
        logger.info(f"Jitsi update notification sent for v{new_version}")
    else:
        logger.error(f"Failed to send Jitsi update notification: {msg}")
    return ok, msg


def send_upgrade_started_notification(service, version, trigger):
    """Send notification that an upgrade has been triggered.

    service: "mastodon", "ghost", "peertube", "elk", or "jitsi"
    version: target version string (may be empty if unknown)
    trigger: "manual" or "auto"
    """
    setting_key = f"discord_notify_{service}_upgrade_started"
    if Setting.get(setting_key, "true") != "true":
        return False, f"{service} upgrade-started notifications disabled"

    label = service.capitalize()
    _icons = {"mastodon": "\U0001f43b", "ghost": "\U0001f47b", "peertube": "\U0001f3ac", "elk": "\U0001f98c", "jitsi": "\U0001f4f9", "prometheus": "\U0001f4ca"}
    icon = _icons.get(service, "\U0001f4e6")
    trigger_label = "Automatic" if trigger == "auto" else "Manual"
    version_str = f" to v{version}" if version else ""

    embeds = [{
        "title": f"{icon} {label} upgrade started{version_str}",
        "description": f"A {trigger_label.lower()} upgrade has been initiated.",
        "color": _COLOR_YELLOW,
        "fields": [
            {"name": "Trigger", "value": trigger_label, "inline": True},
        ],
        "footer": {"text": "Sent by Mastodon Canada Administration Tool"},
    }]
    if version:
        embeds[0]["fields"].append(
            {"name": "Target Version", "value": f"v{version}", "inline": True}
        )

    ok, msg = _send_discord(embeds)
    if ok:
        logger.info(f"{label} upgrade-started notification sent (trigger={trigger})")
    else:
        logger.error(f"Failed to send {label} upgrade-started notification: {msg}")
    return ok, msg


def send_upgrade_result_notification(service, version, success, trigger):
    """Send notification about upgrade outcome.

    service: "mastodon", "ghost", or "peertube"
    version: version string (may be empty)
    success: True if upgrade succeeded, False otherwise
    trigger: "manual" or "auto"
    """
    setting_key = f"discord_notify_{service}_upgrade_result"
    if Setting.get(setting_key, "true") != "true":
        return False, f"{service} upgrade-result notifications disabled"

    label = service.capitalize()
    _icons = {"mastodon": "\U0001f43b", "ghost": "\U0001f47b", "peertube": "\U0001f3ac", "elk": "\U0001f98c", "jitsi": "\U0001f4f9", "prometheus": "\U0001f4ca"}
    icon = _icons.get(service, "\U0001f4e6")
    trigger_label = "Automatic" if trigger == "auto" else "Manual"
    version_str = f" to v{version}" if version else ""

    if success:
        title = f"{icon} {label} upgrade succeeded{version_str}"
        color = _COLOR_GREEN
    else:
        title = f"{icon} {label} upgrade failed{version_str}"
        color = _COLOR_RED

    embeds = [{
        "title": title,
        "color": color,
        "fields": [
            {"name": "Trigger", "value": trigger_label, "inline": True},
            {"name": "Result", "value": "Success" if success else "Failed", "inline": True},
        ],
        "footer": {"text": "Sent by Mastodon Canada Administration Tool"},
    }]

    ok, msg = _send_discord(embeds)
    if ok:
        logger.info(f"{label} upgrade-result notification sent (success={success})")
    else:
        logger.error(f"Failed to send {label} upgrade-result notification: {msg}")
    return ok, msg


def send_exporter_notification(action, exporter_type, guest_name, success):
    """Send notification about a Prometheus exporter install/uninstall.

    action: "install" or "uninstall"
    exporter_type: e.g. "node_exporter", "postgres_exporter", "mastodon"
    guest_name: name of the guest the exporter is on
    success: True if operation succeeded
    """
    setting_key = "discord_notify_prometheus_upgrade_result"
    if Setting.get(setting_key, "true") != "true":
        return False, "Prometheus operation-result notifications disabled"

    icon = "\U0001f4ca"
    action_label = action.capitalize()
    color = _COLOR_GREEN if success else _COLOR_RED
    status_label = "succeeded" if success else "failed"

    embeds = [{
        "title": f"{icon} Exporter {action} {status_label}: {exporter_type}",
        "color": color,
        "fields": [
            {"name": "Exporter", "value": exporter_type, "inline": True},
            {"name": "Guest", "value": guest_name, "inline": True},
            {"name": "Action", "value": action_label, "inline": True},
            {"name": "Result", "value": "Success" if success else "Failed", "inline": True},
        ],
        "footer": {"text": "Sent by Mastodon Canada Administration Tool"},
    }]

    ok, msg = _send_discord(embeds)
    if ok:
        logger.info(f"Exporter {action} notification sent ({exporter_type} on {guest_name})")
    else:
        logger.error(f"Failed to send exporter {action} notification: {msg}")
    return ok, msg


def send_app_update_notification(current_version, new_version):
    """Send notification about a new MCAT app release."""
    if Setting.get("discord_notify_app", "true") != "true":
        return False, "App update notifications disabled"

    auto_update = Setting.get("app_auto_update", "false") == "true"
    note = (
        "Auto-update is enabled. The application will update and restart shortly."
        if auto_update
        else "Log in to MCAT and go to Settings to apply the update."
    )

    embeds = [{
        "title": f"\u2b06\ufe0f MCAT application update available: v{new_version}",
        "description": note,
        "color": _COLOR_CYAN,
        "fields": [
            {"name": "Current Version", "value": f"v{current_version}", "inline": True},
            {"name": "New Version", "value": f"v{new_version}", "inline": True},
        ],
        "footer": {"text": "Sent by Mastodon Canada Administration Tool"},
    }]

    ok, msg = _send_discord(embeds)
    if ok:
        logger.info(f"App update notification sent for v{new_version}")
    else:
        logger.error(f"Failed to send app update notification: {msg}")
    return ok, msg


def summarize_applied_packages(packages):
    """Return (applied_count, security_count) for the given update packages.

    Callers MUST pass the packages captured *before* the apply/commit. The
    ``applied_at`` column is timezone-naive, so after ``db.session.commit()``
    a reloaded ``applied_at`` (naive) compared against a tz-aware ``now`` never
    matches — which silently produced "0 update(s) applied" notifications.
    Counting the in-memory pending list up front avoids that entirely.
    """
    packages = list(packages)
    applied = len(packages)
    security = sum(1 for p in packages if p.severity == "critical")
    return applied, security


def send_updates_applied_notification(results):
    """Send notification about updates that were just applied.

    results: list of dicts with keys name, type, applied, security.
    """
    if Setting.get("discord_notify_updates", "true") != "true":
        return

    if not results:
        return

    total_applied = sum(r["applied"] for r in results)
    entity_count = len(results)
    entity_word = "guest(s)" if all(r["type"] in ("CT", "VM") for r in results) else "target(s)"

    fields = []
    for r in results:
        value = f"{r['applied']} applied"
        if r["security"] > 0:
            value += f" ({r['security']} security)"
        fields.append({
            "name": f"{r['name']} ({r['type']})",
            "value": value,
            "inline": False,
        })

    embeds = [{
        "title": "\u2705 Updates applied",
        "description": f"**{total_applied}** update(s) applied across **{entity_count}** {entity_word}.",
        "color": _COLOR_GREEN,
        "fields": fields,
        "footer": {"text": "Log in to MCAT to review details."},
    }]

    ok, msg = _send_discord(embeds)
    if ok:
        logger.info(f"Updates-applied notification sent for {entity_count} target(s)")
    else:
        logger.error(f"Failed to send updates-applied notification: {msg}")


def send_service_failed_notification(guest_name, service_name):
    """Send notification when a service transitions to failed state."""
    if Setting.get("discord_notify_services", "true") != "true":
        return

    embeds = [{
        "title": f"\u274c Service failed: {service_name}",
        "description": f"**{service_name}** on **{guest_name}** has stopped running.",
        "color": _COLOR_RED,
        "footer": {"text": "Log in to MCAT to investigate."},
    }]

    ok, msg = _send_discord(embeds)
    if ok:
        logger.info(f"Service-failed notification sent: {service_name} on {guest_name}")
    else:
        logger.error(f"Failed to send service-failed notification: {msg}")


def send_service_recovery_notification(guest_name, service_name):
    """Send notification when a service recovers from failed state."""
    if Setting.get("discord_notify_services", "true") != "true":
        return

    embeds = [{
        "title": f"\u2705 Service recovered: {service_name}",
        "description": f"**{service_name}** on **{guest_name}** is running again.",
        "color": _COLOR_GREEN,
        "footer": {"text": "Log in to MCAT to review."},
    }]

    ok, msg = _send_discord(embeds)
    if ok:
        logger.info(f"Service-recovery notification sent: {service_name} on {guest_name}")
    else:
        logger.error(f"Failed to send service-recovery notification: {msg}")
