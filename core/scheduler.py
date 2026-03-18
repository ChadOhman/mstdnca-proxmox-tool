import logging
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

logger = logging.getLogger(__name__)

_scheduler = None


def _run_scan(app):
    """Run a full scan of all guests and send notifications."""
    with app.app_context():
        from models import Setting
        if Setting.get("scan_enabled", "true") == "false":
            logger.info("Automatic scanning is disabled, skipping.")
            return

        logger.info("Starting scheduled scan of all guests...")
        from core.scanner import scan_all_guests
        results = scan_all_guests()

        from core.notifier import send_update_notification
        send_update_notification(results)

        logger.info(f"Scheduled scan complete. Scanned {len(results)} guest(s).")


def _run_auto_updates(app):
    """Apply updates to guests with auto-update enabled during their maintenance window."""
    with app.app_context():
        import calendar

        from core.scanner import apply_updates
        from models import Guest

        now = datetime.now()
        current_day = calendar.day_name[now.weekday()].lower()
        current_time = now.strftime("%H:%M")

        guests = Guest.query.filter_by(enabled=True, auto_update=True).all()

        for guest in guests:
            window = guest.maintenance_window
            if not window or not window.enabled:
                continue

            # Check if current day matches
            if window.day_of_week != "daily" and window.day_of_week != current_day:
                continue

            # Check if current time is within window
            if not (window.start_time <= current_time <= window.end_time):
                continue

            # Check if there are pending updates
            if not guest.pending_updates():
                continue

            dist_upgrade = window.update_type == "dist-upgrade"
            logger.info(f"Auto-updating {guest.name} (window: {window.name})")

            ok, output = apply_updates(guest, dist_upgrade=dist_upgrade)
            if ok:
                logger.info(f"Auto-update successful for {guest.name}")
            else:
                logger.error(f"Auto-update failed for {guest.name}: {output}")


def _check_mastodon_release(app):
    """Check for new Mastodon releases and optionally auto-upgrade."""
    with app.app_context():
        from models import Setting

        # Only check if a Mastodon guest is configured
        if not Setting.get("mastodon_guest_id"):
            return

        from apps.mastodon import check_mastodon_release
        update_available, latest, release_url = check_mastodon_release()

        if not update_available:
            return

        current = Setting.get("mastodon_current_version", "")
        logger.info(f"Mastodon update available: v{current} -> v{latest}")

        # Send Discord notification (only if not already notified for this version)
        last_notified = Setting.get("mastodon_last_notified_version", "")
        if latest != last_notified:
            from core.notifier import send_mastodon_update_notification
            ok, _msg = send_mastodon_update_notification(current, latest, release_url)
            if ok:
                Setting.set("mastodon_last_notified_version", latest)

        # Auto-upgrade if enabled
        if Setting.get("mastodon_auto_upgrade", "false") == "true":
            logger.info("Auto-upgrade enabled, starting Mastodon upgrade...")
            from apps.mastodon import run_mastodon_upgrade
            from auth.audit import log_action
            from core.notifier import send_upgrade_result_notification, send_upgrade_started_notification
            from models import db
            send_upgrade_started_notification("mastodon", latest, "auto")
            try:
                ok, log_output = run_mastodon_upgrade()
            except Exception as exc:
                logger.exception("Mastodon auto-upgrade crashed")
                ok, log_output = False, f"Auto-upgrade crashed: {exc}"
            log_action("mastodon_upgrade", "settings", resource_name="mastodon",
                       details={"status": "success" if ok else "error", "trigger": "auto"})
            db.session.commit()
            now = datetime.now(timezone.utc).isoformat()
            Setting.set("mastodon_last_upgrade_at", now)
            Setting.set("mastodon_last_upgrade_status", "success" if ok else "error")
            Setting.set("mastodon_last_upgrade_log", log_output)
            send_upgrade_result_notification("mastodon", latest, ok, "auto")
            if ok:
                logger.info("Mastodon auto-upgrade completed successfully")
            else:
                logger.error("Mastodon auto-upgrade failed")


def _check_ghost_release(app):
    """Check for new Ghost releases and optionally auto-upgrade."""
    with app.app_context():
        from models import Setting

        # Only check if a Ghost guest is configured
        if not Setting.get("ghost_guest_id"):
            return

        from apps.ghost import check_ghost_release
        update_available, latest, release_url = check_ghost_release()

        if not update_available:
            return

        current = Setting.get("ghost_current_version", "")
        logger.info(f"Ghost update available: v{current} -> v{latest}")

        # Send Discord notification (only if not already notified for this version)
        last_notified = Setting.get("ghost_last_notified_version", "")
        if latest != last_notified:
            from core.notifier import send_ghost_update_notification
            ok, _msg = send_ghost_update_notification(current, latest, release_url)
            if ok:
                Setting.set("ghost_last_notified_version", latest)

        # Auto-upgrade if enabled
        if Setting.get("ghost_auto_upgrade", "false") == "true":
            logger.info("Auto-upgrade enabled, starting Ghost upgrade...")
            from apps.ghost import run_ghost_upgrade
            from auth.audit import log_action
            from core.notifier import send_upgrade_result_notification, send_upgrade_started_notification
            from models import db
            send_upgrade_started_notification("ghost", latest, "auto")
            try:
                ok, log_output = run_ghost_upgrade()
            except Exception as exc:
                logger.exception("Ghost auto-upgrade crashed")
                ok, log_output = False, f"Auto-upgrade crashed: {exc}"
            log_action("ghost_upgrade", "settings", resource_name="ghost",
                       details={"status": "success" if ok else "error", "trigger": "auto"})
            db.session.commit()
            now = datetime.now(timezone.utc).isoformat()
            Setting.set("ghost_last_upgrade_at", now)
            Setting.set("ghost_last_upgrade_status", "success" if ok else "error")
            Setting.set("ghost_last_upgrade_log", log_output)
            send_upgrade_result_notification("ghost", latest, ok, "auto")
            if ok:
                logger.info("Ghost auto-upgrade completed successfully")
            else:
                logger.error("Ghost auto-upgrade failed")


def _check_peertube_release(app):
    """Check for new PeerTube releases and optionally auto-upgrade."""
    with app.app_context():
        from models import Setting

        # Only check if a PeerTube guest is configured
        if not Setting.get("peertube_guest_id"):
            return

        from apps.peertube import check_peertube_release
        update_available, latest, release_url = check_peertube_release()

        if not update_available:
            return

        current = Setting.get("peertube_current_version", "")
        logger.info(f"PeerTube update available: v{current} -> v{latest}")

        # Send Discord notification (only if not already notified for this version)
        last_notified = Setting.get("peertube_last_notified_version", "")
        if latest != last_notified:
            from core.notifier import send_peertube_update_notification
            ok, _msg = send_peertube_update_notification(current, latest, release_url)
            if ok:
                Setting.set("peertube_last_notified_version", latest)

        # Auto-upgrade if enabled
        if Setting.get("peertube_auto_upgrade", "false") == "true":
            logger.info("Auto-upgrade enabled, starting PeerTube upgrade...")
            from apps.peertube import run_peertube_upgrade
            from auth.audit import log_action
            from core.notifier import send_upgrade_result_notification, send_upgrade_started_notification
            from models import db
            send_upgrade_started_notification("peertube", latest, "auto")
            try:
                ok, log_output = run_peertube_upgrade()
            except Exception as exc:
                logger.exception("PeerTube auto-upgrade crashed")
                ok, log_output = False, f"Auto-upgrade crashed: {exc}"
            log_action("peertube_upgrade", "settings", resource_name="peertube",
                       details={"status": "success" if ok else "error", "trigger": "auto"})
            db.session.commit()
            now = datetime.now(timezone.utc).isoformat()
            Setting.set("peertube_last_upgrade_at", now)
            Setting.set("peertube_last_upgrade_status", "success" if ok else "error")
            Setting.set("peertube_last_upgrade_log", log_output)
            send_upgrade_result_notification("peertube", latest, ok, "auto")
            if ok:
                logger.info("PeerTube auto-upgrade completed successfully")
            else:
                logger.error("PeerTube auto-upgrade failed")


def _check_elk_release(app):
    """Check for new Elk releases and optionally auto-upgrade."""
    with app.app_context():
        from models import Setting

        # Only check if an Elk guest is configured and installed
        if not Setting.get("elk_guest_id"):
            return
        if Setting.get("elk_installed", "false") != "true":
            return

        from apps.elk import check_elk_release
        update_available, latest, release_url = check_elk_release()

        if not update_available:
            return

        current = Setting.get("elk_current_version", "")
        logger.info(f"Elk update available: v{current} -> v{latest}")

        # Send Discord notification (only if not already notified for this version)
        last_notified = Setting.get("elk_last_notified_version", "")
        if latest != last_notified:
            from core.notifier import send_elk_update_notification
            ok, _msg = send_elk_update_notification(current, latest, release_url)
            if ok:
                Setting.set("elk_last_notified_version", latest)

        # Auto-upgrade if enabled
        if Setting.get("elk_auto_upgrade", "false") == "true":
            logger.info("Auto-upgrade enabled, starting Elk upgrade...")
            from apps.elk import run_elk_upgrade
            from auth.audit import log_action
            from core.notifier import send_upgrade_result_notification, send_upgrade_started_notification
            from models import db
            send_upgrade_started_notification("elk", latest, "auto")
            try:
                ok, log_output = run_elk_upgrade()
            except Exception as exc:
                logger.exception("Elk auto-upgrade crashed")
                ok, log_output = False, f"Auto-upgrade crashed: {exc}"
            log_action("elk_upgrade", "settings", resource_name="elk",
                       details={"status": "success" if ok else "error", "trigger": "auto"})
            db.session.commit()
            now = datetime.now(timezone.utc).isoformat()
            Setting.set("elk_last_upgrade_at", now)
            Setting.set("elk_last_upgrade_status", "success" if ok else "error")
            Setting.set("elk_last_upgrade_log", log_output)
            send_upgrade_result_notification("elk", latest, ok, "auto")
            if ok:
                logger.info("Elk auto-upgrade completed successfully")
            else:
                logger.error("Elk auto-upgrade failed")


def _check_jitsi_release(app):
    """Check for new Jitsi releases and optionally auto-upgrade."""
    with app.app_context():
        from models import Setting

        # Only check if a Jitsi guest is configured and installed
        if not Setting.get("jitsi_guest_id"):
            return
        if Setting.get("jitsi_installed", "false") != "true":
            return

        from apps.jitsi import check_jitsi_release
        update_available, latest, release_url = check_jitsi_release()

        if not update_available:
            return

        current = Setting.get("jitsi_current_version", "")
        logger.info(f"Jitsi update available: v{current} -> v{latest}")

        # Send Discord notification (only if not already notified for this version)
        last_notified = Setting.get("jitsi_last_notified_version", "")
        if latest != last_notified:
            from core.notifier import send_jitsi_update_notification
            ok, _msg = send_jitsi_update_notification(current, latest, release_url)
            if ok:
                Setting.set("jitsi_last_notified_version", latest)

        # Auto-upgrade if enabled
        if Setting.get("jitsi_auto_upgrade", "false") == "true":
            logger.info("Auto-upgrade enabled, starting Jitsi upgrade...")
            from apps.jitsi import run_jitsi_upgrade
            from auth.audit import log_action
            from core.notifier import send_upgrade_result_notification, send_upgrade_started_notification
            from models import db
            send_upgrade_started_notification("jitsi", latest, "auto")
            try:
                ok, log_output = run_jitsi_upgrade()
            except Exception as exc:
                logger.exception("Jitsi auto-upgrade crashed")
                ok, log_output = False, f"Auto-upgrade crashed: {exc}"
            log_action("jitsi_upgrade", "settings", resource_name="jitsi",
                       details={"status": "success" if ok else "error", "trigger": "auto"})
            db.session.commit()
            now = datetime.now(timezone.utc).isoformat()
            Setting.set("jitsi_last_upgrade_at", now)
            Setting.set("jitsi_last_upgrade_status", "success" if ok else "error")
            Setting.set("jitsi_last_upgrade_log", log_output)
            send_upgrade_result_notification("jitsi", latest, ok, "auto")
            if ok:
                logger.info("Jitsi auto-upgrade completed successfully")
            else:
                logger.error("Jitsi auto-upgrade failed")


def _run_discovery(app):
    """Refresh guest discovery for all Proxmox hosts."""
    with app.app_context():
        import re

        from clients.proxmox_api import ProxmoxClient
        from models import Guest, ProxmoxHost, Setting, Tag, db

        if Setting.get("discovery_enabled", "true") == "false":
            logger.info("Automatic discovery is disabled, skipping.")
            return

        hosts = ProxmoxHost.query.all()
        if not hosts:
            return

        for host in hosts:
            try:
                client = ProxmoxClient(host)
                node_name = client.get_local_node_name()
                if node_name:
                    node_guests = client.get_node_guests(node_name)
                else:
                    node_guests = client.get_all_guests()
                    node_name = "cluster"

                repl_map = client.get_replication_map()

                # Pre-load all tag names seen in this batch to avoid O(N×M) per-guest queries
                all_tag_names = {
                    t.strip()
                    for g in node_guests
                    for t in re.split(r"[;,]", g.get("tags", ""))
                    if t.strip()
                }
                tag_cache = {t.name: t for t in Tag.query.filter(Tag.name.in_(all_tag_names)).all()}

                def _resolve_tag(name, _cache=tag_cache):
                    if name not in _cache:
                        _cache[name] = Tag(name=name)
                        db.session.add(_cache[name])
                    return _cache[name]

                # Clean up stale guests on this host
                node_vmids = {g.get("vmid") for g in node_guests}
                stale = Guest.query.filter(
                    Guest.proxmox_host_id == host.id,
                    Guest.vmid.isnot(None),
                    ~Guest.vmid.in_(node_vmids),
                ).all()
                for s in stale:
                    db.session.delete(s)

                added = 0
                updated = 0
                reused = 0
                for g in node_guests:
                    vmid = g.get("vmid")
                    status = g.get("status", "")

                    existing = Guest.query.filter_by(proxmox_host_id=host.id, vmid=vmid).first()

                    if not existing:
                        other = Guest.query.filter(Guest.vmid == vmid, Guest.proxmox_host_id != host.id).first()
                        if other:
                            if status != "running":
                                continue
                            existing = other
                            existing.proxmox_host_id = host.id

                    proxmox_tags = g.get("tags", "")
                    tag_names = [t.strip() for t in re.split(r"[;,]", proxmox_tags) if t.strip()] if proxmox_tags else []

                    ip = None
                    if status == "running":
                        ip = client.get_guest_ip(g["node"], vmid, g["type"])

                    repl_target = repl_map.get(vmid)
                    mac = client.get_guest_mac(g["node"], vmid, g["type"])
                    power_state = status if status in ("running", "stopped", "paused") else "unknown"

                    if not existing:
                        guest = Guest(
                            proxmox_host_id=host.id,
                            vmid=vmid,
                            name=g.get("name", f"guest-{vmid}"),
                            guest_type=g["type"],
                            ip_address=ip,
                            connection_method="auto",
                            replication_target=repl_target,
                            mac_address=mac,
                            power_state=power_state,
                        )
                        db.session.add(guest)
                        added += 1

                        for tag_name in tag_names:
                            guest.tags.append(_resolve_tag(tag_name))
                    else:
                        # Detect VMID reuse: type changed means old guest was destroyed
                        if existing.guest_type != g["type"]:
                            old_type = existing.guest_type
                            existing.guest_type = g["type"]
                            existing.clear_stale_data()
                            reused += 1
                            logger.warning(
                                "VMID %s on '%s': type changed %s -> %s (reuse detected, stale data cleared)",
                                vmid, host.name, old_type, g["type"],
                            )

                        if ip:
                            existing.ip_address = ip
                        existing.name = g.get("name", existing.name)
                        existing.replication_target = repl_target
                        existing.power_state = power_state
                        if mac:
                            existing.mac_address = mac
                        existing.tags.clear()
                        for tag_name in tag_names:
                            existing.tags.append(_resolve_tag(tag_name))
                        updated += 1

                db.session.commit()
                msg = f"Discovery for '{host.name}' node '{node_name}': {added} new, {updated} updated, {len(stale)} stale removed"
                if reused:
                    msg += f", {reused} VMID reuse(s) detected"
                logger.info(msg)
            except Exception as e:
                logger.error(f"Scheduled discovery failed for '{host.name}': {e}")


def _persist_host_packages(host, api_updates):
    """Persist APT update packages from Proxmox API to HostUpdatePackage table."""
    from models import HostUpdatePackage, db

    HostUpdatePackage.query.filter_by(host_id=host.id, status="pending").delete()

    _PRIORITY_MAP = {"important": "critical", "required": "important"}

    for upd in api_updates:
        severity = _PRIORITY_MAP.get(upd.get("Priority", ""), "normal")
        pkg = HostUpdatePackage(
            host_id=host.id,
            package_name=upd.get("Package", "unknown"),
            current_version=upd.get("OldVersion", ""),
            available_version=upd.get("Version") or upd.get("NewVersion", ""),
            severity=severity,
            status="pending",
        )
        db.session.add(pkg)

    db.session.commit()


def _check_host_updates(app):
    """Check all Proxmox hosts for pending APT updates and notify."""
    with app.app_context():
        from models import ProxmoxHost, Setting

        if Setting.get("scan_enabled", "true") == "false":
            return

        hosts = ProxmoxHost.query.all()
        if not hosts:
            return

        host_results = []
        for host in hosts:
            try:
                if host.is_pbs:
                    from clients.pbs_client import PBSClient
                    client = PBSClient(host)
                    updates = client.get_apt_updates()
                else:
                    from clients.proxmox_api import ProxmoxClient
                    client = ProxmoxClient(host)
                    node_name = client.get_local_node_name()
                    updates = client.get_apt_updates(node_name) if node_name else []

                _persist_host_packages(host, updates)

                host_results.append({
                    "name": host.name,
                    "host_type": host.host_type,
                    "update_count": len(updates),
                })
            except Exception as e:
                logger.error(f"Failed to check host updates for '{host.name}': {e}")

        if host_results:
            from core.notifier import send_host_update_notification
            send_host_update_notification(host_results)


def _check_app_update(app):
    """Check for new app releases, store result, and optionally auto-update."""
    with app.app_context():
        import json
        import os
        import subprocess
        import urllib.request

        from config import BASE_DIR
        from models import Setting

        repo = app.config.get("GITHUB_REPO", "")
        current_version = app.config.get("APP_VERSION", "0.0.0")
        update_branch = Setting.get("app_update_branch", "")
        auto_update = Setting.get("app_auto_update", "false") == "true"
        update_script = os.path.join(BASE_DIR, "scripts", "update.sh")

        if not repo:
            return

        # Always fetch the latest release and store it
        try:
            url = f"https://api.github.com/repos/{repo}/releases/latest"
            req = urllib.request.Request(url, headers={"User-Agent": "MCAT"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                latest = data.get("tag_name", "").lstrip("v")
                if latest:
                    Setting.set("latest_app_version", latest)
                    Setting.set("latest_app_check", datetime.now(tz=timezone.utc).isoformat())
        except Exception as e:
            logger.error(f"Failed to check for app updates: {e}")
            return

        # Send Discord notification (independent of auto-update setting)
        if latest and latest != current_version and current_version != "unknown":
            last_notified = Setting.get("app_last_notified_version", "")
            if latest != last_notified:
                logger.info(f"New app version available: v{current_version} -> v{latest}")
                from core.notifier import send_app_update_notification
                ok, _msg = send_app_update_notification(current_version, latest)
                if ok:
                    Setting.set("app_last_notified_version", latest)

        if not auto_update:
            return

        # Branch-based auto-update: always pull latest from configured branch
        if update_branch:
            import re as _re
            if not _re.match(r'^[A-Za-z0-9._\-/]+$', update_branch) or update_branch.startswith("-"):
                logger.error("Invalid update branch name, skipping auto-update")
                return
            logger.info(f"Auto-update from branch '{update_branch}'...")
            if os.path.exists(update_script):
                subprocess.Popen(["bash", update_script, "--branch", update_branch], cwd=BASE_DIR)
            else:
                logger.warning("update.sh not found, cannot auto-update")
            return

        if current_version == "unknown":
            return

        if not latest or latest == current_version:
            return

        # Run update.sh
        if os.path.exists(update_script):
            logger.info("Auto-update enabled, running update.sh...")
            subprocess.Popen(["bash", update_script], cwd=BASE_DIR)
        else:
            logger.warning("update.sh not found, cannot auto-update")


def _purge_old_audit_logs(app):
    """Delete audit log entries older than 90 days."""
    with app.app_context():
        from models import AuditLog, db
        cutoff = datetime.now(timezone.utc) - timedelta(days=90)
        deleted = AuditLog.query.filter(AuditLog.timestamp < cutoff).delete()
        db.session.commit()
        if deleted:
            logger.info(f"Purged {deleted} audit log entries older than 90 days.")


def _poll_unifi_events(app):
    """Poll UniFi controller API for events and alarms and persist them."""
    with app.app_context():
        from models import Setting, UnifiLogEntry, db

        if Setting.get("unifi_api_poll_enabled", "true") == "false":
            return
        if Setting.get("unifi_enabled", "false") != "true":
            return

        from auth.credential_store import decrypt
        from clients.unifi_client import get_cached_client

        base_url = Setting.get("unifi_base_url", "")
        username = Setting.get("unifi_username", "")
        encrypted_pw = Setting.get("unifi_password", "")
        site = Setting.get("unifi_site", "default")
        is_udm = Setting.get("unifi_is_udm", "true") == "true"
        verify_ssl = Setting.get("unifi_verify_ssl", "false") == "true"

        if not base_url or not username or not encrypted_pw:
            return

        password = decrypt(encrypted_pw)
        if not password:
            return

        client = get_cached_client(base_url, username, password, site=site, is_udm=is_udm, verify_ssl=verify_ssl)

        geoip_enabled = Setting.get("unifi_geoip_enabled", "false") == "true"
        geoip_db_path = Setting.get("unifi_geoip_db_path", "")

        added = 0
        for endpoint, log_type in [
            (f"/api/s/{site}/stat/event", "system"),
            (f"/api/s/{site}/stat/alarm", "firewall"),
        ]:
            raw = client._api_get(endpoint)
            if not raw:
                continue
            for evt in raw:
                # Use the event's _id as dedup key
                event_key = str(evt.get("_id", ""))
                if event_key and UnifiLogEntry.query.filter_by(rule_id=event_key, source="api").first():
                    continue

                # Parse timestamp
                ts_str = evt.get("datetime", "")
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")) if ts_str else datetime.now(timezone.utc)
                except ValueError:
                    ts = datetime.now(timezone.utc)

                src_ip = evt.get("src_ip") or evt.get("src") or None
                dst_ip = evt.get("dst_ip") or evt.get("dst") or None
                msg = evt.get("msg", "")

                # GeoIP enrichment
                geo = {}
                if geoip_enabled and geoip_db_path:
                    from clients import unifi_geoip
                    ext_ip = src_ip or dst_ip
                    if ext_ip:
                        geo = unifi_geoip.lookup(ext_ip, geoip_db_path)

                entry = UnifiLogEntry(
                    timestamp=ts,
                    source="api",
                    log_type=log_type,
                    action="block" if evt.get("key", "").endswith("_Blocked") else "allow",
                    direction=None,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=evt.get("sport"),
                    dst_port=evt.get("dport"),
                    protocol=evt.get("proto"),
                    interface=evt.get("iface"),
                    rule_id=event_key or None,
                    mac=evt.get("host"),
                    msg=msg[:512] if msg else None,
                    raw=None,
                    country=geo.get("country"),
                    country_code=geo.get("country_code"),
                    city=geo.get("city"),
                )
                db.session.add(entry)
                added += 1

        if added:
            db.session.commit()
            logger.info(f"UniFi API poll: added {added} new event(s).")


def _purge_old_unifi_logs(app):
    """Delete UniFi log entries older than the configured retention period."""
    with app.app_context():
        from models import Setting, UnifiLogEntry, db
        try:
            days = int(Setting.get("unifi_log_retention_days", "60") or 60)
        except ValueError:
            days = 60
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        deleted = UnifiLogEntry.query.filter(UnifiLogEntry.timestamp < cutoff).delete()
        db.session.commit()
        if deleted:
            logger.info(f"Purged {deleted} UniFi log entries older than {days} days.")


def _run_service_health_checks(app):
    """Check status of all tracked services on all guests."""
    with app.app_context():
        from core.scanner import check_service_statuses
        from models import Guest, Setting

        if Setting.get("service_check_enabled", "true") == "false":
            logger.info("Service health checks disabled, skipping.")
            return

        guests = Guest.query.filter(Guest.enabled == True, Guest.services.any()).all()
        if not guests:
            return

        checked = 0
        for guest in guests:
            try:
                check_service_statuses(guest)
                checked += 1
            except Exception as e:
                logger.debug(f"Service check failed for {guest.name}: {e}")

        logger.info(f"Service health checks complete: {checked}/{len(guests)} guests checked.")

        # Collect detailed stats and save snapshots for services with historical charts
        _collect_service_snapshots(guests)

        # Feed Prometheus exporter with service health data
        _update_prometheus_service_health(guests)


_SNAPSHOT_SERVICE_TYPES = {"redis", "postgresql", "jitsi-videobridge2"}


def _collect_service_snapshots(guests):
    """Collect detailed stats and save metric snapshots for services with historical charts."""
    from core.scanner import get_service_stats
    from routes.services import save_service_snapshot

    collected = 0
    for guest in guests:
        for svc in guest.services:
            if svc.service_name not in _SNAPSHOT_SERVICE_TYPES:
                continue
            if svc.status != "running":
                continue
            try:
                data = get_service_stats(guest, svc)
                save_service_snapshot(svc, data)
                collected += 1
            except Exception:
                logger.debug(f"Snapshot collection failed for {svc.service_name} on {guest.name}", exc_info=True)

    if collected:
        logger.info(f"Service snapshots collected: {collected}")


def _update_prometheus_service_health(guests):
    """Push service health data to the Prometheus exporter."""
    try:
        from clients.prometheus_exporter import update_service_health
        for guest in guests:
            for svc in guest.services:
                update_service_health(
                    svc.id, svc.service_name, guest.name,
                    svc.unit_name or svc.service_name,
                    svc.status or "unknown",
                )
    except Exception:
        logger.debug("Failed to update Prometheus service health metrics", exc_info=True)


def _collect_prometheus_metrics(app):
    """Collect host and guest metrics from Proxmox and feed the Prometheus exporter.

    Runs on a short interval (default 60s) to keep gauges fresh for scraping.
    """
    with app.app_context():
        from clients.prometheus_exporter import (
            update_app_version_info,
            update_apt_metrics,
            update_guest_metrics,
            update_host_metrics,
        )
        from clients.proxmox_api import ProxmoxClient
        from models import Guest, ProxmoxHost, Setting

        if Setting.get("prometheus_enabled", "false") != "true":
            return

        hosts = ProxmoxHost.query.all()
        for host in hosts:
            try:
                client = ProxmoxClient(host)
                node_name = client.get_local_node_name()
                if not node_name:
                    continue

                # Host-level metrics
                status = client.get_node_status(node_name)
                if status:
                    update_host_metrics(host.id, host.name, host.host_type, status)

                # Guest-level metrics — get status for all guests on this host
                guests = Guest.query.filter_by(proxmox_host_id=host.id, enabled=True).all()
                for guest in guests:
                    if not guest.vmid:
                        continue
                    try:
                        gstatus = client.get_guest_status(node_name, guest.vmid, guest.guest_type)
                        if gstatus:
                            update_guest_metrics(
                                guest.id, guest.name, guest.guest_type,
                                host.name, guest.vmid, gstatus,
                            )
                    except Exception:
                        logger.debug("Failed to get status for guest %s", guest.name, exc_info=True)

            except Exception:
                logger.debug("Failed to collect Prometheus metrics for host %s", host.name, exc_info=True)

        # APT update counts from DB
        guests_all = Guest.query.filter_by(enabled=True).all()
        for guest in guests_all:
            try:
                pending = guest.pending_update_count if hasattr(guest, "pending_update_count") else 0
                security = guest.security_update_count if hasattr(guest, "security_update_count") else 0
                reboot = guest.reboot_required if hasattr(guest, "reboot_required") else False
                # Use the pending_updates method if available
                if hasattr(guest, "pending_updates"):
                    pkgs = guest.pending_updates()
                    pending = len(pkgs) if pkgs else 0
                    security = sum(1 for p in (pkgs or []) if getattr(p, "severity", "") in ("critical", "important"))
                update_apt_metrics(guest.id, guest.name, pending, security, reboot)
            except Exception:
                logger.debug("Failed to update APT metrics for %s", guest.name, exc_info=True)

        # Application version info
        for app_name in ("mastodon", "ghost", "peertube", "elk", "jitsi", "prometheus"):
            current = Setting.get(f"{app_name}_current_version", "")
            latest = Setting.get(f"{app_name}_latest_version", "")
            update_avail = Setting.get(f"{app_name}_update_available", "false") == "true"
            if current or latest:
                update_app_version_info(app_name, current, latest, update_avail)

        # UniFi device & health metrics
        if Setting.get("unifi_enabled", "false") == "true":
            try:
                from auth.credential_store import decrypt
                from clients.prometheus_exporter import (
                    update_unifi_device_metrics,
                    update_unifi_health_metrics,
                    update_unifi_metrics,
                )
                from clients.unifi_client import get_cached_client

                base_url = Setting.get("unifi_base_url", "")
                username = Setting.get("unifi_username", "")
                encrypted_pw = Setting.get("unifi_password", "")
                site = Setting.get("unifi_site", "default")
                is_udm = Setting.get("unifi_is_udm", "true") == "true"
                verify_ssl = Setting.get("unifi_verify_ssl", "false") == "true"
                if base_url and username and encrypted_pw:
                    password = decrypt(encrypted_pw)
                    if password:
                        uc = get_cached_client(base_url, username, password, site=site, is_udm=is_udm, verify_ssl=verify_ssl)
                        devices = uc.get_devices() or []
                        clients_list = uc.get_clients() or []
                        update_unifi_metrics(site, device_count=len(devices), client_count=len(clients_list))
                        update_unifi_device_metrics(site, devices)

                        health = uc.get_site_health()
                        if health:
                            update_unifi_health_metrics(site, health)
            except Exception:
                logger.debug("Failed to collect UniFi Prometheus metrics", exc_info=True)


def _check_prometheus_release(app):
    """Check for new Prometheus releases on GitHub."""
    with app.app_context():
        import json
        import urllib.request

        from models import Setting

        if not Setting.get("prometheus_guest_id"):
            return
        if Setting.get("prometheus_installed", "false") != "true":
            return

        try:
            url = "https://api.github.com/repos/prometheus/prometheus/releases/latest"
            req = urllib.request.Request(url, headers={"User-Agent": "mstdnca-proxmox-tool"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                latest = data.get("tag_name", "").lstrip("v")
                if not latest:
                    return

            Setting.set("prometheus_latest_version", latest)
            current = Setting.get("prometheus_current_version", "")

            from apps.utils import _version_gt
            update_available = bool(current and _version_gt(latest, current))
            Setting.set("prometheus_update_available", "true" if update_available else "false")

            if update_available:
                logger.info("Prometheus update available: v%s -> v%s", current, latest)

                # Auto-upgrade if enabled
                if Setting.get("prometheus_auto_upgrade", "false") == "true":
                    logger.info("Auto-upgrade enabled, starting Prometheus upgrade...")
                    from apps.prometheus_app import run_prometheus_upgrade
                    from auth.audit import log_action
                    from models import db
                    ok, _ = run_prometheus_upgrade()
                    log_action("prometheus_upgrade", "settings", resource_name="prometheus",
                               details={"status": "success" if ok else "error", "trigger": "auto"})
                    db.session.commit()

        except Exception as e:
            logger.error("Failed to check Prometheus releases: %s", e)


def _check_unpoller_release(app):
    """Check for new unpoller releases on GitHub."""
    with app.app_context():
        import json
        import urllib.request

        from models import Setting

        if Setting.get("unpoller_installed", "false") != "true":
            return

        try:
            url = "https://api.github.com/repos/unpoller/unpoller/releases/latest"
            req = urllib.request.Request(url, headers={"User-Agent": "mstdnca-proxmox-tool"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                latest = data.get("tag_name", "").lstrip("v")
                if not latest:
                    return

            Setting.set("unpoller_latest_version", latest)
            current = Setting.get("unpoller_current_version", "")

            from apps.utils import _version_gt
            update_available = bool(current and _version_gt(latest, current))
            Setting.set("unpoller_update_available", "true" if update_available else "false")

            if update_available:
                logger.info("Unpoller update available: v%s -> v%s", current, latest)

                # Auto-upgrade if enabled
                if Setting.get("unpoller_auto_upgrade", "false") == "true":
                    logger.info("Auto-upgrade enabled, starting unpoller upgrade...")
                    from apps.unpoller import run_unpoller_upgrade
                    from auth.audit import log_action
                    from models import db
                    ok, _ = run_unpoller_upgrade()
                    log_action("unpoller_upgrade", "settings", resource_name="unpoller",
                               details={"status": "success" if ok else "error", "trigger": "auto"})
                    db.session.commit()

        except Exception as e:
            logger.error("Failed to check unpoller releases: %s", e)


def _poll_ipmi_sensors(app):
    """Poll IPMI sensors for all IPMI-enabled hosts and store snapshots."""
    with app.app_context():
        import json

        from models import HostMetricSnapshot, ProxmoxHost, Setting, db

        if Setting.get("ipmi_polling_enabled", "true") == "false":
            return

        hosts = ProxmoxHost.query.filter_by(ipmi_enabled=True).all()
        if not hosts:
            return

        from auth.credential_store import decrypt
        from clients.ipmi_client import RedfishClient

        for host in hosts:
            if not host.ipmi_address or not host.ipmi_password:
                continue
            try:
                password = decrypt(host.ipmi_password)
                if not password:
                    continue
                client = RedfishClient(
                    base_url=f"https://{host.ipmi_address}",
                    username=host.ipmi_username or "",
                    password=password,
                    verify_ssl=host.ipmi_verify_ssl,
                )
                snapshot = client.get_health_snapshot()
                if snapshot:
                    snap = HostMetricSnapshot(
                        host_id=host.id,
                        data=json.dumps({
                            "cpu_temp": snapshot.get("cpu_temp"),
                            "system_temp": snapshot.get("system_temp"),
                            "power_watts": snapshot.get("total_watts"),
                            "power_state": snapshot.get("power_state"),
                            "health": snapshot.get("health"),
                            "fan_count": len(snapshot.get("fans", [])),
                            "psu_count": len(snapshot.get("power_supplies", [])),
                        }),
                    )
                    db.session.add(snap)
                    db.session.commit()
                client.logout()
            except Exception:
                logger.debug("IPMI poll failed for host %s (%s)", host.name, host.ipmi_address, exc_info=True)


def _purge_old_ipmi_snapshots(app):
    """Purge IPMI metric snapshots older than the configured retention period."""
    with app.app_context():
        from models import HostMetricSnapshot, Setting, db

        days = int(Setting.get("ipmi_snapshot_retention_days", "30") or 30)
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        deleted = HostMetricSnapshot.query.filter(HostMetricSnapshot.captured_at < cutoff).delete()
        if deleted:
            db.session.commit()
            logger.info("Purged %d old IPMI metric snapshots (older than %d days).", deleted, days)


def _prune_revoked_tokens(app):
    """Remove expired revoked JWT tokens (they can no longer be used anyway)."""
    with app.app_context():
        from models import RevokedToken, db
        deleted = RevokedToken.query.filter(RevokedToken.expires_at < datetime.now(timezone.utc)).delete()
        if deleted:
            db.session.commit()
            logger.info("Pruned %d expired revoked JWT tokens.", deleted)


def init_scheduler(app):
    global _scheduler

    if _scheduler is not None:
        return _scheduler

    _scheduler = BackgroundScheduler()

    with app.app_context():
        from models import Setting
        interval_hours = int(Setting.get("scan_interval", "6") or 6)
        discovery_hours = int(Setting.get("discovery_interval", "4") or 4)
        service_check_minutes = int(Setting.get("service_check_interval", "5") or 5)
        unifi_poll_minutes = int(Setting.get("unifi_api_poll_interval", "5") or 5)
        prometheus_collect_seconds = int(Setting.get("prometheus_collect_interval", "60") or 60)

    # Discovery job - refresh hosts periodically
    _scheduler.add_job(
        _run_discovery,
        trigger=IntervalTrigger(hours=discovery_hours),
        args=[app],
        id="discovery",
        name="Refresh guest discovery for all hosts",
        replace_existing=True,
        max_instances=1,
    )

    # Scan job - runs every N hours

    _scheduler.add_job(
        _run_scan,
        trigger=IntervalTrigger(hours=interval_hours),
        args=[app],
        id="scan_all",
        name="Scan all guests for updates",
        replace_existing=True,
        max_instances=1,
    )

    # Auto-update check - runs every 15 minutes to check maintenance windows
    _scheduler.add_job(
        _run_auto_updates,
        trigger=IntervalTrigger(minutes=15),
        args=[app],
        id="auto_update",
        name="Check maintenance windows and apply updates",
        replace_existing=True,
        max_instances=1,
    )

    # Mastodon release check - runs alongside the scan job
    _scheduler.add_job(
        _check_mastodon_release,
        trigger=IntervalTrigger(hours=interval_hours),
        args=[app],
        id="mastodon_check",
        name="Check for Mastodon releases",
        replace_existing=True,
        max_instances=1,
    )

    # Ghost release check - runs alongside the scan job
    _scheduler.add_job(
        _check_ghost_release,
        trigger=IntervalTrigger(hours=interval_hours),
        args=[app],
        id="ghost_check",
        name="Check for Ghost releases",
        replace_existing=True,
        max_instances=1,
    )

    # PeerTube release check - runs alongside the scan job
    _scheduler.add_job(
        _check_peertube_release,
        trigger=IntervalTrigger(hours=interval_hours),
        args=[app],
        id="peertube_check",
        name="Check for PeerTube releases",
        replace_existing=True,
        max_instances=1,
    )

    # Elk release check - runs alongside the scan job
    _scheduler.add_job(
        _check_elk_release,
        trigger=IntervalTrigger(hours=interval_hours),
        args=[app],
        id="elk_check",
        name="Check for Elk releases",
        replace_existing=True,
        max_instances=1,
    )

    # Jitsi release check - runs alongside the scan job
    _scheduler.add_job(
        _check_jitsi_release,
        trigger=IntervalTrigger(hours=interval_hours),
        args=[app],
        id="jitsi_check",
        name="Check for Jitsi releases",
        replace_existing=True,
        max_instances=1,
    )

    # Host update check - runs alongside the guest scan
    _scheduler.add_job(
        _check_host_updates,
        trigger=IntervalTrigger(hours=interval_hours),
        args=[app],
        id="host_update_check",
        name="Check Proxmox hosts for APT updates",
        replace_existing=True,
        max_instances=1,
    )

    # Service health checks - runs every N minutes
    _scheduler.add_job(
        _run_service_health_checks,
        trigger=IntervalTrigger(minutes=service_check_minutes),
        args=[app],
        id="service_health",
        name="Check service health on all guests",
        replace_existing=True,
        max_instances=1,
    )

    # App self-update check - runs every 6 hours
    _scheduler.add_job(
        _check_app_update,
        trigger=IntervalTrigger(hours=6),
        args=[app],
        id="app_update_check",
        name="Check for app updates",
        replace_existing=True,
        max_instances=1,
    )

    # Audit log retention purge - runs daily
    _scheduler.add_job(
        _purge_old_audit_logs,
        trigger=IntervalTrigger(hours=24),
        args=[app],
        id="audit_log_purge",
        name="Purge audit log entries older than 90 days",
        replace_existing=True,
        max_instances=1,
    )

    # UniFi API event poll - runs every N minutes
    _scheduler.add_job(
        _poll_unifi_events,
        trigger=IntervalTrigger(minutes=unifi_poll_minutes),
        args=[app],
        id="unifi_event_poll",
        name="Poll UniFi API for events and alarms",
        replace_existing=True,
        max_instances=1,
    )

    # UniFi log retention purge - runs daily
    _scheduler.add_job(
        _purge_old_unifi_logs,
        trigger=IntervalTrigger(hours=24),
        args=[app],
        id="unifi_log_purge",
        name="Purge UniFi log entries past retention period",
        replace_existing=True,
        max_instances=1,
    )

    # Prometheus metric collection - runs every 60s to keep gauges fresh
    _scheduler.add_job(
        _collect_prometheus_metrics,
        trigger=IntervalTrigger(seconds=prometheus_collect_seconds),
        args=[app],
        id="prometheus_collect",
        name="Collect metrics for Prometheus exporter",
        replace_existing=True,
        max_instances=1,
    )

    # Prometheus release check - runs alongside other release checks
    _scheduler.add_job(
        _check_prometheus_release,
        trigger=IntervalTrigger(hours=interval_hours),
        args=[app],
        id="prometheus_check",
        name="Check for Prometheus releases",
        replace_existing=True,
        max_instances=1,
    )

    # Unpoller release check - runs alongside other release checks
    _scheduler.add_job(
        _check_unpoller_release,
        trigger=IntervalTrigger(hours=interval_hours),
        args=[app],
        id="unpoller_check",
        name="Check for unpoller releases",
        replace_existing=True,
        max_instances=1,
    )

    # IPMI sensor polling - runs every 5 minutes
    _scheduler.add_job(
        _poll_ipmi_sensors,
        trigger=IntervalTrigger(minutes=5),
        args=[app],
        id="ipmi_sensor_poll",
        name="Poll IPMI sensors on all enabled hosts",
        replace_existing=True,
        max_instances=1,
    )

    # IPMI snapshot retention purge - runs daily
    _scheduler.add_job(
        _purge_old_ipmi_snapshots,
        trigger=IntervalTrigger(hours=24),
        args=[app],
        id="ipmi_snapshot_purge",
        name="Purge old IPMI metric snapshots",
        replace_existing=True,
        max_instances=1,
    )

    # Revoked JWT token cleanup - runs daily
    _scheduler.add_job(
        _prune_revoked_tokens,
        trigger=IntervalTrigger(hours=24),
        args=[app],
        id="revoked_token_prune",
        name="Prune expired revoked JWT tokens",
        replace_existing=True,
        max_instances=1,
    )

    _scheduler.start()
    logger.info(f"Scheduler started: discovery every {discovery_hours}h, scan every {interval_hours}h, auto-update check every 15m, service check every {service_check_minutes}m, mastodon check every {interval_hours}h, ghost check every {interval_hours}h, peertube check every {interval_hours}h, elk check every {interval_hours}h, jitsi check every {interval_hours}h, host update check every {interval_hours}h, app update check every 6h, unifi event poll every {unifi_poll_minutes}m")

    return _scheduler


def reschedule_jobs(interval_hours, discovery_hours, service_check_minutes):
    """Reschedule configurable interval jobs with updated values. No-op if scheduler is not running."""
    if _scheduler is None or not _scheduler.running:
        return
    _scheduler.reschedule_job("scan_all", trigger=IntervalTrigger(hours=interval_hours))
    _scheduler.reschedule_job("mastodon_check", trigger=IntervalTrigger(hours=interval_hours))
    _scheduler.reschedule_job("ghost_check", trigger=IntervalTrigger(hours=interval_hours))
    _scheduler.reschedule_job("peertube_check", trigger=IntervalTrigger(hours=interval_hours))
    _scheduler.reschedule_job("elk_check", trigger=IntervalTrigger(hours=interval_hours))
    _scheduler.reschedule_job("jitsi_check", trigger=IntervalTrigger(hours=interval_hours))
    _scheduler.reschedule_job("host_update_check", trigger=IntervalTrigger(hours=interval_hours))
    _scheduler.reschedule_job("discovery", trigger=IntervalTrigger(hours=discovery_hours))
    _scheduler.reschedule_job("service_health", trigger=IntervalTrigger(minutes=service_check_minutes))
    logger.info(f"Scheduler rescheduled: discovery every {discovery_hours}h, scan every {interval_hours}h, service check every {service_check_minutes}m")
