import json
import logging
import os
import subprocess
from datetime import datetime, timezone

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import current_user, login_required

from auth.audit import log_action
from auth.credential_store import encrypt
from config import BASE_DIR, DATA_DIR
from core.app_update_auth import github_auth_headers, github_token_env
from models import Setting, db

logger = logging.getLogger(__name__)


def _parse_iso(value):
    """Parse an ISO 8601 string into a timezone-aware datetime, or return None."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


bp = Blueprint("settings", __name__)


@bp.before_request
@login_required
def _require_login():
    if not current_user.can_manage_settings:
        flash("Super admin access required.", "error")
        return redirect(url_for("dashboard.index"))


def _get_settings_dict():
    return {
        "discord_webhook_url": Setting.get("discord_webhook_url"),
        "discord_enabled": Setting.get("discord_enabled", "false"),
        "discord_notify_updates": Setting.get("discord_notify_updates", "true"),
        "discord_notify_updates_security_only": Setting.get("discord_notify_updates_security_only", "false"),
        "discord_notify_mastodon": Setting.get("discord_notify_mastodon", "true"),
        "discord_notify_mastodon_upgrade_started": Setting.get("discord_notify_mastodon_upgrade_started", "true"),
        "discord_notify_mastodon_upgrade_result": Setting.get("discord_notify_mastodon_upgrade_result", "true"),
        "discord_notify_ghost": Setting.get("discord_notify_ghost", "true"),
        "discord_notify_ghost_upgrade_started": Setting.get("discord_notify_ghost_upgrade_started", "true"),
        "discord_notify_ghost_upgrade_result": Setting.get("discord_notify_ghost_upgrade_result", "true"),
        "discord_notify_peertube": Setting.get("discord_notify_peertube", "true"),
        "discord_notify_peertube_upgrade_started": Setting.get("discord_notify_peertube_upgrade_started", "true"),
        "discord_notify_peertube_upgrade_result": Setting.get("discord_notify_peertube_upgrade_result", "true"),
        "discord_notify_elk": Setting.get("discord_notify_elk", "true"),
        "discord_notify_elk_upgrade_started": Setting.get("discord_notify_elk_upgrade_started", "true"),
        "discord_notify_elk_upgrade_result": Setting.get("discord_notify_elk_upgrade_result", "true"),
        "discord_notify_jitsi": Setting.get("discord_notify_jitsi", "true"),
        "discord_notify_jitsi_upgrade_started": Setting.get("discord_notify_jitsi_upgrade_started", "true"),
        "discord_notify_jitsi_upgrade_result": Setting.get("discord_notify_jitsi_upgrade_result", "true"),
        "discord_notify_prometheus": Setting.get("discord_notify_prometheus", "true"),
        "discord_notify_prometheus_upgrade_started": Setting.get("discord_notify_prometheus_upgrade_started", "true"),
        "discord_notify_prometheus_upgrade_result": Setting.get("discord_notify_prometheus_upgrade_result", "true"),
        "discord_notify_app": Setting.get("discord_notify_app", "true"),
        "discord_notify_tags": Setting.get("discord_notify_tags", ""),
        "scan_interval": Setting.get("scan_interval", "6"),
        "scan_enabled": Setting.get("scan_enabled", "true"),
        "discovery_interval": Setting.get("discovery_interval", "4"),
        "discovery_enabled": Setting.get("discovery_enabled", "true"),
        "service_check_interval": Setting.get("service_check_interval", "5"),
        "service_check_enabled": Setting.get("service_check_enabled", "true"),
        "unifi_enabled": Setting.get("unifi_enabled", "false"),
        "unifi_base_url": Setting.get("unifi_base_url", ""),
        "unifi_username": Setting.get("unifi_username", ""),
        "unifi_password": Setting.get("unifi_password", ""),
        "unifi_site": Setting.get("unifi_site", "default"),
        "unifi_is_udm": Setting.get("unifi_is_udm", "true"),
        "unifi_filter_subnet": Setting.get("unifi_filter_subnet", ""),
        "unifi_verify_ssl": Setting.get("unifi_verify_ssl", "false"),
        "unifi_geoip_enabled": Setting.get("unifi_geoip_enabled", "false"),
        "unifi_geoip_db_path": Setting.get("unifi_geoip_db_path", ""),
        "unifi_api_poll_enabled": Setting.get("unifi_api_poll_enabled", "true"),
        "unifi_api_poll_interval": Setting.get("unifi_api_poll_interval", "5"),
        "unifi_log_retention_days": Setting.get("unifi_log_retention_days", "60"),
        "unpoller_enabled": Setting.get("unpoller_enabled", "false"),
        "unpoller_metric_prefix": Setting.get("unpoller_metric_prefix", "unpoller"),
        "unpoller_site_name": Setting.get("unpoller_site_name", "default"),
        "app_auto_update": Setting.get("app_auto_update", "false"),
        "app_update_branch": Setting.get("app_update_branch", ""),
        "github_token": Setting.get("github_token", ""),
        # Global backup_storage/mode/compress removed; per-tag overrides only
    }


def _github_auth_headers():
    """Return an Authorization header dict for GitHub API calls, or {} if no
    token is configured. Delegates to the shared helper."""
    return github_auth_headers()


def _get_backup_template_context():
    """Return backup-related template variables (storages cache, tag defaults, tags)."""
    backup_storages = []
    cache_raw = Setting.get("backup_storages_cache", "")
    if cache_raw:
        try:
            backup_storages = json.loads(cache_raw)
        except (json.JSONDecodeError, TypeError):
            pass
    cache_time = _parse_iso(Setting.get("backup_storages_cache_time", ""))

    backup_tag_defaults = {}
    raw = Setting.get("backup_tag_defaults", "")
    if raw:
        try:
            backup_tag_defaults = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            pass
    from models import Tag
    all_tags = Tag.query.order_by(Tag.name).all()

    return {
        "backup_storages": backup_storages,
        "backup_storages_cache_time": cache_time,
        "backup_tag_defaults": backup_tag_defaults,
        "all_tags": all_tags,
    }


def _get_latest_release():
    """Fetch the latest release version from GitHub. Returns version string or None."""
    import json
    import urllib.request
    repo = current_app.config.get("GITHUB_REPO", "")
    if not repo:
        return None
    try:
        url = f"https://api.github.com/repos/{repo}/releases/latest"
        req = urllib.request.Request(url, headers={"User-Agent": "MCAT"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            return data.get("tag_name", "").lstrip("v") or None
    except Exception as e:
        logger.debug("Could not fetch latest release: %s", e)
        return None


@bp.route("/")
def index():
    settings = _get_settings_dict()
    latest_release = _get_latest_release()
    backup_ctx = _get_backup_template_context()

    # GeoIP file status for the upload widget
    geoip_db_path = settings.get("unifi_geoip_db_path", "")
    geoip_db_info = None
    if geoip_db_path:
        try:
            stat = os.stat(geoip_db_path)
            geoip_db_info = {"path": geoip_db_path, "size_mb": round(stat.st_size / 1024 / 1024, 1)}
        except OSError:
            geoip_db_info = {"path": geoip_db_path, "size_mb": None}

    from models import Tag
    tags = Tag.query.order_by(Tag.name).all()

    return render_template("settings.html", settings=settings, update_available=False, update_version=None, latest_release=latest_release, geoip_db_info=geoip_db_info, tags=tags, **backup_ctx)


@bp.route("/discord", methods=["POST"])
def save_discord():
    webhook_url = request.form.get("discord_webhook_url", "").strip()
    enabled = "discord_enabled" in request.form
    notify_updates = "discord_notify_updates" in request.form
    notify_security_only = "discord_notify_updates_security_only" in request.form
    notify_mastodon = "discord_notify_mastodon" in request.form
    notify_mastodon_upgrade_started = "discord_notify_mastodon_upgrade_started" in request.form
    notify_mastodon_upgrade_result = "discord_notify_mastodon_upgrade_result" in request.form
    notify_ghost = "discord_notify_ghost" in request.form
    notify_ghost_upgrade_started = "discord_notify_ghost_upgrade_started" in request.form
    notify_ghost_upgrade_result = "discord_notify_ghost_upgrade_result" in request.form
    notify_peertube = "discord_notify_peertube" in request.form
    notify_peertube_upgrade_started = "discord_notify_peertube_upgrade_started" in request.form
    notify_peertube_upgrade_result = "discord_notify_peertube_upgrade_result" in request.form
    notify_elk = "discord_notify_elk" in request.form
    notify_elk_upgrade_started = "discord_notify_elk_upgrade_started" in request.form
    notify_elk_upgrade_result = "discord_notify_elk_upgrade_result" in request.form
    notify_jitsi = "discord_notify_jitsi" in request.form
    notify_jitsi_upgrade_started = "discord_notify_jitsi_upgrade_started" in request.form
    notify_jitsi_upgrade_result = "discord_notify_jitsi_upgrade_result" in request.form
    notify_prometheus = "discord_notify_prometheus" in request.form
    notify_prometheus_upgrade_started = "discord_notify_prometheus_upgrade_started" in request.form
    notify_prometheus_upgrade_result = "discord_notify_prometheus_upgrade_result" in request.form
    notify_app = "discord_notify_app" in request.form

    # Tag-scoping: only notify about guests carrying one of the selected tags.
    # The multiselect submits zero or more values under discord_notify_tags.
    # Empty selection => notify for all guests (backward-compatible default).
    from models import Tag
    raw_tag_ids = [t for t in request.form.getlist("discord_notify_tags") if t.strip().isdigit()]
    valid_tag_ids = {str(tag.id) for tag in Tag.query.all()}
    selected_tag_ids = [t for t in raw_tag_ids if t in valid_tag_ids]

    if webhook_url:
        Setting.set("discord_webhook_url", webhook_url)
    Setting.set("discord_enabled", "true" if enabled else "false")
    Setting.set("discord_notify_updates", "true" if notify_updates else "false")
    Setting.set("discord_notify_updates_security_only", "true" if notify_security_only else "false")
    Setting.set("discord_notify_mastodon", "true" if notify_mastodon else "false")
    Setting.set("discord_notify_mastodon_upgrade_started", "true" if notify_mastodon_upgrade_started else "false")
    Setting.set("discord_notify_mastodon_upgrade_result", "true" if notify_mastodon_upgrade_result else "false")
    Setting.set("discord_notify_ghost", "true" if notify_ghost else "false")
    Setting.set("discord_notify_ghost_upgrade_started", "true" if notify_ghost_upgrade_started else "false")
    Setting.set("discord_notify_ghost_upgrade_result", "true" if notify_ghost_upgrade_result else "false")
    Setting.set("discord_notify_peertube", "true" if notify_peertube else "false")
    Setting.set("discord_notify_peertube_upgrade_started", "true" if notify_peertube_upgrade_started else "false")
    Setting.set("discord_notify_peertube_upgrade_result", "true" if notify_peertube_upgrade_result else "false")
    Setting.set("discord_notify_elk", "true" if notify_elk else "false")
    Setting.set("discord_notify_elk_upgrade_started", "true" if notify_elk_upgrade_started else "false")
    Setting.set("discord_notify_elk_upgrade_result", "true" if notify_elk_upgrade_result else "false")
    Setting.set("discord_notify_jitsi", "true" if notify_jitsi else "false")
    Setting.set("discord_notify_jitsi_upgrade_started", "true" if notify_jitsi_upgrade_started else "false")
    Setting.set("discord_notify_jitsi_upgrade_result", "true" if notify_jitsi_upgrade_result else "false")
    Setting.set("discord_notify_prometheus", "true" if notify_prometheus else "false")
    Setting.set("discord_notify_prometheus_upgrade_started", "true" if notify_prometheus_upgrade_started else "false")
    Setting.set("discord_notify_prometheus_upgrade_result", "true" if notify_prometheus_upgrade_result else "false")
    Setting.set("discord_notify_app", "true" if notify_app else "false")
    Setting.set("discord_notify_tags", ",".join(selected_tag_ids))

    log_action("settings_discord_save", "settings", resource_name="discord")
    db.session.commit()
    flash("Discord settings saved.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/discord/test", methods=["POST"])
def test_discord():
    # Save settings first
    save_discord()

    from core.notifier import send_test_notification
    ok, message = send_test_notification()
    if ok:
        flash(f"Test notification sent: {message}", "success")
    else:
        flash(f"Test notification failed: {message}", "error")

    return redirect(url_for("settings.index"))


@bp.route("/scan", methods=["POST"])
def save_scan():
    interval = request.form.get("scan_interval", "6").strip()
    enabled = "scan_enabled" in request.form
    discovery_interval = request.form.get("discovery_interval", "4").strip()
    discovery_enabled = "discovery_enabled" in request.form

    service_check_interval = request.form.get("service_check_interval", "5").strip()
    service_check_enabled = "service_check_enabled" in request.form

    Setting.set("scan_interval", interval)
    Setting.set("scan_enabled", "true" if enabled else "false")
    Setting.set("discovery_interval", discovery_interval)
    Setting.set("discovery_enabled", "true" if discovery_enabled else "false")
    Setting.set("service_check_interval", service_check_interval)
    Setting.set("service_check_enabled", "true" if service_check_enabled else "false")

    log_action("settings_scan_save", "settings", resource_name="scan_discovery")
    db.session.commit()

    try:
        from core.scheduler import reschedule_jobs
        reschedule_jobs(int(interval), int(discovery_interval), int(service_check_interval))
    except Exception:
        logger.warning("Failed to reschedule background jobs", exc_info=True)

    flash("Scan & discovery settings saved.", "success")
    return redirect(url_for("settings.index"))



@bp.route("/backups/refresh-storages", methods=["POST"])
def refresh_backup_storages():
    """Re-poll all PVE hosts for backup-capable storages and update the cache."""
    storages = []
    seen = set()
    try:
        from clients.proxmox_api import ProxmoxClient
        from models import ProxmoxHost
        for host in ProxmoxHost.query.filter(ProxmoxHost.host_type != "pbs").all():
            try:
                client = ProxmoxClient(host)
                nodes = client.api.nodes.get()
                if nodes:
                    node_storages = client.list_node_storages(nodes[0]['node'], content_type="backup")
                    for st in node_storages:
                        sid = st.get('storage', '')
                        if sid and sid not in seen:
                            seen.add(sid)
                            storages.append(st)
            except Exception:
                pass
    except Exception:
        pass

    cached_at = datetime.now(timezone.utc).isoformat()
    Setting.set("backup_storages_cache", json.dumps(storages))
    Setting.set("backup_storages_cache_time", cached_at)

    is_xhr = request.headers.get("X-Requested-With") == "XMLHttpRequest"
    if is_xhr:
        return jsonify({"ok": True, "storages": storages, "cached_at": cached_at})
    flash(f"Backup storages refreshed ({len(storages)} found).", "success")
    return redirect(url_for("settings.index"))


@bp.route("/backups/tag-defaults", methods=["POST"])
def save_backup_tag_defaults():
    """Save per-tag backup override settings."""
    tag_names = request.form.getlist("tag_name")
    tag_storages = request.form.getlist("tag_storage")
    tag_modes = request.form.getlist("tag_mode")
    tag_compresses = request.form.getlist("tag_compress")

    overrides = {}
    for name, storage, mode, compress in zip(tag_names, tag_storages, tag_modes, tag_compresses, strict=False):
        name = name.strip()
        if not name:
            continue
        storage = storage.strip()
        if not storage:
            continue  # storage is required
        override = {"storage": storage}
        override["mode"] = mode.strip() or "snapshot"
        override["compress"] = compress.strip() or "zstd"
        overrides[name] = override

    Setting.set("backup_tag_defaults", json.dumps(overrides))
    log_action("settings_backup_tag_defaults_save", "settings", resource_name="backup_tag_defaults")
    db.session.commit()
    flash("Per-tag backup defaults saved.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/unifi", methods=["POST"])
def save_unifi():
    enabled = "unifi_enabled" in request.form
    base_url = request.form.get("unifi_base_url", "").strip()
    username = request.form.get("unifi_username", "").strip()
    password = request.form.get("unifi_password", "").strip()
    site = request.form.get("unifi_site", "default").strip()
    is_udm = "unifi_is_udm" in request.form
    filter_subnet = request.form.get("unifi_filter_subnet", "").strip()

    Setting.set("unifi_enabled", "true" if enabled else "false")
    Setting.set("unifi_base_url", base_url)
    Setting.set("unifi_username", username)
    if password:
        Setting.set("unifi_password", encrypt(password))
    Setting.set("unifi_site", site or "default")
    Setting.set("unifi_is_udm", "true" if is_udm else "false")
    Setting.set("unifi_filter_subnet", filter_subnet)
    verify_ssl = "unifi_verify_ssl" in request.form
    Setting.set("unifi_verify_ssl", "true" if verify_ssl else "false")

    from clients.unifi_client import invalidate_cached_client
    invalidate_cached_client()

    log_action("settings_unifi_save", "settings", resource_name="unifi")
    db.session.commit()
    flash("UniFi settings saved.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/unifi/test", methods=["POST"])
def test_unifi():
    save_unifi()

    from auth.credential_store import decrypt
    from clients.unifi_client import UniFiClient

    base_url = Setting.get("unifi_base_url", "")
    username = Setting.get("unifi_username", "")
    encrypted_pw = Setting.get("unifi_password", "")
    site = Setting.get("unifi_site", "default")
    is_udm = Setting.get("unifi_is_udm", "true") == "true"
    verify_ssl = Setting.get("unifi_verify_ssl", "false") == "true"

    if not base_url or not username or not encrypted_pw:
        flash("UniFi controller URL, username, and password are required.", "error")
        return redirect(url_for("settings.index"))

    password = decrypt(encrypted_pw)
    client = UniFiClient(base_url, username, password, site=site, is_udm=is_udm, verify_ssl=verify_ssl)
    ok, msg = client.test_connection()

    if ok:
        flash(f"UniFi connection successful: {msg}", "success")
    else:
        flash(f"UniFi connection failed: {msg}", "error")

    return redirect(url_for("settings.index"))


@bp.route("/unifi-logging", methods=["POST"])
def save_unifi_logging():
    geoip_enabled = "unifi_geoip_enabled" in request.form
    geoip_db_path = request.form.get("unifi_geoip_db_path", "").strip()
    api_poll_enabled = "unifi_api_poll_enabled" in request.form
    api_poll_interval = request.form.get("unifi_api_poll_interval", "5").strip()
    retention_days = request.form.get("unifi_log_retention_days", "60").strip()

    try:
        interval_int = int(api_poll_interval)
        if not (1 <= interval_int <= 1440):
            raise ValueError
    except ValueError:
        flash("Poll interval must be between 1 and 1440 minutes.", "error")
        return redirect(url_for("settings.index"))

    try:
        retention_int = int(retention_days)
        if not (1 <= retention_int <= 365):
            raise ValueError
    except ValueError:
        flash("Retention must be between 1 and 365 days.", "error")
        return redirect(url_for("settings.index"))

    Setting.set("unifi_geoip_enabled", "true" if geoip_enabled else "false")
    Setting.set("unifi_geoip_db_path", geoip_db_path)
    Setting.set("unifi_api_poll_enabled", "true" if api_poll_enabled else "false")
    Setting.set("unifi_api_poll_interval", str(interval_int))
    Setting.set("unifi_log_retention_days", str(retention_int))

    log_action("settings_unifi_logging_save", "settings", resource_name="unifi_logging")
    db.session.commit()
    flash("UniFi log collection settings saved.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/unpoller", methods=["POST"])
def save_unpoller():
    enabled = "unpoller_enabled" in request.form
    prefix = request.form.get("unpoller_metric_prefix", "unpoller").strip()
    site_name = request.form.get("unpoller_site_name", "default").strip()

    Setting.set("unpoller_enabled", "true" if enabled else "false")
    Setting.set("unpoller_metric_prefix", prefix or "unpoller")
    Setting.set("unpoller_site_name", site_name or "default")

    log_action("settings_unpoller_save", "settings", resource_name="unpoller")
    db.session.commit()
    flash("Unpoller settings saved.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/unpoller/test", methods=["POST"])
def test_unpoller():
    save_unpoller()

    prefix = Setting.get("unpoller_metric_prefix", "unpoller")
    try:
        from clients.prometheus_query import PrometheusQueryClient
        prom = PrometheusQueryClient()
        result = prom.query(f'{prefix}_site_num_user')
        if result:
            flash(f"Unpoller metrics found in Prometheus ({len(result)} series).", "success")
        else:
            flash(
                f"No unpoller metrics found. Ensure unpoller is running and Prometheus is scraping it. "
                f"Searched for: {prefix}_site_num_user",
                "warning",
            )
    except ValueError:
        flash("Prometheus URL is not configured. Configure it first.", "error")
    except Exception as e:
        flash(f"Unpoller test failed: {e}", "error")

    return redirect(url_for("settings.index"))


@bp.route("/unifi-logging/upload-geoip", methods=["POST"])
def upload_geoip_db():
    """Accept an uploaded MaxMind GeoLite2-City .mmdb file and save it to DATA_DIR."""
    _MAX_BYTES = 150 * 1024 * 1024  # 150 MB
    _ANCHOR = "#geoip-section"
    is_xhr = request.headers.get("X-Requested-With") == "XMLHttpRequest"

    def _err(msg, status=400):
        if is_xhr:
            return jsonify({"ok": False, "message": msg}), status
        flash(msg, "error")
        return redirect(url_for("settings.index") + _ANCHOR)

    if "geoip_db" not in request.files:
        return _err("No file selected.")

    f = request.files["geoip_db"]
    if not f or not f.filename:
        return _err("No file selected.")

    if not f.filename.lower().endswith(".mmdb"):
        return _err("Invalid file type — expected a .mmdb file.")

    dest_path = os.path.join(DATA_DIR, "GeoLite2-City.mmdb")

    # Stream to disk to avoid large in-memory buffers
    bytes_written = 0
    tmp_path = dest_path + ".tmp"
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(tmp_path, "wb") as out:
            while True:
                chunk = f.stream.read(65536)
                if not chunk:
                    break
                bytes_written += len(chunk)
                if bytes_written > _MAX_BYTES:
                    out.close()
                    os.remove(tmp_path)
                    return _err("File too large (max 150 MB).")
                out.write(chunk)
    except OSError as e:
        return _err(f"Could not save file: {e}")

    # Validate: try opening with geoip2 if available
    try:
        import geoip2.database
        reader = geoip2.database.Reader(tmp_path)
        reader.close()
    except ImportError:
        pass  # geoip2 not installed yet — accept the file
    except Exception as e:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        return _err(f"File does not appear to be a valid MaxMind database: {e}")

    os.replace(tmp_path, dest_path)

    # Reset the cached reader so the new file is used immediately
    from clients import unifi_geoip
    unifi_geoip.close()

    size_mb = round(bytes_written / 1024 / 1024, 1)
    Setting.set("unifi_geoip_db_path", dest_path)
    log_action("settings_geoip_upload", "settings", resource_name="geoip_db",
               details={"path": dest_path, "size_mb": size_mb})
    db.session.commit()

    msg = f"GeoIP database uploaded ({size_mb} MB). Path set to {dest_path}."
    if is_xhr:
        return jsonify({"ok": True, "message": msg, "path": dest_path, "size_mb": size_mb})
    flash(msg, "success")
    return redirect(url_for("settings.index") + _ANCHOR)


@bp.route("/unifi-logging/verify-geoip")
def verify_geoip_db():
    """Check that the configured GeoIP database is readable and valid."""
    db_path = Setting.get("unifi_geoip_db_path", "")
    if not db_path:
        return jsonify({"ok": False, "message": "No database path configured."})

    if not os.path.exists(db_path):
        size_mb = None
        return jsonify({"ok": False, "message": f"File not found: {db_path}"})

    try:
        size_mb = round(os.stat(db_path).st_size / 1024 / 1024, 1)
    except OSError:
        size_mb = None

    try:
        import geoip2.database
        reader = geoip2.database.Reader(db_path)
        meta = reader.metadata()
        db_type = meta.database_type
        # Test lookup on a known public IP (Google DNS)
        test_ip = "8.8.8.8"
        try:
            rec = reader.city(test_ip)
            test_result = f"{rec.city.name or '—'}, {rec.country.iso_code or '—'}"
        except Exception:
            test_result = None
        reader.close()
    except ImportError:
        return jsonify({"ok": True, "message": f"File exists ({size_mb} MB) — geoip2 library not installed, cannot validate contents.", "size_mb": size_mb, "path": db_path})
    except Exception as e:
        return jsonify({"ok": False, "message": f"Invalid database: {e}", "size_mb": size_mb, "path": db_path})

    msg = f"Valid {db_type} — {size_mb} MB"
    if test_result:
        msg += f" — test lookup 8.8.8.8: {test_result}"
    return jsonify({"ok": True, "message": msg, "size_mb": size_mb, "path": db_path})


@bp.route("/app-update-mode", methods=["POST"])
def save_app_update_mode():
    auto_update = "app_auto_update" in request.form
    update_branch = request.form.get("app_update_branch", "").strip()
    Setting.set("app_auto_update", "true" if auto_update else "false")
    Setting.set("app_update_branch", update_branch)
    _save_github_token_from_form()
    log_action("settings_update_mode_save", "settings", resource_name="app_update",
               details={"auto_update": auto_update, "branch": update_branch or None})
    db.session.commit()
    flash("Application update settings saved.", "success")
    return redirect(url_for("settings.index"))


def _save_github_token_from_form():
    """Persist the GitHub token from the submitted form, encrypted. Only updates
    when a non-blank value is supplied so a blank submit preserves the existing token."""
    token = request.form.get("github_token", "").strip()
    if token:
        Setting.set("github_token", encrypt(token))


def _update_check_hint(exc):
    """Return a short, actionable hint to append to an update-check error flash."""
    import urllib.error
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code in (401, 403):
            return " — check the GitHub access token in Settings"
        if exc.code == 404:
            return " — for a private repo, set a GitHub access token in Settings"
    return ""


@bp.route("/check-update", methods=["POST"])
def check_update():
    import json
    import urllib.request

    # Also save the settings from the same form
    auto_update = "app_auto_update" in request.form
    update_branch = request.form.get("app_update_branch", "").strip()
    Setting.set("app_auto_update", "true" if auto_update else "false")
    Setting.set("app_update_branch", update_branch)
    _save_github_token_from_form()

    repo = current_app.config.get("GITHUB_REPO", "")
    current_version = current_app.config.get("APP_VERSION", "0.0.0")

    # If a branch is configured, check if it has new commits instead of releases
    if update_branch:
        try:
            url = f"https://api.github.com/repos/{repo}/branches/{update_branch}"
            req = urllib.request.Request(url, headers={"User-Agent": "MCAT", **_github_auth_headers()})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                full_sha = data.get("commit", {}).get("sha", "")
                sha = full_sha[:7]
                message = data.get("commit", {}).get("commit", {}).get("message", "").split("\n")[0]
                current_commit = current_app.config.get("GIT_COMMIT", "")
                if current_commit and full_sha.startswith(current_commit):
                    flash(f"Already up to date on branch '{update_branch}' ({sha}).", "success")
                    return redirect(url_for("settings.index"))
                settings = _get_settings_dict()
                return render_template(
                    "settings.html", settings=settings,
                    update_available=True,
                    update_version=f"branch '{update_branch}' (latest: {sha} - {message})",
                    latest_release=_get_latest_release(),
                    **_get_backup_template_context(),
                )
        except Exception as e:
            flash(f"Could not check branch '{update_branch}': {e}{_update_check_hint(e)}", "error")
            return redirect(url_for("settings.index"))

    try:
        url = f"https://api.github.com/repos/{repo}/releases/latest"
        req = urllib.request.Request(url, headers={"User-Agent": "MCAT", **_github_auth_headers()})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            latest = data.get("tag_name", "").lstrip("v")
            if latest and latest != current_version:
                settings = _get_settings_dict()
                return render_template("settings.html", settings=settings, update_available=True, update_version=latest, latest_release=latest, **_get_backup_template_context())
            flash(f"You are running the latest version (v{current_version}).", "success")
    except Exception as e:
        flash(f"Could not check for updates: {e}{_update_check_hint(e)}", "error")

    return redirect(url_for("settings.index"))


@bp.route("/apply-update", methods=["POST"])
def apply_update():
    update_script = os.path.join(BASE_DIR, "scripts", "update.sh")
    if not os.path.exists(update_script):
        flash("Update script not found.", "error")
        return redirect(url_for("settings.index"))

    try:
        import re as _re
        update_branch = Setting.get("app_update_branch", "")
        cmd = ["bash", update_script]
        if update_branch:
            if not _re.match(r'^[A-Za-z0-9._\-/]+$', update_branch) or update_branch.startswith("-"):
                flash("Invalid branch name.", "error")
                return redirect(url_for("settings.index"))
            cmd += ["--branch", update_branch]

        env = github_token_env()
        proc = subprocess.Popen(cmd, cwd=BASE_DIR, env=env)

        # Write PID marker so we can track the process
        pid_file = os.path.join(DATA_DIR, "update.pid")
        with open(pid_file, "w") as f:
            f.write(str(proc.pid))

        log_action("settings_apply_update", "settings", resource_name="app_update",
                   details={"branch": Setting.get("app_update_branch") or None})
        db.session.commit()

    except Exception as e:
        flash(f"Update failed to start: {e}", "error")
        return redirect(url_for("settings.index"))

    return redirect(url_for("settings.update_progress"))


@bp.route("/update-progress")
def update_progress():
    return render_template("update_progress.html")


@bp.route("/update-status")
def update_status():
    log_file = os.path.join(DATA_DIR, "update.log")
    pid_file = os.path.join(DATA_DIR, "update.pid")

    # Read log contents
    log_text = ""
    if os.path.exists(log_file):
        try:
            with open(log_file, "r") as f:
                log_text = f.read()
        except Exception:
            log_text = ""

    # Check if process is still running
    running = False
    if os.path.exists(pid_file):
        try:
            with open(pid_file, "r") as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)  # signal 0 = check if process exists
            running = True
        except (ProcessLookupError, ValueError, PermissionError):
            running = False

    return jsonify({
        "log": log_text,
        "running": running,
        "line_count": log_text.count("\n"),
    })


# --- Config export / import & database backup (super_admin only) ---

def _require_super_admin():
    """Strictest gate: only super admins may export/import config or download the DB."""
    if not current_user.is_super_admin:
        abort(403, description="Super admin access required.")


@bp.route("/config/export")
def export_config():
    """Download a JSON snapshot of hosts, guests, tags, roles, and settings.

    Never includes decrypted secrets — see core.config_backup.build_export.
    """
    _require_super_admin()
    from core.config_backup import build_export

    doc = build_export()
    log_action("settings_config_export", "settings", resource_name="config_export",
               details={"hosts": len(doc["hosts"]), "guests": len(doc["guests"]),
                        "tags": len(doc["tags"])})
    db.session.commit()

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    payload = json.dumps(doc, indent=2, default=str)
    resp = Response(payload, mimetype="application/json")
    resp.headers["Content-Disposition"] = f'attachment; filename="mstdnca-config-{ts}.json"'
    return resp


@bp.route("/config/import", methods=["POST"])
def import_config():
    """Upload a config JSON and upsert hosts/guests/tags/roles/settings.

    Secrets are never imported.  Malformed input is rejected with a clear
    error; the endpoint never returns a 500 for bad user input.
    """
    _require_super_admin()
    from core.config_backup import ImportError_, apply_import

    _MAX_BYTES = 10 * 1024 * 1024  # 10 MB is far more than any real config

    if "config_file" not in request.files:
        flash("No file selected.", "error")
        return redirect(url_for("settings.index"))

    f = request.files["config_file"]
    if not f or not f.filename:
        flash("No file selected.", "error")
        return redirect(url_for("settings.index"))

    raw = f.read(_MAX_BYTES + 1)
    if len(raw) > _MAX_BYTES:
        flash("Config file too large (max 10 MB).", "error")
        return redirect(url_for("settings.index"))

    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        flash(f"Invalid JSON: {e}", "error")
        return redirect(url_for("settings.index"))

    try:
        counts = apply_import(doc)
    except ImportError_ as e:
        db.session.rollback()
        flash(f"Import rejected: {e}", "error")
        return redirect(url_for("settings.index"))
    except Exception:
        db.session.rollback()
        logger.warning("Config import failed", exc_info=True)
        flash("Import failed due to an unexpected error. No changes were applied.", "error")
        return redirect(url_for("settings.index"))

    log_action("settings_config_import", "settings", resource_name="config_import",
               details=counts)
    db.session.commit()
    flash(
        f"Config imported: {counts['hosts']} host(s), {counts['guests']} guest(s), "
        f"{counts['tags']} tag(s), {counts['roles']} role(s), {counts['settings']} setting(s). "
        "Secrets were not imported — re-enter any credentials.",
        "success",
    )
    return redirect(url_for("settings.index"))


@bp.route("/config/backup-db")
def backup_database():
    """Stream a consistent SQLite backup of the app's own database."""
    _require_super_admin()
    from core.config_backup import make_backup_tempfile

    try:
        tmp_path = make_backup_tempfile()
    except Exception:
        logger.warning("Database backup failed", exc_info=True)
        flash("Database backup failed.", "error")
        return redirect(url_for("settings.index"))

    if tmp_path is None:
        flash("Database backup is unavailable (no file-backed SQLite database).", "error")
        return redirect(url_for("settings.index"))

    log_action("settings_db_backup", "settings", resource_name="database_backup")
    db.session.commit()

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    resp = send_file(
        tmp_path,
        mimetype="application/x-sqlite3",
        as_attachment=True,
        download_name=f"mstdnca-db-{ts}.sqlite3",
    )

    @resp.call_on_close
    def _cleanup():
        try:
            os.remove(tmp_path)
        except OSError:
            pass

    return resp
