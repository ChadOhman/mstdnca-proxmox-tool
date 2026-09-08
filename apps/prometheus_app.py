"""
Prometheus install and upgrade automation.

Installs Prometheus from GitHub binary releases onto a target VM/CT via SSH.
Creates a dedicated user, systemd service, and generates a prometheus.yml
config that scrapes the mstdnca app's /metrics endpoint.
"""

import json
import logging
import re
import shlex
import time
import urllib.request
from datetime import datetime

from apps.utils import (
    _cleanup_workdir,
    _fetch_verified_tarball,
    _log_cmd_output,
    _remote_write_cmd,
    _validate_release_tag,
    _validate_shell_param,
    _version_gt,
)
from clients.proxmox_api import ProxmoxClient
from clients.ssh_client import SSHClient
from models import Guest, Setting

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Version check
# ---------------------------------------------------------------------------

def _prometheus_release_urls(latest, prom_arch):
    """Return (asset_name, download_url, checksum_url, extract_dir) for a release.

    The Prometheus project publishes ``sha256sums.txt`` alongside the tarballs
    in every release, so the digest is checked on the target host before
    anything is unpacked and installed as root.
    """
    extract_dir = f"prometheus-{latest}.linux-{prom_arch}"
    asset = f"{extract_dir}.tar.gz"
    base = f"https://github.com/prometheus/prometheus/releases/download/v{latest}"
    return asset, f"{base}/{asset}", f"{base}/sha256sums.txt", extract_dir


def check_prometheus_release():
    """Check GitHub for the latest Prometheus release.

    Returns (update_available, latest_version, release_url).
    """
    try:
        url = "https://api.github.com/repos/prometheus/prometheus/releases/latest"
        req = urllib.request.Request(url, headers={"User-Agent": "mstdnca-proxmox-tool"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            tag = data.get("tag_name", "")
            release_url = data.get("html_url", "")

        if not tag:
            return False, "", ""

        # The tag is interpolated into a download URL and an extraction path on
        # the target host — validate it before it can reach either.
        try:
            _validate_release_tag(tag, "Prometheus release tag")
        except ValueError as e:
            logger.error("Rejected Prometheus release tag: %s", e)
            return False, "", ""
        latest = tag.lstrip("v")

        Setting.set("prometheus_latest_version", latest)

        current = Setting.get("prometheus_current_version", "")
        update_available = bool(current and _version_gt(latest, current))
        Setting.set("prometheus_update_available", "true" if update_available else "false")

        return update_available, latest, release_url
    except Exception as e:
        logger.error("Failed to check Prometheus releases: %s", e)
        return False, "", ""


def detect_prometheus_version(guest):
    """Detect the installed Prometheus version on a guest via SSH.

    Returns (version_string, error_string).
    """
    from models import Credential

    credential = guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return None, "No SSH credential configured"

    has_ip = guest.ip_address and guest.ip_address.lower() not in ("dhcp", "dhcp6", "auto")
    if not has_ip:
        return None, "Guest has no usable IP address"

    try:
        with SSHClient.from_credential(guest.ip_address, credential) as ssh:
            stdout, stderr, code = ssh.execute_sudo(
                "/usr/local/bin/prometheus --version 2>&1 | head -1", timeout=10
            )
            if code == 0 and stdout:
                m = re.search(r"prometheus.*?version (\d+\.\d+\.\d+)", stdout)
                if m:
                    return m.group(1), None
            return None, f"Prometheus not found (exit code {code})"
    except Exception as e:
        return None, str(e)


# ---------------------------------------------------------------------------
# Proxmox protection (snapshot/backup)
# ---------------------------------------------------------------------------

def _snapshot_guest(guest):
    """Create a Proxmox snapshot before install/upgrade."""
    if not guest.proxmox_host:
        return False, f"Guest '{guest.name}' has no Proxmox host configured"

    client = ProxmoxClient(guest.proxmox_host)
    node = client.find_guest_node(guest.vmid)
    if not node:
        return False, f"Could not find {guest.guest_type}/{guest.vmid} on any node"

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    snapname = f"pre-prometheus-{timestamp}"
    description = f"Auto-snapshot before Prometheus install/upgrade at {timestamp}"

    ok, upid = client.create_snapshot(node, guest.vmid, guest.guest_type, snapname, description)
    if not ok:
        return False, f"Failed to start snapshot: {upid}"

    deadline = time.time() + 300
    while time.time() < deadline:
        time.sleep(2)
        try:
            status = client.get_task_status(node, upid)
            if status.get("status") == "stopped":
                exit_status = status.get("exitstatus", "")
                if exit_status == "OK":
                    return True, f"Snapshot {snapname} completed"
                return False, f"Snapshot task failed: {exit_status}"
        except Exception as e:
            logger.debug("Error polling snapshot task: %s", e)

    return False, "Snapshot timed out after 5 minutes"


def _backup_guest(guest, storage, mode="snapshot"):
    """Create a vzdump backup before install/upgrade."""
    if not guest.proxmox_host:
        return False, f"Guest '{guest.name}' has no Proxmox host configured"

    client = ProxmoxClient(guest.proxmox_host)
    node = client.find_guest_node(guest.vmid)
    if not node:
        return False, f"Could not find {guest.guest_type}/{guest.vmid} on any node"

    _validate_shell_param(storage, "Backup storage")
    ok, upid = client.create_backup(node, guest.vmid, guest.guest_type, storage, mode=mode)
    if not ok:
        return False, f"Failed to start backup: {upid}"

    deadline = time.time() + 600
    while time.time() < deadline:
        time.sleep(5)
        try:
            status = client.get_task_status(node, upid)
            if status.get("status") == "stopped":
                exit_status = status.get("exitstatus", "")
                if exit_status == "OK":
                    return True, "Backup completed"
                return False, f"Backup failed: {exit_status}"
        except Exception as e:
            logger.debug("Error polling backup task: %s", e)

    return False, "Backup timed out after 10 minutes"


# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

def run_prometheus_install(log_callback=None):
    """Install Prometheus on the configured target guest via SSH.

    Returns (success, log_lines).
    """
    from models import Credential, db

    log = log_callback or (lambda msg: None)
    log_lines = []

    def _log(msg):
        log_lines.append(msg)
        log(msg)

    config = _get_config()
    guest_id = config.get("guest_id", "")
    if not guest_id:
        _log("ERROR: Prometheus guest is not configured.")
        return False, log_lines

    try:
        guest = Guest.query.get(int(guest_id))
    except (TypeError, ValueError):
        _log("ERROR: Invalid guest ID.")
        return False, log_lines

    if not guest:
        _log("ERROR: Guest not found.")
        return False, log_lines

    credential = guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        _log("ERROR: No SSH credential configured for this guest.")
        return False, log_lines

    has_ip = guest.ip_address and guest.ip_address.lower() not in ("dhcp", "dhcp6", "auto")
    if not has_ip:
        _log("ERROR: Guest has no usable IP address.")
        return False, log_lines

    # Get version to install
    latest = config.get("latest_version") or Setting.get("prometheus_latest_version", "")
    if not latest:
        _log("Checking for latest Prometheus version...")
        _, latest, _ = check_prometheus_release()
    if not latest:
        _log("ERROR: Could not determine latest Prometheus version.")
        return False, log_lines

    _log(f"Installing Prometheus v{latest} on {guest.name} ({guest.ip_address})...")

    # Protection (snapshot)
    protection_type = config.get("protection_type", "snapshot")
    _log(f"Creating {protection_type} protection...")
    if protection_type == "backup":
        storage = config.get("backup_storage", "")
        mode = config.get("backup_mode", "snapshot")
        ok, msg = _backup_guest(guest, storage, mode)
    else:
        ok, msg = _snapshot_guest(guest)
    _log(msg)
    if not ok:
        _log("ERROR: Protection failed, aborting install.")
        return False, log_lines

    # Determine architecture
    try:
        with SSHClient.from_credential(guest.ip_address, credential) as ssh:
            arch_out, _, _ = ssh.execute_sudo("dpkg --print-architecture", timeout=10)
            arch = (arch_out or "amd64").strip()
            prom_arch = "arm64" if arch == "arm64" else "amd64"

            # Create prometheus user
            _log("Creating prometheus user...")
            stdout, stderr, code = ssh.execute_sudo(
                "id prometheus >/dev/null 2>&1 || useradd --no-create-home --shell /bin/false prometheus",
                timeout=15,
            )
            _log_cmd_output(_log, stdout, stderr, code)

            # Create directories
            _log("Creating directories...")
            stdout, stderr, code = ssh.execute_sudo(
                "mkdir -p /etc/prometheus /var/lib/prometheus && "
                "chown prometheus:prometheus /var/lib/prometheus",
                timeout=15,
            )
            _log_cmd_output(_log, stdout, stderr, code)
            if code != 0:
                _log("ERROR: Failed to create directories.")
                return False, log_lines

            # Download Prometheus, verify its published SHA-256, and extract it
            # into a private temp dir (not a predictable /tmp path).
            asset, dl_url, sums_url, extract_dir = _prometheus_release_urls(latest, prom_arch)
            _log(f"Downloading Prometheus v{latest} ({prom_arch})...")
            ok, workdir, err = _fetch_verified_tarball(ssh, _log, dl_url, asset, sums_url)
            if not ok:
                _log(f"ERROR: Failed to download Prometheus: {err}")
                return False, log_lines

            # Install binaries
            src = shlex.quote(f"{workdir}/{extract_dir}")
            _log("Installing binaries...")
            stdout, stderr, code = ssh.execute_sudo(
                f"cp {src}/prometheus /usr/local/bin/ && "
                f"cp {src}/promtool /usr/local/bin/ && "
                "chown prometheus:prometheus /usr/local/bin/prometheus /usr/local/bin/promtool",
                timeout=30,
            )
            _log_cmd_output(_log, stdout, stderr, code)
            if code != 0:
                _log("ERROR: Failed to install binaries.")
                _cleanup_workdir(ssh, workdir)
                return False, log_lines

            # Copy console files
            stdout, stderr, code = ssh.execute_sudo(
                f"cp -r {src}/consoles /etc/prometheus/ && "
                f"cp -r {src}/console_libraries /etc/prometheus/ && "
                "chown -R prometheus:prometheus /etc/prometheus",
                timeout=15,
            )
            _log_cmd_output(_log, stdout, stderr, code)

            retention_days = config.get("retention_days", "365")

            # Write a minimal bootstrap prometheus.yml so the service has a valid
            # config to start with. The full config (mstdnca + exporters + unpoller)
            # is generated, validated with promtool, and reloaded right after start by
            # apps.exporters._regenerate_prometheus_config() — this repo's single
            # prometheus.yml generator, so install/uninstall of any one component
            # never wipes out another component's scrape jobs.
            _log("Writing bootstrap prometheus.yml...")
            bootstrap_yml = _generate_prometheus_yml("")
            stdout, stderr, code = ssh.execute_sudo(
                _remote_write_cmd(
                    "/etc/prometheus/prometheus.yml", bootstrap_yml,
                    mode="644", owner="prometheus",
                ),
                timeout=15,
            )
            _log_cmd_output(_log, stdout, stderr, code)
            if code != 0:
                _log("ERROR: Failed to write bootstrap prometheus.yml.")
                _cleanup_workdir(ssh, workdir)
                return False, log_lines

            # Create systemd service
            _log("Creating systemd service...")
            service_content = _generate_systemd_unit(retention_days)
            stdout, stderr, code = ssh.execute_sudo(
                _remote_write_cmd(
                    "/etc/systemd/system/prometheus.service", service_content,
                    mode="644", owner="root",
                ),
                timeout=15,
            )
            _log_cmd_output(_log, stdout, stderr, code)
            if code != 0:
                _log("ERROR: Failed to create systemd service.")
                _cleanup_workdir(ssh, workdir)
                return False, log_lines

            # Enable and start
            _log("Starting Prometheus...")
            stdout, stderr, code = ssh.execute_sudo(
                "systemctl daemon-reload && systemctl enable prometheus && systemctl start prometheus",
                timeout=30,
            )
            _log_cmd_output(_log, stdout, stderr, code)
            if code != 0:
                _log("ERROR: Failed to start Prometheus.")
                return False, log_lines

            # Verify it's running
            time.sleep(3)
            stdout, stderr, code = ssh.execute_sudo(
                "systemctl is-active prometheus", timeout=10
            )
            if code != 0 or (stdout or "").strip() != "active":
                _log("WARNING: Prometheus may not be running. Check logs with: journalctl -u prometheus")

            # Clean up
            _cleanup_workdir(ssh, workdir)

    except Exception as e:
        _log(f"FATAL ERROR: {e}")
        logger.exception("Prometheus install failed")
        return False, log_lines

    # Generate, validate, and install the full prometheus.yml now that Prometheus
    # is running and promtool is available to check it against.
    _log("Generating full prometheus.yml...")
    from apps.exporters import _regenerate_prometheus_config
    if not _regenerate_prometheus_config(_log):
        _log("ERROR: Failed to generate/validate the full prometheus.yml.")
        return False, log_lines

    _log(f"Prometheus v{latest} installed successfully.")

    # Update settings
    Setting.set("prometheus_installed", "true")
    Setting.set("prometheus_current_version", latest)
    Setting.set("prometheus_update_available", "false")
    db.session.commit()

    return True, log_lines


# ---------------------------------------------------------------------------
# Upgrade
# ---------------------------------------------------------------------------

def run_prometheus_upgrade(log_callback=None):
    """Upgrade Prometheus on the configured target guest."""
    from models import Credential, db

    log = log_callback or (lambda msg: None)
    log_lines = []

    def _log(msg):
        log_lines.append(msg)
        log(msg)

    config = _get_config()
    guest_id = config.get("guest_id", "")
    if not guest_id:
        _log("ERROR: Prometheus guest is not configured.")
        return False, log_lines

    try:
        guest = Guest.query.get(int(guest_id))
    except (TypeError, ValueError):
        _log("ERROR: Invalid guest ID.")
        return False, log_lines

    if not guest:
        _log("ERROR: Guest not found.")
        return False, log_lines

    credential = guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        _log("ERROR: No SSH credential configured.")
        return False, log_lines

    has_ip = guest.ip_address and guest.ip_address.lower() not in ("dhcp", "dhcp6", "auto")
    if not has_ip:
        _log("ERROR: Guest has no usable IP address.")
        return False, log_lines

    latest = Setting.get("prometheus_latest_version", "")
    current = Setting.get("prometheus_current_version", "")
    if not latest:
        _log("ERROR: No target version available.")
        return False, log_lines

    _log(f"Upgrading Prometheus from v{current} to v{latest} on {guest.name}...")

    # Protection
    protection_type = config.get("protection_type", "snapshot")
    _log(f"Creating {protection_type} protection...")
    if protection_type == "backup":
        ok, msg = _backup_guest(guest, config.get("backup_storage", ""), config.get("backup_mode", "snapshot"))
    else:
        ok, msg = _snapshot_guest(guest)
    _log(msg)
    if not ok:
        _log("ERROR: Protection failed, aborting upgrade.")
        return False, log_lines

    try:
        with SSHClient.from_credential(guest.ip_address, credential) as ssh:
            arch_out, _, _ = ssh.execute_sudo("dpkg --print-architecture", timeout=10)
            arch = (arch_out or "amd64").strip()
            prom_arch = "arm64" if arch == "arm64" else "amd64"

            # Download the new version and verify its published SHA-256
            asset, dl_url, sums_url, extract_dir = _prometheus_release_urls(latest, prom_arch)
            _log(f"Downloading Prometheus v{latest}...")
            ok, workdir, err = _fetch_verified_tarball(ssh, _log, dl_url, asset, sums_url)
            if not ok:
                _log(f"ERROR: Failed to download new version: {err}")
                return False, log_lines

            # Stop service
            _log("Stopping Prometheus...")
            ssh.execute_sudo("systemctl stop prometheus", timeout=30)

            # Replace binaries
            src = shlex.quote(f"{workdir}/{extract_dir}")
            _log("Replacing binaries...")
            stdout, stderr, code = ssh.execute_sudo(
                f"cp {src}/prometheus /usr/local/bin/ && "
                f"cp {src}/promtool /usr/local/bin/ && "
                "chown prometheus:prometheus /usr/local/bin/prometheus /usr/local/bin/promtool",
                timeout=30,
            )
            _log_cmd_output(_log, stdout, stderr, code)
            if code != 0:
                _log("ERROR: Failed to replace binaries.")
                _cleanup_workdir(ssh, workdir)
                return False, log_lines

            # Start service
            _log("Starting Prometheus...")
            stdout, stderr, code = ssh.execute_sudo("systemctl start prometheus", timeout=30)
            _log_cmd_output(_log, stdout, stderr, code)
            if code != 0:
                _log("ERROR: Failed to start Prometheus after upgrade.")
                return False, log_lines

            # Clean up
            _cleanup_workdir(ssh, workdir)

            _log(f"Prometheus upgraded to v{latest} successfully.")
            Setting.set("prometheus_current_version", latest)
            Setting.set("prometheus_update_available", "false")
            db.session.commit()

            return True, log_lines

    except Exception as e:
        _log(f"FATAL ERROR: {e}")
        logger.exception("Prometheus upgrade failed")
        return False, log_lines


# ---------------------------------------------------------------------------
# Pre-flight check
# ---------------------------------------------------------------------------

def run_prometheus_preflight(log_callback=None):
    """Run read-only pre-flight checks before Prometheus install or upgrade.

    Validates configuration, Proxmox guest status, SSH connectivity,
    and Prometheus-specific prerequisites.

    Returns (all_pass: bool, log_output: str).
    """
    from models import Credential

    config = _get_config()
    log_lines = []
    checks_passed = 0
    checks_total = 0
    checks_failed = 0

    def log(msg):
        logger.info(msg)
        log_lines.append(msg)
        if log_callback:
            log_callback(msg)

    def check(label, passed, fail_msg=None):
        nonlocal checks_passed, checks_total, checks_failed
        checks_total += 1
        if passed:
            checks_passed += 1
            log(f"  [PASS] {label}")
        else:
            checks_failed += 1
            msg = f"  [FAIL] {label}"
            if fail_msg:
                msg += f" — {fail_msg}"
            log(msg)

    log("=== Prometheus Pre-flight Check ===")
    log("")

    # ── A. Configuration ──────────────────────────────────────────────────────
    log("--- A. Configuration ---")

    config_ok = True
    guest_id = config.get("guest_id", "")
    if guest_id:
        check("Prometheus guest configured", True)
    else:
        check("Prometheus guest configured", False, "not set in settings")
        config_ok = False

    protection_type = config.get("protection_type", "snapshot")
    backup_storage = config.get("backup_storage", "")
    if protection_type == "backup":
        if backup_storage:
            check("Backup storage configured", True)
        else:
            check("Backup storage configured", False,
                  "backup protection selected but no storage configured")
            config_ok = False

    if not config_ok:
        log("")
        log(f"=== Pre-flight complete: {checks_passed}/{checks_total} checks passed — "
            f"{checks_failed} failure(s), blocked ===")
        return False, "\n".join(log_lines)

    # ── B. Proxmox guest status ───────────────────────────────────────────────
    log("")
    log("--- B. Proxmox guest ---")

    app_guest = Guest.query.get(int(config["guest_id"]))
    check("Prometheus guest in database", app_guest is not None,
          f"guest ID {config['guest_id']} not found")

    if not app_guest:
        log("")
        log(f"=== Pre-flight complete: {checks_passed}/{checks_total} checks passed — "
            f"{checks_failed} failure(s), blocked ===")
        return False, "\n".join(log_lines)

    if app_guest.proxmox_host:
        try:
            client = ProxmoxClient(app_guest.proxmox_host)
            node = client.find_guest_node(app_guest.vmid)
            if not node:
                check(f"{app_guest.name} found on Proxmox", False, "not found on any PVE node")
            else:
                check(f"{app_guest.name} found on Proxmox", True)
                status = client.get_guest_status(node, app_guest.vmid, app_guest.guest_type)
                check(f"{app_guest.name} running", status == "running",
                      f"current status: {status}")
                if protection_type == "snapshot":
                    supports_snap = client.guest_supports_snapshot(
                        node, app_guest.vmid, app_guest.guest_type
                    )
                    check(f"{app_guest.name} supports snapshots", supports_snap,
                          "storage does not support snapshots — switch to Backup protection")
        except Exception as e:
            check(f"{app_guest.name} Proxmox reachable", False, str(e))
    else:
        log(f"  [WARN] {app_guest.name} has no Proxmox host configured — skipping Proxmox checks")

    # ── C. SSH checks ─────────────────────────────────────────────────────────
    log("")
    log(f"--- C. SSH checks on {app_guest.name} ---")

    credential = app_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()

    if not credential:
        check("SSH credential available", False,
              "no credential configured for guest or as default")
    elif not app_guest.ip_address or app_guest.ip_address.lower() in ("dhcp", "dhcp6", "auto"):
        check("SSH credential available", True)
        check("Guest IP configured", False, "no usable IP address set on guest")
    else:
        check("SSH credential available", True)
        check("Guest IP configured", True)
        try:
            with SSHClient.from_credential(app_guest.ip_address, credential) as ssh:
                check("SSH connection established", True)

                # Check download tool available (curl or wget)
                stdout, stderr, code = ssh.execute_sudo(
                    "command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 && echo ok",
                    timeout=10,
                )
                check("Download tool available (curl or wget)",
                      code == 0 and "ok" in (stdout or ""),
                      "neither curl nor wget found — install one before proceeding")

                # Check if prometheus binary exists
                stdout, stderr, code = ssh.execute_sudo(
                    "test -f /usr/local/bin/prometheus && echo ok", timeout=10
                )
                prom_installed = code == 0 and "ok" in (stdout or "")
                if prom_installed:
                    log("  [INFO] Prometheus binary found at /usr/local/bin/prometheus")
                else:
                    log("  [INFO] Prometheus binary not found — fresh install expected")

                # Check prometheus user
                stdout, stderr, code = ssh.execute_sudo("id prometheus 2>/dev/null", timeout=10)
                if code == 0:
                    log("  [INFO] prometheus user exists")
                else:
                    log("  [INFO] prometheus user does not exist — will be created on install")

                # Check directories
                stdout, stderr, code = ssh.execute_sudo(
                    "test -d /etc/prometheus && echo ok", timeout=10
                )
                if code == 0 and "ok" in (stdout or ""):
                    log("  [INFO] /etc/prometheus exists")
                else:
                    log("  [INFO] /etc/prometheus does not exist — will be created on install")

                stdout, stderr, code = ssh.execute_sudo(
                    "test -d /var/lib/prometheus && echo ok", timeout=10
                )
                if code == 0 and "ok" in (stdout or ""):
                    log("  [INFO] /var/lib/prometheus exists")
                else:
                    log("  [INFO] /var/lib/prometheus does not exist — will be created on install")

                # Systemd service status (informational)
                if prom_installed:
                    stdout, stderr, code = ssh.execute_sudo(
                        "systemctl is-active prometheus 2>/dev/null", timeout=10
                    )
                    svc_status = (stdout or "").strip()
                    if svc_status == "active":
                        log("  [INFO] prometheus service is active")
                    elif svc_status:
                        log(f"  [WARN] prometheus service status: {svc_status}")

                    # Current version (informational)
                    stdout, stderr, code = ssh.execute_sudo(
                        "/usr/local/bin/prometheus --version 2>&1 | head -1", timeout=10
                    )
                    if code == 0 and stdout:
                        m = re.search(r"prometheus.*?version (\d+\.\d+\.\d+)", stdout)
                        if m:
                            log(f"  [INFO] Current version: {m.group(1)}")

                # Disk space on /var/lib/prometheus (informational)
                stdout, stderr, code = ssh.execute_sudo(
                    "df -h /var/lib/prometheus 2>/dev/null | tail -1", timeout=10
                )
                if code == 0 and stdout and stdout.strip():
                    parts = stdout.strip().split()
                    if len(parts) >= 4:
                        log(f"  [INFO] Disk space: {parts[3]} available on {parts[0]}")

        except Exception as e:
            check("SSH connection established", False, str(e))

    log("")
    all_pass = checks_failed == 0
    if all_pass:
        log(f"=== Pre-flight complete: {checks_passed}/{checks_total} checks passed — all clear ===")
    else:
        log(f"=== Pre-flight complete: {checks_passed}/{checks_total} checks passed — "
            f"{checks_failed} failure(s) ===")

    return all_pass, "\n".join(log_lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_config():
    """Read all Prometheus settings into a dict."""
    return {
        "guest_id": Setting.get("prometheus_guest_id", ""),
        "url": Setting.get("prometheus_url", ""),
        "retention_days": Setting.get("prometheus_retention_days", "365"),
        "protection_type": Setting.get("prometheus_protection_type", "snapshot"),
        "backup_storage": Setting.get("prometheus_backup_storage", ""),
        "backup_mode": Setting.get("prometheus_backup_mode", "snapshot"),
        "mstdnca_metrics_url": Setting.get("prometheus_mstdnca_metrics_url", ""),
        "latest_version": Setting.get("prometheus_latest_version", ""),
    }


def _generate_prometheus_yml(mstdnca_metrics_url, auth_token="", extra_scrape_configs=""):
    """Generate a prometheus.yml config file."""
    scrape_configs = """  - job_name: "prometheus"
    static_configs:
      - targets: ["localhost:9090"]"""

    if mstdnca_metrics_url:
        auth_section = ""
        if auth_token:
            auth_section = f"""
    authorization:
      type: Bearer
      credentials: "{auth_token}" """

        scrape_configs += f"""

  - job_name: "mstdnca"
    scrape_interval: 60s
    static_configs:
      - targets: ["{mstdnca_metrics_url}"]{auth_section}"""

    if extra_scrape_configs:
        scrape_configs += extra_scrape_configs

    return f"""global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
{scrape_configs}
"""


def _generate_systemd_unit(retention_days="365"):
    """Generate the Prometheus systemd service unit."""
    return f"""[Unit]
Description=Prometheus Monitoring System
Documentation=https://prometheus.io/docs/
Wants=network-online.target
After=network-online.target

[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/usr/local/bin/prometheus \\
  --config.file=/etc/prometheus/prometheus.yml \\
  --storage.tsdb.path=/var/lib/prometheus/ \\
  --storage.tsdb.retention.time={retention_days}d \\
  --web.console.templates=/etc/prometheus/consoles \\
  --web.console.libraries=/etc/prometheus/console_libraries \\
  --web.listen-address=0.0.0.0:9090
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
