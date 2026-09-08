"""
Unpoller install and upgrade automation.

Installs unpoller from GitHub binary releases onto the Prometheus guest via SSH.
Creates a dedicated user, systemd service, and generates an up.conf config file
that connects to the UniFi controller using credentials from app settings.
"""

import base64
import json
import logging
import re
import time
import urllib.request
from datetime import datetime

from apps.utils import _log_cmd_output, _validate_shell_param, _version_gt
from clients.proxmox_api import ProxmoxClient
from clients.ssh_client import SSHClient
from models import Guest, Setting

logger = logging.getLogger(__name__)

GITHUB_REPO = "unpoller/unpoller"
DEFAULT_PORT = 9130


def _write_remote_file(ssh, content, path, mode="640", owner="root", group=None, timeout=15):
    """Write `content` to `path` on the remote host atomically, with no
    world-readable window and without a heredoc (whose terminator a value in
    `content` — e.g. the UniFi password — could accidentally match and break out of).

    Base64-encodes `content` and pipes it through `install`, which writes the
    destination with its final mode/ownership in one step rather than creating it at
    the shell's default umask and `chmod`/`chown`ing afterward.

    Returns (success, stderr).
    """
    group = group or owner
    b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")
    cmd = (
        f"echo {b64} | base64 -d | "
        f"install -m {mode} -o {owner} -g {group} /dev/stdin {path}"
    )
    stdout, stderr, code = ssh.execute_sudo(cmd, timeout=timeout)
    return code == 0, stderr or stdout or ""


# ---------------------------------------------------------------------------
# Version check
# ---------------------------------------------------------------------------

def check_unpoller_release():
    """Check GitHub for the latest unpoller release.

    Returns (update_available, latest_version, release_url).
    """
    try:
        url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
        req = urllib.request.Request(url, headers={"User-Agent": "mstdnca-proxmox-tool"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            latest = data.get("tag_name", "").lstrip("v")
            release_url = data.get("html_url", "")

        if not latest:
            return False, "", ""

        Setting.set("unpoller_latest_version", latest)

        current = Setting.get("unpoller_current_version", "")
        update_available = bool(current and _version_gt(latest, current))
        Setting.set("unpoller_update_available", "true" if update_available else "false")

        return update_available, latest, release_url
    except Exception as e:
        logger.error("Failed to check unpoller releases: %s", e)
        return False, "", ""


def detect_unpoller_version(guest):
    """Detect the installed unpoller version on a guest via SSH.

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
                "/usr/local/bin/unpoller --version 2>&1 | head -1", timeout=10
            )
            if code == 0 and stdout:
                m = re.search(r"(\d+\.\d+\.\d+)", stdout)
                if m:
                    return m.group(1), None
            return None, f"Unpoller not found (exit code {code})"
    except Exception as e:
        return None, str(e)


# ---------------------------------------------------------------------------
# Proxmox protection (snapshot/backup) — reuse from prometheus_app
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
    snapname = f"pre-unpoller-{timestamp}"
    description = f"Auto-snapshot before unpoller install/upgrade at {timestamp}"

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

def run_unpoller_install(log_callback=None):
    """Install unpoller on the Prometheus guest via SSH.

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
        _log("ERROR: Prometheus guest is not configured (unpoller installs on the same guest).")
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

    # Validate UniFi controller settings
    unifi_url = config.get("unifi_url", "")
    unifi_user = config.get("unifi_user", "")
    unifi_pass = config.get("unifi_pass", "")
    if not unifi_url or not unifi_user or not unifi_pass:
        _log("ERROR: UniFi controller URL, username, and password are required.")
        _log("Configure them in Settings > UniFi Controller.")
        return False, log_lines

    # Get version to install
    latest = Setting.get("unpoller_latest_version", "")
    if not latest:
        _log("Checking for latest unpoller version...")
        _, latest, _ = check_unpoller_release()
    if not latest:
        _log("ERROR: Could not determine latest unpoller version.")
        return False, log_lines

    _log(f"Installing unpoller v{latest} on {guest.name} ({guest.ip_address})...")

    # Protection (snapshot) — use Prometheus protection settings
    protection_type = Setting.get("prometheus_protection_type", "snapshot")
    _log(f"Creating {protection_type} protection...")
    if protection_type == "backup":
        storage = Setting.get("prometheus_backup_storage", "")
        mode = Setting.get("prometheus_backup_mode", "snapshot")
        ok, msg = _backup_guest(guest, storage, mode)
    else:
        ok, msg = _snapshot_guest(guest)
    _log(msg)
    if not ok:
        _log("ERROR: Protection failed, aborting install.")
        return False, log_lines

    try:
        with SSHClient.from_credential(guest.ip_address, credential) as ssh:
            arch_out, _, _ = ssh.execute_sudo("dpkg --print-architecture", timeout=10)
            arch = (arch_out or "amd64").strip()
            up_arch = "arm64" if arch == "arm64" else "amd64"

            # Create unpoller user
            _log("Creating unpoller user...")
            stdout, stderr, code = ssh.execute_sudo(
                "id unpoller >/dev/null 2>&1 || useradd --no-create-home --shell /bin/false unpoller",
                timeout=15,
            )
            _log_cmd_output(_log, stdout, stderr, code)

            # Create directories
            _log("Creating directories...")
            stdout, stderr, code = ssh.execute_sudo(
                "mkdir -p /etc/unpoller",
                timeout=15,
            )
            _log_cmd_output(_log, stdout, stderr, code)
            if code != 0:
                _log("ERROR: Failed to create directories.")
                return False, log_lines

            # Download and extract unpoller
            dl_url = (
                f"https://github.com/{GITHUB_REPO}/releases/download/v{latest}/"
                f"unpoller_{latest}_linux_{up_arch}.tar.gz"
            )
            _log(f"Downloading unpoller v{latest} ({up_arch})...")
            dl_cmd = (
                f"cd /tmp && rm -rf unpoller_extract && mkdir unpoller_extract && "
                f"(curl -sSL -o unpoller.tar.gz '{dl_url}' 2>/dev/null "
                f"|| wget -q -O unpoller.tar.gz '{dl_url}') && "
                f"tar xzf unpoller.tar.gz -C unpoller_extract"
            )
            stdout, stderr, code = ssh.execute_sudo(dl_cmd, timeout=120)
            _log_cmd_output(_log, stdout, stderr, code)
            if code != 0:
                _log("ERROR: Failed to download unpoller.")
                return False, log_lines

            # Install binary
            _log("Installing binary...")
            stdout, stderr, code = ssh.execute_sudo(
                "cp /tmp/unpoller_extract/unpoller /usr/local/bin/unpoller && "
                "chmod +x /usr/local/bin/unpoller && "
                "chown root:root /usr/local/bin/unpoller",
                timeout=30,
            )
            _log_cmd_output(_log, stdout, stderr, code)
            if code != 0:
                _log("ERROR: Failed to install binary.")
                return False, log_lines

            # Generate config — written atomically with its final mode/ownership so
            # the UniFi credentials it contains are never briefly world-readable.
            _log("Generating unpoller config...")
            conf = _generate_unpoller_config(config)
            ok, err = _write_remote_file(ssh, conf, "/etc/unpoller/up.conf", mode="640", owner="root", group="unpoller")
            if not ok:
                _log(f"ERROR: Failed to write config: {err[:200]}")
                return False, log_lines

            # Create systemd service
            _log("Creating systemd service...")
            service_content = _generate_systemd_unit()
            stdout, stderr, code = ssh.execute_sudo(
                f"cat > /etc/systemd/system/unpoller.service << 'SVCEOF'\n{service_content}\nSVCEOF",
                timeout=15,
            )
            _log_cmd_output(_log, stdout, stderr, code)
            if code != 0:
                _log("ERROR: Failed to create systemd service.")
                return False, log_lines

            # Enable and start
            _log("Starting unpoller...")
            stdout, stderr, code = ssh.execute_sudo(
                "systemctl daemon-reload && systemctl enable unpoller && systemctl start unpoller",
                timeout=30,
            )
            _log_cmd_output(_log, stdout, stderr, code)
            if code != 0:
                _log("ERROR: Failed to start unpoller.")
                return False, log_lines

            # Verify it's running
            time.sleep(3)
            stdout, stderr, code = ssh.execute_sudo(
                "systemctl is-active unpoller", timeout=10
            )
            if code != 0 or (stdout or "").strip() != "active":
                _log("WARNING: Unpoller may not be running. Check logs with: journalctl -u unpoller")

            # Clean up
            ssh.execute_sudo("rm -rf /tmp/unpoller_extract /tmp/unpoller.tar.gz", timeout=15)

            _log(f"Unpoller v{latest} installed successfully.")

            # Update settings
            Setting.set("unpoller_installed", "true")
            Setting.set("unpoller_current_version", latest)
            Setting.set("unpoller_update_available", "false")
            db.session.commit()

    except Exception as e:
        _log(f"FATAL ERROR: {e}")
        logger.exception("Unpoller install failed")
        return False, log_lines

    # Regenerate prometheus.yml to include the unpoller scrape target. This uses
    # apps.exporters._regenerate_prometheus_config() — this repo's single
    # prometheus.yml generator — rather than a local copy, so this install no
    # longer wipes out exporter scrape jobs another component added.
    _log("Updating prometheus.yml with unpoller scrape target...")
    from apps.exporters import _regenerate_prometheus_config
    if not _regenerate_prometheus_config(_log):
        _log("ERROR: Failed to update prometheus.yml with the unpoller scrape target.")
        return False, log_lines

    return True, log_lines


# ---------------------------------------------------------------------------
# Upgrade
# ---------------------------------------------------------------------------

def run_unpoller_upgrade(log_callback=None):
    """Upgrade unpoller on the Prometheus guest."""
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

    latest = Setting.get("unpoller_latest_version", "")
    current = Setting.get("unpoller_current_version", "")
    if not latest:
        _log("ERROR: No target version available.")
        return False, log_lines

    _log(f"Upgrading unpoller from v{current} to v{latest} on {guest.name}...")

    # Protection
    protection_type = Setting.get("prometheus_protection_type", "snapshot")
    _log(f"Creating {protection_type} protection...")
    if protection_type == "backup":
        ok, msg = _backup_guest(
            guest, Setting.get("prometheus_backup_storage", ""),
            Setting.get("prometheus_backup_mode", "snapshot"),
        )
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
            up_arch = "arm64" if arch == "arm64" else "amd64"

            # Download new version
            dl_url = (
                f"https://github.com/{GITHUB_REPO}/releases/download/v{latest}/"
                f"unpoller_{latest}_linux_{up_arch}.tar.gz"
            )
            _log(f"Downloading unpoller v{latest}...")
            dl_cmd = (
                f"cd /tmp && rm -rf unpoller_extract && mkdir unpoller_extract && "
                f"(curl -sSL -o unpoller.tar.gz '{dl_url}' 2>/dev/null "
                f"|| wget -q -O unpoller.tar.gz '{dl_url}') && "
                f"tar xzf unpoller.tar.gz -C unpoller_extract"
            )
            stdout, stderr, code = ssh.execute_sudo(dl_cmd, timeout=120)
            _log_cmd_output(_log, stdout, stderr, code)
            if code != 0:
                _log("ERROR: Failed to download new version.")
                return False, log_lines

            # Stop service
            _log("Stopping unpoller...")
            ssh.execute_sudo("systemctl stop unpoller", timeout=30)

            # Replace binary
            _log("Replacing binary...")
            stdout, stderr, code = ssh.execute_sudo(
                "cp /tmp/unpoller_extract/unpoller /usr/local/bin/unpoller && "
                "chmod +x /usr/local/bin/unpoller && "
                "chown root:root /usr/local/bin/unpoller",
                timeout=30,
            )
            _log_cmd_output(_log, stdout, stderr, code)
            if code != 0:
                _log("ERROR: Failed to replace binary.")
                return False, log_lines

            # Start service
            _log("Starting unpoller...")
            stdout, stderr, code = ssh.execute_sudo("systemctl start unpoller", timeout=30)
            _log_cmd_output(_log, stdout, stderr, code)
            if code != 0:
                _log("ERROR: Failed to start unpoller after upgrade.")
                return False, log_lines

            # Clean up
            ssh.execute_sudo("rm -rf /tmp/unpoller_extract /tmp/unpoller.tar.gz", timeout=15)

            _log(f"Unpoller upgraded to v{latest} successfully.")
            Setting.set("unpoller_current_version", latest)
            Setting.set("unpoller_update_available", "false")
            db.session.commit()

            return True, log_lines

    except Exception as e:
        _log(f"FATAL ERROR: {e}")
        logger.exception("Unpoller upgrade failed")
        return False, log_lines


# ---------------------------------------------------------------------------
# Pre-flight check
# ---------------------------------------------------------------------------

def run_unpoller_preflight(log_callback=None):
    """Run read-only pre-flight checks before unpoller install or upgrade.

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

    log("=== Unpoller Pre-flight Check ===")
    log("")

    # ── A. Configuration ──────────────────────────────────────────────────────
    log("--- A. Configuration ---")

    config_ok = True
    guest_id = config.get("guest_id", "")
    if guest_id:
        check("Prometheus guest configured", True)
    else:
        check("Prometheus guest configured", False, "not set in Prometheus settings")
        config_ok = False

    unifi_url = config.get("unifi_url", "")
    unifi_user = config.get("unifi_user", "")
    unifi_pass = config.get("unifi_pass", "")
    check("UniFi controller URL configured", bool(unifi_url), "set it in Settings > UniFi Controller")
    check("UniFi username configured", bool(unifi_user), "set it in Settings > UniFi Controller")
    check("UniFi password configured", bool(unifi_pass), "set it in Settings > UniFi Controller")

    if not unifi_url or not unifi_user or not unifi_pass:
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

                # Check download tool available
                stdout, stderr, code = ssh.execute_sudo(
                    "command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 && echo ok",
                    timeout=10,
                )
                check("Download tool available (curl or wget)",
                      code == 0 and "ok" in (stdout or ""),
                      "neither curl nor wget found — install one before proceeding")

                # Check if unpoller binary exists
                stdout, stderr, code = ssh.execute_sudo(
                    "test -f /usr/local/bin/unpoller && echo ok", timeout=10
                )
                up_installed = code == 0 and "ok" in (stdout or "")
                if up_installed:
                    log("  [INFO] Unpoller binary found at /usr/local/bin/unpoller")
                else:
                    log("  [INFO] Unpoller binary not found — fresh install expected")

                # Check unpoller user
                stdout, stderr, code = ssh.execute_sudo("id unpoller 2>/dev/null", timeout=10)
                if code == 0:
                    log("  [INFO] unpoller user exists")
                else:
                    log("  [INFO] unpoller user does not exist — will be created on install")

                # Check Prometheus is running (since unpoller scrapes are served to Prometheus)
                stdout, stderr, code = ssh.execute_sudo(
                    "systemctl is-active prometheus 2>/dev/null", timeout=10
                )
                prom_status = (stdout or "").strip()
                if prom_status == "active":
                    check("Prometheus service running", True)
                else:
                    check("Prometheus service running", False,
                          f"status: {prom_status or 'not found'} — install Prometheus first")

                # Systemd service status (informational)
                if up_installed:
                    stdout, stderr, code = ssh.execute_sudo(
                        "systemctl is-active unpoller 2>/dev/null", timeout=10
                    )
                    svc_status = (stdout or "").strip()
                    if svc_status == "active":
                        log("  [INFO] unpoller service is active")
                    elif svc_status:
                        log(f"  [WARN] unpoller service status: {svc_status}")

                    # Current version
                    stdout, stderr, code = ssh.execute_sudo(
                        "/usr/local/bin/unpoller --version 2>&1 | head -1", timeout=10
                    )
                    if code == 0 and stdout:
                        m = re.search(r"(\d+\.\d+\.\d+)", stdout)
                        if m:
                            log(f"  [INFO] Current version: {m.group(1)}")

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
# Regenerate config (update credentials without reinstall)
# ---------------------------------------------------------------------------

def run_unpoller_reconfig(log_callback=None):
    """Regenerate unpoller config and restart the service.

    Returns (success, log_lines).
    """
    from models import Credential

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

    _log("Regenerating unpoller config...")

    try:
        with SSHClient.from_credential(guest.ip_address, credential) as ssh:
            conf = _generate_unpoller_config(config)
            ok, err = _write_remote_file(ssh, conf, "/etc/unpoller/up.conf", mode="640", owner="root", group="unpoller")
            if not ok:
                _log(f"ERROR: Failed to write config: {err[:200]}")
                return False, log_lines

            _log("Restarting unpoller...")
            stdout, stderr, code = ssh.execute_sudo("systemctl restart unpoller", timeout=30)
            _log_cmd_output(_log, stdout, stderr, code)
            if code != 0:
                _log("ERROR: Failed to restart unpoller.")
                return False, log_lines

            _log("Unpoller config updated and service restarted.")
            return True, log_lines

    except Exception as e:
        _log(f"FATAL ERROR: {e}")
        logger.exception("Unpoller reconfig failed")
        return False, log_lines


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_config():
    """Read all relevant settings into a dict."""
    return {
        "guest_id": Setting.get("prometheus_guest_id", ""),
        "unifi_url": Setting.get("unifi_base_url", ""),
        "unifi_user": Setting.get("unifi_username", ""),
        "unifi_pass": _get_unifi_password(),
        "unifi_site": Setting.get("unpoller_site_name", "default"),
        "metric_prefix": Setting.get("unpoller_metric_prefix", "unpoller"),
        "listen_port": Setting.get("unpoller_listen_port", str(DEFAULT_PORT)),
        # Follow the app's existing UniFi controller verify-SSL setting (see
        # routes/settings.py, clients/unifi_client.py) instead of hardcoding false.
        "verify_ssl": Setting.get("unifi_verify_ssl", "false") == "true",
    }


def _get_unifi_password():
    """Return the decrypted UniFi controller password, or "" if unavailable.

    The value is stored Fernet-encrypted by the settings UI. decrypt() returns
    None for an empty value and raises (e.g. InvalidToken) on a non-Fernet or
    corrupt string, so guard both cases rather than crash install/reconfigure.
    """
    from auth.credential_store import decrypt

    encrypted_pw = Setting.get("unifi_password", "")
    if not encrypted_pw:
        return ""
    try:
        return decrypt(encrypted_pw) or ""
    except Exception:
        logger.error(
            "Failed to decrypt unifi_password; unpoller up.conf will have an empty "
            "UniFi password. Re-save the UniFi credentials in Settings to fix this.",
            exc_info=True,
        )
        return ""


def _toml_escape(value):
    """Escape `value` for embedding in a double-quoted TOML basic string.

    TOML basic strings support \\, \\", \\n, \\r, \\t escapes and disallow a raw
    newline/tab in the source — so anything typed into a UniFi URL/user/password
    field (which could contain a `"` or an actual newline) is escaped rather than
    interpolated as-is, which could otherwise break the file or inject new keys.
    """
    text = str(value)
    text = text.replace("\\", "\\\\").replace('"', '\\"')
    return text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")


def _generate_unpoller_config(config):
    """Generate the unpoller up.conf TOML config file."""
    unifi_url = config.get("unifi_url", "")
    unifi_user = config.get("unifi_user", "")
    unifi_pass = config.get("unifi_pass", "")
    site = config.get("unifi_site", "default")
    prefix = config.get("metric_prefix", "unpoller")
    port = config.get("listen_port", str(DEFAULT_PORT))
    verify_ssl = "true" if config.get("verify_ssl") else "false"

    # Ensure URL has https:// prefix
    if unifi_url and not unifi_url.startswith("http"):
        unifi_url = f"https://{unifi_url}"

    return f"""# Unpoller configuration — managed by mstdnca-proxmox-tool
# Do not edit manually; changes will be overwritten on reconfigure.

[poller]
  debug = false
  quiet = false

[prometheus]
  disable = false
  http_listen = "0.0.0.0:{_toml_escape(port)}"
  report_errors = false
  namespace = "{_toml_escape(prefix)}"

[influxdb]
  disable = true

[loki]
  disable = true

[[unifi.controller]]
  url = "{_toml_escape(unifi_url)}"
  user = "{_toml_escape(unifi_user)}"
  pass = "{_toml_escape(unifi_pass)}"
  sites = ["{_toml_escape(site)}"]
  save_ids = true
  save_events = false
  save_alarms = false
  save_anomalies = false
  save_dpi = true
  save_sites = true
  verify_ssl = {verify_ssl}
"""


def _generate_systemd_unit():
    """Generate the unpoller systemd service unit."""
    return """[Unit]
Description=Unpoller — UniFi Prometheus Exporter
Documentation=https://unpoller.com
Wants=network-online.target
After=network-online.target

[Service]
User=unpoller
Group=unpoller
Type=simple
ExecStart=/usr/local/bin/unpoller --config /etc/unpoller/up.conf
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""


def get_unpoller_scrape_config(guest_ip, port=None):
    """Return a Prometheus scrape config snippet for unpoller.

    Used by the Prometheus config generator to include unpoller as a scrape target.
    """
    port = port or Setting.get("unpoller_listen_port", str(DEFAULT_PORT))
    return f"""

  - job_name: "unpoller"
    scrape_interval: 30s
    static_configs:
      - targets: ["{guest_ip}:{port}"]"""
