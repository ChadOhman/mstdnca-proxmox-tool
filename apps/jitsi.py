"""
Jitsi Meet install, upgrade, and Cloudflare Zero Trust configuration automation.

Installs Jitsi Meet via apt packages with debconf preseeding for non-interactive
setup, or upgrades existing installations via targeted apt upgrade.  Takes a
Proxmox snapshot or vzdump backup of the guest before any changes.
"""

import base64
import logging
import re
import shlex
import time

from apps.backup import backup_guest, snapshot_guest

# Shared shell-safety and output helpers from the Mastodon module
from apps.utils import (
    _log_cmd_output,
    _validate_email,
    _validate_hostname,
    _validate_shell_param,
    _version_gt,
)
from clients.proxmox_api import ProxmoxClient
from clients.ssh_client import SSHClient
from core.errors import describe_exception
from models import Guest, Setting

logger = logging.getLogger(__name__)

# Jitsi services that must be running for a healthy installation
_JITSI_SERVICES = ["jitsi-videobridge2", "jicofo", "prosody"]

# All Jitsi-related services (including coturn and nginx) for full restarts
_JITSI_ALL_SERVICES = ["jitsi-videobridge2", "jicofo", "prosody", "coturn", "nginx"]

# Packages to upgrade during a targeted apt upgrade
_JITSI_APT_PACKAGES = [
    "jitsi-meet",
    "jitsi-videobridge2",
    "jicofo",
    "jitsi-meet-web",
    "jitsi-meet-prosody",
    "jitsi-meet-web-config",
]

# Hostname validation: FQDN pattern (letters, digits, hyphens, dots)
_HOSTNAME_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')

# Email validation: basic pattern for Let's Encrypt email
_EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')

# IPv4 address validation
_IP_RE = re.compile(r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')


# ---------------------------------------------------------------------------
# Version check (via apt on the target guest)
# ---------------------------------------------------------------------------

def check_jitsi_release():
    """Check the Jitsi apt repository for the latest available version.

    Unlike other apps that query GitHub, Jitsi versions come from the apt
    repo on the target guest.  Requires the guest to be configured and
    reachable via SSH.

    Returns (update_available, latest_version, release_url).
    """
    from models import Credential

    config = _get_jitsi_config()
    guest_id = config.get("guest_id", "")
    if not guest_id:
        logger.debug("Jitsi guest not configured, skipping release check")
        return False, "", ""

    try:
        guest = Guest.query.get(int(guest_id))
    except (TypeError, ValueError):
        return False, "", ""
    if not guest:
        return False, "", ""

    credential = guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()

    stdout = None
    has_usable_ip = guest.ip_address and guest.ip_address.lower() not in ("dhcp", "dhcp6", "auto")

    # Try SSH first
    if has_usable_ip and credential:
        try:
            with SSHClient.from_credential(guest.ip_address, credential) as ssh:
                ssh.execute_sudo("apt-get update -qq 2>/dev/null", timeout=120)
                stdout, stderr, code = ssh.execute_sudo(
                    "apt-cache policy jitsi-meet 2>/dev/null", timeout=15
                )
                if code != 0:
                    stdout = None
        except Exception as e:
            logger.debug("SSH failed for Jitsi release check: %s", e)

    # Fall back to guest agent
    if stdout is None and guest.proxmox_host and guest.guest_type == "vm":
        try:
            client = ProxmoxClient(guest.proxmox_host)
            node = client.find_guest_node(guest.vmid)
            if node:
                client.exec_guest_agent(node, guest.vmid, "apt-get update -qq", timeout=120)
                stdout, err = client.exec_guest_agent(
                    node, guest.vmid, "apt-cache policy jitsi-meet", timeout=15
                )
                if err:
                    logger.debug("Guest agent apt-cache failed: %s", err)
                    stdout = None
        except Exception as e:
            logger.debug("Guest agent failed for Jitsi release check: %s", e)

    if not stdout:
        logger.error("Failed to check Jitsi releases: no reachable connection to guest %s", guest.name)
        return False, "", ""

    try:
        # Parse "Candidate: X.Y.Z-N" from output
        candidate = ""
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("Candidate:"):
                candidate = line.split(":", 1)[1].strip()
                break

        if not candidate or candidate == "(none)":
            return False, "", ""

        # Strip Debian revision suffix (e.g., "2.0.9457-1" -> "2.0.9457")
        latest = re.sub(r'-\d+$', '', candidate)

        Setting.set("jitsi_latest_version", latest)

        current = Setting.get("jitsi_current_version", "")
        update_available = bool(current and _version_gt(latest, current))
        Setting.set("jitsi_update_available", "true" if update_available else "false")

        return update_available, latest, ""

    except Exception as e:
        logger.error("Failed to parse Jitsi version: %s", e)
        return False, "", ""


# ---------------------------------------------------------------------------
# Proxmox protection helpers
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Internal config helper
# ---------------------------------------------------------------------------

def _ssh_write_file(ssh, path, content, log):
    """Write content to a remote file via base64 pipe.

    Uses base64 encoding to avoid heredoc quoting issues with special
    characters in config file content.  Returns True on success.
    """
    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
    stdout, stderr, code = ssh.execute_sudo(
        f"printf '%s' '{encoded}' | base64 -d | tee {shlex.quote(path)} > /dev/null",
        timeout=15,
    )
    if code != 0:
        log(f"  ERROR: Could not write {path} (exit {code})")
        _log_cmd_output(log, stdout, stderr, code, max_chars=500)
        return False
    return True


def _require_valid_hostname(config):
    """Return an error string if the configured Jitsi hostname is unusable.

    Every configure/user-management entry point calls this before opening an SSH
    connection: the hostname is interpolated into config-file paths and into
    `cat`/`grep`/`sed` arguments, so it must be a real FQDN and nothing else.
    """
    hostname = config.get("hostname", "")
    if not hostname:
        return "Jitsi hostname not configured"
    try:
        _validate_hostname(hostname, "Jitsi hostname")
    except ValueError as e:
        return str(e)
    return None


def _get_jitsi_config():
    """Read all Jitsi-related settings."""
    return {
        "guest_id": Setting.get("jitsi_guest_id", ""),
        "hostname": Setting.get("jitsi_hostname", ""),
        "cert_type": Setting.get("jitsi_cert_type", "self-signed"),
        "letsencrypt_email": Setting.get("jitsi_letsencrypt_email", ""),
        "url": Setting.get("jitsi_url", ""),
        "current_version": Setting.get("jitsi_current_version", ""),
        "latest_version": Setting.get("jitsi_latest_version", ""),
        "protection_type": Setting.get("jitsi_protection_type", "snapshot"),
        "backup_storage": Setting.get("jitsi_backup_storage", ""),
        "backup_mode": Setting.get("jitsi_backup_mode", "snapshot"),
        "auto_upgrade": Setting.get("jitsi_auto_upgrade", "false") == "true",
        "installed": Setting.get("jitsi_installed", "false") == "true",
        "cf_mode": Setting.get("jitsi_cf_mode", "none"),
        "public_ip": Setting.get("jitsi_public_ip", ""),
        "secure_domain": Setting.get("jitsi_secure_domain", "false") == "true",
    }


# ---------------------------------------------------------------------------
# Version detection
# ---------------------------------------------------------------------------

def detect_jitsi_version(guest):
    """Detect the installed Jitsi Meet version via SSH.

    Reads the version from dpkg package info.

    Returns (version_string, None) on success, or (None, error_message) on failure.
    """
    from models import Credential

    credential = guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return None, "No SSH credential configured for this guest"
    if not guest.ip_address:
        return None, "No IP address set on the Jitsi guest"

    try:
        with SSHClient.from_credential(guest.ip_address, credential) as ssh:
            # Read version from dpkg
            stdout, stderr, code = ssh.execute_sudo(
                "dpkg -s jitsi-meet 2>/dev/null | grep '^Version:'", timeout=10
            )
            if code == 0 and stdout and stdout.strip():
                # Parse "Version: 2.0.9457-1" -> "2.0.9457"
                version_line = stdout.strip().splitlines()[0]
                version = version_line.replace("Version:", "").strip()
                # Strip Debian revision suffix
                version = re.sub(r'-\d+$', '', version)
                if version:
                    return version, None

            return None, "jitsi-meet package not found or version could not be determined"

    except Exception as e:
        logger.warning("Could not detect Jitsi version: %s", e)
        return None, str(e)


# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

def run_jitsi_preflight(log_callback=None):
    """Run read-only pre-flight checks before Jitsi install or upgrade.

    Validates configuration, Proxmox guest status, SSH connectivity,
    and Jitsi-specific prerequisites.

    Returns (all_pass: bool, log_output: str).
    """
    from models import Credential

    config = _get_jitsi_config()
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

    log("=== Jitsi Meet Pre-flight Check ===")
    log("")

    # ── A. Configuration ──────────────────────────────────────────────────────
    log("--- A. Configuration ---")

    config_ok = True
    guest_id = config.get("guest_id", "")
    if guest_id:
        check("Jitsi guest configured", True)
    else:
        check("Jitsi guest configured", False, "not set in settings")
        config_ok = False

    hostname = config.get("hostname", "")
    if hostname:
        check("Hostname configured", True)
        if _HOSTNAME_RE.match(hostname):
            check("Hostname format valid", True)
        else:
            check("Hostname format valid", False, f"'{hostname}' is not a valid FQDN")
            config_ok = False
    else:
        check("Hostname configured", False, "not set in settings")
        config_ok = False

    cert_type = config.get("cert_type", "self-signed")
    if cert_type in ("letsencrypt", "self-signed", "custom"):
        check(f"Certificate type valid ({cert_type})", True)
    else:
        check("Certificate type valid", False, f"unknown type: {cert_type}")
        config_ok = False

    if cert_type == "letsencrypt":
        email = config.get("letsencrypt_email", "")
        if email:
            if _EMAIL_RE.match(email):
                check("Let's Encrypt email configured", True)
            else:
                check("Let's Encrypt email configured", False, f"'{email}' is not a valid email")
                config_ok = False
        else:
            check("Let's Encrypt email configured", False,
                  "Let's Encrypt selected but no email provided")
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

    try:
        _validate_hostname(hostname, "Hostname")
        if cert_type == "letsencrypt":
            # Email addresses contain '@' (and often '+'), which _SHELL_SAFE_RE
            # excludes — running _validate_shell_param over one rejected every
            # valid address and made this check unpassable.
            _validate_email(config.get("letsencrypt_email", ""), "Email")
        check("Shell-safe config values", True)
    except ValueError as e:
        check("Shell-safe config values", False, str(e))
        config_ok = False

    if not config_ok:
        log("")
        log(f"=== Pre-flight complete: {checks_passed}/{checks_total} checks passed — "
            f"{checks_failed} failure(s), blocked ===")
        return False, "\n".join(log_lines)

    # ── B. Proxmox guest status ───────────────────────────────────────────────
    log("")
    log("--- B. Proxmox guests ---")

    app_guest = Guest.query.get(int(config["guest_id"]))
    check("Jitsi guest in database", app_guest is not None,
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

    # ── C. SSH checks on guest ────────────────────────────────────────────────
    log("")
    log(f"--- C. SSH checks on {app_guest.name} ---")

    credential = app_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()

    if not credential:
        check("SSH credential available", False,
              "no credential configured for Jitsi guest or as default")
    elif not app_guest.ip_address:
        check("SSH credential available", True)
        check("Jitsi guest IP configured", False, "no IP address set on guest")
    else:
        check("SSH credential available", True)
        check("Jitsi guest IP configured", True)
        try:
            with SSHClient.from_credential(app_guest.ip_address, credential) as ssh:
                check("SSH connection established", True)

                installed = config.get("installed", False)

                if installed:
                    # Upgrade pre-flight: verify jitsi-meet is installed
                    stdout, stderr, code = ssh.execute_sudo(
                        "dpkg -s jitsi-meet 2>/dev/null | grep '^Status:.*installed'",
                        timeout=10
                    )
                    check("jitsi-meet package installed",
                          code == 0 and "installed" in (stdout or ""),
                          "jitsi-meet package not found")

                    # Check apt repos configured
                    stdout, stderr, code = ssh.execute_sudo(
                        "test -f /etc/apt/sources.list.d/jitsi-stable.list && echo ok",
                        timeout=10
                    )
                    check("Jitsi apt repository configured",
                          code == 0 and "ok" in (stdout or ""),
                          "/etc/apt/sources.list.d/jitsi-stable.list not found")

                    # Check services status
                    for svc in _JITSI_SERVICES:
                        stdout, stderr, code = ssh.execute_sudo(
                            f"systemctl is-active {svc} 2>/dev/null", timeout=10
                        )
                        svc_status = (stdout or "").strip()
                        if svc_status == "active":
                            log(f"  [INFO] {svc} is active")
                        elif svc_status:
                            log(f"  [WARN] {svc} status: {svc_status}")
                        else:
                            log(f"  [WARN] Could not determine {svc} status")

                    # Current version (informational)
                    stdout, stderr, code = ssh.execute_sudo(
                        "dpkg -s jitsi-meet 2>/dev/null | grep '^Version:'", timeout=10
                    )
                    if code == 0 and stdout and stdout.strip():
                        log(f"  [INFO] {stdout.strip()}")

                else:
                    # Install pre-flight: verify jitsi-meet NOT already installed
                    stdout, stderr, code = ssh.execute_sudo(
                        "dpkg -s jitsi-meet 2>/dev/null | grep '^Status:.*installed'",
                        timeout=10
                    )
                    if code == 0 and "installed" in (stdout or ""):
                        check("Jitsi not yet installed", False,
                              "jitsi-meet is already installed — use upgrade instead")
                    else:
                        check("Jitsi not yet installed", True)

                    # Check hostname resolves (informational)
                    stdout, stderr, code = ssh.execute_sudo(
                        f"host {hostname} 2>/dev/null || dig +short {hostname} 2>/dev/null",
                        timeout=10
                    )
                    if code == 0 and stdout and stdout.strip():
                        log(f"  [INFO] Hostname {hostname} resolves")
                    else:
                        log(f"  [WARN] Hostname {hostname} may not resolve — "
                            "ensure DNS is configured before install")

                    # Check if OS is Debian/Ubuntu
                    stdout, stderr, code = ssh.execute_sudo(
                        "lsb_release -si 2>/dev/null", timeout=10
                    )
                    distro = (stdout or "").strip()
                    if distro in ("Debian", "Ubuntu"):
                        check(f"OS is {distro}", True)
                    elif distro:
                        check("OS is Debian/Ubuntu", False,
                              f"detected {distro} — Jitsi requires Debian or Ubuntu")
                    else:
                        log("  [WARN] Could not determine OS distribution")

        except Exception as e:
            check("SSH connection established", False, str(e))

    all_pass = checks_failed == 0
    log("")
    if all_pass:
        log(f"=== Pre-flight complete: {checks_passed}/{checks_total} checks passed — all clear ===")
    else:
        log(f"=== Pre-flight complete: {checks_passed}/{checks_total} checks passed — "
            f"{checks_failed} failure(s), blocked ===")
    return all_pass, "\n".join(log_lines)


# ---------------------------------------------------------------------------
# Protection helper (shared by install and upgrade)
# ---------------------------------------------------------------------------

def _run_protection(config, app_guest, log, skip_protection=False):
    """Run snapshot or backup protection on the Jitsi guest.

    Returns True on success, False on failure.
    """
    if skip_protection:
        log("=== Step 1: Skipping snapshot/backup (requested by super-admin) ===")
        return True

    protection_type = config.get("protection_type", "snapshot")
    backup_storage = config.get("backup_storage", "")

    if protection_type == "backup" and not backup_storage:
        log("ERROR: Backup protection selected but no backup storage is configured")
        return False

    if protection_type == "backup":
        backup_mode = config.get("backup_mode", "snapshot")
        log(f"=== Step 1: Creating vzdump backup to storage '{backup_storage}' "
            f"(mode: {backup_mode}) ===")
        log("(This may take several minutes — please be patient)")
        ok, msg = backup_guest(app_guest, backup_storage, "jitsi", mode=backup_mode)
        log(f"Backup {app_guest.name}: {msg}")
        if not ok:
            return False
    else:
        log("=== Step 1: Creating Proxmox snapshot ===")
        ok, msg = snapshot_guest(app_guest, "jitsi")
        log(f"Snapshot {app_guest.name}: {msg}")
        if not ok:
            return False

    log("")
    return True


# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

def run_jitsi_install(log_callback=None):
    """Install Jitsi Meet on the configured guest via apt.

    Steps:
    1. Snapshot or backup the guest.
    2. Add Jitsi apt repository.
    3. Update apt cache.
    4. Preseed debconf with hostname and certificate choice.
    5. Install jitsi-meet package (non-interactive).
    6. If Let's Encrypt: run certificate setup script.
    7. Configure UFW firewall (if active).
    8. Verify all Jitsi services are running.
    9. Detect and persist the installed version.

    Returns (ok: bool, log_output: str).
    """
    from models import Credential

    config = _get_jitsi_config()
    log_lines = []

    def log(msg):
        logger.info(msg)
        log_lines.append(msg)
        if log_callback:
            log_callback(msg)

    # Validate config
    if not config["guest_id"]:
        return False, "Jitsi guest not configured"

    app_guest = Guest.query.get(int(config["guest_id"]))
    if not app_guest:
        return False, "Jitsi guest not found"

    hostname = config["hostname"]
    cert_type = config["cert_type"]
    letsencrypt_email = config.get("letsencrypt_email", "")

    if not hostname:
        return False, "Jitsi hostname not configured"

    try:
        _validate_hostname(hostname, "Hostname")
        if cert_type == "letsencrypt" and letsencrypt_email:
            # _validate_shell_param rejects '@', so it rejected every valid
            # address; an email needs the email allow-list, not the shell one.
            _validate_email(letsencrypt_email, "Email")
    except ValueError as e:
        return False, str(e)

    credential = app_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return False, "No SSH credential available"
    if not app_guest.ip_address:
        return False, "Jitsi guest has no IP address"

    log("=== Jitsi Meet Installation ===")
    log(f"Guest: {app_guest.name} ({app_guest.ip_address})")
    log(f"Hostname: {hostname}")
    log(f"Certificate: {cert_type}")
    log("")

    # Step 1: Protection
    if not _run_protection(config, app_guest, log):
        return False, "\n".join(log_lines)

    try:
        with SSHClient.from_credential(app_guest.ip_address, credential) as ssh:
            # Remove the Prosody community repo if a previous attempt added it.
            ssh.execute_sudo(
                "rm -f /etc/apt/sources.list.d/prosody.list "
                "/etc/apt/keyrings/prosody-keyring.gpg 2>/dev/null",
                timeout=10
            )

            # Prosody 13.x (shipped by the Jitsi stable repo) requires Lua 5.2+.
            # The luarocks dependency can pull in Lua 5.1 and set it as the system
            # default via update-alternatives, which causes Prosody to fail with
            # "Prosody is no longer compatible with Lua 5.1".  Fix: install lua5.4,
            # set it as the default, and remove lua5.1 if present.
            log("=== Step 2: Ensuring Lua 5.4 for Prosody 13.x ===")
            ssh.execute_sudo("apt-get install -y lua5.4 2>&1", timeout=60)
            ssh.execute_sudo(
                "update-alternatives --set lua-interpreter /usr/bin/lua5.4 2>/dev/null || "
                "update-alternatives --install /usr/bin/lua lua-interpreter /usr/bin/lua5.4 400 2>/dev/null",
                timeout=10
            )
            # Remove lua5.1 if installed — it conflicts with Prosody 13.x
            ssh.execute_sudo(
                "apt-get remove -y lua5.1 liblua5.1-0 2>&1 || true",
                timeout=30
            )
            log("Lua 5.4 installed and set as default")
            log("")

            # Force-purge any broken Prosody from a previous failed install
            # (e.g. 13.x that failed to start due to Lua 5.1)
            ssh.execute_sudo(
                "dpkg --force-remove-reinstreq --purge prosody 2>&1 || true",
                timeout=60
            )
            ssh.execute_sudo(
                "DEBIAN_FRONTEND=noninteractive apt-get -f install -y 2>&1 || true",
                timeout=120
            )

            # Step 3: Add Jitsi apt repository
            log("=== Step 3: Adding Jitsi apt repository ===")

            stdout, stderr, code = ssh.execute_sudo(
                "curl -fsSL https://download.jitsi.org/jitsi-key.gpg.key "
                "| gpg --dearmor -o /etc/apt/keyrings/jitsi-keyring.gpg --yes 2>&1",
                timeout=30
            )
            if code != 0:
                log(f"WARNING: Could not add Jitsi keyring (exit {code})")
                _log_cmd_output(log, stdout, stderr, code, max_chars=500)
            else:
                log("Jitsi keyring added")

            stdout, stderr, code = ssh.execute_sudo(
                'echo "deb [signed-by=/etc/apt/keyrings/jitsi-keyring.gpg] '
                'https://download.jitsi.org stable/" '
                "> /etc/apt/sources.list.d/jitsi-stable.list",
                timeout=10
            )
            if code != 0:
                log(f"WARNING: Could not add Jitsi repository (exit {code})")
                _log_cmd_output(log, stdout, stderr, code, max_chars=500)
            else:
                log("Jitsi repository added")
            log("")

            # Step 4: Update apt cache
            log("=== Step 4: Updating apt cache ===")
            stdout, stderr, code = ssh.execute_sudo(
                "apt-get update -qq 2>&1", timeout=120
            )
            if code != 0:
                log(f"ERROR: apt-get update failed (exit {code})")
                _log_cmd_output(log, stdout, stderr, code, max_chars=1000)
                return False, "\n".join(log_lines)
            log("apt cache updated")
            log("")

            # Step 5: Preseed debconf
            log("=== Step 5: Preseeding debconf ===")

            # Preseed hostname
            stdout, stderr, code = ssh.execute_sudo(
                f'echo "jitsi-videobridge2 jitsi-videobridge/jvb-hostname string {hostname}" '
                "| debconf-set-selections",
                timeout=10
            )
            if code != 0:
                log(f"ERROR: Failed to preseed hostname (exit {code})")
                _log_cmd_output(log, stdout, stderr, code, max_chars=500)
                return False, "\n".join(log_lines)

            # Preseed certificate choice
            # The debconf value uses "Generate a new self-signed certificate" for
            # both self-signed and letsencrypt (LE cert is set up post-install).
            if cert_type == "custom":
                cert_preseed = "I want to use my own certificate"
            else:
                cert_preseed = (
                    "Generate a new self-signed certificate "
                    "(oportunity to obtain a Let's Encrypt certificate later)"
                )

            stdout, stderr, code = ssh.execute_sudo(
                'echo "jitsi-meet-web-config jitsi-meet/cert-choice select '
                f'{cert_preseed}" | debconf-set-selections',
                timeout=10
            )

            if code != 0:
                log(f"WARNING: debconf preseed for certificate may have failed (exit {code})")
                _log_cmd_output(log, stdout, stderr, code, max_chars=500)
            else:
                log(f"debconf preseeded: hostname={hostname}, cert={cert_type}")
            log("")

            # Step 6: Install jitsi-meet
            log("=== Step 6: Installing jitsi-meet package ===")
            log("(This may take several minutes...)")
            stdout, stderr, code = ssh.execute_sudo(
                "DEBIAN_FRONTEND=noninteractive apt-get install -y jitsi-meet 2>&1",
                timeout=600
            )
            _log_cmd_output(log, stdout, stderr, code, max_chars=4000)
            if code != 0:
                log(f"ERROR: jitsi-meet installation failed (exit {code})")
                return False, "\n".join(log_lines)
            log("jitsi-meet package installed successfully")
            log("")

            # Step 7: Let's Encrypt certificate (if requested)
            if cert_type == "letsencrypt":
                log("=== Step 7: Setting up Let's Encrypt certificate ===")
                if letsencrypt_email:
                    le_cmd = (
                        f"echo '{letsencrypt_email}' | "
                        "/usr/share/jitsi-meet/scripts/install-letsencrypt-cert.sh 2>&1"
                    )
                else:
                    le_cmd = "/usr/share/jitsi-meet/scripts/install-letsencrypt-cert.sh 2>&1"

                stdout, stderr, code = ssh.execute_sudo(le_cmd, timeout=120)
                _log_cmd_output(log, stdout, stderr, code, max_chars=2000)
                if code != 0:
                    log(f"WARNING: Let's Encrypt setup returned exit code {code}")
                    log("You may need to run the certificate script manually")
                else:
                    log("Let's Encrypt certificate installed successfully")
                log("")
            else:
                log("=== Step 7: Skipping Let's Encrypt (not selected) ===")
                log("")

            # Step 8: Configure UFW firewall
            log("=== Step 8: Configuring firewall ===")
            stdout, stderr, code = ssh.execute_sudo(
                "ufw status 2>/dev/null | head -1", timeout=10
            )
            ufw_active = code == 0 and "active" in (stdout or "").lower()

            if ufw_active:
                for rule in ["80/tcp", "443/tcp", "10000/udp", "5349/tcp"]:
                    stdout, stderr, code = ssh.execute_sudo(
                        f"ufw allow {rule} 2>&1", timeout=10
                    )
                    if code == 0:
                        log(f"  UFW: allowed {rule}")
                    else:
                        log(f"  WARNING: Could not add UFW rule for {rule}")
            else:
                log("  UFW not active — skipping firewall configuration")
                log("  Ensure ports 80/tcp, 443/tcp, 10000/udp, 5349/tcp are open")
            log("")

            # Step 9: Configure coturn TLS for external TURN relay
            log("")
            _configure_coturn_tls(ssh, hostname, log)
            log("")

            # Step 10: Configure Prosody to advertise TURN to clients
            _configure_prosody_turn(ssh, hostname, log)
            log("")

            # Step 11: Configure JVB NAT harvester (if public IP is set)
            public_ip = config.get("public_ip", "")
            if public_ip:
                _configure_jvb_nat_harvester(ssh, app_guest.ip_address, public_ip, log)
                log("")

            # Step 12: Verify services
            log("=== Step 12: Verifying Jitsi services ===")
            all_active = True
            for svc in _JITSI_SERVICES:
                stdout, stderr, code = ssh.execute_sudo(
                    f"systemctl is-active {svc} 2>/dev/null", timeout=10
                )
                svc_status = (stdout or "").strip()
                if svc_status == "active":
                    log(f"  {svc}: active")
                else:
                    log(f"  {svc}: {svc_status or 'unknown'}")
                    # Try to start it
                    ssh.execute_sudo(f"systemctl start {svc} 2>&1", timeout=30)
                    stdout2, _, code2 = ssh.execute_sudo(
                        f"systemctl is-active {svc} 2>/dev/null", timeout=10
                    )
                    if code2 == 0 and (stdout2 or "").strip() == "active":
                        log(f"  {svc}: started successfully")
                    else:
                        log(f"  WARNING: {svc} is not active")
                        all_active = False

            if not all_active:
                log("WARNING: Not all services are active — Jitsi may not be fully functional")
            log("")

            # Step 13: Detect and persist version
            log("=== Step 13: Detecting installed version ===")
            stdout, stderr, code = ssh.execute_sudo(
                "dpkg -s jitsi-meet 2>/dev/null | grep '^Version:'", timeout=10
            )
            if code == 0 and stdout and stdout.strip():
                version_line = stdout.strip().splitlines()[0]
                version = version_line.replace("Version:", "").strip()
                version = re.sub(r'-\d+$', '', version)
                if version:
                    Setting.set("jitsi_current_version", version)
                    Setting.set("jitsi_update_available", "false")
                    Setting.set("jitsi_installed", "true")
                    Setting.set("jitsi_url", f"https://{hostname}")
                    from models import db
                    db.session.commit()
                    log(f"Jitsi Meet v{version} installed successfully")
                else:
                    log("WARNING: Could not parse version from dpkg output")
            else:
                log("WARNING: Could not detect installed version")

            # Step 14: Enable JVB REST API for service monitoring
            log("")
            _enable_jvb_rest_api(ssh, log)

            log("")
            log("=== Jitsi Meet installation complete ===")
            return True, "\n".join(log_lines)

    except Exception as e:
        log(f"FATAL ERROR: {e}")
        return False, "\n".join(log_lines)


# ---------------------------------------------------------------------------
# Upgrade
# ---------------------------------------------------------------------------

def run_jitsi_upgrade(log_callback=None, skip_protection=False):
    """Upgrade Jitsi Meet via targeted apt upgrade.

    Steps:
    1. Snapshot or backup the guest.
    2. Update apt cache.
    3. Upgrade Jitsi packages.
    4. Restart Jitsi services.
    5. Verify services are active.
    6. Detect and persist new version.

    Returns (ok: bool, log_output: str).
    """
    from models import Credential

    config = _get_jitsi_config()
    log_lines = []

    def log(msg):
        logger.info(msg)
        log_lines.append(msg)
        if log_callback:
            log_callback(msg)

    # Validate config
    if not config["guest_id"]:
        return False, "Jitsi guest not configured"

    app_guest = Guest.query.get(int(config["guest_id"]))
    if not app_guest:
        return False, "Jitsi guest not found"

    credential = app_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return False, "No SSH credential available"
    if not app_guest.ip_address:
        return False, "Jitsi guest has no IP address"

    log("=== Jitsi Meet Upgrade ===")
    log(f"Guest: {app_guest.name} ({app_guest.ip_address})")
    log("")

    # Step 1: Protection
    if not _run_protection(config, app_guest, log, skip_protection=skip_protection):
        return False, "\n".join(log_lines)

    try:
        with SSHClient.from_credential(app_guest.ip_address, credential) as ssh:
            # Step 2: Update apt cache
            log("=== Step 2: Updating apt cache ===")
            stdout, stderr, code = ssh.execute_sudo(
                "apt-get update -qq 2>&1", timeout=120
            )
            if code != 0:
                log(f"ERROR: apt-get update failed (exit {code})")
                _log_cmd_output(log, stdout, stderr, code, max_chars=1000)
                return False, "\n".join(log_lines)
            log("apt cache updated")
            log("")

            # Step 3: Upgrade Jitsi packages
            log("=== Step 3: Upgrading Jitsi packages ===")
            log("(This may take several minutes...)")
            packages = " ".join(_JITSI_APT_PACKAGES)
            stdout, stderr, code = ssh.execute_sudo(
                f"DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade {packages} 2>&1",
                timeout=600
            )
            _log_cmd_output(log, stdout, stderr, code, max_chars=4000)
            if code != 0:
                log(f"ERROR: Jitsi upgrade failed (exit {code})")
                return False, "\n".join(log_lines)
            log("Jitsi packages upgraded successfully")
            log("")

            # Step 4: Restart services
            log("=== Step 4: Restarting Jitsi services ===")
            for svc in _JITSI_SERVICES:
                stdout, stderr, code = ssh.execute_sudo(
                    f"systemctl restart {svc} 2>&1", timeout=30
                )
                if code != 0:
                    log(f"  WARNING: {svc} restart returned exit code {code}")
                else:
                    log(f"  {svc} restarted")
            log("")

            # Step 5: Verify services
            log("=== Step 5: Verifying Jitsi services ===")
            # Give services a moment to stabilize
            time.sleep(3)
            all_active = True
            for svc in _JITSI_SERVICES:
                stdout, stderr, code = ssh.execute_sudo(
                    f"systemctl is-active {svc} 2>/dev/null", timeout=10
                )
                svc_status = (stdout or "").strip()
                if svc_status == "active":
                    log(f"  {svc}: active")
                else:
                    log(f"  {svc}: {svc_status or 'unknown'}")
                    all_active = False

            if not all_active:
                log("WARNING: Not all services are active after upgrade")
            log("")

            # Step 6: Detect and persist new version
            log("=== Step 6: Detecting new version ===")
            stdout, stderr, code = ssh.execute_sudo(
                "dpkg -s jitsi-meet 2>/dev/null | grep '^Version:'", timeout=10
            )
            if code == 0 and stdout and stdout.strip():
                version_line = stdout.strip().splitlines()[0]
                version = version_line.replace("Version:", "").strip()
                version = re.sub(r'-\d+$', '', version)
                if version:
                    Setting.set("jitsi_current_version", version)
                    Setting.set("jitsi_update_available", "false")
                    from models import db
                    db.session.commit()
                    log(f"Jitsi Meet is now at v{version}")
                else:
                    log("WARNING: Could not parse version from dpkg output")
            else:
                log("WARNING: Could not detect installed version after upgrade")

            log("")
            ok = all_active
            if ok:
                log("=== Jitsi Meet upgrade complete ===")
            else:
                log("=== Jitsi Meet upgrade finished with warnings ===")
            return ok, "\n".join(log_lines)

    except Exception as e:
        log(f"FATAL ERROR: {e}")
        return False, "\n".join(log_lines)


# ---------------------------------------------------------------------------
# Cloudflare Zero Trust configuration
# ---------------------------------------------------------------------------

def run_cloudflare_configure(log_callback=None):
    """Configure Jitsi Meet for Cloudflare Zero Trust networking.

    TCP-only mode (Option A): Forces all media through TURN/TCP by enabling
    TCP transport in JVB and disabling P2P in the client config.

    Hybrid mode (Option B): Sets NAT harvester addresses so JVB advertises
    the correct public IP for direct UDP media.

    Both modes verify Prosody TURN advertisement and coturn, then restart
    all Jitsi services.

    Returns (ok: bool, log_output: str).
    """
    from models import Credential

    config = _get_jitsi_config()
    log_lines = []

    def log(msg):
        logger.info(msg)
        log_lines.append(msg)
        if log_callback:
            log_callback(msg)

    # --- Validate config ---
    cf_mode = config.get("cf_mode", "none")
    if cf_mode == "none":
        return False, "Cloudflare mode is set to 'none' — nothing to configure"
    if cf_mode not in ("tcp_only", "hybrid"):
        return False, f"Unknown Cloudflare mode: {cf_mode!r}"

    if not config.get("installed"):
        return False, "Jitsi must be installed before configuring Cloudflare"

    err = _require_valid_hostname(config)
    if err:
        return False, err
    hostname = config["hostname"]

    public_ip = config.get("public_ip", "")
    if cf_mode == "hybrid":
        if not public_ip:
            return False, "Public IP is required for hybrid mode"
        if not _IP_RE.match(public_ip):
            return False, f"Public IP '{public_ip}' is not a valid IPv4 address"

    if not config["guest_id"]:
        return False, "Jitsi guest not configured"

    app_guest = Guest.query.get(int(config["guest_id"]))
    if not app_guest:
        return False, "Jitsi guest not found"

    credential = app_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return False, "No SSH credential available"
    if not app_guest.ip_address:
        return False, "Jitsi guest has no IP address"

    guest_ip = app_guest.ip_address
    mode_label = "TCP-only" if cf_mode == "tcp_only" else "Hybrid"

    log("=== Cloudflare Zero Trust Configuration ===")
    log(f"Guest: {app_guest.name} ({guest_ip})")
    log(f"Hostname: {hostname}")
    log(f"Mode: {mode_label}")
    if cf_mode == "hybrid":
        log(f"Public IP: {public_ip}")
    log("")

    warnings = 0

    try:
        with SSHClient.from_credential(guest_ip, credential) as ssh:

            if cf_mode == "tcp_only":
                # --- Option A: Force TCP-only ---
                warnings += _cf_patch_jvb_conf_tcp(ssh, log)
                warnings += _cf_patch_meet_config_js(ssh, hostname, log)
            else:
                # --- Option B: Hybrid (NAT harvester) ---
                warnings += _cf_patch_nat_harvester(ssh, guest_ip, public_ip, log)

            # --- Common: configure coturn TLS (not just verify) ---
            log("")
            warnings += _configure_coturn_tls(ssh, hostname, log)

            # --- Common: configure Prosody TURN advertisement ---
            log("")
            warnings += _configure_prosody_turn(ssh, hostname, log)

            # --- Verify coturn is listening after configuration ---
            _cf_verify_coturn(ssh, log)

            # --- Restart all services ---
            log("")
            log("=== Restarting Jitsi services ===")
            for svc in _JITSI_ALL_SERVICES:
                stdout, stderr, code = ssh.execute_sudo(
                    f"systemctl restart {svc} 2>&1", timeout=30
                )
                if code != 0:
                    log(f"  WARNING: {svc} restart returned exit code {code}")
                    warnings += 1
                else:
                    log(f"  {svc} restarted")

            # Brief stabilization delay
            time.sleep(3)

            # Verify core services
            log("")
            log("=== Verifying services ===")
            for svc in _JITSI_SERVICES:
                stdout, stderr, code = ssh.execute_sudo(
                    f"systemctl is-active {svc} 2>/dev/null", timeout=10
                )
                status = (stdout or "").strip()
                if status == "active":
                    log(f"  {svc}: active")
                else:
                    log(f"  WARNING: {svc}: {status or 'unknown'}")
                    warnings += 1

            log("")
            if warnings:
                log(f"=== Cloudflare configuration FAILED with {warnings} warning(s) ===")
                return False, "\n".join(log_lines)
            log("=== Cloudflare configuration complete ===")
            return True, "\n".join(log_lines)

    except Exception as e:
        log(f"FATAL ERROR: {e}")
        return False, "\n".join(log_lines)


def _enable_jvb_rest_api(ssh, log):
    """Enable the JVB colibri REST API for service monitoring."""
    log("=== Step 11: Enabling JVB REST API for monitoring ===")
    path = "/etc/jitsi/videobridge/jvb.conf"

    stdout, stderr, code = ssh.execute_sudo(f"cat {shlex.quote(path)} 2>/dev/null", timeout=10)
    if code != 0 or not stdout:
        log(f"  WARNING: Could not read {path} — skipping REST API enablement")
        return

    content = stdout

    # Idempotency: check if REST API is already enabled
    if "rest {" in content and "enabled = true" in content:
        log("  [SKIP] REST API already enabled in jvb.conf")
        return

    # Insert apis { rest { enabled = true } } block before last closing brace
    # of the videobridge { } block
    lines = content.split("\n")
    # Find the last } which closes the videobridge block
    insert_idx = None
    for i in range(len(lines) - 1, -1, -1):
        if "}" in lines[i]:
            insert_idx = i
            break

    if insert_idx is None:
        log("  WARNING: Could not find videobridge block boundary — skipping")
        return

    apis_block = (
        "  apis {\n"
        "    rest {\n"
        "      enabled = true\n"
        "    }\n"
        "  }"
    )
    lines.insert(insert_idx, apis_block)
    new_content = "\n".join(lines)

    if _ssh_write_file(ssh, path, new_content, log):
        log("  REST API enabled — restarting jitsi-videobridge2")
        ssh.execute_sudo("systemctl restart jitsi-videobridge2", timeout=30)
        log("  Done")
    else:
        log("  WARNING: Failed to write updated jvb.conf")


def configure_jvb_rest_binding(bind_all=True):
    """Configure JVB REST API to bind to 0.0.0.0 (for Prometheus) or 127.0.0.1 (localhost only).

    Called when the Prometheus scrape toggle changes.  JVB serves /metrics on
    its **private** HTTP server (default 127.0.0.1:8080).  When bind_all=True
    we set ``http-servers.private.host = 0.0.0.0`` so external Prometheus can
    reach it.  When False, reverts to ``127.0.0.1``.

    Returns (success: bool, message: str).
    """
    import re

    ssh, guest, err = _sd_get_ssh()
    if err:
        return False, err

    try:
        path = "/etc/jitsi/videobridge/jvb.conf"
        stdout, stderr, code = ssh.execute_sudo(f"cat {shlex.quote(path)} 2>/dev/null", timeout=10)
        if code != 0 or not stdout:
            return False, f"Could not read {path}"

        content = stdout
        target_host = "0.0.0.0" if bind_all else "127.0.0.1"

        # ---- Idempotency: check private block already has the right host ----
        # Look specifically inside a private { ... } block for the host value
        m = re.search(r'private\s*\{[^}]*host\s*=\s*["\']?([\d.]+)["\']?', content, re.DOTALL)
        if m and m.group(1) == target_host:
            return True, f"JVB REST API already bound to {target_host}"

        # ---- Patch the config ----
        if m:
            # private block exists with a host line — replace the host value
            new_content = content[:m.start(1)] + target_host + content[m.end(1):]
        elif "private" in content and "http-servers" in content:
            # private block exists but has no host line — add one
            new_content = re.sub(
                r'(private\s*\{)',
                rf'\1\n      host = {target_host}',
                content,
            )
        elif "http-servers" in content:
            # http-servers block exists but no private sub-block — add one
            new_content = re.sub(
                r'(http-servers\s*\{)',
                f'\\1\n    private {{\n      host = {target_host}\n    }}',
                content,
            )
        else:
            # No http-servers block at all — insert before last closing brace
            lines = content.split("\n")
            insert_idx = None
            for i in range(len(lines) - 1, -1, -1):
                if "}" in lines[i]:
                    insert_idx = i
                    break
            if insert_idx is None:
                return False, "Could not find videobridge block boundary"

            http_block = (
                "  http-servers {\n"
                "    private {\n"
                f"      host = {target_host}\n"
                "    }\n"
                "  }"
            )
            lines.insert(insert_idx, http_block)
            new_content = "\n".join(lines)

        def _log_noop(msg):
            pass

        if not _ssh_write_file(ssh, path, new_content, _log_noop):
            return False, f"Failed to write {path}"

        # Restart JVB for the change to take effect
        ssh.execute_sudo("systemctl restart jitsi-videobridge2", timeout=30)
        return True, f"JVB REST API now bound to {target_host}, service restarted"
    finally:
        ssh.close()


def _cf_patch_jvb_conf_tcp(ssh, log):
    """Patch jvb.conf to enable TCP transport (Option A). Returns warning count."""
    log("=== Step 1: Enabling TCP transport in jvb.conf ===")
    path = "/etc/jitsi/videobridge/jvb.conf"

    stdout, stderr, code = ssh.execute_sudo(f"cat {shlex.quote(path)} 2>/dev/null", timeout=10)
    if code != 0 or not stdout:
        log(f"  WARNING: Could not read {path}")
        return 1

    content = stdout

    # Idempotency: check if TCP is already enabled
    if "tcp {" in content and "enabled = true" in content:
        log("  [SKIP] TCP transport already enabled in jvb.conf")
        return 0

    # Check if ice { block exists
    if "ice {" in content:
        # Replace existing ice { block with our version
        lines = content.split("\n")
        new_lines = []
        in_ice = False
        brace_depth = 0
        replaced = False
        for line in lines:
            if not in_ice and line.strip().startswith("ice {"):
                in_ice = True
                brace_depth = 1
                replaced = True
                continue
            elif in_ice:
                brace_depth += line.count("{") - line.count("}")
                if brace_depth <= 0:
                    in_ice = False
                continue
            new_lines.append(line)

        if replaced:
            # Insert new ice block before last closing brace of videobridge block
            ice_block = (
                "ice {\n"
                "    udp {\n"
                "        port = 10000\n"
                "    }\n"
                "    tcp {\n"
                "        enabled = true\n"
                "        port = 4443\n"
                "    }\n"
                "}"
            )
            # Find the last } and insert before it
            for i in range(len(new_lines) - 1, -1, -1):
                if "}" in new_lines[i]:
                    new_lines.insert(i, ice_block)
                    break
            content = "\n".join(new_lines)
        else:
            log("  WARNING: Could not find ice { block boundary")
            return 1
    else:
        # No ice block — append before final closing brace
        ice_block = (
            "\nice {\n"
            "    udp {\n"
            "        port = 10000\n"
            "    }\n"
            "    tcp {\n"
            "        enabled = true\n"
            "        port = 4443\n"
            "    }\n"
            "}\n"
        )
        # Insert before last }
        last_brace = content.rfind("}")
        if last_brace >= 0:
            content = content[:last_brace] + ice_block + content[last_brace:]
        else:
            content += ice_block

    if _ssh_write_file(ssh, path, content, log):
        log("  TCP transport enabled in jvb.conf")
        return 0
    return 1


def _cf_patch_meet_config_js(ssh, hostname, log):
    """Patch Jitsi Meet config.js to disable P2P and force WebSocket (Option A).

    Returns warning count.
    """
    log("")
    log("=== Step 2: Patching Jitsi Meet client config ===")
    path = f"/etc/jitsi/meet/{hostname}-config.js"

    stdout, stderr, code = ssh.execute_sudo(f"cat {shlex.quote(path)} 2>/dev/null", timeout=10)
    if code != 0 or not stdout:
        log(f"  WARNING: Could not read {path}")
        return 1

    content = stdout
    modified = False

    if "config.p2p" not in content or "enabled: false" not in content:
        content = content.rstrip() + "\nconfig.p2p = { enabled: false };\n"
        modified = True
        log("  Added: config.p2p = { enabled: false }")
    else:
        log("  [SKIP] config.p2p already disabled")

    if "config.openBridgeChannel" not in content:
        content = content.rstrip() + "\nconfig.openBridgeChannel = 'websocket';\n"
        modified = True
        log("  Added: config.openBridgeChannel = 'websocket'")
    else:
        log("  [SKIP] config.openBridgeChannel already set")

    if modified:
        if not _ssh_write_file(ssh, path, content, log):
            return 1
    return 0


def _cf_patch_nat_harvester(ssh, guest_ip, public_ip, log):
    """Patch sip-communicator.properties with NAT harvester IPs (Option B).

    Returns warning count.
    """
    log("=== Step 1: Configuring NAT Harvester ===")
    path = "/etc/jitsi/videobridge/sip-communicator.properties"

    stdout, stderr, code = ssh.execute_sudo(f"cat {shlex.quote(path)} 2>/dev/null", timeout=10)
    if code != 0:
        log(f"  WARNING: Could not read {path} — file may not exist yet")
        # Create the file with just the harvester config
        content = (
            f"org.ice4j.ice.harvest.NAT_HARVESTER_LOCAL_ADDRESS={guest_ip}\n"
            f"org.ice4j.ice.harvest.NAT_HARVESTER_PUBLIC_ADDRESS={public_ip}\n"
        )
        if _ssh_write_file(ssh, path, content, log):
            log(f"  Created {path} with NAT harvester config")
            return 0
        return 1

    content = stdout
    lines = content.split("\n")
    new_lines = []
    local_set = False
    public_set = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("org.ice4j.ice.harvest.NAT_HARVESTER_LOCAL_ADDRESS="):
            new_lines.append(f"org.ice4j.ice.harvest.NAT_HARVESTER_LOCAL_ADDRESS={guest_ip}")
            local_set = True
        elif stripped.startswith("org.ice4j.ice.harvest.NAT_HARVESTER_PUBLIC_ADDRESS="):
            new_lines.append(f"org.ice4j.ice.harvest.NAT_HARVESTER_PUBLIC_ADDRESS={public_ip}")
            public_set = True
        else:
            new_lines.append(line)

    if not local_set:
        new_lines.append(f"org.ice4j.ice.harvest.NAT_HARVESTER_LOCAL_ADDRESS={guest_ip}")
    if not public_set:
        new_lines.append(f"org.ice4j.ice.harvest.NAT_HARVESTER_PUBLIC_ADDRESS={public_ip}")

    content = "\n".join(new_lines)
    if not content.endswith("\n"):
        content += "\n"

    if _ssh_write_file(ssh, path, content, log):
        log(f"  NAT_HARVESTER_LOCAL_ADDRESS={guest_ip}")
        log(f"  NAT_HARVESTER_PUBLIC_ADDRESS={public_ip}")
        return 0
    return 1


def _cf_verify_prosody_turns(ssh, hostname, log):
    """Verify Prosody has a 'turns' external_services entry (read-only)."""
    log("")
    log("=== Verifying Prosody TURN advertisement ===")
    path = f"/etc/prosody/conf.d/{hostname}.cfg.lua"

    stdout, stderr, code = ssh.execute_sudo(f"cat {shlex.quote(path)} 2>/dev/null", timeout=10)
    if code != 0 or not stdout:
        log(f"  WARNING: Could not read {path}")
        return

    if 'type = "turns"' in stdout and "5349" in stdout:
        log("  [OK] Prosody external_services has turns entry (5349/tcp)")
    else:
        log("  [WARN] Prosody external_services may be missing the 'turns' entry for 5349/tcp")
        log("  Check /etc/prosody/conf.d/ for the external_services block — see setup guide for details")


def _cf_verify_coturn(ssh, log):
    """Verify coturn is listening on port 5349 (read-only)."""
    log("")
    log("=== Verifying coturn TURN relay ===")
    stdout, stderr, code = ssh.execute_sudo(
        "ss -tlnp 'sport = 5349' 2>/dev/null || netstat -tlnp 2>/dev/null | grep 5349",
        timeout=10,
    )
    if code == 0 and stdout and "5349" in stdout:
        log("  [OK] coturn listening on 5349/tcp")
    else:
        log("  [WARN] coturn does not appear to be listening on 5349/tcp")
        log("  Verify /etc/turnserver.conf has tls-listening-port=5349")


# ---------------------------------------------------------------------------
# TURN / NAT configuration helpers (used by both install and CF configure)
# ---------------------------------------------------------------------------

def _configure_coturn_tls(ssh, hostname, log):
    """Ensure coturn has proper TLS configuration for external TURN relay.

    The jitsi-meet-turnserver package installs coturn but may not configure TLS
    on port 5349.  External users behind Cloudflare need TURNS (TLS) to relay
    media.  This function reads /etc/turnserver.conf, ensures key directives
    are present, and restarts coturn if changes were made.

    Returns warning count.
    """
    log("=== Configuring coturn TLS ===")
    path = "/etc/turnserver.conf"

    stdout, stderr, code = ssh.execute_sudo(f"cat {shlex.quote(path)} 2>/dev/null", timeout=10)
    if code != 0 or not stdout:
        log(f"  WARNING: Could not read {path} — coturn may not be installed")
        log("  Install coturn: apt-get install -y coturn")
        return 1

    content = stdout
    modified = False

    # Determine TLS cert paths — Jitsi typically uses its own certs
    cert_path = f"/etc/jitsi/meet/{hostname}.crt"
    key_path = f"/etc/jitsi/meet/{hostname}.key"

    # Check for Let's Encrypt certs (preferred if they exist)
    le_check, _, le_code = ssh.execute_sudo(
        f"test -f {shlex.quote(f'/etc/letsencrypt/live/{hostname}/fullchain.pem')} && echo yes",
        timeout=5,
    )
    if le_code == 0 and "yes" in (le_check or ""):
        cert_path = f"/etc/letsencrypt/live/{hostname}/fullchain.pem"
        key_path = f"/etc/letsencrypt/live/{hostname}/privkey.pem"
        log("  Using Let's Encrypt certs for TURN TLS")

    # Required directives and their values
    required = {
        "tls-listening-port": "5349",
        "cert": cert_path,
        "pkey": key_path,
        "no-multicast-peers": None,  # flag, no value
        "no-cli": None,
        "no-loopback-peers": None,
    }

    lines = content.split("\n")
    existing_keys = set()
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        key = stripped.split("=")[0].strip()
        existing_keys.add(key)

    for key, value in required.items():
        if key not in existing_keys:
            if value is not None:
                lines.append(f"{key}={value}")
            else:
                lines.append(key)
            modified = True
            log(f"  Added: {key}{'=' + value if value else ''}")
        elif key in ("cert", "pkey") and value is not None:
            # Update cert/key paths if they exist but point elsewhere
            new_lines = []
            for line in lines:
                stripped = line.strip()
                if stripped.startswith(f"{key}=") and not stripped.startswith("#"):
                    old_val = stripped.split("=", 1)[1].strip()
                    if old_val != value:
                        new_lines.append(f"{key}={value}")
                        modified = True
                        log(f"  Updated: {key}={value} (was {old_val})")
                    else:
                        new_lines.append(line)
                else:
                    new_lines.append(line)
            lines = new_lines

    # Ensure coturn is enabled (TURNSERVER_ENABLED=1 in /etc/default/coturn)
    ssh.execute_sudo(
        "sed -i 's/^#*TURNSERVER_ENABLED=.*/TURNSERVER_ENABLED=1/' /etc/default/coturn 2>/dev/null || true",
        timeout=5,
    )

    if modified:
        new_content = "\n".join(lines)
        if not new_content.endswith("\n"):
            new_content += "\n"
        if _ssh_write_file(ssh, path, new_content, log):
            log("  coturn TLS configuration updated — restarting coturn")
            ssh.execute_sudo("systemctl restart coturn 2>&1", timeout=30)
        else:
            return 1
    else:
        log("  [SKIP] coturn TLS already configured")

    return 0


def _configure_prosody_turn(ssh, hostname, log):
    """Ensure Prosody advertises TURN/TURNS to Jitsi clients.

    Clients need to know where the TURN server is so they can relay media when
    direct UDP is blocked (e.g., behind Cloudflare Tunnel).  Prosody's
    external_services module advertises this.  This function reads the Prosody
    config, checks for the external_services block, and adds it if missing.

    Returns warning count.
    """
    log("=== Configuring Prosody TURN advertisement ===")
    path = f"/etc/prosody/conf.d/{hostname}.cfg.lua"

    stdout, stderr, code = ssh.execute_sudo(f"cat {shlex.quote(path)} 2>/dev/null", timeout=10)
    if code != 0 or not stdout:
        log(f"  WARNING: Could not read {path}")
        return 1

    content = stdout

    # Check if external_services is already present with turns
    if 'type = "turns"' in content and "5349" in content:
        log("  [SKIP] Prosody external_services already has turns entry")
        return 0

    # Read the TURN secret from the standard Jitsi location
    secret_path = f"/etc/jitsi/meet/{hostname}-oauthl-oauthSecret.key"
    secret_stdout, _, secret_code = ssh.execute_sudo(
        f"cat {shlex.quote(secret_path)} 2>/dev/null", timeout=5
    )
    # Fall back to turnserver.conf static-auth-secret
    if secret_code != 0 or not (secret_stdout or "").strip():
        secret_stdout, _, secret_code = ssh.execute_sudo(
            "grep '^static-auth-secret=' /etc/turnserver.conf 2>/dev/null | head -1 | cut -d= -f2",
            timeout=5,
        )
    turn_secret = (secret_stdout or "").strip()
    if not turn_secret:
        log("  WARNING: Could not find TURN secret — external_services block may need manual configuration")
        log(f"  Checked: {secret_path} and /etc/turnserver.conf static-auth-secret")
        return 1

    # Ensure mod_external_services is loaded
    if "external_services" not in content:
        # Add the modules and external_services block before the last VirtualHost closing
        # Find a good insertion point — after the last modules_enabled block or before Component lines
        ext_block = f'''
-- TURN/TURNS advertisement for external clients (auto-configured)
modules_enabled = {{
    "external_services";
}}
external_services = {{
    {{ type = "turns", transport = "tcp", host = "{hostname}", port = 5349, secret = true, ttl = 86400, algorithm = "turn" }},
    {{ type = "turn", transport = "udp", host = "{hostname}", port = 3478, secret = true, ttl = 86400, algorithm = "turn" }},
}}
turn_external_secret = "{turn_secret}"
turn_external_host = "{hostname}"
turn_external_port = 3478
'''
        # Insert before the first Component line or at end of VirtualHost
        component_idx = content.find('\nComponent "')
        if component_idx >= 0:
            content = content[:component_idx] + ext_block + content[component_idx:]
        else:
            content = content.rstrip() + "\n" + ext_block + "\n"

        if _ssh_write_file(ssh, path, content, log):
            log("  Prosody external_services block added with TURNS on 5349/tcp")
            log("  Restarting prosody")
            ssh.execute_sudo("systemctl restart prosody 2>&1", timeout=30)
        else:
            return 1
    else:
        log("  [SKIP] external_services block exists (may need manual review for turns entry)")

    return 0


def _configure_jvb_nat_harvester(ssh, guest_ip, public_ip, log):
    """Configure JVB NAT harvester so it advertises the correct public IP.

    Without this, JVB sends ICE candidates with the private IP, which external
    users cannot reach for direct UDP media.

    Returns warning count.
    """
    if not public_ip:
        log("  [SKIP] No public IP configured — NAT harvester not set")
        return 0

    if not _IP_RE.match(public_ip):
        log(f"  WARNING: Public IP '{public_ip}' is not a valid IPv4 address — skipping")
        return 1

    log("=== Configuring JVB NAT Harvester ===")
    return _cf_patch_nat_harvester(ssh, guest_ip, public_ip, log)


# ---------------------------------------------------------------------------
# Secure Domain (authenticated room creation)
# ---------------------------------------------------------------------------

# Username regex: alphanumeric, dots, hyphens, underscores — safe for prosodyctl
_SD_USERNAME_RE = re.compile(r'^[a-zA-Z0-9._-]{1,64}$')


def _sd_patch_prosody(ssh, hostname, enable, log):
    """Patch Prosody config to enable or disable secure domain.

    Enable: changes main VirtualHost auth to internal_hashed, adds guest VirtualHost.
    Disable: reverts to jitsi-anonymous, removes guest VirtualHost.

    Returns warning count.
    """
    log("=== Patching Prosody config for secure domain ===")
    path = f"/etc/prosody/conf.d/{hostname}.cfg.lua"

    stdout, stderr, code = ssh.execute_sudo(f"cat {shlex.quote(path)} 2>/dev/null", timeout=10)
    if code != 0 or not stdout:
        log(f"  WARNING: Could not read {path}")
        return 1

    content = stdout

    if enable:
        # --- Enable: internal_hashed + guest VirtualHost ---
        if 'authentication = "internal_hashed"' in content and f'VirtualHost "guest.{hostname}"' in content:
            log("  [SKIP] Secure domain already configured in Prosody")
            return 0

        # Change main VirtualHost authentication
        if 'authentication = "jitsi-anonymous"' in content:
            content = content.replace(
                'authentication = "jitsi-anonymous"',
                'authentication = "internal_hashed"',
                1,  # only first occurrence (main VirtualHost)
            )
            log('  Changed authentication to "internal_hashed"')
        elif 'authentication = "internal_hashed"' in content:
            log("  [SKIP] Authentication already set to internal_hashed")
        else:
            log("  WARNING: Could not find authentication line in Prosody config")
            return 1

        # Add guest VirtualHost if not present
        if f'VirtualHost "guest.{hostname}"' not in content:
            guest_block = f'''
-- Guest domain for unauthenticated participants (auto-configured)
VirtualHost "guest.{hostname}"
    authentication = "jitsi-anonymous"
    modules_enabled = {{
        "turncredentials";
    }}
    c2s_require_encryption = false
'''
            # Insert before first Component line (same pattern as _configure_prosody_turn)
            component_idx = content.find('\nComponent "')
            if component_idx >= 0:
                content = content[:component_idx] + guest_block + content[component_idx:]
            else:
                content = content.rstrip() + "\n" + guest_block + "\n"
            log(f'  Added VirtualHost "guest.{hostname}"')
        else:
            log("  [SKIP] Guest VirtualHost already exists")

    else:
        # --- Disable: revert to jitsi-anonymous, remove guest VirtualHost ---
        if 'authentication = "jitsi-anonymous"' in content and f'VirtualHost "guest.{hostname}"' not in content:
            log("  [SKIP] Secure domain already disabled in Prosody")
            return 0

        if 'authentication = "internal_hashed"' in content:
            content = content.replace(
                'authentication = "internal_hashed"',
                'authentication = "jitsi-anonymous"',
                1,
            )
            log('  Reverted authentication to "jitsi-anonymous"')

        # Remove the guest VirtualHost block
        guest_marker = f'VirtualHost "guest.{hostname}"'
        if guest_marker in content:
            lines = content.split("\n")
            new_lines = []
            skip = False
            # Also skip the comment line before the VirtualHost
            pending_comment = None
            for line in lines:
                if line.strip().startswith("-- Guest domain") and "auto-configured" in line:
                    pending_comment = line
                    continue
                if guest_marker in line:
                    skip = True
                    pending_comment = None
                    continue
                if skip:
                    # Stop skipping at next VirtualHost, Component, or non-indented non-empty line
                    stripped = line.strip()
                    if stripped and not stripped.startswith(("--",)) and not line.startswith((" ", "\t")):
                        skip = False
                        new_lines.append(line)
                    # Skip indented lines and comments within the block
                    continue
                if pending_comment is not None:
                    new_lines.append(pending_comment)
                    pending_comment = None
                new_lines.append(line)
            content = "\n".join(new_lines)
            log(f'  Removed VirtualHost "guest.{hostname}"')

    if _ssh_write_file(ssh, path, content, log):
        return 0
    return 1


def _sd_patch_meet_config_js(ssh, hostname, enable, log):
    """Patch Jitsi Meet config.js for secure domain (anonymousdomain).

    Returns warning count.
    """
    log("")
    log("=== Patching Jitsi Meet config.js for secure domain ===")
    path = f"/etc/jitsi/meet/{hostname}-config.js"

    stdout, stderr, code = ssh.execute_sudo(f"cat {shlex.quote(path)} 2>/dev/null", timeout=10)
    if code != 0 or not stdout:
        log(f"  WARNING: Could not read {path}")
        return 1

    content = stdout

    if enable:
        if "anonymousdomain" in content:
            log("  [SKIP] anonymousdomain already set in config.js")
            return 0
        content = content.rstrip() + f"\nconfig.hosts.anonymousdomain = 'guest.{hostname}';\n"
        log(f"  Added: config.hosts.anonymousdomain = 'guest.{hostname}'")
    else:
        if "anonymousdomain" not in content:
            log("  [SKIP] anonymousdomain not present — nothing to remove")
            return 0
        lines = content.split("\n")
        lines = [ln for ln in lines if "anonymousdomain" not in ln]
        content = "\n".join(lines)
        log("  Removed anonymousdomain from config.js")

    if _ssh_write_file(ssh, path, content, log):
        return 0
    return 1


def _sd_patch_jicofo_conf(ssh, hostname, enable, log):
    """Patch jicofo.conf for secure domain authentication.

    Returns warning count.
    """
    log("")
    log("=== Patching Jicofo config for secure domain ===")
    path = "/etc/jitsi/jicofo/jicofo.conf"

    stdout, stderr, code = ssh.execute_sudo(f"cat {shlex.quote(path)} 2>/dev/null", timeout=10)
    if code != 0 or not stdout:
        log(f"  WARNING: Could not read {path}")
        return 1

    content = stdout

    if enable:
        if "authentication {" in content and "login-url" in content:
            log("  [SKIP] Jicofo authentication block already present")
            return 0

        auth_block = (
            "  authentication {\n"
            "    enabled = true\n"
            "    type = \"XMPP\"\n"
            f"    login-url = \"{hostname}\"\n"
            "  }"
        )

        # Insert inside the jicofo { } block, before its closing brace
        lines = content.split("\n")
        # Find last } that closes the jicofo block
        insert_idx = None
        for i in range(len(lines) - 1, -1, -1):
            if "}" in lines[i]:
                insert_idx = i
                break

        if insert_idx is None:
            log("  WARNING: Could not find jicofo block boundary — skipping")
            return 1

        lines.insert(insert_idx, auth_block)
        content = "\n".join(lines)
        log("  Added authentication block to jicofo.conf")

    else:
        if "authentication {" not in content:
            log("  [SKIP] No authentication block in jicofo.conf — nothing to remove")
            return 0

        # Remove the authentication { ... } block
        lines = content.split("\n")
        new_lines = []
        skip = False
        brace_depth = 0
        for line in lines:
            if not skip and line.strip().startswith("authentication {"):
                skip = True
                brace_depth = 1
                continue
            if skip:
                brace_depth += line.count("{") - line.count("}")
                if brace_depth <= 0:
                    skip = False
                continue
            new_lines.append(line)
        content = "\n".join(new_lines)
        log("  Removed authentication block from jicofo.conf")

    if _ssh_write_file(ssh, path, content, log):
        return 0
    return 1


def run_secure_domain_configure(log_callback=None):
    """Enable or disable Jitsi Secure Domain via SSH.

    Mirrors run_cloudflare_configure: validates config, SSHes in, patches
    Prosody/Jicofo/Meet configs, restarts services, verifies health.

    Returns (success: bool, log_output: str).
    """
    from models import Credential

    config = _get_jitsi_config()
    log_lines = []

    def log(msg):
        logger.info(msg)
        log_lines.append(msg)
        if log_callback:
            log_callback(msg)

    if not config.get("installed"):
        return False, "Jitsi must be installed before configuring Secure Domain"

    err = _require_valid_hostname(config)
    if err:
        return False, err
    hostname = config["hostname"]

    if not config["guest_id"]:
        return False, "Jitsi guest not configured"

    app_guest = Guest.query.get(int(config["guest_id"]))
    if not app_guest:
        return False, "Jitsi guest not found"

    credential = app_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return False, "No SSH credential available"
    if not app_guest.ip_address:
        return False, "Jitsi guest has no IP address"

    enable = config.get("secure_domain", False)
    action = "Enabling" if enable else "Disabling"

    log(f"=== {action} Jitsi Secure Domain ===")
    log(f"Guest: {app_guest.name} ({app_guest.ip_address})")
    log(f"Hostname: {hostname}")
    log("")

    warnings = 0

    try:
        with SSHClient.from_credential(app_guest.ip_address, credential) as ssh:
            warnings += _sd_patch_prosody(ssh, hostname, enable, log)
            warnings += _sd_patch_meet_config_js(ssh, hostname, enable, log)
            warnings += _sd_patch_jicofo_conf(ssh, hostname, enable, log)

            # Restart services
            log("")
            log("=== Restarting Jitsi services ===")
            for svc in _JITSI_SERVICES:
                stdout, stderr, code = ssh.execute_sudo(
                    f"systemctl restart {svc} 2>&1", timeout=30
                )
                if code != 0:
                    log(f"  WARNING: {svc} restart returned exit code {code}")
                    warnings += 1
                else:
                    log(f"  {svc} restarted")

            time.sleep(3)

            # Verify services
            log("")
            log("=== Verifying services ===")
            for svc in _JITSI_SERVICES:
                stdout, stderr, code = ssh.execute_sudo(
                    f"systemctl is-active {svc} 2>/dev/null", timeout=10
                )
                status = (stdout or "").strip()
                if status == "active":
                    log(f"  {svc}: active")
                else:
                    log(f"  WARNING: {svc}: {status or 'unknown'}")
                    warnings += 1

            log("")
            if warnings:
                log(f"=== Secure Domain configuration FAILED with {warnings} warning(s) ===")
                return False, "\n".join(log_lines)
            log(f"=== Secure Domain {action.lower().replace('ing', 'ed')} successfully ===")
            return True, "\n".join(log_lines)

    except Exception as e:
        log(f"FATAL ERROR: {e}")
        return False, "\n".join(log_lines)


def _sd_get_ssh(config=None):
    """Open an SSH connection to the Jitsi guest. Returns (ssh, guest, error)."""
    from models import Credential

    if config is None:
        config = _get_jitsi_config()

    if not config.get("guest_id"):
        return None, None, "Jitsi guest not configured"

    guest = Guest.query.get(int(config["guest_id"]))
    if not guest:
        return None, None, "Jitsi guest not found"
    if not guest.ip_address:
        return None, None, "Jitsi guest has no IP address"

    credential = guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return None, None, "No SSH credential available"

    try:
        ssh = SSHClient.from_credential(guest.ip_address, credential)
        return ssh, guest, None
    except Exception as e:
        logger.warning(f"Could not open SSH session to Jitsi guest {guest.name}: {e}")
        return None, None, f"SSH connection failed: {describe_exception(e)}"


def sd_list_users():
    """List Prosody user accounts for the Jitsi hostname.

    Returns (users_list, error_message).
    """
    config = _get_jitsi_config()
    err = _require_valid_hostname(config)
    if err:
        return [], err
    hostname = config["hostname"]

    ssh, guest, err = _sd_get_ssh(config)
    if err:
        return [], err

    # Prosody encodes dots as %2e in its data directory
    encoded_host = hostname.replace(".", "%2e")
    accounts_dir = shlex.quote(f"/var/lib/prosody/{encoded_host}/accounts/")
    try:
        with ssh:
            stdout, stderr, code = ssh.execute_sudo(
                f"ls {accounts_dir} 2>/dev/null",
                timeout=10,
            )
            if code != 0 or not stdout:
                return [], None  # No users or directory doesn't exist
            users = [f.replace(".dat", "") for f in stdout.strip().split("\n") if f.strip().endswith(".dat")]
            return users, None
    except Exception as e:
        logger.warning(f"Listing Prosody users on {guest.name} failed: {e}")
        return [], describe_exception(e)


def sd_add_user(username, password):
    """Register a Prosody user account for the Jitsi hostname.

    Returns (success, message).
    """
    if not username or not _SD_USERNAME_RE.match(username):
        return False, "Invalid username (alphanumeric, dots, hyphens, underscores only; max 64 chars)"
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters"

    config = _get_jitsi_config()
    err = _require_valid_hostname(config)
    if err:
        return False, err
    hostname = config["hostname"]

    ssh, guest, err = _sd_get_ssh(config)
    if err:
        return False, err

    try:
        _validate_shell_param(username, "username")
    except ValueError as e:
        return False, str(e)

    # Pass password via base64-decoded positional argument to prosodyctl register.
    # We use base64 to avoid shell quoting issues with special characters.
    pw_b64 = base64.b64encode(password.encode("utf-8")).decode("ascii")
    try:
        with ssh:
            stdout, stderr, code = ssh.execute_sudo(
                f"prosodyctl register {username} {hostname} \"$(printf '%s' '{pw_b64}' | base64 -d)\"",
                timeout=15,
            )
            if code != 0:
                err_msg = (stderr or stdout or "").strip()
                if "user already exists" in err_msg.lower():
                    return False, f"User '{username}' already exists"
                return False, f"Failed to register user: {err_msg}"
            return True, f"User '{username}' registered successfully"
    except Exception as e:
        logger.warning(f"Registering Prosody user on {guest.name} failed: {e}")
        return False, describe_exception(e)


def sd_remove_user(username):
    """Delete a Prosody user account for the Jitsi hostname.

    Returns (success, message).
    """
    if not username or not _SD_USERNAME_RE.match(username):
        return False, "Invalid username"

    config = _get_jitsi_config()
    err = _require_valid_hostname(config)
    if err:
        return False, err
    hostname = config["hostname"]

    ssh, guest, err = _sd_get_ssh(config)
    if err:
        return False, err

    try:
        _validate_shell_param(username, "username")
    except ValueError as e:
        return False, str(e)

    try:
        with ssh:
            stdout, stderr, code = ssh.execute_sudo(
                f"prosodyctl deluser {username}@{hostname}",
                timeout=15,
            )
            if code != 0:
                err_msg = (stderr or stdout or "").strip()
                return False, f"Failed to delete user: {err_msg}"
            return True, f"User '{username}' deleted successfully"
    except Exception as e:
        logger.warning(f"Deleting Prosody user on {guest.name} failed: {e}")
        return False, describe_exception(e)
