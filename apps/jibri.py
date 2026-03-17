"""
Jibri (Jitsi Broadcasting Infrastructure) recording and streaming automation.

Provisions a bare Ubuntu 24.04 VM into a Jibri instance, configures the Jitsi
Meet server to enable recording/streaming, manages SMB storage mounts, and
provides on-demand recording and RTMP streaming control via the Jibri REST API.
"""

import base64
import logging
import re
import secrets
import time
import uuid

from apps.backup import backup_guest, snapshot_guest
from apps.utils import _log_cmd_output, _validate_shell_param
from clients.proxmox_api import ProxmoxClient
from clients.ssh_client import SSHClient
from models import Guest, Setting

logger = logging.getLogger(__name__)

# IPv4 address validation
_IP_RE = re.compile(r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')

# Hostname validation: FQDN pattern
_HOSTNAME_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')

# SMB share path validation: //server/share or //server/share/subfolder
_SMB_PATH_RE = re.compile(r'^//[a-zA-Z0-9.\-]+/[\w.\-/]+$')

# Filename validation for recordings (prevent path traversal)
_SAFE_FILENAME_RE = re.compile(r'^[\w.\-]+$')


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def _get_jibri_config():
    """Read all Jibri-related settings plus relevant Jitsi settings.

    Note: Passwords/secrets are intentionally excluded to prevent accidental
    logging.  Callers that need credentials should read them directly from
    Setting.get() at the point of use.
    """
    return {
        "guest_id": Setting.get("jibri_guest_id", ""),
        "installed": Setting.get("jibri_installed", "false") == "true",
        "enabled": Setting.get("jibri_enabled", "false") == "true",
        "recording_dir": Setting.get("jibri_recording_dir", "/srv/recordings"),
        "smb_share": Setting.get("jibri_smb_share", ""),
        "smb_username": Setting.get("jibri_smb_username", ""),
        "smb_configured": Setting.get("jibri_smb_configured", "false") == "true",
        "protection_type": Setting.get("jibri_protection_type", "snapshot"),
        "backup_storage": Setting.get("jibri_backup_storage", ""),
        "backup_mode": Setting.get("jibri_backup_mode", "snapshot"),
        # Jitsi settings needed for XMPP configuration
        "jitsi_guest_id": Setting.get("jitsi_guest_id", ""),
        "jitsi_hostname": Setting.get("jitsi_hostname", ""),
        "jitsi_installed": Setting.get("jitsi_installed", "false") == "true",
    }


def _ssh_write_file(ssh, path, content, log):
    """Write content to a remote file via base64 pipe.

    Uses base64 encoding to avoid heredoc quoting issues with special
    characters in config file content.  Returns True on success.
    """
    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
    stdout, stderr, code = ssh.execute_sudo(
        f"printf '%s' '{encoded}' | base64 -d | tee {path} > /dev/null",
        timeout=15,
    )
    if code != 0:
        log(f"  ERROR: Could not write {path} (exit {code})")
        _log_cmd_output(log, stdout, stderr, code, max_chars=500)
        return False
    return True


def _run_protection(config, app_guest, log, skip_protection=False):
    """Run snapshot or backup protection on the Jibri guest.

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
        ok, msg = backup_guest(app_guest, backup_storage, "jibri", mode=backup_mode)
        log(f"Backup {app_guest.name}: {msg}")
        if not ok:
            return False
    else:
        log("=== Step 1: Creating Proxmox snapshot ===")
        ok, msg = snapshot_guest(app_guest, "jibri")
        log(f"Snapshot {app_guest.name}: {msg}")
        if not ok:
            return False

    log("")
    return True


# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

def run_jibri_preflight(log_callback=None):
    """Run read-only pre-flight checks before Jibri install.

    Validates configuration, Proxmox guest status (must be VM, not LXC),
    SSH connectivity, kernel module availability, and OS version.

    Returns (all_pass: bool, log_output: str).
    """
    from models import Credential

    config = _get_jibri_config()
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

    log("=== Jibri Pre-flight Check ===")
    log("")

    # ── A. Configuration ──────────────────────────────────────────────────────
    log("--- A. Configuration ---")

    config_ok = True
    guest_id = config.get("guest_id", "")
    if guest_id:
        check("Jibri guest configured", True)
    else:
        check("Jibri guest configured", False, "not set in settings")
        config_ok = False

    # Jitsi must be installed for Jibri to connect
    if config.get("jitsi_installed"):
        check("Jitsi Meet installed", True)
    else:
        check("Jitsi Meet installed", False,
              "Jitsi must be installed before setting up Jibri")
        config_ok = False

    jitsi_hostname = config.get("jitsi_hostname", "")
    if jitsi_hostname:
        check("Jitsi hostname configured", True)
    else:
        check("Jitsi hostname configured", False,
              "Jitsi hostname must be set for XMPP connection")
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
    check("Jibri guest in database", app_guest is not None,
          f"guest ID {config['guest_id']} not found")

    if not app_guest:
        log("")
        log(f"=== Pre-flight complete: {checks_passed}/{checks_total} checks passed — "
            f"{checks_failed} failure(s), blocked ===")
        return False, "\n".join(log_lines)

    # Jibri requires a VM (not LXC) for snd-aloop kernel module
    if app_guest.guest_type == "vm":
        check("Guest is a VM (required for snd-aloop)", True)
    else:
        check("Guest is a VM (required for snd-aloop)", False,
              f"guest type is '{app_guest.guest_type}' — Jibri requires a full VM for "
              "the snd-aloop kernel module")

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

    # ── C. SSH checks on Jibri VM ─────────────────────────────────────────────
    log("")
    log(f"--- C. SSH checks on {app_guest.name} ---")

    credential = app_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()

    if not credential:
        check("SSH credential available", False,
              "no credential configured for Jibri guest or as default")
    elif not app_guest.ip_address:
        check("SSH credential available", True)
        check("Jibri guest IP configured", False, "no IP address set on guest")
    else:
        check("SSH credential available", True)
        check("Jibri guest IP configured", True)
        try:
            with SSHClient.from_credential(app_guest.ip_address, credential) as ssh:
                check("SSH connection established", True)

                installed = config.get("installed", False)

                # Check OS version
                stdout, stderr, code = ssh.execute_sudo(
                    "lsb_release -si 2>/dev/null", timeout=10
                )
                distro = (stdout or "").strip()
                if distro in ("Ubuntu", "Debian"):
                    check(f"OS is {distro}", True)
                    # Check version
                    stdout, stderr, code = ssh.execute_sudo(
                        "lsb_release -rs 2>/dev/null", timeout=10
                    )
                    os_version = (stdout or "").strip()
                    if os_version:
                        log(f"  [INFO] OS version: {distro} {os_version}")
                elif distro:
                    check("OS is Ubuntu/Debian", False,
                          f"detected {distro} — Jibri requires Ubuntu or Debian")
                else:
                    log("  [WARN] Could not determine OS distribution")

                # Check if VM (not container) from inside
                stdout, stderr, code = ssh.execute_sudo(
                    "systemd-detect-virt --vm 2>/dev/null || echo unknown", timeout=10
                )
                virt_type = (stdout or "").strip()
                if virt_type and virt_type != "none":
                    log(f"  [INFO] Virtualization type: {virt_type}")

                # Check snd-aloop module availability
                stdout, stderr, code = ssh.execute_sudo(
                    "modprobe --dry-run snd-aloop 2>&1", timeout=10
                )
                if code == 0:
                    check("snd-aloop kernel module available", True)
                else:
                    check("snd-aloop kernel module available", False,
                          "install linux-modules-extra-$(uname -r) or linux-image-extra-virtual")

                if installed:
                    # Check jibri service
                    stdout, stderr, code = ssh.execute_sudo(
                        "systemctl is-active jibri 2>/dev/null", timeout=10
                    )
                    svc_status = (stdout or "").strip()
                    if svc_status == "active":
                        log("  [INFO] jibri service is active")
                    elif svc_status:
                        log(f"  [WARN] jibri service status: {svc_status}")
                    else:
                        log("  [WARN] Could not determine jibri service status")

                    # Check Jibri health API
                    stdout, stderr, code = ssh.execute_sudo(
                        "curl -s http://localhost:2222/jibri/api/v1.0/health 2>/dev/null",
                        timeout=10
                    )
                    if code == 0 and stdout:
                        log(f"  [INFO] Jibri health: {stdout.strip()[:200]}")

                else:
                    # Fresh install check: verify jibri NOT already installed
                    stdout, stderr, code = ssh.execute_sudo(
                        "dpkg -s jibri 2>/dev/null | grep '^Status:.*installed'",
                        timeout=10
                    )
                    if code == 0 and "installed" in (stdout or ""):
                        check("Jibri not yet installed", False,
                              "jibri package is already installed")
                    else:
                        check("Jibri not yet installed", True)

                # Check Cloudflare Zero Trust warning
                cf_mode = Setting.get("jitsi_cf_mode", "none")
                if cf_mode != "none":
                    log(f"  [WARN] Cloudflare Zero Trust is enabled (mode: {cf_mode})")
                    log("  [WARN] Ensure Jibri VM has direct network access to "
                        "Jitsi Meet server's internal IP on port 5222 (XMPP)")

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
# Install — provision bare Ubuntu 24.04 VM into Jibri instance
# ---------------------------------------------------------------------------

def run_jibri_install(log_callback=None):
    """Install Jibri on a bare Ubuntu 24.04 VM.

    Provisions the VM with all prerequisites (Java, Chrome, FFmpeg, snd-aloop),
    installs the Jibri package, generates XMPP credentials, and writes the
    Jibri configuration.

    Returns (ok: bool, log_output: str).
    """
    from models import Credential

    config = _get_jibri_config()
    log_lines = []

    def log(msg):
        logger.info(msg)
        log_lines.append(msg)
        if log_callback:
            log_callback(msg)

    # Validate config
    if not config["guest_id"]:
        return False, "Jibri guest not configured"

    app_guest = Guest.query.get(int(config["guest_id"]))
    if not app_guest:
        return False, "Jibri guest not found"

    if app_guest.guest_type != "vm":
        return False, "Jibri requires a VM (not LXC) for the snd-aloop kernel module"

    jitsi_hostname = config.get("jitsi_hostname", "")
    if not jitsi_hostname:
        return False, "Jitsi hostname not configured"

    if not config.get("jitsi_installed"):
        return False, "Jitsi Meet must be installed first"

    # Get Jitsi guest IP for XMPP connection
    jitsi_guest_id = config.get("jitsi_guest_id", "")
    jitsi_guest = Guest.query.get(int(jitsi_guest_id)) if jitsi_guest_id else None
    if not jitsi_guest or not jitsi_guest.ip_address:
        return False, "Jitsi guest IP address not available"
    jitsi_ip = jitsi_guest.ip_address

    try:
        _validate_shell_param(jitsi_hostname, "Jitsi hostname")
    except ValueError as e:
        return False, str(e)

    credential = app_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return False, "No SSH credential available"
    if not app_guest.ip_address:
        return False, "Jibri guest has no IP address"

    log("=== Jibri Installation ===")
    log(f"Jibri VM: {app_guest.name} ({app_guest.ip_address})")
    log(f"Jitsi server: {jitsi_hostname} ({jitsi_ip})")
    log("")

    # Step 1: Protection
    if not _run_protection(config, app_guest, log):
        return False, "\n".join(log_lines)

    try:
        with SSHClient.from_credential(app_guest.ip_address, credential) as ssh:
            # Phase A: Verify OS
            log("=== Phase A: Verifying OS ===")
            stdout, stderr, code = ssh.execute_sudo(
                "lsb_release -rs 2>/dev/null", timeout=10
            )
            os_version = (stdout or "").strip()
            log(f"OS version: {os_version}")

            stdout, stderr, code = ssh.execute_sudo(
                "lsb_release -si 2>/dev/null", timeout=10
            )
            distro = (stdout or "").strip()
            if distro not in ("Ubuntu", "Debian"):
                log(f"ERROR: Unsupported OS: {distro}. Jibri requires Ubuntu or Debian.")
                return False, "\n".join(log_lines)
            log(f"Distro: {distro} {os_version}")
            log("")

            # Phase B: System prerequisites
            log("=== Phase B: System prerequisites ===")
            log("Updating package lists...")
            stdout, stderr, code = ssh.execute_sudo(
                "apt-get update -qq 2>&1", timeout=120
            )
            if code != 0:
                log(f"ERROR: apt-get update failed (exit {code})")
                _log_cmd_output(log, stdout, stderr, code, max_chars=1000)
                return False, "\n".join(log_lines)

            log("Installing base packages...")
            stdout, stderr, code = ssh.execute_sudo(
                "DEBIAN_FRONTEND=noninteractive apt-get install -y "
                "curl gnupg2 software-properties-common apt-transport-https 2>&1",
                timeout=120
            )
            if code != 0:
                log(f"ERROR: Base package install failed (exit {code})")
                _log_cmd_output(log, stdout, stderr, code, max_chars=1000)
                return False, "\n".join(log_lines)
            log("Base packages installed")

            # Install kernel extras for snd-aloop
            log("Installing kernel extras for ALSA loopback...")
            stdout, stderr, code = ssh.execute_sudo(
                "DEBIAN_FRONTEND=noninteractive apt-get install -y "
                "linux-modules-extra-$(uname -r) 2>&1 || "
                "DEBIAN_FRONTEND=noninteractive apt-get install -y "
                "linux-image-extra-virtual 2>&1",
                timeout=300
            )
            if code != 0:
                log(f"WARNING: Kernel extras install may have failed (exit {code})")
                _log_cmd_output(log, stdout, stderr, code, max_chars=500)

            # Load snd-aloop
            log("Loading snd-aloop kernel module...")
            ssh.execute_sudo("modprobe snd-aloop 2>&1", timeout=10)

            # Persist module
            stdout, stderr, code = ssh.execute_sudo(
                "grep -q snd-aloop /etc/modules 2>/dev/null || "
                "echo snd-aloop >> /etc/modules",
                timeout=10
            )
            # Also add modprobe.d config for number of loopback devices
            _ssh_write_file(ssh, "/etc/modprobe.d/alsa-loopback.conf",
                            "options snd-aloop enable=1,1,1,1,1 index=0,1,2,3,4\n", log)

            # Verify module loaded
            stdout, stderr, code = ssh.execute_sudo(
                "lsmod | grep snd_aloop", timeout=10
            )
            if code == 0:
                log("snd-aloop module loaded successfully")
            else:
                log("WARNING: snd-aloop module may not be loaded (may need reboot)")
            log("")

            # Phase C: Install Java
            log("=== Phase C: Installing Java ===")
            stdout, stderr, code = ssh.execute_sudo(
                "DEBIAN_FRONTEND=noninteractive apt-get install -y "
                "openjdk-17-jre-headless 2>&1",
                timeout=300
            )
            if code != 0:
                log(f"ERROR: Java install failed (exit {code})")
                _log_cmd_output(log, stdout, stderr, code, max_chars=1000)
                return False, "\n".join(log_lines)
            stdout, stderr, code = ssh.execute_sudo(
                "java -version 2>&1", timeout=10
            )
            log(f"Java: {(stdout or stderr or '').strip()[:100]}")
            log("")

            # Phase D: Install headless Chrome
            log("=== Phase D: Installing headless Chrome ===")
            # Add Google Chrome repo
            stdout, stderr, code = ssh.execute_sudo(
                "curl -fsSL https://dl.google.com/linux/linux_signing_key.pub "
                "| gpg --dearmor -o /etc/apt/keyrings/google-chrome.gpg --yes 2>&1",
                timeout=30
            )
            if code != 0:
                log(f"WARNING: Chrome key import may have failed (exit {code})")

            stdout, stderr, code = ssh.execute_sudo(
                'echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/google-chrome.gpg] '
                'http://dl.google.com/linux/chrome/deb/ stable main" '
                "> /etc/apt/sources.list.d/google-chrome.list",
                timeout=10
            )

            stdout, stderr, code = ssh.execute_sudo(
                "apt-get update -qq 2>&1", timeout=60
            )

            stdout, stderr, code = ssh.execute_sudo(
                "DEBIAN_FRONTEND=noninteractive apt-get install -y "
                "google-chrome-stable 2>&1",
                timeout=300
            )
            if code != 0:
                log(f"WARNING: Chrome install failed (exit {code}), trying chromium...")
                _log_cmd_output(log, stdout, stderr, code, max_chars=500)
                stdout, stderr, code = ssh.execute_sudo(
                    "DEBIAN_FRONTEND=noninteractive apt-get install -y "
                    "chromium-browser 2>&1",
                    timeout=300
                )
                if code != 0:
                    log(f"ERROR: Neither Chrome nor Chromium could be installed (exit {code})")
                    _log_cmd_output(log, stdout, stderr, code, max_chars=1000)
                    return False, "\n".join(log_lines)
                log("Chromium installed as fallback")
            else:
                log("Google Chrome installed")

            # Create Chrome managed policy
            ssh.execute_sudo(
                "mkdir -p /etc/opt/chrome/policies/managed", timeout=10
            )
            _ssh_write_file(
                ssh,
                "/etc/opt/chrome/policies/managed/managed_policies.json",
                '{"CommandLineFlagSecurityWarningsEnabled": false}\n',
                log
            )

            # Also create Chromium policy directory
            ssh.execute_sudo(
                "mkdir -p /etc/chromium/policies/managed", timeout=10
            )
            _ssh_write_file(
                ssh,
                "/etc/chromium/policies/managed/managed_policies.json",
                '{"CommandLineFlagSecurityWarningsEnabled": false}\n',
                log
            )
            log("")

            # Phase E: Install FFmpeg & ALSA utils
            log("=== Phase E: Installing FFmpeg & ALSA utils ===")
            stdout, stderr, code = ssh.execute_sudo(
                "DEBIAN_FRONTEND=noninteractive apt-get install -y "
                "ffmpeg alsa-utils 2>&1",
                timeout=120
            )
            if code != 0:
                log(f"ERROR: FFmpeg/ALSA install failed (exit {code})")
                _log_cmd_output(log, stdout, stderr, code, max_chars=1000)
                return False, "\n".join(log_lines)
            log("FFmpeg and ALSA utils installed")
            log("")

            # Phase F: Install Jibri package
            log("=== Phase F: Installing Jibri package ===")

            # Add Jitsi apt repository
            stdout, stderr, code = ssh.execute_sudo(
                "curl -fsSL https://download.jitsi.org/jitsi-key.gpg.key "
                "| gpg --dearmor -o /etc/apt/keyrings/jitsi-keyring.gpg --yes 2>&1",
                timeout=30
            )
            if code != 0:
                log(f"WARNING: Could not add Jitsi keyring (exit {code})")
                _log_cmd_output(log, stdout, stderr, code, max_chars=500)

            stdout, stderr, code = ssh.execute_sudo(
                'echo "deb [signed-by=/etc/apt/keyrings/jitsi-keyring.gpg] '
                'https://download.jitsi.org stable/" '
                "> /etc/apt/sources.list.d/jitsi-stable.list",
                timeout=10
            )
            if code != 0:
                log(f"WARNING: Could not add Jitsi repository (exit {code})")

            stdout, stderr, code = ssh.execute_sudo(
                "apt-get update -qq 2>&1", timeout=60
            )
            if code != 0:
                log(f"ERROR: apt-get update failed (exit {code})")
                _log_cmd_output(log, stdout, stderr, code, max_chars=1000)
                return False, "\n".join(log_lines)

            log("Installing jibri package (this may take several minutes)...")
            stdout, stderr, code = ssh.execute_sudo(
                "DEBIAN_FRONTEND=noninteractive apt-get install -y jibri 2>&1",
                timeout=600
            )
            _log_cmd_output(log, stdout, stderr, code, max_chars=4000)
            if code != 0:
                log(f"ERROR: jibri installation failed (exit {code})")
                return False, "\n".join(log_lines)
            log("jibri package installed")

            # Add jibri user to required groups
            ssh.execute_sudo(
                "usermod -aG adm,audio,video,plugdev jibri 2>&1",
                timeout=10
            )
            log("jibri user added to groups (adm, audio, video, plugdev)")
            log("")

            # Phase G: Generate XMPP credentials
            log("=== Phase G: Generating XMPP credentials ===")
            xmpp_password = Setting.get("jibri_xmpp_password", "") or secrets.token_urlsafe(32)
            recorder_password = Setting.get("jibri_recorder_password", "") or secrets.token_urlsafe(32)
            Setting.set("jibri_xmpp_password", xmpp_password)
            Setting.set("jibri_recorder_password", recorder_password)
            log("XMPP credentials generated and stored")
            log("")

            # Phase H: Write Jibri config
            log("=== Phase H: Writing Jibri configuration ===")
            recording_dir = config.get("recording_dir", "/srv/recordings")
            jibri_nickname = f"jibri-{uuid.uuid4().hex[:8]}"

            jibri_conf = f"""jibri {{
  recording {{
    recordings-directory = "{recording_dir}"
    finalize-script = ""
  }}
  streaming {{
    rtmp-allow-list = [".*"]
  }}
  api {{
    xmpp {{
      environments = [{{
        name = "prod"
        xmpp-server-hosts = ["{jitsi_ip}"]
        xmpp-domain = "{jitsi_hostname}"
        control-muc {{
          domain = "internal.auth.{jitsi_hostname}"
          room-name = "JibriBrewery"
          nickname = "{jibri_nickname}"
        }}
        control-login {{
          domain = "auth.{jitsi_hostname}"
          username = "jibri"
          password = "{xmpp_password}"
        }}
        call-login {{
          domain = "recorder.{jitsi_hostname}"
          username = "recorder"
          password = "{recorder_password}"
        }}
        strip-from-room-domain = "conference."
        usage-timeout = 0
        trust-all-xmpp-certs = true
      }}]
    }}
  }}
  chrome {{
    flags = [
      "--use-fake-ui-for-media-stream",
      "--start-maximized",
      "--kiosk",
      "--enabled",
      "--autoplay-policy=no-user-gesture-required"
    ]
  }}
}}
"""
            ssh.execute_sudo(f"mkdir -p {recording_dir}", timeout=10)
            ssh.execute_sudo(f"chown jibri:jibri {recording_dir}", timeout=10)

            if not _ssh_write_file(ssh, "/etc/jitsi/jibri/jibri.conf", jibri_conf, log):
                return False, "\n".join(log_lines)
            log("Jibri configuration written to /etc/jitsi/jibri/jibri.conf")
            log("")

            # Phase I: Start & verify
            log("=== Phase I: Starting Jibri service ===")
            ssh.execute_sudo("systemctl enable jibri 2>&1", timeout=15)
            ssh.execute_sudo("systemctl restart jibri 2>&1", timeout=30)

            log("Waiting for Jibri to start...")
            time.sleep(5)

            stdout, stderr, code = ssh.execute_sudo(
                "systemctl is-active jibri 2>/dev/null", timeout=10
            )
            svc_status = (stdout or "").strip()
            if svc_status == "active":
                log("jibri service is active")
            else:
                log(f"WARNING: jibri service status: {svc_status}")
                stdout, stderr, code = ssh.execute_sudo(
                    "journalctl -u jibri --no-pager -n 30 2>&1", timeout=15
                )
                _log_cmd_output(log, stdout, stderr, code, max_chars=2000)

            # Check health API
            stdout, stderr, code = ssh.execute_sudo(
                "curl -s http://localhost:2222/jibri/api/v1.0/health 2>/dev/null",
                timeout=10
            )
            if code == 0 and stdout:
                log(f"Jibri health: {stdout.strip()[:200]}")
            else:
                log("WARNING: Could not reach Jibri health API (may still be starting)")

            Setting.set("jibri_installed", "true")
            log("")
            log("=== Jibri installation complete ===")

    except Exception as e:
        log(f"FATAL ERROR: {e}")
        return False, "\n".join(log_lines)

    return True, "\n".join(log_lines)


# ---------------------------------------------------------------------------
# Jitsi server-side configuration for recording/streaming
# ---------------------------------------------------------------------------

def run_jibri_jitsi_configure(log_callback=None):
    """Configure the Jitsi Meet server to enable Jibri recording and streaming.

    Patches Prosody, Jicofo, and Jitsi Meet config on the Jitsi server.
    Returns (ok: bool, log_output: str).
    """
    from models import Credential

    config = _get_jibri_config()
    log_lines = []

    def log(msg):
        logger.info(msg)
        log_lines.append(msg)
        if log_callback:
            log_callback(msg)

    if not config.get("jitsi_installed"):
        return False, "Jitsi Meet must be installed first"
    if not config.get("installed"):
        return False, "Jibri must be installed first"

    jitsi_hostname = config.get("jitsi_hostname", "")
    if not jitsi_hostname:
        return False, "Jitsi hostname not configured"

    xmpp_password = Setting.get("jibri_xmpp_password", "")
    recorder_password = Setting.get("jibri_recorder_password", "")
    if not xmpp_password or not recorder_password:
        return False, "XMPP credentials not generated — run Jibri install first"

    jitsi_guest_id = config.get("jitsi_guest_id", "")
    jitsi_guest = Guest.query.get(int(jitsi_guest_id)) if jitsi_guest_id else None
    if not jitsi_guest or not jitsi_guest.ip_address:
        return False, "Jitsi guest not available"

    credential = jitsi_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return False, "No SSH credential for Jitsi guest"

    log("=== Configuring Jitsi Meet server for Jibri ===")
    log(f"Jitsi server: {jitsi_hostname} ({jitsi_guest.ip_address})")
    log("")

    try:
        with SSHClient.from_credential(jitsi_guest.ip_address, credential) as ssh:
            # Step 1: Patch Prosody — add Jibri component and recorder VirtualHost
            log("--- Step 1: Patching Prosody configuration ---")
            prosody_conf_path = f"/etc/prosody/conf.avail/{jitsi_hostname}.cfg.lua"

            # Check if Jibri config already exists
            stdout, stderr, code = ssh.execute_sudo(
                f"grep -c 'recorder.{jitsi_hostname}' {prosody_conf_path} 2>/dev/null",
                timeout=10
            )
            if code == 0 and stdout and int(stdout.strip()) > 0:
                log("  Prosody already has Jibri configuration — skipping patch")
            else:
                # Append Jibri configuration to Prosody
                jibri_prosody = f"""

-- Jibri recording/streaming configuration
Component "internal.auth.{jitsi_hostname}" "muc"
    modules_enabled = {{
        "muc_hide_all";
    }}
    storage = "memory"
    admins = {{ "focus@auth.{jitsi_hostname}", "jibri@auth.{jitsi_hostname}" }}

VirtualHost "recorder.{jitsi_hostname}"
    modules_enabled = {{
        "ping";
    }}
    authentication = "internal_hashed"
"""
                # Append Jibri config directly to Prosody via base64 pipe
                encoded = base64.b64encode(jibri_prosody.encode("utf-8")).decode("ascii")
                stdout, stderr, code = ssh.execute_sudo(
                    f"printf '%s' '{encoded}' | base64 -d >> {prosody_conf_path}",
                    timeout=15
                )
                if code != 0:
                    log(f"ERROR: Failed to patch Prosody config (exit {code})")
                    _log_cmd_output(log, stdout, stderr, code, max_chars=500)
                    return False, "\n".join(log_lines)
                log("  Prosody configuration patched")

            # Register XMPP accounts (passwords passed via base64 to avoid shell exposure)
            log("  Registering XMPP accounts...")
            xmpp_pw_b64 = base64.b64encode(xmpp_password.encode("utf-8")).decode("ascii")
            recorder_pw_b64 = base64.b64encode(recorder_password.encode("utf-8")).decode("ascii")
            ssh.execute_sudo(
                f"prosodyctl register jibri auth.{jitsi_hostname} "
                f"\"$(printf '%s' '{xmpp_pw_b64}' | base64 -d)\" 2>&1",
                timeout=15
            )
            ssh.execute_sudo(
                f"prosodyctl register recorder recorder.{jitsi_hostname} "
                f"\"$(printf '%s' '{recorder_pw_b64}' | base64 -d)\" 2>&1",
                timeout=15
            )
            log("  XMPP accounts registered (jibri@auth, recorder@recorder)")
            log("")

            # Step 2: Patch Jicofo config
            log("--- Step 2: Patching Jicofo configuration ---")
            jicofo_conf_path = "/etc/jitsi/jicofo/jicofo.conf"

            stdout, stderr, code = ssh.execute_sudo(
                f"grep -c 'JibriBrewery' {jicofo_conf_path} 2>/dev/null",
                timeout=10
            )
            if code == 0 and stdout and int(stdout.strip()) > 0:
                log("  Jicofo already has Jibri configuration — skipping patch")
            else:
                # Read current jicofo.conf and inject jibri section into jicofo block
                stdout, stderr, code = ssh.execute_sudo(
                    f"cat {jicofo_conf_path} 2>/dev/null", timeout=10
                )
                if code != 0 or not stdout:
                    log("ERROR: Could not read Jicofo config")
                    return False, "\n".join(log_lines)

                jicofo_content = stdout
                jibri_jicofo = f"""
  jibri {{
    brewery-jid = "JibriBrewery@internal.auth.{jitsi_hostname}"
    pending-timeout = 90 seconds
  }}"""

                # Insert before last closing brace of jicofo block
                if "jicofo {" in jicofo_content:
                    # Find the last } and insert before it
                    last_brace = jicofo_content.rfind("}")
                    if last_brace > 0:
                        jicofo_content = (
                            jicofo_content[:last_brace] +
                            jibri_jicofo + "\n" +
                            jicofo_content[last_brace:]
                        )

                if not _ssh_write_file(ssh, jicofo_conf_path, jicofo_content, log):
                    return False, "\n".join(log_lines)
                log("  Jicofo configuration patched")
            log("")

            # Step 3: Patch Jitsi Meet config.js
            log("--- Step 3: Patching Jitsi Meet config.js ---")
            meet_conf_path = f"/etc/jitsi/meet/{jitsi_hostname}-config.js"

            # Enable recording service
            stdout, stderr, code = ssh.execute_sudo(
                f"grep -c 'recordingService' {meet_conf_path} 2>/dev/null",
                timeout=10
            )
            # Use sed to enable/add recording and streaming config
            ssh.execute_sudo(
                f"grep -q 'fileRecordingsEnabled' {meet_conf_path} 2>/dev/null && "
                f"sed -i 's/.*fileRecordingsEnabled.*/    fileRecordingsEnabled: true,/' "
                f"{meet_conf_path} || "
                f"sed -i '/^var config/a\\    fileRecordingsEnabled: true,' "
                f"{meet_conf_path}",
                timeout=15
            )
            ssh.execute_sudo(
                f"grep -q 'liveStreamingEnabled' {meet_conf_path} 2>/dev/null && "
                f"sed -i 's/.*liveStreamingEnabled.*/    liveStreamingEnabled: true,/' "
                f"{meet_conf_path} || "
                f"sed -i '/^var config/a\\    liveStreamingEnabled: true,' "
                f"{meet_conf_path}",
                timeout=15
            )
            ssh.execute_sudo(
                f"grep -q 'hiddenDomain' {meet_conf_path} 2>/dev/null && "
                f"sed -i \"s/.*hiddenDomain.*/    hiddenDomain: 'recorder.{jitsi_hostname}',/\" "
                f"{meet_conf_path} || "
                f"sed -i \"/^var config/a\\    hiddenDomain: 'recorder.{jitsi_hostname}',\" "
                f"{meet_conf_path}",
                timeout=15
            )
            log("  Jitsi Meet config.js patched")
            log("")

            # Step 4: Restart services
            log("--- Step 4: Restarting Jitsi services ---")
            for svc in ["prosody", "jicofo", "jitsi-videobridge2"]:
                stdout, stderr, code = ssh.execute_sudo(
                    f"systemctl restart {svc} 2>&1", timeout=30
                )
                if code != 0:
                    log(f"  WARNING: {svc} restart may have failed (exit {code})")
                else:
                    log(f"  {svc} restarted")

            time.sleep(3)

            # Verify services
            log("")
            log("--- Step 5: Verifying services ---")
            for svc in ["prosody", "jicofo", "jitsi-videobridge2"]:
                stdout, stderr, code = ssh.execute_sudo(
                    f"systemctl is-active {svc} 2>/dev/null", timeout=10
                )
                svc_status = (stdout or "").strip()
                if svc_status == "active":
                    log(f"  {svc}: active")
                else:
                    log(f"  WARNING: {svc} status: {svc_status}")

            Setting.set("jibri_enabled", "true")
            log("")
            log("=== Jitsi server configuration for Jibri complete ===")

    except Exception as e:
        log(f"FATAL ERROR: {e}")
        return False, "\n".join(log_lines)

    return True, "\n".join(log_lines)


# ---------------------------------------------------------------------------
# SMB mount configuration
# ---------------------------------------------------------------------------

def configure_smb_mount(log_callback=None):
    """Configure SMB/CIFS mount on the Jibri VM for recording storage.

    Returns (ok: bool, log_output: str).
    """
    from models import Credential

    config = _get_jibri_config()
    log_lines = []

    def log(msg):
        logger.info(msg)
        log_lines.append(msg)
        if log_callback:
            log_callback(msg)

    if not config.get("installed"):
        return False, "Jibri must be installed first"

    smb_share = config.get("smb_share", "")
    smb_username = config.get("smb_username", "")
    smb_password = Setting.get("jibri_smb_password", "")
    recording_dir = config.get("recording_dir", "/srv/recordings")

    if not smb_share:
        return False, "SMB share path not configured"
    if not _SMB_PATH_RE.match(smb_share):
        return False, f"Invalid SMB share path: {smb_share}"
    if not smb_username:
        return False, "SMB username not configured"

    app_guest = Guest.query.get(int(config["guest_id"]))
    if not app_guest:
        return False, "Jibri guest not found"

    credential = app_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return False, "No SSH credential available"

    log("=== Configuring SMB mount ===")
    log(f"Share: {smb_share}")
    log(f"Mount point: {recording_dir}")
    log("")

    try:
        with SSHClient.from_credential(app_guest.ip_address, credential) as ssh:
            # Install cifs-utils
            log("Installing cifs-utils...")
            stdout, stderr, code = ssh.execute_sudo(
                "DEBIAN_FRONTEND=noninteractive apt-get install -y cifs-utils 2>&1",
                timeout=60
            )
            if code != 0:
                log(f"ERROR: cifs-utils install failed (exit {code})")
                _log_cmd_output(log, stdout, stderr, code, max_chars=500)
                return False, "\n".join(log_lines)

            # Create mount point
            ssh.execute_sudo(f"mkdir -p {recording_dir}", timeout=10)

            # Write SMB credentials file
            log("Writing SMB credentials...")
            smb_creds_content = f"username={smb_username}\npassword={smb_password}\n"
            if not _ssh_write_file(ssh, "/etc/jibri/.smbcredentials", smb_creds_content, log):
                return False, "\n".join(log_lines)
            ssh.execute_sudo("chmod 600 /etc/jibri/.smbcredentials", timeout=10)
            ssh.execute_sudo("chown root:root /etc/jibri/.smbcredentials", timeout=10)

            # Get jibri user UID/GID
            stdout, stderr, code = ssh.execute_sudo(
                "id -u jibri 2>/dev/null", timeout=10
            )
            jibri_uid = (stdout or "").strip() or "location"
            stdout, stderr, code = ssh.execute_sudo(
                "id -g jibri 2>/dev/null", timeout=10
            )
            jibri_gid = (stdout or "").strip() or "location"

            # Remove existing fstab entry if present
            ssh.execute_sudo(
                f"sed -i '\\|{recording_dir}|d' /etc/fstab 2>/dev/null",
                timeout=10
            )

            # Add fstab entry
            fstab_entry = (
                f"{smb_share} {recording_dir} cifs "
                f"credentials=/etc/jibri/.smbcredentials,"
                f"uid={jibri_uid},gid={jibri_gid},"
                f"file_mode=0775,dir_mode=0775,"
                f"_netdev,nofail 0 0"
            )
            stdout, stderr, code = ssh.execute_sudo(
                f"echo '{fstab_entry}' >> /etc/fstab",
                timeout=10
            )
            log("fstab entry added")

            # Mount the share
            log("Mounting SMB share...")
            stdout, stderr, code = ssh.execute_sudo(
                f"mount {recording_dir} 2>&1",
                timeout=30
            )
            if code != 0:
                log(f"ERROR: Mount failed (exit {code})")
                _log_cmd_output(log, stdout, stderr, code, max_chars=500)
                return False, "\n".join(log_lines)

            # Verify writable
            stdout, stderr, code = ssh.execute_sudo(
                f"sudo -u jibri touch {recording_dir}/.mcat_test 2>&1 && "
                f"rm -f {recording_dir}/.mcat_test",
                timeout=10
            )
            if code == 0:
                log("SMB share mounted and writable by jibri user")
            else:
                log("WARNING: SMB share mounted but may not be writable by jibri user")

            Setting.set("jibri_smb_configured", "true")
            log("")
            log("=== SMB mount configuration complete ===")

    except Exception as e:
        log(f"FATAL ERROR: {e}")
        return False, "\n".join(log_lines)

    return True, "\n".join(log_lines)


# ---------------------------------------------------------------------------
# On-demand recording control
# ---------------------------------------------------------------------------

def start_recording(room_name):
    """Start recording a Jitsi conference room via Jibri XMPP/REST.

    Triggers Jibri to join the specified room as a hidden participant and begin
    recording. Uses the Jibri REST API on the Jibri VM.

    Returns (ok: bool, message: str).
    """
    from models import Credential

    config = _get_jibri_config()

    if not config.get("installed"):
        return False, "Jibri is not installed"
    if not config.get("enabled"):
        return False, "Jibri is not enabled on the Jitsi server"
    if not room_name or not room_name.strip():
        return False, "Room name is required"

    room_name = room_name.strip().lower()

    app_guest = Guest.query.get(int(config["guest_id"]))
    if not app_guest or not app_guest.ip_address:
        return False, "Jibri guest not available"

    credential = app_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return False, "No SSH credential available"

    jitsi_hostname = config.get("jitsi_hostname", "")

    try:
        with SSHClient.from_credential(app_guest.ip_address, credential) as ssh:
            # Check Jibri is idle
            stdout, stderr, code = ssh.execute_sudo(
                "curl -s http://localhost:2222/jibri/api/v1.0/health 2>/dev/null",
                timeout=10
            )
            if code != 0:
                return False, "Cannot reach Jibri health API"

            health = (stdout or "").strip()
            if '"IDLE"' not in health.upper():
                return False, f"Jibri is not idle: {health[:200]}"

            # Start recording via REST API
            import json
            start_payload = json.dumps({
                "sessionId": f"recording-{uuid.uuid4().hex[:12]}",
                "mode": "FILE",
                "meetUrl": f"https://{jitsi_hostname}/{room_name}",
                "token": "",
            })

            encoded_payload = base64.b64encode(start_payload.encode()).decode("ascii")
            stdout, stderr, code = ssh.execute_sudo(
                f"printf '%s' '{encoded_payload}' | base64 -d | "
                "curl -s -X POST -H 'Content-Type: application/json' "
                "-d @- http://localhost:2222/jibri/api/v1.0/startService 2>/dev/null",
                timeout=30
            )
            if code != 0:
                return False, f"Failed to start recording (exit {code})"

            return True, f"Recording started for room '{room_name}'"

    except Exception:
        logger.exception("Error starting recording")
        return False, "Error starting recording — check server logs for details"


def stop_recording():
    """Stop the current Jibri recording.

    Returns (ok: bool, message: str).
    """
    from models import Credential

    config = _get_jibri_config()

    if not config.get("installed"):
        return False, "Jibri is not installed"

    app_guest = Guest.query.get(int(config["guest_id"]))
    if not app_guest or not app_guest.ip_address:
        return False, "Jibri guest not available"

    credential = app_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return False, "No SSH credential available"

    try:
        with SSHClient.from_credential(app_guest.ip_address, credential) as ssh:
            stdout, stderr, code = ssh.execute_sudo(
                "curl -s -X POST http://localhost:2222/jibri/api/v1.0/stopService 2>/dev/null",
                timeout=30
            )
            if code != 0:
                return False, f"Failed to stop recording (exit {code})"

            return True, "Recording stopped"

    except Exception:
        logger.exception("Error stopping recording")
        return False, "Error stopping recording — check server logs for details"


# ---------------------------------------------------------------------------
# RTMP streaming control
# ---------------------------------------------------------------------------

def start_streaming(room_name, rtmp_url, stream_key):
    """Start RTMP live streaming of a Jitsi conference room.

    Returns (ok: bool, message: str).
    """
    from models import Credential

    config = _get_jibri_config()

    if not config.get("installed"):
        return False, "Jibri is not installed"
    if not config.get("enabled"):
        return False, "Jibri is not enabled on the Jitsi server"
    if not room_name or not room_name.strip():
        return False, "Room name is required"
    if not rtmp_url or not rtmp_url.strip():
        return False, "RTMP URL is required"

    room_name = room_name.strip().lower()
    rtmp_url = rtmp_url.strip().rstrip("/")
    stream_key = (stream_key or "").strip()

    full_rtmp = f"{rtmp_url}/{stream_key}" if stream_key else rtmp_url

    app_guest = Guest.query.get(int(config["guest_id"]))
    if not app_guest or not app_guest.ip_address:
        return False, "Jibri guest not available"

    credential = app_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return False, "No SSH credential available"

    jitsi_hostname = config.get("jitsi_hostname", "")

    try:
        with SSHClient.from_credential(app_guest.ip_address, credential) as ssh:
            # Check Jibri is idle
            stdout, stderr, code = ssh.execute_sudo(
                "curl -s http://localhost:2222/jibri/api/v1.0/health 2>/dev/null",
                timeout=10
            )
            if code != 0:
                return False, "Cannot reach Jibri health API"

            health = (stdout or "").strip()
            if '"IDLE"' not in health.upper():
                return False, f"Jibri is not idle: {health[:200]}"

            # Start streaming via REST API
            import json
            start_payload = json.dumps({
                "sessionId": f"stream-{uuid.uuid4().hex[:12]}",
                "mode": "STREAM",
                "meetUrl": f"https://{jitsi_hostname}/{room_name}",
                "token": "",
                "youTubeStreamKey": full_rtmp,
            })

            encoded_payload = base64.b64encode(start_payload.encode()).decode("ascii")
            stdout, stderr, code = ssh.execute_sudo(
                f"printf '%s' '{encoded_payload}' | base64 -d | "
                "curl -s -X POST -H 'Content-Type: application/json' "
                "-d @- http://localhost:2222/jibri/api/v1.0/startService 2>/dev/null",
                timeout=30
            )
            if code != 0:
                return False, f"Failed to start streaming (exit {code})"

            return True, f"Streaming started for room '{room_name}'"

    except Exception:
        logger.exception("Error starting stream")
        return False, "Error starting stream — check server logs for details"


def stop_streaming():
    """Stop the current Jibri RTMP stream.

    Returns (ok: bool, message: str).
    """
    # Jibri uses the same stop endpoint for both recording and streaming
    return stop_recording()


# ---------------------------------------------------------------------------
# Jibri status
# ---------------------------------------------------------------------------

def check_jibri_status():
    """Check Jibri service status and availability.

    Returns a dict: {"status": "idle|busy|unhealthy", "service": "running|stopped|failed",
                     "health": <raw health JSON string>}.
    """
    from models import Credential

    config = _get_jibri_config()
    result = {"status": "unhealthy", "service": "unknown", "health": ""}

    if not config.get("installed"):
        result["service"] = "not_installed"
        return result

    guest_id = config.get("guest_id", "")
    if not guest_id:
        return result

    try:
        app_guest = Guest.query.get(int(guest_id))
    except (TypeError, ValueError):
        return result
    if not app_guest or not app_guest.ip_address:
        return result

    credential = app_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return result

    try:
        with SSHClient.from_credential(app_guest.ip_address, credential) as ssh:
            # Check systemd service
            stdout, stderr, code = ssh.execute_sudo(
                "systemctl is-active jibri 2>/dev/null", timeout=10
            )
            result["service"] = (stdout or "").strip() or "unknown"

            # Check health API
            stdout, stderr, code = ssh.execute_sudo(
                "curl -s http://localhost:2222/jibri/api/v1.0/health 2>/dev/null",
                timeout=10
            )
            if code == 0 and stdout:
                result["health"] = stdout.strip()
                health_upper = stdout.upper()
                if '"IDLE"' in health_upper:
                    result["status"] = "idle"
                elif '"BUSY"' in health_upper:
                    result["status"] = "busy"
                else:
                    result["status"] = "unhealthy"
    except Exception:
        pass

    return result


# ---------------------------------------------------------------------------
# Recording management
# ---------------------------------------------------------------------------

def list_recordings():
    """List recording files on the Jibri VM.

    Returns (recordings: list[dict], error: str|None).
    Each dict has: filename, size_bytes, created_at.
    """
    from models import Credential

    config = _get_jibri_config()

    if not config.get("installed"):
        return [], "Jibri is not installed"

    app_guest = Guest.query.get(int(config["guest_id"]))
    if not app_guest or not app_guest.ip_address:
        return [], "Jibri guest not available"

    credential = app_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return [], "No SSH credential available"

    recording_dir = config.get("recording_dir", "/srv/recordings")

    try:
        with SSHClient.from_credential(app_guest.ip_address, credential) as ssh:
            # List files with size and timestamp
            stdout, stderr, code = ssh.execute_sudo(
                f"find {recording_dir} -maxdepth 2 -type f "
                r"-name '*.mp4' -o -name '*.mkv' -o -name '*.webm' "
                "2>/dev/null | "
                "xargs -r stat --format='%n|%s|%Y' 2>/dev/null | "
                "sort -t'|' -k3 -rn",
                timeout=30
            )

            recordings = []
            if code == 0 and stdout:
                for line in stdout.strip().splitlines():
                    parts = line.split("|")
                    if len(parts) == 3:
                        filepath = parts[0]
                        filename = filepath.replace(recording_dir + "/", "", 1)
                        recordings.append({
                            "filename": filename,
                            "size_bytes": int(parts[1]) if parts[1].isdigit() else 0,
                            "created_at": int(parts[2]) if parts[2].isdigit() else 0,
                        })

            return recordings, None

    except Exception:
        logger.exception("Error listing recordings")
        return [], "Error listing recordings — check server logs for details"


def delete_recording(filename):
    """Delete a recording file on the Jibri VM.

    Validates filename to prevent path traversal.
    Returns (ok: bool, message: str).
    """
    from models import Credential

    if not filename:
        return False, "Filename is required"

    # Prevent path traversal — allow subdirectory but no ..
    if ".." in filename or filename.startswith("/"):
        return False, "Invalid filename"

    config = _get_jibri_config()

    if not config.get("installed"):
        return False, "Jibri is not installed"

    app_guest = Guest.query.get(int(config["guest_id"]))
    if not app_guest or not app_guest.ip_address:
        return False, "Jibri guest not available"

    credential = app_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return False, "No SSH credential available"

    recording_dir = config.get("recording_dir", "/srv/recordings")
    full_path = f"{recording_dir}/{filename}"

    try:
        with SSHClient.from_credential(app_guest.ip_address, credential) as ssh:
            # Verify file exists
            stdout, stderr, code = ssh.execute_sudo(
                f"test -f '{full_path}' && echo exists", timeout=10
            )
            if code != 0 or "exists" not in (stdout or ""):
                return False, "Recording file not found"

            stdout, stderr, code = ssh.execute_sudo(
                f"rm -f '{full_path}' 2>&1", timeout=10
            )
            if code != 0:
                return False, f"Failed to delete recording (exit {code})"

            return True, f"Recording '{filename}' deleted"

    except Exception:
        logger.exception("Error deleting recording")
        return False, "Error deleting recording — check server logs for details"
