"""
Elk (Mastodon web client) install and upgrade automation.

Checks the GitHub API for new Elk releases, takes a Proxmox snapshot or
vzdump backup of the guest, then installs or upgrades Elk via SSH.
Supports both Docker Compose and bare-metal (Node.js/pnpm) deployments.
"""

import json
import logging
import re
import time
from urllib.request import Request, urlopen

from apps.backup import backup_guest, snapshot_guest

# Shared shell-safety and output helpers from the Mastodon module
from apps.utils import (
    _log_cmd_output,
    _remote_write_cmd,
    _validate_abs_path,
    _validate_http_url,
    _validate_username,
    _version_gt,
)
from clients.proxmox_api import ProxmoxClient
from clients.ssh_client import SSHClient
from models import Guest, Setting

logger = logging.getLogger(__name__)

_ELK_GITHUB_API = "https://api.github.com/repos/elk-zone/elk/releases/latest"
_ELK_RELEASE_BASE = "https://github.com/elk-zone/elk/releases/tag/{tag}"

_ELK_SYSTEMD_UNIT = """\
[Unit]
Description=Elk Mastodon Web Client
After=network.target

[Service]
Type=simple
User={user}
WorkingDirectory={elk_dir}
ExecStart=/usr/bin/node .output/server/index.mjs
Restart=on-failure
Environment=PORT=5314
EnvironmentFile={elk_dir}/.env

[Install]
WantedBy=multi-user.target
"""


# ---------------------------------------------------------------------------
# Version check
# ---------------------------------------------------------------------------

def check_elk_release():
    """Check GitHub for the latest Elk release.

    Returns (update_available, latest_version, release_url).
    """
    try:
        req = Request(_ELK_GITHUB_API, headers={"User-Agent": "mstdnca-proxmox-tool"})
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())

        tag = data.get("tag_name", "")
        if not tag:
            return False, "", ""

        latest = tag.lstrip("vV")
        release_url = _ELK_RELEASE_BASE.format(tag=tag)

        Setting.set("elk_latest_version", latest)
        Setting.set("elk_latest_release_url", release_url)

        current = Setting.get("elk_current_version", "")
        update_available = bool(current and _version_gt(latest, current))
        Setting.set("elk_update_available", "true" if update_available else "false")

        return update_available, latest, release_url
    except Exception as e:
        logger.error("Failed to check Elk releases: %s", e)
        return False, "", ""


# ---------------------------------------------------------------------------
# Proxmox protection helpers
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Internal config helper
# ---------------------------------------------------------------------------

def _get_elk_config():
    """Read all Elk-related settings."""
    return {
        "guest_id": Setting.get("elk_guest_id", ""),
        "user": Setting.get("elk_user", "elk"),
        "elk_dir": Setting.get("elk_dir", "/opt/elk"),
        "url": Setting.get("elk_url", ""),
        "instance_url": Setting.get("elk_instance_url", ""),
        "deploy_method": Setting.get("elk_deploy_method", "docker"),
        "current_version": Setting.get("elk_current_version", ""),
        "latest_version": Setting.get("elk_latest_version", ""),
        "protection_type": Setting.get("elk_protection_type", "snapshot"),
        "backup_storage": Setting.get("elk_backup_storage", ""),
        "backup_mode": Setting.get("elk_backup_mode", "snapshot"),
        "auto_upgrade": Setting.get("elk_auto_upgrade", "false") == "true",
        "installed": Setting.get("elk_installed", "false") == "true",
    }


# ---------------------------------------------------------------------------
# Version detection
# ---------------------------------------------------------------------------

def detect_elk_version(guest, elk_dir, deploy_method="docker"):
    """Detect the installed Elk version via SSH.

    Reads the package.json version field from the Elk directory.

    Returns (version_string, None) on success, or (None, error_message) on failure.
    """
    from models import Credential

    try:
        _validate_abs_path(elk_dir, "Elk dir")
    except ValueError as e:
        return None, str(e)

    credential = guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return None, "No SSH credential configured for this guest"
    if not guest.ip_address:
        return None, "No IP address set on the Elk guest"

    try:
        with SSHClient.from_credential(guest.ip_address, credential) as ssh:
            # Pre-check: verify the configured directory exists
            stdout, stderr, code = ssh.execute_sudo(
                f"test -d {elk_dir} && echo ok", timeout=10
            )
            if not (code == 0 and "ok" in (stdout or "")):
                return None, f"Directory '{elk_dir}' does not exist on the guest"

            # Method 1: Read package.json version field
            py_cmd = (
                f"python3 -c \"import json; "
                f"print(json.load(open('{elk_dir}/package.json'))['version'])\" "
                f"2>/dev/null"
            )
            stdout, stderr, code = ssh.execute_sudo(py_cmd, timeout=10)
            if code == 0 and stdout.strip():
                v = stdout.strip().splitlines()[0].strip()
                if re.match(r'^\d+\.\d+', v):
                    return v, None

            pkg_err = (stderr or stdout or "").strip()

            # Method 2: For Docker, try reading from the running container
            if deploy_method == "docker":
                stdout, stderr, code = ssh.execute_sudo(
                    f"docker compose -f {elk_dir}/docker-compose.yml exec -T elk "
                    f"cat /elk/package.json 2>/dev/null",
                    timeout=15,
                )
                if code == 0 and stdout.strip():
                    try:
                        v = json.loads(stdout.strip()).get("version", "")
                        if re.match(r'^\d+\.\d+', v):
                            return v, None
                    except (json.JSONDecodeError, AttributeError):
                        pass

            errors = "; ".join(filter(None, [
                f"package.json: {pkg_err[:100]}" if pkg_err else None,
            ]))
            return None, f"All detection methods failed — {errors}" if errors else "All detection methods returned no output"

    except Exception as e:
        logger.warning("Could not detect Elk version: %s", e)
        return None, str(e)


# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

def run_elk_preflight(log_callback=None):
    """Run read-only pre-flight checks before Elk install or upgrade.

    Validates configuration, Proxmox guest status, SSH connectivity,
    and deployment prerequisites (Docker or Node.js/pnpm).

    Returns (all_pass: bool, log_output: str).
    """
    from models import Credential

    config = _get_elk_config()
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

    log("=== Elk Pre-flight Check ===")
    log("")

    # ── A. Configuration ──────────────────────────────────────────────────────
    log("--- A. Configuration ---")

    config_ok = True
    for field, label in [
        ("guest_id", "Elk guest"),
        ("elk_dir", "Elk directory"),
    ]:
        val = config.get(field, "")
        if val:
            check(f"{label} configured", True)
        else:
            check(f"{label} configured", False, "not set in settings")
            config_ok = False

    deploy_method = config.get("deploy_method", "docker")
    if deploy_method in ("docker", "bare-metal"):
        check(f"Deploy method valid ({deploy_method})", True)
    else:
        check("Deploy method valid", False, f"unknown method: {deploy_method}")
        config_ok = False

    instance_url = config.get("instance_url", "")
    if instance_url:
        check("Mastodon instance URL configured", True)
    else:
        log("  [WARN] No Mastodon instance URL configured — Elk will prompt users to enter one")

    protection_type = config.get("protection_type", "snapshot")
    backup_storage = config.get("backup_storage", "")
    if protection_type == "backup":
        if backup_storage:
            check("Backup storage configured", True)
        else:
            check("Backup storage configured", False, "backup protection selected but no storage configured")
            config_ok = False

    elk_dir = config.get("elk_dir", "/opt/elk")
    user = config.get("user", "elk")

    try:
        _validate_abs_path(elk_dir, "Elk dir")
        if deploy_method == "bare-metal":
            _validate_username(user, "Elk user")
        if instance_url:
            _validate_http_url(instance_url, "Mastodon instance URL")
        check("Shell-safe config values", True)
    except ValueError as e:
        check("Shell-safe config values", False, str(e))
        config_ok = False

    if not config_ok:
        log("")
        log(f"=== Pre-flight complete: {checks_passed}/{checks_total} checks passed — "
            f"{checks_failed} failure(s), upgrade blocked ===")
        return False, "\n".join(log_lines)

    # ── B. Proxmox guest status ───────────────────────────────────────────────
    log("")
    log("--- B. Proxmox guests ---")

    app_guest = Guest.query.get(int(config["guest_id"]))
    check("Elk guest in database", app_guest is not None,
          f"guest ID {config['guest_id']} not found")

    if not app_guest:
        log("")
        log(f"=== Pre-flight complete: {checks_passed}/{checks_total} checks passed — "
            f"{checks_failed} failure(s), upgrade blocked ===")
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

    # ── C. SSH checks on app guest ────────────────────────────────────────────
    log("")
    log(f"--- C. SSH checks on {app_guest.name} ---")

    credential = app_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()

    if not credential:
        check("SSH credential available", False,
              "no credential configured for Elk guest or as default")
    elif not app_guest.ip_address:
        check("SSH credential available", True)
        check("Elk guest IP configured", False, "no IP address set on guest")
    else:
        check("SSH credential available", True)
        check("Elk guest IP configured", True)
        try:
            with SSHClient.from_credential(app_guest.ip_address, credential) as ssh:
                check("SSH connection established", True)

                installed = config.get("installed", False)

                # If already installed, check directory exists
                if installed:
                    stdout, stderr, code = ssh.execute_sudo(
                        f"test -d {elk_dir} && echo ok", timeout=10
                    )
                    check(f"Elk directory {elk_dir} exists",
                          code == 0 and "ok" in (stdout or ""),
                          "directory not found")

                # Check deployment prerequisites
                if deploy_method == "docker":
                    # Docker available
                    stdout, stderr, code = ssh.execute_sudo(
                        "docker --version 2>/dev/null", timeout=10
                    )
                    check("Docker installed",
                          code == 0 and "Docker" in (stdout or ""),
                          "docker command not found")

                    # Docker Compose available
                    stdout, stderr, code = ssh.execute_sudo(
                        "docker compose version 2>/dev/null", timeout=10
                    )
                    check("Docker Compose available",
                          code == 0 and stdout and stdout.strip(),
                          "docker compose not found")

                    # If installed, check container status
                    if installed:
                        stdout, stderr, code = ssh.execute_sudo(
                            f"docker compose -f {elk_dir}/docker-compose.yml ps "
                            f"--format '{{{{.State}}}}' 2>/dev/null",
                            timeout=15,
                        )
                        container_state = (stdout or "").strip()
                        if container_state:
                            log(f"  [INFO] Docker container state: {container_state}")
                        else:
                            log("  [WARN] Could not determine Docker container state")
                else:
                    # Node.js version — informational for fresh installs
                    # (the install process will install Node.js if missing)
                    stdout, stderr, code = ssh.execute_sudo(
                        "node --version 2>/dev/null", timeout=10
                    )
                    if code == 0 and stdout.strip():
                        m = re.search(r'v?(\d+\.\d+\.\d+)', stdout.strip())
                        node_ver = m.group(1) if m else stdout.strip()
                        log(f"  [INFO] Node.js {node_ver} installed")
                    elif installed:
                        check("Node.js installed", False, "node command not found")
                    else:
                        log("  [INFO] Node.js not found — will be installed during install")

                    # corepack — informational for fresh installs
                    stdout, stderr, code = ssh.execute_sudo(
                        "corepack --version 2>/dev/null", timeout=10
                    )
                    if code == 0 and stdout and stdout.strip():
                        log(f"  [INFO] corepack {stdout.strip()} available")
                    elif installed:
                        check("corepack available", False,
                              "corepack not found — run 'npm install -g corepack' or upgrade Node.js")
                    else:
                        log("  [INFO] corepack not found — will be installed during install")

                    # git — required for clone/pull
                    stdout, stderr, code = ssh.execute_sudo(
                        "git --version 2>/dev/null", timeout=10
                    )
                    if code == 0 and stdout and stdout.strip():
                        log(f"  [INFO] {stdout.strip()}")
                    elif installed:
                        log("  [WARN] git not found")
                    else:
                        log("  [INFO] git not found — will be installed during install")

                    # If installed, check service status
                    if installed:
                        stdout, stderr, code = ssh.execute_sudo(
                            "systemctl is-active elk 2>/dev/null", timeout=10
                        )
                        service_status = (stdout or "").strip()
                        if service_status == "active":
                            log("  [INFO] Elk service (elk) is active")
                        elif service_status:
                            log(f"  [WARN] Elk service (elk) status: {service_status}")
                        else:
                            log("  [WARN] Could not determine Elk service status")

                # Current version (informational)
                if installed:
                    py_cmd = (
                        f"python3 -c \"import json; "
                        f"print(json.load(open('{elk_dir}/package.json'))['version'])\" "
                        f"2>/dev/null"
                    )
                    stdout, stderr, code = ssh.execute_sudo(py_cmd, timeout=10)
                    if code == 0 and stdout.strip():
                        log(f"  [INFO] Elk current version: {stdout.strip()}")

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
    """Run snapshot or backup protection on the Elk guest.

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
        ok, msg = backup_guest(app_guest, backup_storage, "elk", mode=backup_mode)
        log(f"Backup {app_guest.name}: {msg}")
        if not ok:
            return False
    else:
        log("=== Step 1: Creating Proxmox snapshot ===")
        ok, msg = snapshot_guest(app_guest, "elk")
        log(f"Snapshot {app_guest.name}: {msg}")
        if not ok:
            return False

    log("")
    return True


# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

def run_elk_install(log_callback=None):
    """Install Elk on the configured guest.

    Supports Docker Compose and bare-metal (Node.js/pnpm) deployment methods.

    Steps:
    1. Snapshot or backup the guest.
    2. Install prerequisites (bare-metal: git, Node.js, corepack, system user;
       Docker: verify Docker/Compose available).
    3. Clone the Elk repository.
    4. Create .env with Mastodon instance configuration.
    5-8. Deploy (Docker: docker compose up, Bare-metal: pnpm install + build + systemd).
    Final. Detect and persist the installed version.

    Returns (ok: bool, log_output: str).
    """
    from models import Credential

    config = _get_elk_config()
    log_lines = []

    def log(msg):
        logger.info(msg)
        log_lines.append(msg)
        if log_callback:
            log_callback(msg)

    # Validate config
    if not config["guest_id"]:
        return False, "Elk guest not configured"

    app_guest = Guest.query.get(int(config["guest_id"]))
    if not app_guest:
        return False, "Elk guest not found"

    elk_dir = config["elk_dir"]
    user = config["user"]
    instance_url = config["instance_url"]
    deploy_method = config["deploy_method"]

    try:
        _validate_abs_path(elk_dir, "Elk dir")
        if deploy_method == "bare-metal":
            _validate_username(user, "Elk user")
        # instance_url is written into .env on the guest — re-check it here so a
        # value stored before this validation existed (or written by another code
        # path) still cannot reach the shell.
        if instance_url:
            _validate_http_url(instance_url, "Mastodon instance URL")
    except ValueError as e:
        return False, str(e)

    credential = app_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return False, "No SSH credential available for Elk guest"
    if not app_guest.ip_address:
        return False, "No IP address configured for Elk guest"

    # --- Step 1: Protection ---
    if not _run_protection(config, app_guest, log):
        return False, "\n".join(log_lines)

    try:
        with SSHClient.from_credential(app_guest.ip_address, credential) as ssh:
            # --- Step 2: Install prerequisites ---
            step = 2
            if deploy_method == "bare-metal":
                log(f"=== Step {step}: Installing prerequisites ===")

                # Check and install git if missing
                stdout, stderr, code = ssh.execute_sudo(
                    "which git 2>/dev/null", timeout=10
                )
                if code != 0:
                    log("git not found — installing...")
                    stdout, stderr, code = ssh.execute_sudo(
                        "DEBIAN_FRONTEND=noninteractive"
                        " apt-get update -qq && DEBIAN_FRONTEND=noninteractive"
                        " apt-get install -y -qq git",
                        timeout=120,
                    )
                    _log_cmd_output(log, stdout, stderr, code, max_chars=1000)
                    if code != 0:
                        log(f"ERROR: Failed to install git (exit {code})")
                        return False, "\n".join(log_lines)
                    log("git installed")
                else:
                    log("git already installed")

                # Check and install Node.js if missing
                stdout, stderr, code = ssh.execute_sudo(
                    "node --version 2>/dev/null", timeout=10
                )
                if code != 0:
                    log("Node.js not found — installing via NodeSource...")
                    # Install Node.js 22.x LTS via NodeSource
                    # (Elk requires Node 22+ for native TypeScript support)
                    node_setup_cmds = (
                        "export DEBIAN_FRONTEND=noninteractive"
                        " && apt-get update -qq && apt-get install -y -qq ca-certificates curl gnupg"
                        " && mkdir -p /etc/apt/keyrings"
                        " && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key"
                        " | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg --yes"
                        " && echo 'deb [signed-by=/etc/apt/keyrings/nodesource.gpg]"
                        " https://deb.nodesource.com/node_22.x nodistro main'"
                        " > /etc/apt/sources.list.d/nodesource.list"
                        " && apt-get update -qq && apt-get install -y -qq nodejs"
                    )
                    stdout, stderr, code = ssh.execute_sudo(node_setup_cmds, timeout=180)
                    _log_cmd_output(log, stdout, stderr, code, max_chars=2000)
                    if code != 0:
                        log(f"ERROR: Failed to install Node.js (exit {code})")
                        return False, "\n".join(log_lines)

                    # Verify Node.js installed
                    stdout, stderr, code = ssh.execute_sudo("node --version", timeout=10)
                    if code == 0 and stdout.strip():
                        log(f"Node.js {stdout.strip()} installed")
                    else:
                        log("ERROR: Node.js installation verification failed")
                        return False, "\n".join(log_lines)
                else:
                    log(f"Node.js {(stdout or '').strip()} already installed")

                # Enable corepack (ships with Node.js 16.9+)
                stdout, stderr, code = ssh.execute_sudo("corepack enable", timeout=30)
                if code != 0:
                    log(f"WARNING: corepack enable failed (exit {code}) — trying npm install")
                    _log_cmd_output(log, stdout, stderr, code, max_chars=500)
                    # Fallback: install corepack via npm
                    stdout, stderr, code = ssh.execute_sudo(
                        "npm install -g corepack && corepack enable", timeout=60
                    )
                    if code != 0:
                        log(f"ERROR: Failed to install corepack (exit {code})")
                        _log_cmd_output(log, stdout, stderr, code, max_chars=500)
                        return False, "\n".join(log_lines)
                log("corepack enabled (pnpm available)")

                # Ensure the system user exists
                stdout, stderr, code = ssh.execute_sudo(
                    f"id {user} 2>/dev/null", timeout=10
                )
                if code != 0:
                    log(f"Creating system user '{user}'...")
                    stdout, stderr, code = ssh.execute_sudo(
                        f"useradd --system --create-home --shell /bin/bash {user}",
                        timeout=10,
                    )
                    if code != 0:
                        log(f"ERROR: Failed to create user '{user}' (exit {code})")
                        _log_cmd_output(log, stdout, stderr, code, max_chars=500)
                        return False, "\n".join(log_lines)
                    log(f"User '{user}' created")
                else:
                    log(f"User '{user}' already exists")

                log("")
            else:
                log(f"=== Step {step}: Checking prerequisites ===")
                # Docker path: verify Docker is available
                stdout, stderr, code = ssh.execute_sudo(
                    "docker --version 2>/dev/null", timeout=10
                )
                if code != 0:
                    log("ERROR: Docker is not installed on the guest")
                    return False, "\n".join(log_lines)
                stdout, stderr, code = ssh.execute_sudo(
                    "docker compose version 2>/dev/null", timeout=10
                )
                if code != 0:
                    log("ERROR: Docker Compose is not available")
                    return False, "\n".join(log_lines)
                log("Docker and Docker Compose available")
                log("")

            # --- Step 3: Clone repository ---
            step = 3
            log(f"=== Step {step}: Cloning Elk repository ===")

            # Check if directory already exists
            stdout, stderr, code = ssh.execute_sudo(
                f"test -d {elk_dir} && echo exists", timeout=10
            )
            if code == 0 and "exists" in (stdout or ""):
                log(f"WARNING: Directory {elk_dir} already exists — aborting to prevent overwrite")
                return False, "\n".join(log_lines)

            clone_cmd = f"git clone https://github.com/elk-zone/elk.git {elk_dir}"
            log(f"Running: {clone_cmd}")
            stdout, stderr, code = ssh.execute_sudo(clone_cmd, timeout=120)
            _log_cmd_output(log, stdout, stderr, code, max_chars=2000)
            if code != 0:
                log(f"ERROR: git clone failed (exit {code})")
                return False, "\n".join(log_lines)
            log("Repository cloned successfully")
            log("")

            # --- Step 4: Create .env ---
            step = 4
            log(f"=== Step {step}: Creating .env configuration ===")
            env_lines = []
            if instance_url:
                env_lines.append(f"NUXT_PUBLIC_DEFAULT_SERVER={instance_url}")
            if deploy_method == "bare-metal":
                env_lines.append("PORT=5314")

            if env_lines:
                # Written via the base64 pipe with a shell-quoted destination:
                # the previous `printf '<content>' > <dir>/.env` let a quote in
                # the instance URL escape into the root shell (and a '%' be eaten
                # as a printf format directive).
                env_content = "\n".join(env_lines) + "\n"
                env_cmd = _remote_write_cmd(f"{elk_dir}/.env", env_content)
                stdout, stderr, code = ssh.execute_sudo(env_cmd, timeout=10)
                if code != 0:
                    # The bare-metal systemd unit declares 'EnvironmentFile={elk_dir}/.env';
                    # without the file systemd refuses to start the service, so a
                    # failed write there is fatal rather than a warning.
                    _log_cmd_output(log, stdout, stderr, code, max_chars=500)
                    if deploy_method == "bare-metal":
                        log(f"ERROR: Could not create .env (exit {code}) — the systemd "
                            f"unit requires {elk_dir}/.env to exist")
                        return False, "\n".join(log_lines)
                    log(f"WARNING: Could not create .env (exit {code})")
                else:
                    log(f"Created {elk_dir}/.env")
            else:
                log("No .env configuration needed")
            log("")

            if deploy_method == "docker":
                # --- Step 5: Docker Compose build and start ---
                step = 5
                log(f"=== Step {step}: Building and starting Docker containers ===")

                # Create local storage directory with correct permissions
                stdout, stderr, code = ssh.execute_sudo(
                    f"mkdir -p {elk_dir}/data && chown 911:911 {elk_dir}/data",
                    timeout=10,
                )
                if code != 0:
                    log("WARNING: Could not create data directory")

                compose_cmd = f"cd {elk_dir} && docker compose up --build -d"
                log(f"Running: {compose_cmd}")
                stdout, stderr, code = ssh.execute_sudo(compose_cmd, timeout=600)
                _log_cmd_output(log, stdout, stderr, code, max_chars=4000)
                if code != 0:
                    log(f"ERROR: docker compose up failed (exit {code})")
                    return False, "\n".join(log_lines)
                log("Docker containers started")
                log("")

                # --- Step 6: Verify container ---
                step = 6
                log(f"=== Step {step}: Verifying Docker container ===")
                time.sleep(5)
                stdout, stderr, code = ssh.execute_sudo(
                    f"docker compose -f {elk_dir}/docker-compose.yml ps "
                    f"--format '{{{{.State}}}}' 2>/dev/null",
                    timeout=15,
                )
                container_state = (stdout or "").strip()
                if "running" in container_state.lower():
                    log(f"Docker container is running (state: {container_state})")
                else:
                    log(f"ERROR: Docker container state: {container_state or 'unknown'}")
                    log("Install did not leave Elk running — reporting failure.")
                    return False, "\n".join(log_lines)
                log("")

            else:
                # --- Step 5: Bare-metal install ---
                step = 5
                log(f"=== Step {step}: Installing dependencies (pnpm install) ===")

                install_cmd = f"cd {elk_dir} && pnpm install"
                log(f"Running: {install_cmd}")
                stdout, stderr, code = ssh.execute_sudo(install_cmd, timeout=300)
                _log_cmd_output(log, stdout, stderr, code, max_chars=4000)
                if code != 0:
                    log(f"ERROR: pnpm install failed (exit {code})")
                    return False, "\n".join(log_lines)
                log("Dependencies installed")
                log("")

                # --- Step 6: Build ---
                step = 6
                log(f"=== Step {step}: Building Elk (pnpm build) ===")
                build_cmd = f"cd {elk_dir} && NODE_OPTIONS=--max-old-space-size=4096 pnpm build"
                log(f"Running: {build_cmd}")
                stdout, stderr, code = ssh.execute_sudo(build_cmd, timeout=600)
                _log_cmd_output(log, stdout, stderr, code, max_chars=4000)
                if code != 0:
                    log(f"ERROR: pnpm build failed (exit {code})")
                    return False, "\n".join(log_lines)
                log("Build completed")
                log("")

                # --- Step 7: Create systemd service ---
                step = 7
                log(f"=== Step {step}: Creating systemd service ===")
                unit_content = _ELK_SYSTEMD_UNIT.format(user=user, elk_dir=elk_dir)
                # Escape for shell
                escaped = unit_content.replace("'", "'\\''")
                write_cmd = f"printf '%s' '{escaped}' > /etc/systemd/system/elk.service"
                stdout, stderr, code = ssh.execute_sudo(write_cmd, timeout=10)
                if code != 0:
                    log(f"ERROR: Could not create systemd service (exit {code})")
                    _log_cmd_output(log, stdout, stderr, code, max_chars=500)
                    return False, "\n".join(log_lines)

                # Set ownership of elk_dir to the elk user
                stdout, stderr, code = ssh.execute_sudo(
                    f"chown -R {user}:{user} {elk_dir}", timeout=30
                )
                if code != 0:
                    log(f"WARNING: chown failed (exit {code})")

                # Reload, enable, and start
                stdout, stderr, code = ssh.execute_sudo(
                    "systemctl daemon-reload && systemctl enable elk && systemctl start elk",
                    timeout=30,
                )
                if code != 0:
                    log(f"ERROR: Could not start Elk service (exit {code})")
                    _log_cmd_output(log, stdout, stderr, code, max_chars=500)
                    return False, "\n".join(log_lines)
                log("Elk systemd service created and started")
                log("")

                # --- Step 8: Verify service ---
                step = 8
                log(f"=== Step {step}: Verifying Elk service ===")
                time.sleep(3)
                stdout, stderr, code = ssh.execute_sudo(
                    "systemctl is-active elk 2>/dev/null", timeout=15
                )
                service_status = (stdout or "").strip()
                if service_status == "active":
                    log("Elk service (elk) is active — install successful")
                else:
                    log(f"ERROR: Elk service (elk) is {service_status or 'unknown'}")
                    stdout, _, _ = ssh.execute_sudo(
                        "journalctl -u elk -n 20 --no-pager 2>/dev/null", timeout=15
                    )
                    if (stdout or "").strip():
                        log("--- Recent service journal ---")
                        log((stdout or "").strip())
                    log("Install did not leave Elk running — reporting failure.")
                    return False, "\n".join(log_lines)
                log("")

            # --- Final: Detect and persist version ---
            log("=== Detecting installed version ===")
            py_cmd = (
                f"python3 -c \"import json; "
                f"print(json.load(open('{elk_dir}/package.json'))['version'])\" "
                f"2>/dev/null"
            )
            stdout, stderr, code = ssh.execute_sudo(py_cmd, timeout=10)
            if code == 0 and stdout.strip():
                v = stdout.strip().splitlines()[0].strip()
                if re.match(r'^\d+\.\d+', v):
                    Setting.set("elk_current_version", v)
                    Setting.set("elk_update_available", "false")
                    log(f"Installed Elk version: {v}")

            Setting.set("elk_installed", "true")

    except Exception as e:
        log(f"SSH ERROR: {e}")
        return False, "\n".join(log_lines)

    log("")
    log("=== Elk installation complete ===")
    return True, "\n".join(log_lines)


# ---------------------------------------------------------------------------
# Upgrade
# ---------------------------------------------------------------------------

def _elk_stash_pop(ssh, elk_dir, log):
    """Pop the stash created before 'git pull'. Returns True on success."""
    stdout, stderr, code = ssh.execute_sudo(f"cd {elk_dir} && git stash pop", timeout=60)
    _log_cmd_output(log, stdout, stderr, code, max_chars=1000)
    if code != 0:
        log(f"WARNING: git stash pop failed (exit {code}) — local changes remain stashed")
        return False
    log("Local changes restored from the stash")
    return True


def run_elk_upgrade(log_callback=None, skip_protection=False):
    """Upgrade an existing Elk installation.

    Supports Docker Compose and bare-metal (Node.js/pnpm) deployment methods.

    Steps:
    1. Snapshot or backup the guest.
    2. Pull latest code from git.
    3. Rebuild/restart (Docker: docker compose up --build, Bare-metal: pnpm install + build + restart).
    4. Verify the deployment.
    5. Detect and persist the new version.

    Returns (ok: bool, log_output: str).
    """
    from models import Credential

    config = _get_elk_config()
    log_lines = []

    def log(msg):
        logger.info(msg)
        log_lines.append(msg)
        if log_callback:
            log_callback(msg)

    # Validate config
    if not config["guest_id"]:
        return False, "Elk guest not configured"

    app_guest = Guest.query.get(int(config["guest_id"]))
    if not app_guest:
        return False, "Elk guest not found"

    elk_dir = config["elk_dir"]
    user = config["user"]
    deploy_method = config["deploy_method"]

    try:
        _validate_abs_path(elk_dir, "Elk dir")
        if deploy_method == "bare-metal":
            _validate_username(user, "Elk user")
    except ValueError as e:
        return False, str(e)

    credential = app_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return False, "No SSH credential available for Elk guest"
    if not app_guest.ip_address:
        return False, "No IP address configured for Elk guest"

    # --- Step 1: Protection ---
    if not _run_protection(config, app_guest, log, skip_protection=skip_protection):
        return False, "\n".join(log_lines)

    try:
        with SSHClient.from_credential(app_guest.ip_address, credential) as ssh:
            # --- Step 2: Pull latest code ---
            step = 2
            log(f"=== Step {step}: Pulling latest code ===")
            # Stash / pull / pop as three separate commands so each exit code is
            # visible: chaining them with '|| true' made the failure check dead
            # and could leave local changes stranded in the stash.
            stdout, stderr, code = ssh.execute_sudo(
                f"cd {elk_dir} && git stash", timeout=60
            )
            _log_cmd_output(log, stdout, stderr, code, max_chars=1000)
            # 'git stash' exits 0 with "No local changes to save" when the tree
            # is clean; only a real stash needs popping afterwards.
            stashed = code == 0 and "No local changes" not in (stdout or "")
            if code != 0:
                log(f"ERROR: git stash failed (exit {code})")
                return False, "\n".join(log_lines)

            log(f"Running: git pull in {elk_dir}")
            stdout, stderr, code = ssh.execute_sudo(f"cd {elk_dir} && git pull", timeout=120)
            _log_cmd_output(log, stdout, stderr, code, max_chars=2000)
            if code != 0:
                log(f"ERROR: git pull failed (exit {code})")
                if stashed:
                    _elk_stash_pop(ssh, elk_dir, log)
                return False, "\n".join(log_lines)

            if stashed and not _elk_stash_pop(ssh, elk_dir, log):
                log("ERROR: could not restore local changes from the stash "
                    "(they are still available via 'git stash list')")
                return False, "\n".join(log_lines)
            log("Code updated")
            log("")

            if deploy_method == "docker":
                # --- Step 3: Rebuild Docker containers ---
                step = 3
                log(f"=== Step {step}: Rebuilding Docker containers ===")
                compose_cmd = f"cd {elk_dir} && docker compose up --build -d"
                log(f"Running: {compose_cmd}")
                stdout, stderr, code = ssh.execute_sudo(compose_cmd, timeout=600)
                _log_cmd_output(log, stdout, stderr, code, max_chars=4000)
                if code != 0:
                    log(f"ERROR: docker compose up failed (exit {code})")
                    return False, "\n".join(log_lines)
                log("Docker containers rebuilt")
                log("")

                # --- Step 4: Verify container ---
                step = 4
                log(f"=== Step {step}: Verifying Docker container ===")
                time.sleep(5)
                stdout, stderr, code = ssh.execute_sudo(
                    f"docker compose -f {elk_dir}/docker-compose.yml ps "
                    f"--format '{{{{.State}}}}' 2>/dev/null",
                    timeout=15,
                )
                container_state = (stdout or "").strip()
                service_ok = "running" in container_state.lower()
                if service_ok:
                    log(f"Docker container is running (state: {container_state})")
                else:
                    log(f"ERROR: Docker container state: {container_state or 'unknown'}")
                log("")

            else:
                # --- Step 3: Reinstall dependencies ---
                step = 3
                log(f"=== Step {step}: Installing dependencies (pnpm install) ===")
                install_cmd = f"cd {elk_dir} && pnpm install"
                log(f"Running: {install_cmd}")
                stdout, stderr, code = ssh.execute_sudo(install_cmd, timeout=300)
                _log_cmd_output(log, stdout, stderr, code, max_chars=4000)
                if code != 0:
                    log(f"ERROR: pnpm install failed (exit {code})")
                    return False, "\n".join(log_lines)
                log("Dependencies installed")
                log("")

                # --- Step 4: Rebuild ---
                step = 4
                log(f"=== Step {step}: Building Elk (pnpm build) ===")
                build_cmd = f"cd {elk_dir} && NODE_OPTIONS=--max-old-space-size=4096 pnpm build"
                log(f"Running: {build_cmd}")
                stdout, stderr, code = ssh.execute_sudo(build_cmd, timeout=600)
                _log_cmd_output(log, stdout, stderr, code, max_chars=4000)
                if code != 0:
                    log(f"ERROR: pnpm build failed (exit {code})")
                    return False, "\n".join(log_lines)
                log("Build completed")
                log("")

                # --- Step 5: Restart service ---
                step = 5
                log(f"=== Step {step}: Restarting Elk service ===")
                stdout, stderr, code = ssh.execute_sudo(
                    "systemctl restart elk 2>&1", timeout=30
                )
                if code != 0:
                    log(f"WARNING: systemctl restart returned exit {code}")
                    _log_cmd_output(log, stdout, stderr, code, max_chars=1000)
                else:
                    log("Elk service restarted")
                log("")

                # --- Step 6: Verify service ---
                step = 6
                log(f"=== Step {step}: Verifying Elk service ===")
                time.sleep(3)
                stdout, stderr, code = ssh.execute_sudo(
                    "systemctl is-active elk 2>/dev/null", timeout=15
                )
                service_status = (stdout or "").strip()
                service_ok = service_status == "active"
                if service_ok:
                    log("Elk service (elk) is active — upgrade successful")
                else:
                    log(f"Elk service (elk) is {service_status or 'unknown'} "
                        f"— attempting to start...")
                    stdout, stderr, code = ssh.execute_sudo(
                        "systemctl start elk 2>&1", timeout=30
                    )
                    if (stdout or "").strip():
                        log((stdout or "").strip())
                    time.sleep(3)
                    stdout, stderr, code = ssh.execute_sudo(
                        "systemctl is-active elk 2>/dev/null", timeout=15
                    )
                    service_status = (stdout or "").strip()
                    service_ok = service_status == "active"
                    if service_ok:
                        log("Elk service (elk) started successfully.")
                    else:
                        log(f"ERROR: Elk service (elk) is still "
                            f"{service_status or 'unknown'} after start attempt.")
                        stdout, _, _ = ssh.execute_sudo(
                            "journalctl -u elk -n 20 --no-pager 2>/dev/null",
                            timeout=15,
                        )
                        if (stdout or "").strip():
                            log("--- Recent service journal ---")
                            log((stdout or "").strip())
                log("")

            if not service_ok:
                # New code is deployed but Elk is down: do not record the new
                # version and do not report success.
                log("Upgrade did not leave Elk running — reporting failure "
                    "(version tracking left unchanged).")
                return False, "\n".join(log_lines)

            # --- Final: Detect and persist new version ---
            log("=== Detecting new version ===")
            py_cmd = (
                f"python3 -c \"import json; "
                f"print(json.load(open('{elk_dir}/package.json'))['version'])\" "
                f"2>/dev/null"
            )
            stdout, stderr, code = ssh.execute_sudo(py_cmd, timeout=10)
            if code == 0 and stdout.strip():
                v = stdout.strip().splitlines()[0].strip()
                if re.match(r'^\d+\.\d+', v):
                    Setting.set("elk_current_version", v)
                    Setting.set("elk_update_available", "false")
                    log(f"Updated Elk version: {v}")

    except Exception as e:
        log(f"SSH ERROR: {e}")
        return False, "\n".join(log_lines)

    log("")
    log("=== Elk upgrade complete ===")
    return True, "\n".join(log_lines)
