"""
PeerTube upgrade automation.

Checks the GitHub API for new PeerTube releases, takes a Proxmox snapshot or
vzdump backup of the app and DB guests, creates a pg_dump backup, then runs
the built-in upgrade.sh script via SSH.
"""

import base64
import json
import logging
import re
import time
from datetime import datetime
from urllib.request import Request, urlopen

from apps.backup import backup_guest, snapshot_guest

# Shared shell-safety and output helpers from the Mastodon module
from apps.utils import _log_cmd_output, _validate_shell_param, _version_gt
from clients.proxmox_api import ProxmoxClient
from clients.ssh_client import SSHClient
from models import Guest, Setting

logger = logging.getLogger(__name__)

_PEERTUBE_GITHUB_API = "https://api.github.com/repos/chocobozzz/PeerTube/releases/latest"
_PEERTUBE_RELEASE_BASE = "https://github.com/Chocobozzz/PeerTube/releases/tag/{tag}"
_PEERTUBE_RELEASE_ZIP = "https://github.com/Chocobozzz/PeerTube/releases/download/{tag}/peertube-{tag}.zip"

_PEERTUBE_PRODUCTION_YAML = """\
listen:
  hostname: '127.0.0.1'
  port: 9000

webserver:
  https: true
  hostname: '{hostname}'
  port: 443

database:
  hostname: '{db_host}'
  port: 5432
  suffix: '_prod'
  username: '{db_user}'
  password: '{db_password}'

redis:
  hostname: '127.0.0.1'

storage:
  tmp: '{peertube_dir}/storage/tmp/'
  bin: '{peertube_dir}/storage/bin/'
  avatars: '{peertube_dir}/storage/avatars/'
  videos: '{peertube_dir}/storage/videos/'
  streaming_playlists: '{peertube_dir}/storage/streaming-playlists/'
  redundancy: '{peertube_dir}/storage/redundancy/'
  logs: '{peertube_dir}/storage/logs/'
  previews: '{peertube_dir}/storage/previews/'
  thumbnails: '{peertube_dir}/storage/thumbnails/'
  torrents: '{peertube_dir}/storage/torrents/'
  captions: '{peertube_dir}/storage/captions/'
  cache: '{peertube_dir}/storage/cache/'
  plugins: '{peertube_dir}/storage/plugins/'
  client_overrides: '{peertube_dir}/storage/client-overrides/'
"""


# ---------------------------------------------------------------------------
# Shell-safe PostgreSQL role creation
# ---------------------------------------------------------------------------

def _build_pg_create_user_cmd(user, db_password):
    """Build the shell command that creates the PeerTube PostgreSQL role.

    ``user`` is validated with ``_validate_shell_param`` by the caller, so it is
    safe to interpolate.  ``db_password`` is fully attacker-controlled (set via
    the Settings UI) and must never reach a shell- or SQL-interpreted context
    unescaped.  We transport it as base64 (decoded on the remote into psql's
    ``-v`` argument) and let psql perform SQL-literal quoting via ``:'pw'`` —
    so neither shell metacharacters (``$()``, backticks, ``;``) nor SQL quotes
    can break out.  Mirrors the base64 pattern used in ``apps/jitsi.py``.
    """
    exists_check = (
        f"sudo -u postgres psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='{user}'\""  # noqa: S608
        f" | grep -q 1 && echo 'User exists'"
    )
    if db_password:
        pw_b64 = base64.b64encode(db_password.encode("utf-8")).decode("ascii")
        create = (
            f"sudo -u postgres psql -v pw=\"$(printf '%s' '{pw_b64}' | base64 -d)\""
            f" -c \"CREATE USER {user} WITH PASSWORD :'pw'\""
        )
    else:
        create = f"sudo -u postgres createuser {user}"
    return f"{exists_check} || {create}"


# ---------------------------------------------------------------------------
# Version check
# ---------------------------------------------------------------------------

def check_peertube_release():
    """Check GitHub for the latest PeerTube release.

    Returns (update_available, latest_version, release_url).
    """
    try:
        req = Request(_PEERTUBE_GITHUB_API, headers={"User-Agent": "mstdnca-proxmox-tool"})
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())

        tag = data.get("tag_name", "")
        if not tag:
            return False, "", ""

        latest = tag.lstrip("vV")
        release_url = _PEERTUBE_RELEASE_BASE.format(tag=tag)

        Setting.set("peertube_latest_version", latest)
        Setting.set("peertube_latest_release_url", release_url)

        current = Setting.get("peertube_current_version", "")
        update_available = bool(current and _version_gt(latest, current))
        Setting.set("peertube_update_available", "true" if update_available else "false")

        return update_available, latest, release_url
    except Exception as e:
        logger.error("Failed to check PeerTube releases: %s", e)
        return False, "", ""


# ---------------------------------------------------------------------------
# Proxmox protection helpers
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Internal config helper
# ---------------------------------------------------------------------------

def _get_peertube_config():
    """Read all PeerTube-related settings."""
    return {
        "guest_id": Setting.get("peertube_guest_id", ""),
        "db_guest_id": Setting.get("peertube_db_guest_id", ""),
        "user": Setting.get("peertube_user", "peertube"),
        "db_name": Setting.get("peertube_db_name", "peertube"),
        "peertube_dir": Setting.get("peertube_dir", "/var/www/peertube"),
        "peertube_url": Setting.get("peertube_url", ""),
        "db_host": Setting.get("peertube_db_host", ""),
        "db_password": Setting.get("peertube_db_password", ""),
        "current_version": Setting.get("peertube_current_version", ""),
        "latest_version": Setting.get("peertube_latest_version", ""),
        "protection_type": Setting.get("peertube_protection_type", "snapshot"),
        "backup_storage": Setting.get("peertube_backup_storage", ""),
        "backup_mode": Setting.get("peertube_backup_mode", "snapshot"),
        "auto_upgrade": Setting.get("peertube_auto_upgrade", "false") == "true",
    }


# ---------------------------------------------------------------------------
# Version detection
# ---------------------------------------------------------------------------

def detect_peertube_version(guest, peertube_dir, user="peertube"):
    """Detect the installed PeerTube version via SSH.

    Tries multiple methods:
    1. Parse the symlink target: readlink peertube-latest → versions/x.y.z
    2. Read peertube-latest/package.json and extract the version field
    3. Read the peertube-latest/config/default.yaml for version hints

    Returns (version_string, None) on success, or (None, error_message) on failure.
    """
    from models import Credential

    try:
        _validate_shell_param(peertube_dir, "PeerTube dir")
        _validate_shell_param(user, "PeerTube user")
    except ValueError as e:
        return None, str(e)

    credential = guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return None, "No SSH credential configured for this guest"
    if not guest.ip_address:
        return None, "No IP address set on the PeerTube guest"

    try:
        with SSHClient.from_credential(guest.ip_address, credential) as ssh:
            # Pre-check: verify the configured directory exists
            stdout, stderr, code = ssh.execute_sudo(
                f"test -d {peertube_dir} && echo ok", timeout=10
            )
            if not (code == 0 and "ok" in (stdout or "")):
                return None, f"Directory '{peertube_dir}' does not exist on the guest"

            # Method 1: Parse symlink target — peertube-latest → versions/x.y.z
            stdout, stderr, code = ssh.execute_sudo(
                f"readlink -f {peertube_dir}/peertube-latest 2>/dev/null", timeout=10
            )
            if code == 0 and stdout.strip():
                # Extract version from path like /var/www/peertube/versions/6.3.1
                m = re.search(r'/versions?/(\d+\.\d+\.\d+)', stdout.strip())
                if m:
                    return m.group(1), None

            symlink_err = (stderr or "").strip()

            # Method 2: Read peertube-latest/package.json
            py_cmd = (
                f"python3 -c \"import json; "
                f"print(json.load(open('{peertube_dir}/peertube-latest/package.json'))['version'])\" "
                f"2>/dev/null"
            )
            stdout, stderr, code = ssh.execute_sudo(py_cmd, timeout=10)
            if code == 0 and stdout.strip():
                v = stdout.strip().splitlines()[0].strip()
                if re.match(r'^\d+\.\d+', v):
                    return v, None

            pkg_err = (stderr or stdout or "").strip()

            # Method 3: List version directories and pick the newest
            stdout, stderr, code = ssh.execute_sudo(
                f"ls -1 {peertube_dir}/versions/ 2>/dev/null | sort -V | tail -1",
                timeout=10,
            )
            if code == 0 and stdout.strip():
                v = stdout.strip().splitlines()[0].strip()
                if re.match(r'^\d+\.\d+', v):
                    return v, None

            ls_err = (stderr or "").strip()

            errors = "; ".join(filter(None, [
                f"symlink: {symlink_err[:100]}" if symlink_err else None,
                f"package.json: {pkg_err[:100]}" if pkg_err else None,
                f"ls versions: {ls_err[:100]}" if ls_err else None,
            ]))
            return None, f"All detection methods failed — {errors}" if errors else "All detection methods returned no output"

    except Exception as e:
        logger.warning("Could not detect PeerTube version: %s", e)
        return None, str(e)


# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

def run_peertube_install(log_callback=None):
    """Install PeerTube on the configured guest.

    Steps:
    1. Snapshot/backup app + DB guests.
    2. Install prerequisites (curl, ffmpeg, python3, unzip, redis-server, Node.js, yarn).
    3. Ensure Redis is running.
    4. Set up PostgreSQL on DB guest (create user, database, extensions).
    5. Create system user.
    6. Create directory structure.
    7. Download and extract latest PeerTube release.
    8. Install Node.js dependencies.
    9. Generate production.yaml configuration.
    10. Apply TCP tuning.
    11. Create and start systemd service.
    12. Verify service is running.
    13. Detect and persist version.

    Returns (ok: bool, log_output: str).
    """
    from urllib.parse import urlparse

    from models import Credential

    config = _get_peertube_config()
    log_lines = []

    def log(msg):
        logger.info(msg)
        log_lines.append(msg)
        if log_callback:
            log_callback(msg)

    # Validate config
    if not config["guest_id"]:
        return False, "PeerTube guest not configured"

    app_guest = Guest.query.get(int(config["guest_id"]))
    if not app_guest:
        return False, "PeerTube guest not found"

    user = config["user"]
    peertube_dir = config["peertube_dir"]
    db_name = config["db_name"]
    peertube_url = config.get("peertube_url", "")
    db_host = config.get("db_host", "")
    db_password_encrypted = config.get("db_password", "")

    if not peertube_url:
        return False, "PeerTube Instance URL is required for installation (used for webserver hostname)"

    # Parse hostname from URL
    parsed = urlparse(peertube_url if "://" in peertube_url else f"https://{peertube_url}")
    hostname = parsed.hostname
    if not hostname:
        return False, f"Could not parse hostname from Instance URL: {peertube_url}"

    try:
        _validate_shell_param(user, "PeerTube user")
        _validate_shell_param(peertube_dir, "PeerTube dir")
        _validate_shell_param(db_name, "Database name")
        if db_host:
            _validate_shell_param(db_host, "Database host")
    except ValueError as e:
        return False, str(e)

    # Decrypt DB password
    db_password = ""
    if db_password_encrypted:
        try:
            from auth.credential_store import decrypt
            db_password = decrypt(db_password_encrypted) or ""
        except Exception as e:
            log(f"WARNING: Could not decrypt database password: {e}")

    credential = app_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return False, "No SSH credential available for PeerTube guest"
    if not app_guest.ip_address:
        return False, "No IP address configured for PeerTube guest"

    # Resolve DB guest if configured
    db_guest = None
    db_guest_id = config.get("db_guest_id", "")
    if db_guest_id:
        db_guest = Guest.query.get(int(db_guest_id))

    # --- Step 1: Protection ---
    step = 1
    protection_type = config.get("protection_type", "snapshot")
    backup_storage = config.get("backup_storage", "")

    if protection_type == "backup" and not backup_storage:
        return False, "Backup protection selected but no backup storage is configured"

    guests_to_protect = [app_guest]
    if db_guest:
        guests_to_protect.append(db_guest)

    if protection_type == "backup":
        backup_mode = config.get("backup_mode", "snapshot")
        log(f"=== Step {step}: Creating vzdump backup to storage '{backup_storage}' "
            f"(mode: {backup_mode}) ===")
        log("(This may take several minutes — please be patient)")
        for g in guests_to_protect:
            ok, msg = backup_guest(g, backup_storage, "peertube", mode=backup_mode)
            log(f"Backup {g.name}: {msg}")
            if not ok:
                return False, "\n".join(log_lines)
    else:
        log(f"=== Step {step}: Creating Proxmox snapshots ===")
        for g in guests_to_protect:
            ok, msg = snapshot_guest(g, "peertube")
            log(f"Snapshot {g.name}: {msg}")
            if not ok:
                return False, "\n".join(log_lines)
    log("")

    try:
        with SSHClient.from_credential(app_guest.ip_address, credential) as ssh:
            # --- Step 2: Install prerequisites ---
            step = 2
            log(f"=== Step {step}: Installing prerequisites ===")

            # Check and install system packages
            prereqs = "curl ffmpeg python3 unzip"
            stdout, stderr, code = ssh.execute_sudo(
                f"DEBIAN_FRONTEND=noninteractive apt-get update -qq"
                f" && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {prereqs}",
                timeout=180,
            )
            _log_cmd_output(log, stdout, stderr, code, max_chars=2000)
            if code != 0:
                log(f"ERROR: Failed to install prerequisites (exit {code})")
                return False, "\n".join(log_lines)
            log("System packages installed")

            # Install Redis
            stdout, stderr, code = ssh.execute_sudo(
                "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq redis-server",
                timeout=120,
            )
            _log_cmd_output(log, stdout, stderr, code, max_chars=1000)
            if code != 0:
                log(f"ERROR: Failed to install redis-server (exit {code})")
                return False, "\n".join(log_lines)
            log("redis-server installed")

            # Install Node.js if missing
            stdout, stderr, code = ssh.execute_sudo("node --version 2>/dev/null", timeout=10)
            if code != 0:
                log("Node.js not found — installing via NodeSource...")
                node_setup_cmds = (
                    "export DEBIAN_FRONTEND=noninteractive"
                    " && apt-get install -y -qq ca-certificates curl gnupg"
                    " && mkdir -p /etc/apt/keyrings"
                    " && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key"
                    " | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg --yes"
                    " && echo 'deb [signed-by=/etc/apt/keyrings/nodesource.gpg]"
                    " https://deb.nodesource.com/node_18.x nodistro main'"
                    " > /etc/apt/sources.list.d/nodesource.list"
                    " && apt-get update -qq && apt-get install -y -qq nodejs"
                )
                stdout, stderr, code = ssh.execute_sudo(node_setup_cmds, timeout=180)
                _log_cmd_output(log, stdout, stderr, code, max_chars=2000)
                if code != 0:
                    log(f"ERROR: Failed to install Node.js (exit {code})")
                    return False, "\n".join(log_lines)

                stdout, stderr, code = ssh.execute_sudo("node --version", timeout=10)
                if code == 0 and stdout.strip():
                    log(f"Node.js {stdout.strip()} installed")
                else:
                    log("ERROR: Node.js installation verification failed")
                    return False, "\n".join(log_lines)
            else:
                log(f"Node.js {(stdout or '').strip()} already installed")

            # Enable corepack for yarn
            stdout, stderr, code = ssh.execute_sudo("corepack enable", timeout=30)
            if code != 0:
                log(f"WARNING: corepack enable failed (exit {code}) — trying npm install")
                _log_cmd_output(log, stdout, stderr, code, max_chars=500)
                stdout, stderr, code = ssh.execute_sudo(
                    "npm install -g corepack && corepack enable", timeout=60
                )
                if code != 0:
                    log(f"ERROR: Failed to install corepack (exit {code})")
                    _log_cmd_output(log, stdout, stderr, code, max_chars=500)
                    return False, "\n".join(log_lines)
            log("corepack enabled (yarn available)")
            log("")

            # --- Step 3: Ensure Redis is running ---
            step = 3
            log(f"=== Step {step}: Ensuring Redis is running ===")
            stdout, stderr, code = ssh.execute_sudo(
                "systemctl enable redis-server && systemctl start redis-server", timeout=30
            )
            if code != 0:
                log(f"WARNING: Could not start redis-server (exit {code})")
                _log_cmd_output(log, stdout, stderr, code, max_chars=500)

            stdout, stderr, code = ssh.execute_sudo(
                "systemctl is-active redis-server 2>/dev/null || systemctl is-active redis 2>/dev/null",
                timeout=10,
            )
            redis_status = (stdout or "").strip()
            if "active" in redis_status:
                log("Redis is running")
            else:
                log(f"WARNING: Redis status: {redis_status or 'unknown'}")
            log("")

    except Exception as e:
        log(f"SSH ERROR on app guest: {e}")
        return False, "\n".join(log_lines)

    # --- Step 4: PostgreSQL setup on DB guest ---
    step = 4
    if db_guest and db_guest.ip_address:
        log(f"=== Step {step}: Setting up PostgreSQL on {db_guest.name} ===")
        db_credential = db_guest.credential
        if not db_credential:
            db_credential = Credential.query.filter_by(is_default=True).first()

        if not db_credential:
            log("ERROR: No SSH credential for DB guest")
            return False, "\n".join(log_lines)

        try:
            with SSHClient.from_credential(db_guest.ip_address, db_credential) as db_ssh:
                # Create PostgreSQL user. The password is base64-transported and
                # SQL-quoted by psql (:'pw') so it cannot break out of the shell
                # or the SQL string -- see _build_pg_create_user_cmd.
                create_user_cmd = _build_pg_create_user_cmd(user, db_password)
                log(f"Creating PostgreSQL user '{user}'...")
                stdout, stderr, code = db_ssh.execute_sudo(create_user_cmd, timeout=30)
                _log_cmd_output(log, stdout, stderr, code, max_chars=500)
                if code != 0:
                    log(f"ERROR: Failed to create PostgreSQL user (exit {code})")
                    return False, "\n".join(log_lines)
                log(f"PostgreSQL user '{user}' ready")

                # Create database
                create_db_cmd = (
                    f"su - postgres -c \"psql -tAc \\\"SELECT 1 FROM pg_database WHERE datname='{db_name}_prod'\\\"\" "  # noqa: S608
                    f"| grep -q 1 && echo 'Database exists' "
                    f"|| su - postgres -c \"createdb -O {user} -E UTF8 -T template0 {db_name}_prod\""
                )
                log(f"Creating database '{db_name}_prod'...")
                stdout, stderr, code = db_ssh.execute_sudo(create_db_cmd, timeout=30)
                _log_cmd_output(log, stdout, stderr, code, max_chars=500)
                if code != 0:
                    log(f"ERROR: Failed to create database (exit {code})")
                    return False, "\n".join(log_lines)
                log(f"Database '{db_name}_prod' ready")

                # Create extensions
                for ext in ("pg_trgm", "unaccent"):
                    ext_cmd = f"su - postgres -c \"psql -c 'CREATE EXTENSION IF NOT EXISTS {ext};' {db_name}_prod\""
                    stdout, stderr, code = db_ssh.execute_sudo(ext_cmd, timeout=15)
                    if code != 0:
                        log(f"WARNING: Could not create extension {ext} (exit {code})")
                        _log_cmd_output(log, stdout, stderr, code, max_chars=300)
                    else:
                        log(f"Extension '{ext}' enabled")

        except Exception as e:
            log(f"SSH ERROR on DB guest: {e}")
            return False, "\n".join(log_lines)
    else:
        log(f"=== Step {step}: Skipping PostgreSQL setup (no DB guest configured) ===")
    log("")

    try:
        with SSHClient.from_credential(app_guest.ip_address, credential) as ssh:
            # --- Step 5: Create system user ---
            step = 5
            log(f"=== Step {step}: Creating system user ===")
            stdout, stderr, code = ssh.execute_sudo(f"id {user} 2>/dev/null", timeout=10)
            if code != 0:
                log(f"Creating system user '{user}'...")
                stdout, stderr, code = ssh.execute_sudo(
                    f"useradd -m -d {peertube_dir} -s /usr/sbin/nologin {user}",
                    timeout=10,
                )
                if code != 0:
                    log(f"ERROR: Failed to create user '{user}' (exit {code})")
                    _log_cmd_output(log, stdout, stderr, code, max_chars=500)
                    return False, "\n".join(log_lines)
                log(f"User '{user}' created with home directory {peertube_dir}")
            else:
                log(f"User '{user}' already exists")

            # Ensure directory permissions
            stdout, stderr, code = ssh.execute_sudo(f"chmod 755 {peertube_dir}", timeout=10)
            log("")

            # --- Step 6: Create directory structure ---
            step = 6
            log(f"=== Step {step}: Creating directory structure ===")
            for subdir in ("config", "storage", "versions"):
                stdout, stderr, code = ssh.execute_sudo(
                    f"su - {user} -s /bin/bash -c 'mkdir -p {peertube_dir}/{subdir}'",
                    timeout=10,
                )
                if code != 0:
                    log(f"ERROR: Failed to create {peertube_dir}/{subdir} (exit {code})")
                    _log_cmd_output(log, stdout, stderr, code, max_chars=300)
                    return False, "\n".join(log_lines)
            # Restrict config directory permissions
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -s /bin/bash -c 'chmod 750 {peertube_dir}/config'",
                timeout=10,
            )
            log(f"Created {peertube_dir}/{{config,storage,versions}}")
            log("")

            # --- Step 7: Download latest release ---
            step = 7
            log(f"=== Step {step}: Downloading latest PeerTube release ===")

            # Check if peertube-latest already exists
            stdout, stderr, code = ssh.execute_sudo(
                f"test -e {peertube_dir}/peertube-latest && echo exists", timeout=10
            )
            if code == 0 and "exists" in (stdout or ""):
                log(f"WARNING: {peertube_dir}/peertube-latest already exists — aborting to prevent overwrite")
                return False, "\n".join(log_lines)

            # Fetch latest version from GitHub
            log("Fetching latest release version from GitHub...")
            stdout, stderr, code = ssh.execute_sudo(
                "curl -s https://api.github.com/repos/chocobozzz/peertube/releases/latest"
                " | python3 -c \"import sys,json; print(json.load(sys.stdin).get('tag_name',''))\"",
                timeout=30,
            )
            if code != 0 or not (stdout or "").strip():
                log("ERROR: Could not determine latest PeerTube version from GitHub")
                _log_cmd_output(log, stdout, stderr, code, max_chars=500)
                return False, "\n".join(log_lines)
            version_tag = (stdout or "").strip()
            version_num = version_tag.lstrip("vV")
            log(f"Latest release: {version_tag}")

            # Download release zip
            zip_url = _PEERTUBE_RELEASE_ZIP.format(tag=version_tag)
            download_cmd = (
                f"cd {peertube_dir}/versions"
                f" && su - {user} -s /bin/bash -c '"
                f"wget -q \"{zip_url}\" -O \"peertube-{version_tag}.zip\"'"
            )
            log(f"Downloading {zip_url}...")
            stdout, stderr, code = ssh.execute_sudo(download_cmd, timeout=300)
            _log_cmd_output(log, stdout, stderr, code, max_chars=1000)
            if code != 0:
                log(f"ERROR: Failed to download PeerTube release (exit {code})")
                return False, "\n".join(log_lines)

            # Extract zip
            extract_cmd = (
                f"cd {peertube_dir}/versions"
                f" && su - {user} -s /bin/bash -c '"
                f"unzip -q peertube-{version_tag}.zip"
                f" && rm peertube-{version_tag}.zip'"
            )
            log("Extracting release...")
            stdout, stderr, code = ssh.execute_sudo(extract_cmd, timeout=120)
            _log_cmd_output(log, stdout, stderr, code, max_chars=1000)
            if code != 0:
                log(f"ERROR: Failed to extract release (exit {code})")
                return False, "\n".join(log_lines)

            # Create symlink
            symlink_cmd = (
                f"cd {peertube_dir}"
                f" && su - {user} -s /bin/bash -c '"
                f"ln -s versions/peertube-{version_tag} peertube-latest'"
            )
            stdout, stderr, code = ssh.execute_sudo(symlink_cmd, timeout=10)
            if code != 0:
                log(f"ERROR: Failed to create peertube-latest symlink (exit {code})")
                _log_cmd_output(log, stdout, stderr, code, max_chars=500)
                return False, "\n".join(log_lines)
            log("Release extracted and symlinked to peertube-latest")
            log("")

            # --- Step 8: Install Node.js dependencies ---
            step = 8
            log(f"=== Step {step}: Installing Node.js dependencies ===")
            install_cmd = (
                f"cd {peertube_dir}/peertube-latest"
                f" && sudo -H -u {user} npm run install-node-dependencies -- --production"
            )
            log("Running: npm run install-node-dependencies")
            stdout, stderr, code = ssh.execute_sudo(install_cmd, timeout=600)
            _log_cmd_output(log, stdout, stderr, code, max_chars=4000)
            if code != 0:
                log(f"ERROR: npm install failed (exit {code})")
                return False, "\n".join(log_lines)
            log("Node.js dependencies installed")
            log("")

            # --- Step 9: Generate production.yaml ---
            step = 9
            log(f"=== Step {step}: Creating production.yaml configuration ===")

            # Determine DB host: use configured db_host, or DB guest IP, or localhost
            effective_db_host = db_host
            if not effective_db_host and db_guest and db_guest.ip_address:
                effective_db_host = db_guest.ip_address
            if not effective_db_host:
                effective_db_host = "localhost"

            # The password sits inside a single-quoted YAML scalar; escape any
            # single quotes (YAML doubles them) so a crafted password cannot
            # break out of the scalar and inject arbitrary YAML keys.
            yaml_password = (db_password or "peertube").replace("'", "''")
            yaml_content = _PEERTUBE_PRODUCTION_YAML.format(
                hostname=hostname,
                db_host=effective_db_host,
                db_user=user,
                db_password=yaml_password,
                peertube_dir=peertube_dir,
            )

            # Copy default.yaml first
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -s /bin/bash -c '"
                f"cp {peertube_dir}/peertube-latest/config/default.yaml {peertube_dir}/config/default.yaml'",
                timeout=10,
            )
            if code != 0:
                log("WARNING: Could not copy default.yaml")

            # Write production.yaml
            escaped = yaml_content.replace("'", "'\\''")
            write_cmd = (
                f"printf '%s' '{escaped}' > {peertube_dir}/config/production.yaml"
                f" && chown {user}:{user} {peertube_dir}/config/production.yaml"
                f" && chmod 640 {peertube_dir}/config/production.yaml"
            )
            stdout, stderr, code = ssh.execute_sudo(write_cmd, timeout=10)
            if code != 0:
                log(f"ERROR: Could not create production.yaml (exit {code})")
                _log_cmd_output(log, stdout, stderr, code, max_chars=500)
                return False, "\n".join(log_lines)
            log("production.yaml created")
            log("")

            # --- Step 10: TCP tuning ---
            step = 10
            log(f"=== Step {step}: Applying TCP tuning ===")
            tcp_src = f"{peertube_dir}/peertube-latest/support/sysctl.d/30-peertube-tcp.conf"
            stdout, stderr, code = ssh.execute_sudo(
                f"test -f {tcp_src} && echo ok", timeout=10
            )
            if code == 0 and "ok" in (stdout or ""):
                stdout, stderr, code = ssh.execute_sudo(
                    f"cp {tcp_src} /etc/sysctl.d/ && sysctl -p /etc/sysctl.d/30-peertube-tcp.conf",
                    timeout=15,
                )
                if code == 0:
                    log("TCP tuning applied")
                else:
                    log("WARNING: Could not apply TCP tuning (non-fatal)")
            else:
                log("TCP tuning config not found in release — skipping")
            log("")

            # --- Step 11: Create and start systemd service ---
            step = 11
            log(f"=== Step {step}: Creating systemd service ===")
            service_src = f"{peertube_dir}/peertube-latest/support/systemd/peertube.service"
            stdout, stderr, code = ssh.execute_sudo(
                f"test -f {service_src} && echo ok", timeout=10
            )
            if code == 0 and "ok" in (stdout or ""):
                stdout, stderr, code = ssh.execute_sudo(
                    f"cp {service_src} /etc/systemd/system/", timeout=10
                )
                if code != 0:
                    log(f"ERROR: Could not copy systemd service file (exit {code})")
                    _log_cmd_output(log, stdout, stderr, code, max_chars=500)
                    return False, "\n".join(log_lines)
            else:
                log("WARNING: systemd service file not found in release")
                return False, "\n".join(log_lines)

            stdout, stderr, code = ssh.execute_sudo(
                "systemctl daemon-reload && systemctl enable peertube && systemctl start peertube",
                timeout=30,
            )
            if code != 0:
                log(f"ERROR: Could not start PeerTube service (exit {code})")
                _log_cmd_output(log, stdout, stderr, code, max_chars=500)
                return False, "\n".join(log_lines)
            log("PeerTube systemd service created and started")
            log("")

            # --- Step 12: Verify service ---
            step = 12
            log(f"=== Step {step}: Verifying PeerTube service ===")
            time.sleep(3)
            stdout, stderr, code = ssh.execute_sudo(
                "systemctl is-active peertube 2>/dev/null", timeout=15
            )
            service_status = (stdout or "").strip()
            if service_status == "active":
                log("PeerTube service is active — install successful")
            else:
                log(f"WARNING: PeerTube service is {service_status or 'unknown'}")
                stdout, _, _ = ssh.execute_sudo(
                    "journalctl -u peertube -n 20 --no-pager 2>/dev/null", timeout=15
                )
                if (stdout or "").strip():
                    log("--- Recent service journal ---")
                    log((stdout or "").strip())
            log("")

            # --- Step 13: Detect and persist version ---
            step = 13
            log(f"=== Step {step}: Detecting installed version ===")
            Setting.set("peertube_current_version", version_num)
            Setting.set("peertube_update_available", "false")
            log(f"Installed PeerTube version: {version_num}")

            Setting.set("peertube_installed", "true")

    except Exception as e:
        log(f"SSH ERROR: {e}")
        return False, "\n".join(log_lines)

    log("")
    log("=== PeerTube installation complete ===")
    return True, "\n".join(log_lines)


# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

def run_peertube_preflight(log_callback=None):
    """Run read-only pre-flight checks before PeerTube upgrade.

    Validates configuration, Proxmox guest status, SSH connectivity, PeerTube
    installation, Node.js availability, and service status.

    Returns (all_pass: bool, log_output: str).
    """
    from models import Credential

    config = _get_peertube_config()
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

    log("=== PeerTube Pre-flight Check ===")
    log("")

    # ── A. Configuration ──────────────────────────────────────────────────────
    log("--- A. Configuration ---")

    config_ok = True
    for field, label in [
        ("guest_id", "PeerTube guest"),
        ("user", "PeerTube user"),
        ("peertube_dir", "PeerTube directory"),
    ]:
        val = config.get(field, "")
        if val:
            check(f"{label} configured", True)
        else:
            check(f"{label} configured", False, "not set in settings")
            config_ok = False

    # DB guest is optional but recommended
    db_guest_id = config.get("db_guest_id", "")
    if db_guest_id:
        check("Database guest configured", True)
    else:
        log("  [WARN] No separate database guest configured — pg_dump backup will be skipped")

    protection_type = config.get("protection_type", "snapshot")
    backup_storage = config.get("backup_storage", "")
    if protection_type == "backup":
        if backup_storage:
            check("Backup storage configured", True)
        else:
            check("Backup storage configured", False, "backup protection selected but no storage configured")
            config_ok = False

    user = config.get("user", "peertube")
    peertube_dir = config.get("peertube_dir", "/var/www/peertube")

    try:
        _validate_shell_param(user, "PeerTube user")
        _validate_shell_param(peertube_dir, "PeerTube dir")
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
    check("PeerTube guest in database", app_guest is not None,
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

    # Check DB guest if configured
    db_guest = None
    if db_guest_id:
        db_guest = Guest.query.get(int(db_guest_id))
        if db_guest:
            check("Database guest in database", True)
            if db_guest.proxmox_host:
                try:
                    client = ProxmoxClient(db_guest.proxmox_host)
                    node = client.find_guest_node(db_guest.vmid)
                    if node:
                        check(f"{db_guest.name} found on Proxmox", True)
                        status = client.get_guest_status(node, db_guest.vmid, db_guest.guest_type)
                        check(f"{db_guest.name} running", status == "running",
                              f"current status: {status}")
                    else:
                        check(f"{db_guest.name} found on Proxmox", False, "not found on any PVE node")
                except Exception as e:
                    check(f"{db_guest.name} Proxmox reachable", False, str(e))
        else:
            check("Database guest in database", False, f"guest ID {db_guest_id} not found")

    # ── C. SSH checks on app guest ────────────────────────────────────────────
    log("")
    log(f"--- C. SSH checks on {app_guest.name} ---")

    credential = app_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()

    if not credential:
        check("SSH credential available", False,
              "no credential configured for PeerTube guest or as default")
    elif not app_guest.ip_address:
        check("SSH credential available", True)
        check("PeerTube guest IP configured", False, "no IP address set on guest")
    else:
        check("SSH credential available", True)
        check("PeerTube guest IP configured", True)
        try:
            with SSHClient.from_credential(app_guest.ip_address, credential) as ssh:
                check("SSH connection established", True)

                # PeerTube directory exists
                stdout, stderr, code = ssh.execute_sudo(
                    f"test -d {peertube_dir} && echo ok", timeout=10
                )
                check(f"PeerTube directory {peertube_dir} exists",
                      code == 0 and "ok" in (stdout or ""),
                      "directory not found")

                # peertube-latest symlink exists
                stdout, stderr, code = ssh.execute_sudo(
                    f"test -L {peertube_dir}/peertube-latest && echo ok", timeout=10
                )
                check("peertube-latest symlink exists",
                      code == 0 and "ok" in (stdout or ""),
                      f"symlink not found at {peertube_dir}/peertube-latest")

                # Key subdirectories exist
                for subdir in ["config", "storage", "versions"]:
                    stdout, stderr, code = ssh.execute_sudo(
                        f"test -d {peertube_dir}/{subdir} && echo ok", timeout=10
                    )
                    check(f"{subdir}/ directory exists",
                          code == 0 and "ok" in (stdout or ""),
                          f"{peertube_dir}/{subdir} not found")

                # upgrade.sh exists
                stdout, stderr, code = ssh.execute_sudo(
                    f"test -f {peertube_dir}/peertube-latest/scripts/upgrade.sh && echo ok",
                    timeout=10,
                )
                check("upgrade.sh script exists",
                      code == 0 and "ok" in (stdout or ""),
                      "scripts/upgrade.sh not found in peertube-latest")

                # Node.js version (informational)
                stdout, stderr, code = ssh.execute_sudo(
                    f"su - {user} -c 'node --version 2>/dev/null'", timeout=10
                )
                if code == 0 and stdout.strip():
                    m = re.search(r'v?(\d+\.\d+\.\d+)', stdout.strip())
                    node_ver = m.group(1) if m else stdout.strip()
                    log(f"  [INFO] Node.js {node_ver} installed")
                else:
                    log("  [WARN] Could not determine Node.js version")

                # Current PeerTube version (informational)
                stdout, stderr, code = ssh.execute_sudo(
                    f"readlink -f {peertube_dir}/peertube-latest 2>/dev/null", timeout=10
                )
                if code == 0 and stdout.strip():
                    m = re.search(r'/versions?/(\d+\.\d+\.\d+)', stdout.strip())
                    if m:
                        log(f"  [INFO] PeerTube current version: {m.group(1)}")

                # Service status (informational)
                stdout, stderr, code = ssh.execute_sudo(
                    "systemctl is-active peertube 2>/dev/null", timeout=10
                )
                service_status = (stdout or "").strip()
                if service_status == "active":
                    log("  [INFO] PeerTube service (peertube) is active")
                elif service_status:
                    log(f"  [WARN] PeerTube service (peertube) status: {service_status}")
                else:
                    log("  [WARN] Could not determine PeerTube service status")

        except Exception as e:
            check("SSH connection established", False, str(e))

    # ── D. SSH checks on DB guest ─────────────────────────────────────────────
    if db_guest and db_guest.ip_address:
        log("")
        log(f"--- D. SSH checks on {db_guest.name} (database) ---")
        db_credential = db_guest.credential
        if not db_credential:
            db_credential = Credential.query.filter_by(is_default=True).first()

        if not db_credential:
            check("SSH credential for DB guest", False, "no credential configured")
        else:
            try:
                with SSHClient.from_credential(db_guest.ip_address, db_credential) as ssh:
                    check("SSH connection to DB guest", True)

                    # PostgreSQL running check
                    stdout, stderr, code = ssh.execute_sudo(
                        "systemctl is-active postgresql 2>/dev/null", timeout=10
                    )
                    pg_status = (stdout or "").strip()
                    check("PostgreSQL service active", pg_status == "active",
                          f"status: {pg_status or 'unknown'}")

                    # pg_dump available
                    stdout, stderr, code = ssh.execute_sudo(
                        "which pg_dump 2>/dev/null && echo ok", timeout=10
                    )
                    check("pg_dump available", code == 0 and "ok" in (stdout or ""),
                          "pg_dump not found on PATH")

            except Exception as e:
                check("SSH connection to DB guest", False, str(e))

    all_pass = checks_failed == 0
    log("")
    if all_pass:
        log(f"=== Pre-flight complete: {checks_passed}/{checks_total} checks passed — all clear ===")
    else:
        log(f"=== Pre-flight complete: {checks_passed}/{checks_total} checks passed — "
            f"{checks_failed} failure(s), upgrade blocked ===")
    return all_pass, "\n".join(log_lines)


# ---------------------------------------------------------------------------
# Upgrade
# ---------------------------------------------------------------------------

def run_peertube_upgrade(log_callback=None, skip_protection=False):
    """Run the PeerTube upgrade via the built-in upgrade.sh script.

    Steps:
    1. Snapshot or backup app and DB guests.
    2. pg_dump the PeerTube database on the DB guest.
    3. Run upgrade.sh on the app guest.
    4. Restart the peertube systemd service.
    5. Verify the service is running.
    6. Clean up pnpm store.

    Returns (ok: bool, log_output: str).
    """
    from models import Credential

    config = _get_peertube_config()
    log_lines = []

    def log(msg):
        logger.info(msg)
        log_lines.append(msg)
        if log_callback:
            log_callback(msg)

    # Validate config
    if not config["guest_id"]:
        return False, "PeerTube guest not configured"

    app_guest = Guest.query.get(int(config["guest_id"]))
    if not app_guest:
        return False, "PeerTube guest not found"

    user = config["user"]
    peertube_dir = config["peertube_dir"]
    db_name = config["db_name"]

    try:
        _validate_shell_param(user, "PeerTube user")
        _validate_shell_param(peertube_dir, "PeerTube dir")
        _validate_shell_param(db_name, "Database name")
    except ValueError as e:
        return False, str(e)

    credential = app_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return False, "No SSH credential available for PeerTube guest"
    if not app_guest.ip_address:
        return False, "No IP address configured for PeerTube guest"

    # Resolve DB guest if configured
    db_guest = None
    db_guest_id = config.get("db_guest_id", "")
    if db_guest_id:
        db_guest = Guest.query.get(int(db_guest_id))

    # --- Step 1: Protection ---
    step = 1
    if skip_protection:
        log(f"=== Step {step}: Skipping snapshot/backup (requested by super-admin) ===")
    else:
        protection_type = config.get("protection_type", "snapshot")
        backup_storage = config.get("backup_storage", "")

        if protection_type == "backup" and not backup_storage:
            return False, "Backup protection selected but no backup storage is configured"

        guests_to_protect = [app_guest]
        if db_guest:
            guests_to_protect.append(db_guest)

        if protection_type == "backup":
            backup_mode = config.get("backup_mode", "snapshot")
            log(f"=== Step {step}: Creating vzdump backup to storage '{backup_storage}' "
                f"(mode: {backup_mode}) ===")
            log("(This may take several minutes — please be patient)")
            for g in guests_to_protect:
                ok, msg = backup_guest(g, backup_storage, "peertube", mode=backup_mode)
                log(f"Backup {g.name}: {msg}")
                if not ok:
                    return False, "\n".join(log_lines)
        else:
            log(f"=== Step {step}: Creating Proxmox snapshots ===")
            for g in guests_to_protect:
                ok, msg = snapshot_guest(g, "peertube")
                log(f"Snapshot {g.name}: {msg}")
                if not ok:
                    return False, "\n".join(log_lines)

    log("")

    # --- Step 2: pg_dump backup ---
    step = 2
    if db_guest and db_guest.ip_address:
        log(f"=== Step {step}: PostgreSQL backup (pg_dump) ===")
        db_credential = db_guest.credential
        if not db_credential:
            db_credential = Credential.query.filter_by(is_default=True).first()

        if db_credential:
            try:
                with SSHClient.from_credential(db_guest.ip_address, db_credential) as ssh:
                    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                    dump_file = f"/tmp/peertube_backup_{timestamp}.sql"  # nosec B108 — remote SSH path, not a local temp file
                    dump_cmd = f"su - postgres -c 'pg_dump {db_name} > {dump_file}'"
                    log(f"Running: pg_dump {db_name} > {dump_file}")
                    stdout, stderr, code = ssh.execute_sudo(dump_cmd, timeout=300)
                    if code == 0:
                        log(f"Database backup saved to {dump_file}")
                    else:
                        log(f"WARNING: pg_dump failed (exit {code})")
                        _log_cmd_output(log, stdout, stderr, code, max_chars=1000)
                        log("Continuing with upgrade despite pg_dump failure...")
            except Exception as e:
                log(f"WARNING: Could not connect to DB guest for pg_dump: {e}")
                log("Continuing with upgrade...")
        else:
            log("WARNING: No SSH credential for DB guest — skipping pg_dump")
        log("")
    else:
        log(f"=== Step {step}: Skipping pg_dump (no DB guest configured) ===")
        log("")

    # --- Step 3: Run upgrade.sh ---
    step = 3
    log(f"=== Step {step}: Running PeerTube upgrade.sh ===")

    try:
        with SSHClient.from_credential(app_guest.ip_address, credential) as ssh:
            upgrade_cmd = (
                f"cd {peertube_dir}/peertube-latest/scripts "
                f"&& sudo -H -u {user} ./upgrade.sh"
            )
            log(f"Running: {upgrade_cmd}")
            stdout, stderr, code = ssh.execute_sudo(upgrade_cmd, timeout=600)
            _log_cmd_output(log, stdout, stderr, code, max_chars=4000)

            if code != 0:
                log(f"ERROR: upgrade.sh failed (exit {code})")
                return False, "\n".join(log_lines)

            log("upgrade.sh completed successfully")
            log("")

            # --- Step 4: Restart service ---
            step = 4
            log(f"=== Step {step}: Restarting PeerTube service ===")
            stdout, stderr, code = ssh.execute_sudo(
                "systemctl restart peertube 2>&1", timeout=30
            )
            if code != 0:
                log(f"WARNING: systemctl restart returned exit {code}")
                _log_cmd_output(log, stdout, stderr, code, max_chars=1000)
            else:
                log("PeerTube service restarted")
            log("")

            # --- Step 5: Verify service ---
            step = 5
            log(f"=== Step {step}: Verifying PeerTube service ===")
            # Give the service a moment to start up
            time.sleep(3)
            stdout, stderr, code = ssh.execute_sudo(
                "systemctl is-active peertube 2>/dev/null", timeout=15
            )
            service_status = (stdout or "").strip()
            if service_status == "active":
                log("PeerTube service (peertube) is active — upgrade successful")
            else:
                log(f"PeerTube service (peertube) is {service_status or 'unknown'} "
                    f"— attempting to start...")
                stdout, stderr, code = ssh.execute_sudo(
                    "systemctl start peertube 2>&1", timeout=30
                )
                if (stdout or "").strip():
                    log((stdout or "").strip())
                # Re-check
                time.sleep(3)
                stdout, stderr, code = ssh.execute_sudo(
                    "systemctl is-active peertube 2>/dev/null", timeout=15
                )
                service_status = (stdout or "").strip()
                if service_status == "active":
                    log("PeerTube service (peertube) started successfully.")
                else:
                    log(f"WARNING: PeerTube service (peertube) is still "
                        f"{service_status or 'unknown'} after start attempt.")
                    # Show recent journal entries to aid diagnosis
                    stdout, _, _ = ssh.execute_sudo(
                        "journalctl -u peertube -n 20 --no-pager 2>/dev/null",
                        timeout=15,
                    )
                    if (stdout or "").strip():
                        log("--- Recent service journal ---")
                        log((stdout or "").strip())

            log("")

            # --- Step 6: Detect and persist new version ---
            step = 6
            log(f"=== Step {step}: Detecting new version ===")
            stdout, stderr, code = ssh.execute_sudo(
                f"readlink -f {peertube_dir}/peertube-latest 2>/dev/null", timeout=10
            )
            if code == 0 and stdout.strip():
                m = re.search(r'/versions?/(\d+\.\d+\.\d+)', stdout.strip())
                if m:
                    Setting.set("peertube_current_version", m.group(1))
                    Setting.set("peertube_update_available", "false")
                    log(f"Updated PeerTube version: {m.group(1)}")
                else:
                    # Fallback: try package.json
                    py_cmd = (
                        f"python3 -c \"import json; "
                        f"print(json.load(open('{peertube_dir}/peertube-latest/package.json'))['version'])\" "
                        f"2>/dev/null"
                    )
                    stdout2, _, code2 = ssh.execute_sudo(py_cmd, timeout=10)
                    if code2 == 0 and stdout2.strip():
                        v = stdout2.strip().splitlines()[0].strip()
                        if re.match(r'^\d+\.\d+', v):
                            Setting.set("peertube_current_version", v)
                            Setting.set("peertube_update_available", "false")
                            log(f"Updated PeerTube version: {v}")

            log("")

            # --- Step 7: Cleanup pnpm store ---
            step = 7
            log(f"=== Step {step}: Cleaning up pnpm store ===")
            stdout, stderr, code = ssh.execute_sudo(
                f"sudo -u {user} pnpm store prune 2>&1 || true", timeout=60
            )
            if code == 0:
                log("pnpm store pruned")
            else:
                log("pnpm store prune skipped or failed (non-fatal)")

    except Exception as e:
        log(f"SSH ERROR: {e}")
        return False, "\n".join(log_lines)

    log("")
    log("=== PeerTube upgrade complete ===")
    return True, "\n".join(log_lines)
