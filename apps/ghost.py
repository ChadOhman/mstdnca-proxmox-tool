"""
Ghost CMS upgrade automation.

Checks the npm registry for new Ghost releases, takes a Proxmox snapshot or
vzdump backup of the app guest, then runs 'ghost update' via SSH.
"""

import json
import logging
import os.path as _osp
import re
from urllib.request import Request, urlopen

from apps.backup import backup_guest, snapshot_guest

# Shared shell-safety and output helpers from the Mastodon module
from apps.utils import _log_cmd_output, _validate_shell_param, _version_gt
from clients.proxmox_api import ProxmoxClient
from clients.ssh_client import SSHClient
from models import Guest, Setting

logger = logging.getLogger(__name__)

_GHOST_NPM_URL = "https://registry.npmjs.org/ghost/latest"
_GHOST_RELEASE_BASE = "https://github.com/TryGhost/Ghost/releases/tag/v{version}"


# ---------------------------------------------------------------------------
# Version check
# ---------------------------------------------------------------------------

def check_ghost_release():
    """Check npm registry for the latest Ghost release.

    Returns (update_available, latest_version, release_url).
    """
    try:
        req = Request(_GHOST_NPM_URL, headers={"User-Agent": "mstdnca-proxmox-tool"})
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())

        latest = data.get("version", "")
        if not latest:
            return False, "", ""

        release_url = _GHOST_RELEASE_BASE.format(version=latest)

        Setting.set("ghost_latest_version", latest)
        Setting.set("ghost_latest_release_url", release_url)

        current = Setting.get("ghost_current_version", "")
        update_available = bool(current and _version_gt(latest, current))
        Setting.set("ghost_update_available", "true" if update_available else "false")

        return update_available, latest, release_url
    except Exception as e:
        logger.error("Failed to check Ghost releases: %s", e)
        return False, "", ""


# ---------------------------------------------------------------------------
# Internal config helper
# ---------------------------------------------------------------------------

def _get_ghost_config():
    """Read all Ghost-related settings."""
    return {
        "guest_id": Setting.get("ghost_guest_id", ""),
        "user": Setting.get("ghost_user", "ghost_user"),
        "ghost_dir": Setting.get("ghost_dir", "/opt/ghost"),
        "current_version": Setting.get("ghost_current_version", ""),
        "latest_version": Setting.get("ghost_latest_version", ""),
        "protection_type": Setting.get("ghost_protection_type", "snapshot"),
        "backup_storage": Setting.get("ghost_backup_storage", ""),
        "backup_mode": Setting.get("ghost_backup_mode", "snapshot"),
        "auto_upgrade": Setting.get("ghost_auto_upgrade", "false") == "true",
    }


# ---------------------------------------------------------------------------
# Permission remediation
# ---------------------------------------------------------------------------

def _fix_ghost_permissions(ssh, ghost_dir, user, log):
    """Re-assert Ghost file ownership and modes over an SSH connection.

    Files outside ``versions/`` are normalised to 664, directories to 775, and
    the whole tree is chowned to *user*.  The ``versions/`` trees are excluded
    from chmod so executable bits under ``node_modules/.bin`` survive.

    Run this both *before* ``ghost update`` (ghost-cli's check-permissions step
    rejects files with wrong modes) and *after* it: the update unpacks a new
    ``versions/<v>`` tree and runs migrations, which can leave ``content/``
    files owned by root and make Ghost hit ``EACCES`` at runtime.

    Returns True on success.  On a non-zero exit it logs a warning and returns
    False — the failure is non-fatal, so the caller decides whether to proceed.
    """
    perms_cmds = (
        f"find {ghost_dir} ! -path '*/versions/*' -type f -exec chmod 664 {{}} + "
        f"&& find {ghost_dir} ! -path '*/versions/*' -type d -exec chmod 775 {{}} + "
        f"&& chown -R {user}: {ghost_dir}"
    )
    stdout, stderr, code = ssh.execute_sudo(perms_cmds, timeout=120)
    if code == 0:
        log("File permissions fixed")
        return True
    log(f"WARNING: Permission fix returned exit {code}: "
        f"{(stderr or stdout or '').strip()[:200]}")
    return False


# ---------------------------------------------------------------------------
# Database privilege remediation (FM4)
# ---------------------------------------------------------------------------

# Ghost's DB name and user are read from config at runtime, never assumed.  They
# are interpolated into SQL only after matching this pattern, so a plain
# (un-backticked) identifier is safe to use directly — no shell metacharacters
# and no SQL-quote-breaking characters are possible.
_DB_IDENT_RE = re.compile(r"^[A-Za-z0-9_]+$")


def _resolve_ghost_db(ssh, ghost_dir):
    """Read (database, user) from ``config.production.json`` on the guest.

    Parsed with python3 rather than Node to avoid PATH issues (same approach as
    detect_ghost_version).  Returns (db, user), or (None, None) if the config
    cannot be read or parsed.
    """
    cfg = f"{ghost_dir}/config.production.json"
    py_cmd = (
        f"python3 -c \"import json; "
        f"c = json.load(open('{cfg}'))['database']['connection']; "
        f"print(json.dumps([c.get('database', ''), c.get('user', '')]))\" 2>/dev/null"
    )
    stdout, _, code = ssh.execute_sudo(py_cmd, timeout=10)
    if code != 0 or not stdout.strip():
        return None, None
    try:
        db, user = json.loads(stdout.strip())
    except (ValueError, TypeError):
        return None, None
    return (db or None), (user or None)


def _ensure_ghost_db_privileges(ssh, ghost_dir, log):
    """Make sure the Ghost MySQL user can run migration DDL before an update.

    Ghost's app user is sometimes created with a CRUD-only grant; a version bump
    can add a migration needing DDL (CREATE VIEW, ALTER, index creation, ...)
    the user lacks, so the upgrade fails only on update with errno 1142 (FM4).
    This asserts, *before* 'ghost update', that 'user'@'localhost' already holds
    ALL PRIVILEGES on its own database — the grant Ghost's own docs recommend,
    scoped to the single DB rather than ``*.*``.

    Check-first, so it is idempotent and never auto-creates a missing account (a
    bare GRANT would, with no password).  Best-effort: any problem logs a
    warning and returns False without aborting the upgrade.  Runs as root over
    SSH, which authenticates to MariaDB via the unix socket.
    """
    db, user = _resolve_ghost_db(ssh, ghost_dir)
    if not db or not user:
        log("WARNING: could not resolve database/user from config.production.json "
            "— skipping DB privilege check")
        return False
    if not _DB_IDENT_RE.match(db) or not _DB_IDENT_RE.match(user):
        log(f"WARNING: resolved DB name/user has unexpected characters "
            f"(db={db!r}, user={user!r}) — skipping DB privilege check")
        return False

    show_sql = f"SHOW GRANTS FOR '{user}'@'localhost'"  # noqa: S608
    grants_out, grants_err, grants_code = ssh.execute_sudo(
        f'mysql -u root -e "{show_sql}"', timeout=15
    )
    if grants_code != 0:
        log(f"WARNING: could not read MySQL grants for '{user}'@'localhost' "
            f"(account may not exist) — skipping DB privilege check: "
            f"{(grants_err or '').strip()[:200]}")
        return False

    has_all = any(
        ("ALL PRIVILEGES ON *.*" in ln) or (f"ALL PRIVILEGES ON `{db}`.*" in ln)
        for ln in grants_out.splitlines()
    )
    if has_all:
        log(f"MySQL user '{user}' already holds ALL PRIVILEGES on `{db}` — no change needed")
        return True

    log(f"Granting ALL PRIVILEGES on `{db}` to '{user}'@'localhost' "
        f"(prevents migration DDL failures)...")
    grant_sql = f"GRANT ALL PRIVILEGES ON {db}.* TO '{user}'@'localhost'; FLUSH PRIVILEGES;"  # noqa: S608
    g_out, g_err, g_code = ssh.execute_sudo(f'mysql -u root -e "{grant_sql}"', timeout=15)
    if g_code != 0:
        log(f"WARNING: GRANT failed (exit {g_code}) — proceeding anyway: "
            f"{(g_err or g_out or '').strip()[:200]}")
        return False
    log(f"MySQL privileges granted for '{user}'@'localhost' on `{db}`")
    return True


# ---------------------------------------------------------------------------
# Version detection
# ---------------------------------------------------------------------------

def detect_ghost_version(guest, ghost_dir, user="ghost"):
    """Detect the installed Ghost version via SSH.

    Commands run as *user* (via su -) so that Node.js installed under that
    user's profile (nvm, n, system package) is on PATH.

    Returns (version_string, None) on success, or (None, error_message) on failure.
    """
    from models import Credential

    try:
        _validate_shell_param(ghost_dir, "Ghost dir")
        _validate_shell_param(user, "Ghost user")
    except ValueError as e:
        return None, str(e)

    credential = guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return None, "No SSH credential configured for this guest"
    if not guest.ip_address:
        return None, "No IP address set on the Ghost guest"

    try:
        with SSHClient.from_credential(guest.ip_address, credential) as ssh:
            # Pre-check: verify the configured directory exists.
            # If it doesn't, scan for .ghost-cli files to help the user find the right path.
            stdout, stderr, code = ssh.execute_sudo(
                f"test -d {ghost_dir} && echo ok", timeout=10
            )
            if not (code == 0 and "ok" in (stdout or "")):
                found = ""
                scan_out, _, scan_code = ssh.execute_sudo(
                    "find /var /home /opt /srv -maxdepth 5 -name '.ghost-cli' 2>/dev/null | head -5",
                    timeout=15,
                )
                if scan_code == 0 and scan_out.strip():
                    paths = [
                        _osp.dirname(p.strip())
                        for p in scan_out.strip().splitlines()
                        if p.strip()
                    ]
                    found = f" Found Ghost install(s) at: {', '.join(paths)}"
                return None, f"Directory '{ghost_dir}' does not exist on the guest.{found}"

            # Method 1: read .ghost-cli metadata file — ghost-cli always writes this,
            # no Node.js required.  Contains {"active-version": "5.82.0", ...}
            stdout, stderr, code = ssh.execute_sudo(
                f"cat {ghost_dir}/.ghost-cli 2>/dev/null", timeout=10
            )
            if code == 0 and stdout.strip():
                m = re.search(r'"active-version"\s*:\s*"([^"]+)"', stdout)
                if m:
                    return m.group(1), None

            ghost_cli_err = (stderr or "").strip()

            # Method 2: ghost version (not --version) run from install dir as ghost user.
            # Outputs "Ghost version: X.Y.Z" among other lines.
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c 'cd {ghost_dir} && ghost version 2>/dev/null'",
                timeout=20,
            )
            if code == 0 and stdout.strip():
                m = re.search(r'Ghost version:\s*(\S+)', stdout)
                if m:
                    return m.group(1), None

            ghost_ver_err = (stderr or stdout or "").strip()

            # Method 3: read current/package.json via python3 (avoids Node PATH issues)
            py_cmd = (
                f"python3 -c \"import json; "
                f"print(json.load(open('{ghost_dir}/current/package.json'))['version'])\" 2>/dev/null"
            )
            stdout, stderr, code = ssh.execute_sudo(py_cmd, timeout=10)
            if code == 0 and stdout.strip():
                v = stdout.strip().splitlines()[0].strip()
                if re.match(r'^\d+\.\d+', v):
                    return v, None

            py_err = (stderr or stdout or "").strip()

            errors = "; ".join(filter(None, [
                f".ghost-cli: {ghost_cli_err[:100]}" if ghost_cli_err else None,
                f"ghost version: {ghost_ver_err[:100]}" if ghost_ver_err else None,
                f"package.json: {py_err[:100]}" if py_err else None,
            ]))
            return None, f"All detection methods failed — {errors}" if errors else "All detection methods returned no output"

    except Exception as e:
        logger.warning("Could not detect Ghost version: %s", e)
        return None, str(e)


# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

def run_ghost_preflight(log_callback=None):
    """Run read-only pre-flight checks before Ghost upgrade.

    Validates configuration, Proxmox guest status, SSH connectivity, Ghost
    installation, Node.js availability, and service status.

    Returns (all_pass: bool, log_output: str).
    """
    from models import Credential

    config = _get_ghost_config()
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

    log("=== Ghost Pre-flight Check ===")
    log("")

    # ── A. Configuration ──────────────────────────────────────────────────────
    log("--- A. Configuration ---")

    config_ok = True
    for field, label in [
        ("guest_id", "Ghost guest"),
        ("user", "Ghost user"),
        ("ghost_dir", "Ghost directory"),
    ]:
        val = config.get(field, "")
        if val:
            check(f"{label} configured", True)
        else:
            check(f"{label} configured", False, "not set in settings")
            config_ok = False

    protection_type = config.get("protection_type", "snapshot")
    backup_storage = config.get("backup_storage", "")
    if protection_type == "backup":
        if backup_storage:
            check("Backup storage configured", True)
        else:
            check("Backup storage configured", False, "backup protection selected but no storage configured")
            config_ok = False

    user = config.get("user", "ghost")
    ghost_dir = config.get("ghost_dir", "/var/www/ghost")

    try:
        _validate_shell_param(user, "Ghost user")
        _validate_shell_param(ghost_dir, "Ghost dir")
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
    log("--- B. Proxmox guest ---")

    ghost_guest = Guest.query.get(int(config["guest_id"]))
    check("Ghost guest in database", ghost_guest is not None,
          f"guest ID {config['guest_id']} not found")

    if not ghost_guest:
        log("")
        log(f"=== Pre-flight complete: {checks_passed}/{checks_total} checks passed — "
            f"{checks_failed} failure(s), upgrade blocked ===")
        return False, "\n".join(log_lines)

    if ghost_guest.proxmox_host:
        try:
            client = ProxmoxClient(ghost_guest.proxmox_host)
            node = client.find_guest_node(ghost_guest.vmid)
            if not node:
                check(f"{ghost_guest.name} found on Proxmox", False, "not found on any PVE node")
            else:
                check(f"{ghost_guest.name} found on Proxmox", True)
                status = client.get_guest_status(node, ghost_guest.vmid, ghost_guest.guest_type)
                check(f"{ghost_guest.name} running", status == "running",
                      f"current status: {status}")
                if protection_type == "snapshot":
                    supports_snap = client.guest_supports_snapshot(
                        node, ghost_guest.vmid, ghost_guest.guest_type
                    )
                    check(f"{ghost_guest.name} supports snapshots", supports_snap,
                          "storage does not support snapshots — switch to Backup protection")
        except Exception as e:
            check(f"{ghost_guest.name} Proxmox reachable", False, str(e))
    else:
        log(f"  [WARN] {ghost_guest.name} has no Proxmox host configured — skipping Proxmox checks")

    # ── C. SSH checks ─────────────────────────────────────────────────────────
    log("")
    log(f"--- C. SSH checks on {ghost_guest.name} ---")

    credential = ghost_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()

    if not credential:
        check("SSH credential available", False,
              "no credential configured for ghost guest or as default")
    elif not ghost_guest.ip_address:
        check("SSH credential available", True)
        check("Ghost guest IP configured", False, "no IP address set on guest")
    else:
        check("SSH credential available", True)
        check("Ghost guest IP configured", True)
        try:
            with SSHClient.from_credential(ghost_guest.ip_address, credential) as ssh:
                check("SSH connection established", True)

                # Ghost directory exists
                stdout, stderr, code = ssh.execute_sudo(
                    f"test -d {ghost_dir} && echo ok", timeout=10
                )
                check(f"Ghost directory {ghost_dir} exists",
                      code == 0 and "ok" in (stdout or ""),
                      "directory not found")

                # Ghost CLI available (try PATH first, then node_modules/.bin)
                stdout, stderr, code = ssh.execute_sudo(
                    f"su - {user} -c 'which ghost 2>/dev/null && echo ok || "
                    f"(test -x {ghost_dir}/node_modules/.bin/ghost && echo ok)'",
                    timeout=10,
                )
                ghost_cli_ok = code == 0 and "ok" in (stdout or "")
                check("Ghost CLI available", ghost_cli_ok,
                      f"ghost command not found — check Ghost CLI installation in {ghost_dir}")

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

                # Current Ghost version (informational) — read .ghost-cli metadata
                stdout, stderr, code = ssh.execute_sudo(
                    f"cat {ghost_dir}/.ghost-cli 2>/dev/null", timeout=10
                )
                if code == 0 and stdout.strip():
                    m = re.search(r'"active-version"\s*:\s*"([^"]+)"', stdout)
                    if m:
                        log(f"  [INFO] Ghost current version: {m.group(1)}")
                    else:
                        log("  [WARN] .ghost-cli exists but active-version not found")
                else:
                    log(f"  [WARN] Could not read {ghost_dir}/.ghost-cli"
                        + (f" — {(stderr or '').strip()}" if stderr else ""))

                # File permissions (informational) — ghost-cli rejects files
                # outside versions/ that have wrong modes.
                stdout, stderr, code = ssh.execute_sudo(
                    f"find {ghost_dir} ! -path '*/versions/*' -type f ! -perm 664 "
                    f"2>/dev/null | head -5",
                    timeout=20,
                )
                bad_files = [ln.strip() for ln in (stdout or "").splitlines() if ln.strip()]
                if bad_files:
                    log(f"  [WARN] {len(bad_files)}+ file(s) with non-664 permissions "
                        f"(will be fixed during upgrade)")
                else:
                    log("  [INFO] File permissions look correct")

                # Service status (informational)
                dir_basename = _osp.basename(ghost_dir.rstrip("/"))
                service_name = f"ghost_{dir_basename}"
                stdout, stderr, code = ssh.execute_sudo(
                    f"systemctl is-active {service_name} 2>/dev/null", timeout=10
                )
                service_status = (stdout or "").strip()
                if service_status == "active":
                    log(f"  [INFO] Ghost service ({service_name}) is active")
                elif service_status:
                    log(f"  [WARN] Ghost service ({service_name}) status: {service_status}")
                else:
                    log("  [WARN] Could not determine Ghost service status")

        except Exception as e:
            check("SSH connection established", False, str(e))

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

def run_ghost_upgrade(log_callback=None, skip_protection=False):
    """Run the Ghost upgrade via SSH using ghost-cli.

    Steps:
    1. Snapshot or backup the guest.
    2. SSH: su - {user} -c 'cd {ghost_dir} && ghost update'
    3. Verify the Ghost service is running.

    Returns (ok: bool, log_output: str).
    """
    from models import Credential

    config = _get_ghost_config()
    log_lines = []

    def log(msg):
        logger.info(msg)
        log_lines.append(msg)
        if log_callback:
            log_callback(msg)

    # Validate config
    if not config["guest_id"]:
        return False, "Ghost guest not configured"

    ghost_guest = Guest.query.get(int(config["guest_id"]))
    if not ghost_guest:
        return False, "Ghost guest not found"

    user = config["user"]
    ghost_dir = config["ghost_dir"]

    try:
        _validate_shell_param(user, "Ghost user")
        _validate_shell_param(ghost_dir, "Ghost dir")
    except ValueError as e:
        return False, str(e)

    credential = ghost_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return False, "No SSH credential available for Ghost guest"
    if not ghost_guest.ip_address:
        return False, "No IP address configured for Ghost guest"

    # --- Step 1: Protection ---
    if skip_protection:
        log("=== Step 1: Skipping snapshot/backup (requested by super-admin) ===")
    else:
        protection_type = config.get("protection_type", "snapshot")
        backup_storage = config.get("backup_storage", "")

        if protection_type == "backup" and not backup_storage:
            return False, "Backup protection selected but no backup storage is configured"

        if protection_type == "backup":
            backup_mode = config.get("backup_mode", "snapshot")
            log(f"=== Step 1: Creating vzdump backup to storage '{backup_storage}' "
                f"(mode: {backup_mode}) ===")
            log("(This may take several minutes — please be patient)")
            ok, msg = backup_guest(ghost_guest, backup_storage, "ghost", mode=backup_mode)
            log(f"Backup {ghost_guest.name}: {msg}")
            if not ok:
                return False, "\n".join(log_lines)
        else:
            log(f"=== Step 1: Creating Proxmox snapshot of {ghost_guest.name} ===")
            ok, msg = snapshot_guest(ghost_guest, "ghost")
            log(f"Snapshot {ghost_guest.name}: {msg}")
            if not ok:
                return False, "\n".join(log_lines)

    log("")

    # --- Step 2: Ghost update via SSH ---
    log("=== Step 2: Running ghost update ===")

    try:
        with SSHClient.from_credential(ghost_guest.ip_address, credential) as ssh:
            # Detect the real service name from .ghost-cli.  ghost-cli names services
            # after the site hostname (e.g. ghost_news-mstdn-ca), not the directory.
            service_name = f"ghost_{_osp.basename(ghost_dir.rstrip('/'))}"  # fallback
            ghost_cli_raw, _, cli_rc = ssh.execute_sudo(
                f"cat {ghost_dir}/.ghost-cli 2>/dev/null", timeout=10
            )
            if cli_rc == 0 and ghost_cli_raw.strip():
                m_name = re.search(r'"name"\s*:\s*"([^"]+)"', ghost_cli_raw)
                if m_name and re.match(r"^[a-zA-Z0-9_-]+$", m_name.group(1)):
                    service_name = f"ghost_{m_name.group(1)}"
            log(f"Ghost service name: {service_name}")

            # Write/refresh the sudoers entry for ghost_user.  ghost-cli uses
            # 'sudo systemctl ...' to manage the service; without NOPASSWD entries
            # sudo prompts for a password, ghost-cli detects it and calls prompt(),
            # which throws in non-TTY mode.  Always overwrite so the entry stays
            # current if new systemctl sub-commands are required by updated ghost-cli.
            sudoers_path = f"/etc/sudoers.d/ghost-{service_name}"
            sc_out, _, _ = ssh.execute_sudo(
                "command -v systemctl 2>/dev/null || echo /usr/bin/systemctl",
                timeout=5,
            )
            systemctl = (sc_out or "").strip() or "/usr/bin/systemctl"
            sudoers_lines = [
                "# Managed by mstdnca-proxmox-tool",
            ] + [
                f"{user} ALL=(root) NOPASSWD: {systemctl} {action} {service_name}"
                for action in ("start", "stop", "restart", "reset-failed",
                               "is-active", "is-enabled", "enable", "disable")
            ] + [
                f"{user} ALL=(root) NOPASSWD: {systemctl} daemon-reload",
            ]
            write_parts = [
                f"echo '{line}' {'>' if i == 0 else '>>'} {sudoers_path}"
                for i, line in enumerate(sudoers_lines)
            ] + [f"chmod 440 {sudoers_path}"]
            _, w_err, w_code = ssh.execute_sudo(" && ".join(write_parts), timeout=15)
            if w_code == 0:
                log(f"Sudoers entry written: {sudoers_path}")
            else:
                log(f"WARNING: Could not write sudoers: {(w_err or '').strip()}")
            log("")

            # Update ghost-cli itself first so it doesn't try to interactively prompt
            # about running an outdated version (which throws in non-TTY SSH sessions).
            log("Updating ghost-cli to latest version...")
            cli_cmd = "npm install -g ghost-cli@latest 2>&1"
            stdout, stderr, code = ssh.execute_sudo(cli_cmd, timeout=120)
            _log_cmd_output(log, stdout, stderr, code, max_chars=2000)
            if code != 0:
                log("WARNING: ghost-cli update failed — proceeding anyway")
            log("")

            # Fix file/directory permissions before update.  ghost-cli's
            # check-permissions step rejects files with wrong modes (e.g. yarn
            # cache files with executable bits), so do it proactively to keep
            # the update from aborting.
            log("Fixing file permissions...")
            _fix_ghost_permissions(ssh, ghost_dir, user, log)
            log("")

            # Ensure the Ghost DB user can run migration DDL *before* the update
            # touches the schema.  A CRUD-only grant makes version-bump
            # migrations fail with errno 1142 (FM4); this asserts the
            # ALL-PRIVILEGES grant (scoped to the Ghost DB) up front.  Non-fatal.
            log("Checking MySQL privileges for the Ghost database user...")
            _ensure_ghost_db_privileges(ssh, ghost_dir, log)
            log("")

            # Run ghost update as the Ghost system user.  su - creates a full login
            # shell so ghost-cli can find Node.js on PATH and interact with systemd.
            # --no-prompt disables interactive confirmations for non-TTY environments.
            update_cmd = f"su - {user} -c 'cd {ghost_dir} && ghost update --no-prompt'"
            log(f"Running: {update_cmd}")
            stdout, stderr, code = ssh.execute_sudo(update_cmd, timeout=600)
            _log_cmd_output(log, stdout, stderr, code, max_chars=4000)

            if code != 0:
                log(f"ERROR: ghost update failed (exit {code})")
                return False, "\n".join(log_lines)

            log("ghost update completed successfully")
            log("")

            # --- Step 2b: Re-assert permissions after the update ---
            # 'ghost update' unpacks a new versions/<v> tree and runs
            # migrations, which can leave content/ files owned by root — Ghost
            # then hits EACCES on the next content read/write.  Re-run the same
            # remediation, then restart so the service comes up against the
            # corrected tree ('ghost update' already started it, possibly
            # against root-owned content).
            log("=== Step 2b: Re-asserting file permissions ===")
            _fix_ghost_permissions(ssh, ghost_dir, user, log)
            log(f"Restarting {service_name} to apply permission fix...")
            r_out, r_err, r_code = ssh.execute_sudo(
                f"systemctl restart {service_name} 2>&1", timeout=30
            )
            if r_code != 0:
                log(f"WARNING: restart returned exit {r_code}: "
                    f"{(r_err or r_out or '').strip()[:200]}")
            log("")

            # --- Step 3: Verify service ---
            log("=== Step 3: Verifying Ghost service ===")
            stdout, stderr, code = ssh.execute_sudo(
                f"systemctl is-active {service_name} 2>/dev/null", timeout=15
            )
            service_status = (stdout or "").strip()
            if service_status == "active":
                log(f"Ghost service ({service_name}) is active — upgrade successful")
            else:
                log(f"Ghost service ({service_name}) is {service_status or 'unknown'} "
                    f"— attempting to start...")
                stdout, stderr, code = ssh.execute_sudo(
                    f"systemctl start {service_name} 2>&1", timeout=30
                )
                if (stdout or "").strip():
                    log((stdout or "").strip())
                # Re-check
                stdout, stderr, code = ssh.execute_sudo(
                    f"systemctl is-active {service_name} 2>/dev/null", timeout=15
                )
                service_status = (stdout or "").strip()
                if service_status == "active":
                    log(f"Ghost service ({service_name}) started successfully.")
                else:
                    log(f"WARNING: Ghost service ({service_name}) is still "
                        f"{service_status or 'unknown'} after start attempt.")
                    # Show recent journal entries to aid diagnosis
                    stdout, _, _ = ssh.execute_sudo(
                        f"journalctl -u {service_name} -n 20 --no-pager 2>/dev/null",
                        timeout=15,
                    )
                    if (stdout or "").strip():
                        log("--- Recent service journal ---")
                        log((stdout or "").strip())

            # Detect and persist new version via .ghost-cli metadata
            stdout, stderr, code = ssh.execute_sudo(
                f"cat {ghost_dir}/.ghost-cli 2>/dev/null", timeout=10
            )
            if code == 0 and stdout.strip():
                m = re.search(r'"active-version"\s*:\s*"([^"]+)"', stdout)
                if m:
                    Setting.set("ghost_current_version", m.group(1))
                    Setting.set("ghost_update_available", "false")
                    log(f"Updated Ghost version: {m.group(1)}")

    except Exception as e:
        log(f"SSH ERROR: {e}")
        return False, "\n".join(log_lines)

    log("")
    log("=== Ghost upgrade complete ===")
    return True, "\n".join(log_lines)
