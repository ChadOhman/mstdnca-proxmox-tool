"""
Harmony upgrade automation.

Harmony (https://docs.mony.lol/self-host/) is a self-hosted chat server run as
a Docker Compose stack from a git checkout (``/opt/harmony`` by default) and
operated through its own ``self-host/harmony`` CLI.  This module never touches
the compose files directly: every remote action goes through that CLI (or a
read-only ``docker compose`` / ``psql`` query run from ``self-host``), so a
local overlay named by ``COMPOSE_FILE`` in ``self-host/.env`` keeps applying.

Upgrade flow:
1. Proxmox snapshot or vzdump backup of the Harmony guest.
2. ``harmony backup --no-storage``: database, roles and config secrets.
3. ``harmony update --version X.Y.Z`` (streamed; pulls images, migrates,
   recreates containers).
4. Verification: the reported version is the target, selected
   ``harmony doctor --offline`` checks pass, and ``realtime.messages`` still
   has a SELECT policy.

The verification deliberately does not use doctor's exit status or its FAIL
count: an instance behind a tunnel or NAT has permanent DNS / reachability
FAILs and WARNs that say nothing about whether the upgrade worked.
"""

import json
import logging
import re
import shlex
import time
from urllib.request import Request, urlopen

from apps.backup import backup_guest, snapshot_guest
from apps.utils import _log_cmd_output, _validate_abs_path, _validate_release_tag, _version_gt
from clients.proxmox_api import ProxmoxClient
from clients.ssh_client import SSHClient
from core.errors import describe_exception
from models import Guest, Setting

logger = logging.getLogger(__name__)

_HARMONY_GITHUB_API = "https://api.github.com/repos/y4my4my4m/harmony/releases/latest"
_HARMONY_RELEASE_BASE = "https://github.com/y4my4my4m/harmony/releases/tag/{tag}"

# The only version form handed to ``harmony update --version``: the CLI turns
# X.Y.Z into the tag vX.Y.Z, while anything else is taken as a branch name.
_STRICT_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")

# `harmony update` pulls images and runs migrations; give it a generous budget.
_UPDATE_TIMEOUT = 45 * 60
_BACKUP_TIMEOUT = 30 * 60
_DOCTOR_TIMEOUT = 5 * 60

# Post-upgrade verification retries while containers finish starting.
_VERIFY_ATTEMPTS = 3
_VERIFY_DELAY = 30

# Minimum free space on the checkout's filesystem before an upgrade (images +
# a database dump land there).
_MIN_FREE_KB = 2 * 1024 * 1024

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_DOCTOR_LINE_RE = re.compile(r"^\[\s*(OK|WARN|FAIL)\s*\]\s+(.*)$")

# doctor checks that must not FAIL after an upgrade (matched on the check name
# at the start of the line).  ``required`` checks must also be present.
_GATED_CHECKS = (
    ("database", False),
    ("migrations", True),
    ("auth", True),
    ("livekit", False),
)

# Upstream bug y4my4my4m/harmony#168: a migration can leave realtime.messages
# without a SELECT policy, which silently breaks private broadcast channels.
_REALTIME_POLICY_SQL = (
    "SELECT count(*) FROM pg_policies "
    "WHERE schemaname = 'realtime' AND tablename = 'messages' AND cmd IN ('SELECT', 'ALL')"
)


# ---------------------------------------------------------------------------
# Version check
# ---------------------------------------------------------------------------

def check_harmony_release():
    """Check GitHub for the latest Harmony release.

    Returns (update_available, latest_version, release_url).
    """
    try:
        req = Request(_HARMONY_GITHUB_API, headers={"User-Agent": "mstdnca-proxmox-tool"})
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())

        tag = data.get("tag_name", "")
        if not tag:
            return False, "", ""

        # The version is passed to `harmony update --version` on the guest;
        # accept nothing but a plain vX.Y.Z release tag.
        try:
            _validate_release_tag(tag, "Harmony release tag")
        except ValueError as e:
            logger.error("Rejected Harmony release tag: %s", e)
            return False, "", ""
        latest = tag.lstrip("vV")
        if not _STRICT_VERSION_RE.fullmatch(latest):
            logger.error("Rejected Harmony release tag %r: not an X.Y.Z release", tag)
            return False, "", ""

        release_url = _HARMONY_RELEASE_BASE.format(tag=tag)

        Setting.set("harmony_latest_release_tag", tag)
        Setting.set("harmony_latest_version", latest)
        Setting.set("harmony_latest_release_url", release_url)

        current = Setting.get("harmony_current_version", "")
        update_available = bool(current and _version_gt(latest, current))
        Setting.set("harmony_update_available", "true" if update_available else "false")

        return update_available, latest, release_url
    except Exception as e:
        logger.error("Failed to check Harmony releases: %s", e)
        return False, "", ""


# ---------------------------------------------------------------------------
# Config / SSH helpers
# ---------------------------------------------------------------------------

def _get_harmony_config():
    """Read all Harmony-related settings."""
    return {
        "guest_id": Setting.get("harmony_guest_id", ""),
        "harmony_dir": Setting.get("harmony_dir", "/opt/harmony"),
        "current_version": Setting.get("harmony_current_version", ""),
        "latest_version": Setting.get("harmony_latest_version", ""),
        "protection_type": Setting.get("harmony_protection_type", "snapshot"),
        "backup_storage": Setting.get("harmony_backup_storage", ""),
        "backup_mode": Setting.get("harmony_backup_mode", "snapshot"),
        "auto_upgrade": Setting.get("harmony_auto_upgrade", "false") == "true",
    }


def _self_host_dir(harmony_dir):
    return f"{harmony_dir}/self-host"


def _cli(harmony_dir):
    """Absolute path of the operator CLI (``/usr/local/bin/harmony`` links to it)."""
    return f"{harmony_dir}/self-host/harmony"


def _resolve_credential(guest):
    from models import Credential

    credential = guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    return credential


def _strip_ansi(text):
    return _ANSI_RE.sub("", text or "")


class _LineLog:
    """Turn streamed output chunks into whole log lines."""

    def __init__(self, log):
        self._log = log
        self._buf = ""

    def feed(self, chunk):
        self._buf += _strip_ansi(chunk).replace("\r\n", "\n").replace("\r", "\n")
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            self._log(line.rstrip())

    def flush(self):
        if self._buf.strip():
            self._log(self._buf.rstrip())
        self._buf = ""


# ---------------------------------------------------------------------------
# Version detection
# ---------------------------------------------------------------------------

def parse_harmony_version(output):
    """Parse ``harmony version`` output.

    The command prints ``git describe --tags --always`` of the checkout, then
    the image tag (``HARMONY_VERSION`` in ``self-host/.env``).

    Returns (version, code_ref, image_tag); ``version`` is an X.Y.Z string or
    None when the instance runs something else (the ``edge`` channel, a branch).
    """
    lines = [ln.strip() for ln in _strip_ansi(output).splitlines() if ln.strip()]
    code_ref = lines[0] if lines else ""
    image_tag = lines[1] if len(lines) > 1 else ""
    version = None
    if _STRICT_VERSION_RE.fullmatch(image_tag.lstrip("vV")):
        version = image_tag.lstrip("vV")
    elif _STRICT_VERSION_RE.fullmatch(code_ref.lstrip("vV")):
        version = code_ref.lstrip("vV")
    return version, code_ref, image_tag


def _read_version(ssh, harmony_dir):
    """Run ``harmony version`` on an open connection.

    Returns (version, code_ref, image_tag, error).
    """
    stdout, stderr, code = ssh.execute_sudo(f"{_cli(harmony_dir)} version", timeout=30)
    if code != 0 or not (stdout or "").strip():
        detail = (stderr or stdout or "").strip()[:200]
        return None, "", "", f"'harmony version' failed (exit {code}){': ' + detail if detail else ''}"
    version, code_ref, image_tag = parse_harmony_version(stdout)
    if not version:
        return None, code_ref, image_tag, (
            f"Harmony is not on a release (code {code_ref or '?'}, images {image_tag or '?'}); "
            "version tracking needs a vX.Y.Z checkout"
        )
    return version, code_ref, image_tag, None


def detect_harmony_version(guest, harmony_dir):
    """Detect the installed Harmony version via SSH.

    Returns (version_string, None) on success, or (None, error_message).
    """
    try:
        _validate_abs_path(harmony_dir, "Harmony directory")
    except ValueError as e:
        return None, str(e)

    credential = _resolve_credential(guest)
    if not credential:
        return None, "No SSH credential configured for this guest"
    if not guest.ip_address:
        return None, "No IP address set on the Harmony guest"

    try:
        with SSHClient.from_credential(guest.ip_address, credential) as ssh:
            stdout, _, code = ssh.execute_sudo(f"test -x {_cli(harmony_dir)} && echo ok", timeout=10)
            if not (code == 0 and "ok" in (stdout or "")):
                return None, f"Harmony CLI not found at {_cli(harmony_dir)}"
            version, _, _, err = _read_version(ssh, harmony_dir)
            return version, err
    except Exception as e:
        logger.warning("Could not detect Harmony version: %s", e)
        return None, f"SSH error: {describe_exception(e)}"


# ---------------------------------------------------------------------------
# Health: selected doctor checks + realtime policy
# ---------------------------------------------------------------------------

def evaluate_doctor_output(output):
    """Pick the doctor checks that decide whether the instance is healthy.

    Gates:
    * no FAIL in the "Containers" section (a service not created, not
      running, or unhealthy);
    * ``migrations`` and ``auth`` present and not FAIL;
    * ``database`` and ``livekit`` (voice only) not FAIL when present.

    Everything else (DNS, TLS, reachability, published ports, versions, ...)
    is informational: behind a tunnel or NAT those can FAIL permanently.

    Returns (ok, results) where results is a list of (label, passed, detail).
    """
    section = ""
    container_fails = []
    containers_seen = False
    found = {}

    for raw in _strip_ansi(output).splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        m = _DOCTOR_LINE_RE.match(line)
        if not m:
            if not line.startswith((" ", "\t")) and not line.startswith("Harmony doctor"):
                section = line.strip()
            continue
        level, rest = m.group(1), m.group(2)
        if section == "Containers":
            containers_seen = True
            if level == "FAIL":
                container_fails.append(rest.strip())
        name = rest.split(None, 1)[0] if rest.strip() else ""
        for check, _required in _GATED_CHECKS:
            if name == check and not (section == "Containers"):
                # Keep the worst result when a check name appears twice
                # (``database`` is reported by two sections).
                prev = found.get(check)
                if prev is None or prev[0] != "FAIL":
                    found[check] = (level, rest.strip())

    results = []
    if not containers_seen:
        results.append(("containers", False, "doctor printed no Containers section"))
    elif container_fails:
        results.append(("containers", False, "; ".join(container_fails)))
    else:
        results.append(("containers", True, "no container FAILs"))

    for check, required in _GATED_CHECKS:
        if check in found:
            level, detail = found[check]
            results.append((check, level != "FAIL", f"[{level}] {detail}"))
        elif required:
            results.append((check, False, "check missing from doctor output"))

    return all(passed for _, passed, _ in results), results


def _realtime_policy_cmd(harmony_dir):
    """Count SELECT-capable policies on realtime.messages in the stack's Postgres."""
    sql = shlex.quote(_REALTIME_POLICY_SQL)
    return (
        f"cd {_self_host_dir(harmony_dir)}"
        " && id=$(docker compose ps -q --status running db 2>/dev/null | head -1)"
        ' && docker exec -i "${id:-supabase-db}" psql -U supabase_admin -h 127.0.0.1 -d postgres'
        f" -v ON_ERROR_STOP=1 -qtAX -c {sql}"
    )


def check_realtime_policy(ssh, harmony_dir):
    """Return (passed, detail) for the realtime.messages SELECT-policy check."""
    stdout, stderr, code = ssh.execute_sudo(_realtime_policy_cmd(harmony_dir), timeout=60)
    if code != 0:
        detail = (stderr or stdout or "").strip()[:200]
        return False, f"query failed (exit {code}){': ' + detail if detail else ''}"
    lines = [ln.strip() for ln in (stdout or "").splitlines() if ln.strip()]
    count = lines[-1] if lines else ""
    if not count.isdigit():
        return False, f"unexpected output: {count[:100]!r}"
    if int(count) < 1:
        return False, ("realtime.messages has no SELECT policy — private broadcast "
                       "channels stop delivering (y4my4my4m/harmony#168)")
    return True, f"{count} SELECT policy(ies) on realtime.messages"


def _run_health_checks(ssh, harmony_dir):
    """Run doctor + the realtime policy query on an open connection.

    Returns (ok, results, doctor_output, doctor_exit_code).
    """
    stdout, stderr, code = ssh.execute_sudo(
        f"cd {_self_host_dir(harmony_dir)} && {_cli(harmony_dir)} doctor --offline",
        timeout=_DOCTOR_TIMEOUT,
    )
    output = _strip_ansi((stdout or "") + ("\n" + stderr if stderr else ""))
    _, results = evaluate_doctor_output(output)
    results.append(("realtime policy", *check_realtime_policy(ssh, harmony_dir)))
    return all(passed for _, passed, _ in results), results, output, code


def _log_doctor(log, output, code):
    if not output.strip():
        return
    log("--- harmony doctor --offline ---")
    for line in output.strip().splitlines():
        log(line.rstrip())
    log(f"--- doctor exit {code} (informational, not a gate) ---")


def _log_results(log, results):
    for label, passed, detail in results:
        log(f"  [{'PASS' if passed else 'FAIL'}] {label} — {detail}")


def run_harmony_health_check(log_callback=None):
    """Run the health gates on demand (read-only).

    Returns (ok: bool, log_output: str).
    """
    config = _get_harmony_config()
    log_lines = []

    def log(msg):
        logger.info(msg)
        log_lines.append(msg)
        if log_callback:
            log_callback(msg)

    guest, harmony_dir, credential, err = _resolve_target(config)
    if err:
        log(f"ERROR: {err}")
        return False, "\n".join(log_lines)

    log("=== Harmony health check ===")
    try:
        with SSHClient.from_credential(guest.ip_address, credential) as ssh:
            version, code_ref, image_tag, verr = _read_version(ssh, harmony_dir)
            log(f"Version: {version or '?'} (code {code_ref or '?'}, images {image_tag or '?'})"
                if not verr else f"WARNING: {verr}")
            ok, results, output, code = _run_health_checks(ssh, harmony_dir)
            _log_doctor(log, output, code)
    except Exception as e:
        log(f"SSH ERROR: {describe_exception(e)}")
        return False, "\n".join(log_lines)

    log("")
    log("=== Gates ===")
    _log_results(log, results)
    log("")
    log("=== Healthy ===" if ok else "=== Unhealthy: see the FAIL gates above ===")
    return ok, "\n".join(log_lines)


def _resolve_target(config):
    """Validate config and resolve (guest, harmony_dir, credential, error)."""
    if not config["guest_id"]:
        return None, None, None, "Harmony guest not configured"
    try:
        guest = Guest.query.get(int(config["guest_id"]))
    except (TypeError, ValueError):
        guest = None
    if not guest:
        return None, None, None, "Harmony guest not found"
    harmony_dir = config["harmony_dir"]
    try:
        _validate_abs_path(harmony_dir, "Harmony directory")
    except ValueError as e:
        return None, None, None, str(e)
    credential = _resolve_credential(guest)
    if not credential:
        return None, None, None, "No SSH credential available for the Harmony guest"
    if not guest.ip_address:
        return None, None, None, "No IP address configured for the Harmony guest"
    return guest, harmony_dir, credential, None


# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

def run_harmony_preflight(log_callback=None):
    """Run read-only pre-flight checks before a Harmony upgrade.

    Returns (all_pass: bool, log_output: str).
    """
    config = _get_harmony_config()
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

    def finish():
        log("")
        if checks_failed == 0:
            log(f"=== Pre-flight complete: {checks_passed}/{checks_total} checks passed — all clear ===")
        else:
            log(f"=== Pre-flight complete: {checks_passed}/{checks_total} checks passed — "
                f"{checks_failed} failure(s), upgrade blocked ===")
        return checks_failed == 0, "\n".join(log_lines)

    log("=== Harmony Pre-flight Check ===")
    log("")
    log("--- A. Configuration ---")

    check("Harmony guest configured", bool(config["guest_id"]), "not set in settings")
    harmony_dir = config["harmony_dir"]
    try:
        _validate_abs_path(harmony_dir, "Harmony directory")
        check("Harmony directory is a safe absolute path", True)
    except ValueError as e:
        check("Harmony directory is a safe absolute path", False, str(e))

    protection_type = config["protection_type"]
    if protection_type == "backup":
        check("Backup storage configured", bool(config["backup_storage"]),
              "backup protection selected but no storage configured")

    latest = config["latest_version"]
    if latest:
        check(f"Target release v{latest} is an X.Y.Z release",
              bool(_STRICT_VERSION_RE.fullmatch(latest)), "refusing to pass it to harmony update")
    else:
        log("  [WARN] Latest release not checked yet — use 'Check for Updates' first")

    if checks_failed:
        return finish()

    log("")
    log("--- B. Proxmox guest ---")
    try:
        guest = Guest.query.get(int(config["guest_id"]))
    except (TypeError, ValueError):
        guest = None
    check("Harmony guest in database", guest is not None, f"guest ID {config['guest_id']} not found")
    if not guest:
        return finish()

    if guest.proxmox_host:
        try:
            client = ProxmoxClient(guest.proxmox_host)
            node = client.find_guest_node(guest.vmid)
            if not node:
                check(f"{guest.name} found on Proxmox", False, "not found on any PVE node")
            else:
                check(f"{guest.name} found on Proxmox", True)
                status = client.get_guest_status(node, guest.vmid, guest.guest_type)
                check(f"{guest.name} running", status == "running", f"current status: {status}")
                if protection_type == "snapshot":
                    check(f"{guest.name} supports snapshots",
                          client.guest_supports_snapshot(node, guest.vmid, guest.guest_type),
                          "storage does not support snapshots — switch to Backup protection")
        except Exception as e:
            check(f"{guest.name} Proxmox reachable", False, describe_exception(e))
    else:
        log(f"  [WARN] {guest.name} has no Proxmox host configured — skipping Proxmox checks")

    log("")
    log(f"--- C. SSH checks on {guest.name} ---")
    credential = _resolve_credential(guest)
    if not credential:
        check("SSH credential available", False, "no credential configured for the guest or as default")
        return finish()
    check("SSH credential available", True)
    if not guest.ip_address:
        check("Harmony guest IP configured", False, "no IP address set on guest")
        return finish()
    check("Harmony guest IP configured", True)

    self_host = _self_host_dir(harmony_dir)
    try:
        with SSHClient.from_credential(guest.ip_address, credential) as ssh:
            check("SSH connection established", True)

            stdout, _, code = ssh.execute_sudo(f"test -x {_cli(harmony_dir)} && echo ok", timeout=10)
            check("Harmony CLI present", code == 0 and "ok" in (stdout or ""),
                  f"{_cli(harmony_dir)} not found or not executable")

            stdout, _, code = ssh.execute_sudo(f"test -f {self_host}/.env && echo ok", timeout=10)
            check("self-host/.env present (instance configured)", code == 0 and "ok" in (stdout or ""),
                  "not a configured install")

            stdout, _, code = ssh.execute_sudo("docker compose version --short 2>/dev/null", timeout=15)
            check("Docker Compose available", code == 0 and bool((stdout or "").strip()),
                  "docker compose not found")
            if code == 0 and (stdout or "").strip():
                log(f"  [INFO] Docker Compose {(stdout or '').strip()}")

            # update.sh refuses to switch tags over local changes to tracked
            # files; untracked overlays (Caddyfile.local, ...) are fine.
            stdout, stderr, code = ssh.execute_sudo(
                f"git -C {harmony_dir} status --porcelain --untracked-files=no", timeout=20
            )
            dirty = [ln for ln in (stdout or "").splitlines() if ln.strip()]
            if code != 0:
                check("Git checkout readable", False, (stderr or "").strip()[:200] or f"exit {code}")
            else:
                check("No local changes to tracked files", not dirty,
                      "harmony update would refuse to switch versions: " + ", ".join(
                          ln.strip() for ln in dirty[:5]))

            stdout, _, code = ssh.execute_sudo(
                f"df -Pk {self_host} 2>/dev/null | awk 'NR==2 {{print $4}}'", timeout=10
            )
            free_kb = (stdout or "").strip()
            if code == 0 and free_kb.isdigit():
                check(f"Free disk space ({int(free_kb) // 1048576} GB)", int(free_kb) >= _MIN_FREE_KB,
                      "under 2 GB free: images and the pre-upgrade database dump may not fit")
            else:
                log("  [WARN] Could not determine free disk space")

            version, code_ref, image_tag, verr = _read_version(ssh, harmony_dir)
            check("Running a vX.Y.Z release", version is not None, verr)
            if version:
                log(f"  [INFO] Harmony {version} (code {code_ref}, images {image_tag})")
                if latest and _STRICT_VERSION_RE.fullmatch(latest) and not _version_gt(latest, version):
                    log(f"  [INFO] Already at or above the latest release v{latest}")

            stdout, _, code = ssh.execute_sudo(
                f"cd {self_host} && docker compose ps --format '{{{{.Service}}}}: {{{{.State}}}}'",
                timeout=30,
            )
            if code == 0 and (stdout or "").strip():
                states = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
                not_running = [s for s in states if not s.endswith(": running")]
                log(f"  [INFO] {len(states)} container(s), {len(not_running)} not running"
                    + (f": {', '.join(not_running)}" if not_running else ""))
    except Exception as e:
        check("SSH connection established", False, describe_exception(e))

    return finish()


# ---------------------------------------------------------------------------
# Upgrade
# ---------------------------------------------------------------------------

def _run_protection(config, guest, log, skip_protection=False):
    """Snapshot or vzdump the Harmony guest.  Returns True on success."""
    if skip_protection:
        log("=== Step 1: Skipping snapshot/backup (requested by super-admin) ===")
        log("")
        return True

    protection_type = config.get("protection_type", "snapshot")
    backup_storage = config.get("backup_storage", "")

    if protection_type == "backup":
        if not backup_storage:
            log("ERROR: Backup protection selected but no backup storage is configured")
            return False
        backup_mode = config.get("backup_mode", "snapshot")
        log(f"=== Step 1: Creating vzdump backup to storage '{backup_storage}' (mode: {backup_mode}) ===")
        log("(This may take several minutes — please be patient)")
        ok, msg = backup_guest(guest, backup_storage, "harmony", mode=backup_mode)
        log(f"Backup {guest.name}: {msg}")
    else:
        log("=== Step 1: Creating Proxmox snapshot ===")
        ok, msg = snapshot_guest(guest, "harmony")
        log(f"Snapshot {guest.name}: {msg}")
    log("")
    return ok


def _stream_update(ssh, harmony_dir, target, skip_builtin_backup, log):
    """Run ``harmony update --version target``, streaming its output.

    Returns (exit_code, timed_out).
    """
    env = "HARMONY_SKIP_BACKUP=1 " if skip_builtin_backup else ""
    cmd = f"cd {_self_host_dir(harmony_dir)} && {env}{_cli(harmony_dir)} update --version {target}"
    log(f"Running: {cmd}")
    lines = _LineLog(lambda line: log(f"  {line}" if line else ""))
    deadline = time.monotonic() + _UPDATE_TIMEOUT
    timed_out = False

    def _stop():
        nonlocal timed_out
        if time.monotonic() >= deadline:
            timed_out = True
        return timed_out

    code = ssh.execute_sudo_streaming(cmd, lines.feed, timeout=_UPDATE_TIMEOUT, stop_fn=_stop)
    lines.flush()
    return code, timed_out


def run_harmony_upgrade(log_callback=None, skip_protection=False):
    """Upgrade Harmony to the latest checked release.

    Returns (ok: bool, log_output: str).
    """
    config = _get_harmony_config()
    log_lines = []

    def log(msg):
        logger.info(msg)
        log_lines.append(msg)
        if log_callback:
            log_callback(msg)

    def fail(msg):
        log(msg)
        return False, "\n".join(log_lines)

    guest, harmony_dir, credential, err = _resolve_target(config)
    if err:
        return False, err

    target = config["latest_version"]
    if not target:
        return False, "Latest Harmony release unknown — run 'Check for Updates' first"
    if not _STRICT_VERSION_RE.fullmatch(target):
        return False, f"Refusing to upgrade to {target!r}: not an X.Y.Z release"
    current = config["current_version"]
    if current and not _version_gt(target, current):
        return False, f"Harmony {current} is already at or above the latest release {target}"

    # --- Step 1: Proxmox protection ---
    if not _run_protection(config, guest, log, skip_protection):
        return fail("Aborting: the pre-upgrade snapshot/backup did not complete.")

    try:
        with SSHClient.from_credential(guest.ip_address, credential) as ssh:
            before, code_ref, image_tag, verr = _read_version(ssh, harmony_dir)
            if verr:
                return fail(f"ERROR: {verr}")
            log(f"Current: Harmony {before} (code {code_ref}, images {image_tag}) → target {target}")
            if not _version_gt(target, before):
                return fail(f"Harmony is already at {before}; nothing to upgrade.")
            log("")

            # --- Step 2: Harmony's own backup (DB + config secrets) ---
            log("=== Step 2: harmony backup --no-storage (database, roles, configuration) ===")
            backup_cmd = (
                f"cd {_self_host_dir(harmony_dir)} && {_cli(harmony_dir)} backup --no-storage"
                f" --label mcat-pre-{target}"
            )
            log(f"Running: {backup_cmd}")
            stdout, stderr, code = ssh.execute_sudo(backup_cmd, timeout=_BACKUP_TIMEOUT)
            _log_cmd_output(log, _strip_ansi(stdout), _strip_ansi(stderr), code, max_chars=2000)
            backup_ok = code == 0
            if backup_ok:
                log("Backup written to self-host/backups/")
            else:
                log(f"ERROR: harmony backup failed (exit {code})")
                if not skip_protection:
                    return fail("Aborting: the pre-upgrade database backup did not complete. "
                                "Re-run with 'skip protection' to override.")
                log("Continuing (protection explicitly skipped); harmony update takes its own backup.")
            log("")

            # --- Step 3: harmony update ---
            log(f"=== Step 3: harmony update --version {target} ===")
            log("(Pulls images and applies migrations — this can take several minutes)")
            code, timed_out = _stream_update(ssh, harmony_dir, target, backup_ok, log)
            if timed_out:
                return fail(f"ERROR: harmony update did not finish within {_UPDATE_TIMEOUT // 60} minutes; "
                            "check the guest before retrying ('harmony status').")
            if code != 0:
                return fail(f"ERROR: harmony update failed (exit {code}). Its 'Update stopped during' "
                            "message above says what state the instance was left in.")
            log("harmony update completed")
            log("")

            # --- Step 4: Verify ---
            log("=== Step 4: Verifying ===")
            ok = False
            results, output, doctor_code = [], "", 0
            for attempt in range(1, _VERIFY_ATTEMPTS + 1):
                after, code_ref, image_tag, _ = _read_version(ssh, harmony_dir)
                version_ok = after == target
                ok, results, output, doctor_code = _run_health_checks(ssh, harmony_dir)
                results.insert(0, ("version", version_ok,
                                   f"code {code_ref or '?'}, images {image_tag or '?'}"
                                   + ("" if version_ok else f" (expected {target})")))
                ok = ok and version_ok
                if ok:
                    break
                if attempt < _VERIFY_ATTEMPTS:
                    failing = ", ".join(label for label, passed, _ in results if not passed)
                    log(f"Attempt {attempt}/{_VERIFY_ATTEMPTS}: not healthy yet ({failing}); "
                        f"retrying in {_VERIFY_DELAY}s...")
                    time.sleep(_VERIFY_DELAY)
            _log_doctor(log, output, doctor_code)
            _log_results(log, results)
            log("")

            if not ok:
                return fail("Upgrade finished but verification failed — version tracking left unchanged. "
                            "Roll back from the snapshot, or 'harmony restore' the mcat-pre backup, if needed.")

            Setting.set("harmony_current_version", target)
            Setting.set("harmony_update_available", "false")
            log(f"Updated Harmony version: {target}")
    except Exception as e:
        logger.exception("Harmony upgrade crashed")
        return fail(f"SSH ERROR: {describe_exception(e)}")

    log("")
    log("=== Harmony upgrade complete ===")
    return True, "\n".join(log_lines)
