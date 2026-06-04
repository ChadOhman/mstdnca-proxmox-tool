"""
Mastodon (glitch-soc) upgrade automation.

Checks the mastodon/mastodon GitHub repo for new releases, takes Proxmox
snapshots of the app and database guests, creates a pg_dump backup, then
runs the full glitch-soc upgrade procedure via SSH including git stash/pop,
PGBouncer-to-direct-DB swap for migrations, and service restarts.
"""

import json
import logging
import re
from datetime import datetime, timezone
from urllib.request import Request, urlopen

from apps.backup import backup_guest, snapshot_guest
from apps.utils import _log_cmd_output, _validate_shell_param, _version_gt
from clients.proxmox_api import ProxmoxClient
from clients.ssh_client import SSHClient
from models import Guest, Setting

logger = logging.getLogger(__name__)

# PATH prefix for su - user commands. su - creates a non-interactive login shell that sources
# .profile but NOT .bashrc on Debian/Ubuntu, so rbenv shims installed via .bashrc are absent.
# Prepend this to any command that invokes ruby, bundle, or bundler-installed executables.
_RBENV_PATH = "export PATH=$HOME/.rbenv/bin:$HOME/.rbenv/shims:$PATH"


def _check_version_range(installed, requirement):
    """Simple semver range check. Supports >=, ^, and plain version.

    Returns True if installed meets requirement, False if not, None if unparseable.
    """
    parts = [int(x) for x in re.findall(r'\d+', installed)][:3]
    while len(parts) < 3:
        parts.append(0)

    m = re.match(r'>=\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?', requirement.strip())
    if m:
        req = [int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0)]
        return parts >= req

    m = re.match(r'\^\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?', requirement.strip())
    if m:
        req = [int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0)]
        return parts >= req and parts[0] == req[0]

    m = re.match(r'(\d+)(?:\.(\d+))?(?:\.(\d+))?', requirement.strip())
    if m:
        req = [int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0)]
        return parts == req

    return None


def _node_major_from_range(node_range):
    """Return the floor major version from an engines.node range, or None.

    '>=22' -> 22, '^22.1.0' -> 22, '22.x' -> 22, '>=20 <23' -> 20.
    """
    if not node_range:
        return None
    m = re.search(r'(\d+)', node_range)
    return int(m.group(1)) if m else None


_BUNDLED_WITH_RE = re.compile(r'BUNDLED WITH\s+([\d.]+)')


def _bundler_from_lock(gemfile_lock):
    """Return the version under 'BUNDLED WITH' in a Gemfile.lock, or None."""
    if not gemfile_lock:
        return None
    m = _BUNDLED_WITH_RE.search(gemfile_lock)
    return m.group(1).strip() if m else None


def _remediate_node(ssh, required_major, installed_node, log):
    """Ensure Node.js is on `required_major` via the NodeSource apt repo.

    No-op when the installed major already matches. Returns True on success
    (or no-op), False on install/verification failure.
    """
    if required_major is None:
        log("  [WARN] No Node.js requirement detected — skipping Node remediation")
        return True

    installed_major = None
    if installed_node:
        m = re.match(r'(\d+)', installed_node)
        if m:
            installed_major = int(m.group(1))

    if installed_major == required_major:
        log(f"  [OK] Node.js {installed_node} already on major {required_major}")
        return True

    log(f"--- Upgrading Node.js {installed_node or '(none)'} → {required_major}.x (NodeSource) ---")
    node_setup_cmds = (
        "export DEBIAN_FRONTEND=noninteractive"
        " && apt-get update -qq && apt-get install -y -qq ca-certificates curl gnupg"
        " && mkdir -p /etc/apt/keyrings"
        " && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key"
        " | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg --yes"
        " && echo 'deb [signed-by=/etc/apt/keyrings/nodesource.gpg]"
        f" https://deb.nodesource.com/node_{required_major}.x nodistro main'"
        " > /etc/apt/sources.list.d/nodesource.list"
        " && apt-get update -qq && apt-get install -y -qq nodejs"
    )
    stdout, stderr, code = ssh.execute_sudo(node_setup_cmds, timeout=300)
    _log_cmd_output(log, stdout, stderr, code, max_chars=2000)
    if code != 0:
        log(f"ERROR: Node.js install failed (exit {code})")
        return False

    stdout, stderr, code = ssh.execute_sudo("node --version 2>/dev/null", timeout=10)
    m = re.search(r'v?(\d+)', stdout or "")
    if code == 0 and m and int(m.group(1)) == required_major:
        log(f"  [OK] Node.js {(stdout or '').strip()} installed")
        return True
    log(f"ERROR: Node.js verification failed (got {(stdout or '').strip() or 'nothing'})")
    return False


def _remediate_ruby(ssh, user, app_dir, log):
    """Ensure the Ruby version in .ruby-version is installed and global via rbenv.

    Updates the ruby-build plugin first so it knows about newer versions, then
    `rbenv install -s <ver>` and `rbenv global <ver>`. No-op when already
    matched. Returns True on success/no-op, False on failure.
    """
    out, _, code = ssh.execute_sudo(
        f"su - {user} -c 'cat {app_dir}/.ruby-version 2>/dev/null'", timeout=10
    )
    required = (out or "").strip()
    if not required:
        log(f"ERROR: Could not read {app_dir}/.ruby-version — cannot verify Ruby version")
        return False

    installed = None
    for cmd in (
        f"su - {user} -c 'ruby --version 2>/dev/null'",
        f"su - {user} -c '{_RBENV_PATH}; ruby --version 2>/dev/null'",
    ):
        rout, _, rcode = ssh.execute_sudo(cmd, timeout=10)
        if rcode == 0 and rout.strip():
            m = re.search(r'ruby\s+(\d+\.\d+\.\d+)', rout)
            if m:
                installed = m.group(1)
                break

    if installed == required:
        log(f"  [OK] Ruby {installed} already installed")
        return True

    log(f"--- Upgrading Ruby {installed or '(none)'} → {required} (rbenv) ---")
    install_cmd = (
        f"su - {user} -c '{_RBENV_PATH}; "
        f"(cd ~/.rbenv/plugins/ruby-build && git pull --quiet 2>/dev/null || true); "
        f"rbenv install -s {required} && rbenv global {required}'"
    )
    stdout, stderr, code = ssh.execute_sudo(install_cmd, timeout=1800)
    _log_cmd_output(log, stdout, stderr, code, max_chars=2000)
    if code != 0:
        log(f"ERROR: Ruby {required} install failed (exit {code})")
        return False

    vout, _, vcode = ssh.execute_sudo(
        f"su - {user} -c '{_RBENV_PATH}; ruby --version 2>/dev/null'", timeout=10
    )
    m = re.search(r'ruby\s+(\d+\.\d+\.\d+)', vout or "")
    if vcode == 0 and m and m.group(1) == required:
        log(f"  [OK] Ruby {required} installed")
        return True
    log(f"ERROR: Ruby verification failed (got {(vout or '').strip() or 'nothing'})")
    return False


def _remediate_bundler(ssh, user, app_dir, log):
    """Ensure the Bundler version pinned in Gemfile.lock is installed.

    Falls back to latest Bundler when the lockfile has no 'BUNDLED WITH'.
    No-op when already matched. Returns True on success/no-op, False on failure.
    """
    out, _, _ = ssh.execute_sudo(
        f"su - {user} -c 'cat {app_dir}/Gemfile.lock 2>/dev/null'", timeout=15
    )
    required = _bundler_from_lock(out or "")

    if not required:
        log("  [WARN] No 'BUNDLED WITH' in Gemfile.lock — installing latest Bundler")
        cmd = f"su - {user} -c '{_RBENV_PATH}; gem install bundler --no-document'"
    else:
        installed = None
        for c_cmd in (
            f"su - {user} -c 'bundle --version 2>/dev/null'",
            f"su - {user} -c '{_RBENV_PATH}; bundle --version 2>/dev/null'",
        ):
            bout, _, bcode = ssh.execute_sudo(c_cmd, timeout=10)
            if bcode == 0 and bout.strip():
                m = re.search(r'(\d+\.\d+[\.\d]*)', bout)
                if m:
                    installed = m.group(1)
                    break
        if installed == required:
            log(f"  [OK] Bundler {installed} already installed")
            return True
        log(f"--- Installing Bundler {required} (from Gemfile.lock) ---")
        cmd = f"su - {user} -c '{_RBENV_PATH}; gem install bundler -v {required} --no-document'"

    stdout, stderr, code = ssh.execute_sudo(cmd, timeout=300)
    _log_cmd_output(log, stdout, stderr, code, max_chars=1000)
    if code != 0:
        log(f"ERROR: Bundler install failed (exit {code})")
        return False
    log("  [OK] Bundler installed")
    return True


def _remediate_environment(ssh, user, app_dir, log):
    """Upgrade Ruby, Bundler, and Node.js to meet the target's requirements.

    Reads required versions from the working tree (run after `git pull`). Order
    is Ruby → Bundler → Node, since Bundler is a gem under the active Ruby.
    Returns True only if every required remediation succeeded.
    """
    if not _remediate_ruby(ssh, user, app_dir, log):
        return False
    if not _remediate_bundler(ssh, user, app_dir, log):
        return False

    required_major = None
    out, _, code = ssh.execute_sudo(
        f"su - {user} -c 'cat {app_dir}/package.json 2>/dev/null'", timeout=15
    )
    if code == 0 and out.strip():
        try:
            node_range = json.loads(out).get("engines", {}).get("node", "")
            required_major = _node_major_from_range(node_range)
        except Exception:
            pass

    installed_node = None
    nout, _, ncode = ssh.execute_sudo(
        f"su - {user} -c 'node --version 2>/dev/null'", timeout=10
    )
    if ncode == 0 and nout.strip():
        m = re.search(r'v?(\d+\.\d+\.\d+)', nout.strip())
        if m:
            installed_node = m.group(1)

    return _remediate_node(ssh, required_major, installed_node, log)


DEFAULT_MASTODON_REPO = "mastodon/mastodon"
_REPO_RE = re.compile(r'^[\w.\-]+/[\w.\-]+$')

# Patterns for parsing Mastodon's lib/mastodon/version.rb
_VER_MAJOR_RE = re.compile(r'def major\s+(\d+)')
_VER_MINOR_RE = re.compile(r'def minor\s+(\d+)')
_VER_PATCH_RE = re.compile(r'def patch\s+(\d+)')
_VER_PRE_RE = re.compile(r"def default_prerelease\s+'([^']*)'")


def _fetch_branch_version(repo, branch):
    """Fetch the version from a repo branch's lib/mastodon/version.rb.

    Returns the version string (e.g. '4.6.0-alpha.5') or '' on failure.
    """
    try:
        url = f"https://raw.githubusercontent.com/{repo}/{branch}/lib/mastodon/version.rb"
        req = Request(url, headers={"User-Agent": "MCAT"})
        with urlopen(req, timeout=15) as resp:
            content = resp.read().decode()
        major = _VER_MAJOR_RE.search(content)
        minor = _VER_MINOR_RE.search(content)
        patch = _VER_PATCH_RE.search(content)
        if not (major and minor and patch):
            return ""
        version = f"{major.group(1)}.{minor.group(1)}.{patch.group(1)}"
        pre = _VER_PRE_RE.search(content)
        if pre and pre.group(1):
            version += f"-{pre.group(1)}"
        return version
    except Exception as e:
        logger.debug("Could not fetch branch version from %s/%s: %s", repo, branch, e)
        return ""


def check_mastodon_release():
    """Check GitHub for the latest Mastodon release.

    Checks both the latest formal GitHub Release and the version on the
    configured branch (via lib/mastodon/version.rb).  Returns whichever
    is newer so that nightly/alpha users see the correct latest version.

    Returns (update_available, latest_version, release_url).
    """
    try:
        repo = Setting.get("mastodon_repo", DEFAULT_MASTODON_REPO) or DEFAULT_MASTODON_REPO
        if not _REPO_RE.match(repo):
            logger.error("Invalid mastodon_repo format: %r — expected 'owner/repo'", repo)
            return False, "", ""

        # 1. Check latest formal GitHub Release
        latest = ""
        release_url = ""
        try:
            releases_url = f"https://api.github.com/repos/{repo}/releases/latest"
            req = Request(releases_url, headers={"User-Agent": "MCAT"})
            with urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
            latest = data.get("tag_name", "").lstrip("v")
            release_url = data.get("html_url", "")
        except Exception as e:
            logger.debug("Could not fetch GitHub release for %s: %s", repo, e)

        # 2. Check version on the configured branch (or main)
        branch = Setting.get("mastodon_branch", "") or "main"
        branch_version = _fetch_branch_version(repo, branch)

        # Use the higher of the two versions
        if branch_version and (not latest or _version_gt(branch_version, latest)):
            latest = branch_version
            release_url = f"https://github.com/{repo}/tree/{branch}"

        if not latest:
            return False, "", ""

        Setting.set("mastodon_latest_version", latest)
        Setting.set("mastodon_latest_release_url", release_url)

        current = Setting.get("mastodon_current_version", "")
        update_available = bool(current and _version_gt(latest, current))
        Setting.set("mastodon_update_available", "true" if update_available else "false")

        return update_available, latest, release_url
    except Exception as e:
        logger.error(f"Failed to check Mastodon releases: {e}")
        return False, "", ""


def _run_second_guest_sync(guest, user, app_dir, log, branch=""):
    """Sync code to a second Mastodon app guest via SSH (no DB migrations).

    Runs: git stash, git pull, git stash pop, bundle install, yarn install,
    asset precompile, restart mastodon services.
    Returns True on success, False on failure.
    """
    from models import Credential

    credential = guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        log(f"[VM2] No SSH credential available for '{guest.name}'")
        return False
    if not guest.ip_address:
        log(f"[VM2] No IP address configured for '{guest.name}'")
        return False

    pull_cmd = f"git pull origin {branch}" if branch else "git pull"

    try:
        with SSHClient.from_credential(guest.ip_address, credential) as ssh:
            log("--- [VM2] git stash ---")
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c 'cd {app_dir} && git stash'", timeout=30
            )
            log(stdout or stderr or "(no output)")

            log(f"--- [VM2] {pull_cmd} ---")
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c 'cd {app_dir} && {pull_cmd}'", timeout=120
            )
            log(stdout or stderr or "(no output)")
            if code != 0:
                log(f"ERROR: [VM2] git pull failed (exit {code})")
                return False

            log("--- [VM2] git stash pop ---")
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c 'cd {app_dir} && git stash pop'", timeout=30
            )
            log(stdout or stderr or "(no output)")
            if code != 0:
                log("WARNING: [VM2] git stash pop returned non-zero (may be no stash to pop)")

            log("--- [VM2] bundle install ---")
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c '{_RBENV_PATH}; cd {app_dir} && bundle install'", timeout=600
            )
            out = stdout or ""
            log(out[-2000:] if len(out) > 2000 else out or stderr or "(no output)")
            if code != 0:
                log(f"ERROR: [VM2] bundle install failed (exit {code})")
                return False

            log("--- [VM2] yarn install ---")
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c '{_RBENV_PATH}; cd {app_dir} && yarn install --frozen-lockfile'", timeout=600
            )
            out = stdout or ""
            log(out[-2000:] if len(out) > 2000 else out or stderr or "(no output)")
            if code != 0:
                log(f"ERROR: [VM2] yarn install failed (exit {code})")
                return False

            log("--- [VM2] asset precompilation ---")
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c '{_RBENV_PATH}; cd {app_dir} && RAILS_ENV=production bundle exec rails assets:precompile'",
                timeout=900,
            )
            out = stdout or ""
            log(out[-2000:] if len(out) > 2000 else out or stderr or "(no output)")
            if code != 0:
                log(f"ERROR: [VM2] asset precompilation failed (exit {code})")
                return False

            log("--- [VM2] restarting mastodon services ---")
            stdout, stderr, code = ssh.execute_sudo("systemctl restart mastodon-*", timeout=60)
            log(stdout or stderr or "(no output)")

            return True
    except Exception as e:
        log(f"[VM2] SSH ERROR: {e}")
        return False


def _get_mastodon_config():
    """Read all Mastodon-related settings."""
    return {
        "guest_id": Setting.get("mastodon_guest_id", ""),
        "db_guest_id": Setting.get("mastodon_db_guest_id", ""),
        "db_name": Setting.get("mastodon_db_name", "mastodon_production"),
        "user": Setting.get("mastodon_user", "mastodon"),
        "app_dir": Setting.get("mastodon_app_dir", "/home/mastodon/live"),
        "branch": Setting.get("mastodon_branch", ""),
        "pgbouncer_host": Setting.get("mastodon_pgbouncer_host", ""),
        "pgbouncer_port": Setting.get("mastodon_pgbouncer_port", ""),
        "direct_db_host": Setting.get("mastodon_direct_db_host", ""),
        "direct_db_port": Setting.get("mastodon_direct_db_port", "5432"),
        "auto_upgrade": Setting.get("mastodon_auto_upgrade", "false") == "true",
        "current_version": Setting.get("mastodon_current_version", ""),
        "latest_version": Setting.get("mastodon_latest_version", ""),
        "protection_type": Setting.get("mastodon_protection_type", "snapshot"),
        "backup_storage": Setting.get("mastodon_backup_storage", ""),
        "backup_mode": Setting.get("mastodon_backup_mode", "snapshot"),
        "guest_id_2": Setting.get("mastodon_guest_id_2", ""),
    }


def _swap_env_db(ssh, app_dir, new_host, new_port):
    """Swap DB_HOST and DB_PORT in .env.production via sed."""
    _validate_shell_param(app_dir, "app_dir")
    _validate_shell_param(new_host, "DB host")
    if not re.match(r'^\d+$', str(new_port)):
        return False, f"Invalid DB port: {new_port}"

    env_file = f"{app_dir}/.env.production"
    cmds = [
        f"sed -i 's|^DB_HOST=.*|DB_HOST={new_host}|' {env_file}",
        f"sed -i 's|^DB_PORT=.*|DB_PORT={new_port}|' {env_file}",
    ]
    for cmd in cmds:
        stdout, stderr, code = ssh.execute_sudo(cmd, timeout=10)
        if code != 0:
            return False, f"Failed to update .env.production: {stderr}"
    # Read back and verify the swap actually took effect
    verify_out, _, _ = ssh.execute_sudo(
        f"grep -E '^DB_HOST=|^DB_PORT=' {env_file}", timeout=10
    )
    actual = verify_out.strip().replace("\n", "  ")
    return True, f"DB config swapped → {new_host}:{new_port}  (actual: {actual})"


def _check_env_compliance(ssh, user, app_dir, branch, log):
    """Check installed Ruby/Node.js/Bundler against the target branch requirements.

    Reads .ruby-version and package.json from the remote ref via a non-destructive
    git fetch (updates tracking refs only, does not touch the working tree).

    Returns True if all checks pass or only warnings; False if any [FAIL].
    """
    remote_ref = f"origin/{branch}" if branch else "origin/HEAD"
    all_pass = True

    # Step 1: Fetch remote refs (non-destructive — updates tracking refs only)
    fetch_cmd = (
        f"su - {user} -c 'cd {app_dir} && git fetch origin {branch}'"
        if branch else
        f"su - {user} -c 'cd {app_dir} && git fetch origin'"
    )
    stdout, stderr, code = ssh.execute_sudo(fetch_cmd, timeout=60)
    if code != 0:
        log(f"  [WARN] Could not fetch from origin: {(stderr or stdout or '').strip()}")

    # Step 2: Read .ruby-version from remote ref
    required_ruby = None
    stdout, stderr, code = ssh.execute_sudo(
        f"su - {user} -c 'cd {app_dir} && git show {remote_ref}:.ruby-version 2>/dev/null'",
        timeout=10,
    )
    if code == 0 and stdout.strip():
        required_ruby = stdout.strip()

    # Step 3: Read package.json engines.node from remote ref
    required_node = None
    stdout, stderr, code = ssh.execute_sudo(
        f"su - {user} -c 'cd {app_dir} && git show {remote_ref}:package.json 2>/dev/null'",
        timeout=15,
    )
    if code == 0 and stdout.strip():
        try:
            pkg = json.loads(stdout)
            node_range = pkg.get("engines", {}).get("node", "")
            if node_range:
                required_node = node_range
        except Exception:
            pass

    # Step 4: Check installed versions
    # Ruby — try plain PATH first, then explicit rbenv shims.
    # su - user -c '...' creates a non-interactive login shell which sources .profile but
    # NOT .bashrc on most Debian/Ubuntu systems, so rbenv shims may not be in PATH.
    installed_ruby = None
    for _ruby_cmd in [
        f"su - {user} -c 'ruby --version 2>/dev/null'",
        f"su - {user} -c '{_RBENV_PATH}; ruby --version 2>/dev/null'",
    ]:
        stdout, stderr, code = ssh.execute_sudo(_ruby_cmd, timeout=10)
        if code == 0 and stdout.strip():
            m = re.search(r'ruby\s+(\d+\.\d+\.\d+)', stdout)
            if m:
                installed_ruby = m.group(1)
                break

    # Node.js
    installed_node = None
    stdout, stderr, code = ssh.execute_sudo(
        f"su - {user} -c 'node --version 2>/dev/null'",
        timeout=10,
    )
    if code == 0 and stdout.strip():
        m = re.search(r'v?(\d+\.\d+\.\d+)', stdout.strip())
        if m:
            installed_node = m.group(1)

    # Bundler — same rbenv fallback as Ruby
    installed_bundler = None
    for _bundle_cmd in [
        f"su - {user} -c 'bundle --version 2>/dev/null'",
        f"su - {user} -c '{_RBENV_PATH}; bundle --version 2>/dev/null'",
    ]:
        stdout, stderr, code = ssh.execute_sudo(_bundle_cmd, timeout=10)
        if code == 0 and stdout.strip():
            m = re.search(r'(\d+\.\d+[\.\d]*)', stdout.strip())
            if m:
                installed_bundler = m.group(1)
                break

    # Step 5: Compare and log

    # Ruby — compare full version. A patch-level difference is a [WARN] (rbenv install handles
    # it automatically during upgrade). A major.minor mismatch is a [FAIL] and requires
    # manual intervention.
    if required_ruby and installed_ruby:
        req_parts = [int(x) for x in re.findall(r'\d+', required_ruby.strip())][:3]
        ins_parts = [int(x) for x in re.findall(r'\d+', installed_ruby)][:3]
        while len(req_parts) < 3:
            req_parts.append(0)
        while len(ins_parts) < 3:
            ins_parts.append(0)
        if ins_parts == req_parts:
            log(f"  [PASS] Ruby {installed_ruby} installed, required {required_ruby}")
        elif ins_parts[:2] == req_parts[:2]:
            log(f"  [WARN] Ruby {installed_ruby} installed, required {required_ruby} — rbenv will install {required_ruby} automatically during upgrade")
        else:
            log(f"  [FAIL] Ruby {installed_ruby} installed, required {required_ruby} — major.minor mismatch, manual Ruby upgrade required")
            all_pass = False
    elif required_ruby and not installed_ruby:
        log(f"  [FAIL] Ruby required {required_ruby} but could not detect installed version")
        all_pass = False
    elif installed_ruby and not required_ruby:
        log(f"  [WARN] Ruby {installed_ruby} installed (could not read .ruby-version from {remote_ref})")
    else:
        log("  [WARN] Could not determine Ruby requirement or installed version")

    # Node.js
    if required_node and installed_node:
        result = _check_version_range(installed_node, required_node)
        if result is True:
            log(f"  [PASS] Node.js {installed_node} installed, required {required_node}")
        elif result is False:
            log(f"  [FAIL] Node.js {installed_node} installed, required {required_node} — upgrade Node.js before proceeding")
            all_pass = False
        else:
            log(f"  [WARN] Node.js {installed_node} installed, required {required_node} (could not parse requirement range)")
    elif required_node and not installed_node:
        log(f"  [FAIL] Node.js required {required_node} but could not detect installed version")
        all_pass = False
    elif installed_node and not required_node:
        log(f"  [WARN] Node.js {installed_node} installed (engines.node not found in package.json)")
    else:
        log("  [WARN] Could not determine Node.js requirement or installed version")

    # Bundler — informational only
    if installed_bundler:
        log(f"  [PASS] Bundler {installed_bundler} available")
    else:
        log("  [WARN] Could not determine Bundler version (bundle command not found)")

    return all_pass


def run_mastodon_preflight(log_callback=None):
    """Run read-only pre-flight checks for the Mastodon upgrade.

    Validates configuration, Proxmox guest status, SSH connectivity, app directory,
    .env.production readability, git status, environment compliance (Ruby/Node.js),
    and database reachability — without modifying anything.

    Returns (all_pass: bool, log_output: str).
    """
    from models import Credential

    config = _get_mastodon_config()
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

    log("=== Mastodon Pre-flight Check ===")
    log("")

    # ── A. Configuration validation ──────────────────────────────────────────
    log("--- A. Configuration ---")

    required_fields = [
        ("guest_id", "Mastodon app guest"),
        ("db_guest_id", "PostgreSQL guest"),
        ("pgbouncer_host", "PGBouncer host"),
        ("pgbouncer_port", "PGBouncer port"),
        ("direct_db_host", "Direct DB host"),
        ("direct_db_port", "Direct DB port"),
    ]
    config_ok = True
    for field, label in required_fields:
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

    user = config.get("user", "mastodon")
    app_dir = config.get("app_dir", "/home/mastodon/live")
    branch = (config.get("branch") or "").strip()

    try:
        _validate_shell_param(user, "Mastodon user")
        _validate_shell_param(app_dir, "Mastodon app_dir")
        if branch:
            _validate_shell_param(branch, "Git branch")
        _validate_shell_param(config.get("direct_db_host", ""), "Direct DB host")
        _validate_shell_param(config.get("pgbouncer_host", ""), "PGBouncer host")
        if not re.match(r'^\d+$', str(config.get("direct_db_port", ""))):
            raise ValueError("Direct DB port must be numeric")
        if not re.match(r'^\d+$', str(config.get("pgbouncer_port", ""))):
            raise ValueError("PGBouncer port must be numeric")
        check("Shell-safe config values", True)
    except ValueError as e:
        check("Shell-safe config values", False, str(e))
        config_ok = False

    if not config_ok:
        log("")
        log(f"=== Pre-flight complete: {checks_passed}/{checks_total} checks passed — {checks_failed} failure(s), upgrade blocked ===")
        return False, "\n".join(log_lines)

    # ── B. Proxmox guest status ───────────────────────────────────────────────
    log("")
    log("--- B. Proxmox guests ---")

    mastodon_guest = Guest.query.get(int(config["guest_id"]))
    db_guest = Guest.query.get(int(config["db_guest_id"]))

    check("Mastodon app guest in database", mastodon_guest is not None,
          f"guest ID {config['guest_id']} not found")
    check("PostgreSQL guest in database", db_guest is not None,
          f"guest ID {config['db_guest_id']} not found")

    mastodon_guest_2 = None
    guest_id_2 = config.get("guest_id_2", "")
    if guest_id_2:
        mastodon_guest_2 = Guest.query.get(int(guest_id_2))
        if not mastodon_guest_2:
            log(f"  [WARN] Second Mastodon guest ID {guest_id_2} not found — will skip VM2 checks")

    for guest_obj in filter(None, [mastodon_guest, db_guest]):
        if not guest_obj.proxmox_host:
            log(f"  [WARN] {guest_obj.name} has no Proxmox host configured — skipping Proxmox checks")
            continue
        try:
            client = ProxmoxClient(guest_obj.proxmox_host)
            node = client.find_guest_node(guest_obj.vmid)
            if not node:
                check(f"{guest_obj.name} found on Proxmox", False, "not found on any PVE node")
                continue
            check(f"{guest_obj.name} found on Proxmox", True)
            status = client.get_guest_status(node, guest_obj.vmid, guest_obj.guest_type)
            check(f"{guest_obj.name} running", status == "running", f"current status: {status}")
            if protection_type == "snapshot":
                supports_snap = client.guest_supports_snapshot(node, guest_obj.vmid, guest_obj.guest_type)
                check(f"{guest_obj.name} supports snapshots", supports_snap,
                      "storage does not support snapshots — switch to Backup protection")
        except Exception as e:
            check(f"{guest_obj.name} Proxmox reachable", False, str(e))

    if not mastodon_guest or not db_guest:
        log("")
        log(f"=== Pre-flight complete: {checks_passed}/{checks_total} checks passed — {checks_failed} failure(s), upgrade blocked ===")
        return False, "\n".join(log_lines)

    # ── C. SSH checks on mastodon app guest ──────────────────────────────────
    log("")
    log(f"--- C. SSH checks on {mastodon_guest.name} ---")

    credential = mastodon_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()

    if not credential:
        check("SSH credential available", False, "no credential configured for mastodon guest or as default")
    elif not mastodon_guest.ip_address:
        check("SSH credential available", True)
        check("Mastodon guest IP configured", False, "no IP address set on guest")
    else:
        check("SSH credential available", True)
        check("Mastodon guest IP configured", True)
        try:
            with SSHClient.from_credential(mastodon_guest.ip_address, credential) as ssh:
                check("SSH connection established", True)

                # App directory exists
                stdout, stderr, code = ssh.execute_sudo(
                    f"test -d {app_dir} && echo ok", timeout=10
                )
                check(f"App directory {app_dir} exists",
                      code == 0 and "ok" in (stdout or ""),
                      "directory not found")

                # .env.production readable by mastodon user
                stdout, stderr, code = ssh.execute_sudo(
                    f"su - {user} -c 'test -r {app_dir}/.env.production && echo ok'",
                    timeout=10,
                )
                check(".env.production readable",
                      code == 0 and "ok" in (stdout or ""),
                      "file not found or not readable by mastodon user")

                # Uncommitted changes — informational (WARN only, stash handles it)
                stdout, stderr, code = ssh.execute_sudo(
                    f"su - {user} -c 'cd {app_dir} && git status --porcelain'",
                    timeout=15,
                )
                if code == 0:
                    dirty = [ln for ln in (stdout or "").splitlines() if ln.strip()]
                    if dirty:
                        log(f"  [WARN] {len(dirty)} uncommitted change(s) — they will be stashed during upgrade")
                    else:
                        log("  [INFO] Working tree clean (no uncommitted changes)")
                else:
                    log("  [WARN] Could not determine git working tree status")

                # Environment compliance (includes git fetch + version checks)
                log("  Checking environment compliance...")
                env_ok = _check_env_compliance(ssh, user, app_dir, branch, log)
                checks_total += 1
                if env_ok:
                    checks_passed += 1
                else:
                    checks_failed += 1

                # Direct DB reachability — use bash /dev/tcp (no external tools required)
                # Falls back to pg_isready and nc if bash /dev/tcp is unavailable
                stdout, stderr, code = ssh.execute_sudo(
                    f"(timeout 3 bash -c ': >/dev/tcp/{config['direct_db_host']}/{config['direct_db_port']}' 2>/dev/null"
                    f" || pg_isready -h {config['direct_db_host']} -p {config['direct_db_port']} 2>/dev/null"
                    f" || nc -z {config['direct_db_host']} {config['direct_db_port']} 2>/dev/null) && echo ok",
                    timeout=10,
                )
                check(f"Direct DB reachable ({config['direct_db_host']}:{config['direct_db_port']})",
                      code == 0 and "ok" in (stdout or ""),
                      "cannot connect to direct PostgreSQL port")

                # PGBouncer reachability — same bash /dev/tcp approach
                stdout, stderr, code = ssh.execute_sudo(
                    f"(timeout 3 bash -c ': >/dev/tcp/{config['pgbouncer_host']}/{config['pgbouncer_port']}' 2>/dev/null"
                    f" || pg_isready -h {config['pgbouncer_host']} -p {config['pgbouncer_port']} 2>/dev/null"
                    f" || nc -z {config['pgbouncer_host']} {config['pgbouncer_port']} 2>/dev/null) && echo ok",
                    timeout=10,
                )
                check(f"PGBouncer reachable ({config['pgbouncer_host']}:{config['pgbouncer_port']})",
                      code == 0 and "ok" in (stdout or ""),
                      "cannot connect to PGBouncer port")

        except Exception as e:
            check("SSH connection established", False, str(e))

    # ── D. SSH checks on second Mastodon guest (if configured) ───────────────
    if mastodon_guest_2 and mastodon_guest_2.ip_address:
        log("")
        log(f"--- D. SSH checks on {mastodon_guest_2.name} ---")

        cred2 = mastodon_guest_2.credential
        if not cred2:
            cred2 = Credential.query.filter_by(is_default=True).first()

        if not cred2:
            check(f"[VM2] SSH credential for {mastodon_guest_2.name}", False, "no credential configured")
        else:
            try:
                with SSHClient.from_credential(mastodon_guest_2.ip_address, cred2) as ssh2:
                    check(f"[VM2] SSH connection to {mastodon_guest_2.name}", True)
                    stdout, stderr, code = ssh2.execute_sudo(
                        f"test -d {app_dir} && echo ok", timeout=10
                    )
                    check(f"[VM2] App directory exists on {mastodon_guest_2.name}",
                          code == 0 and "ok" in (stdout or ""),
                          "directory not found")
            except Exception as e:
                check(f"[VM2] SSH connection to {mastodon_guest_2.name}", False, str(e))

    # ── E. SSH checks on DB guest (pg_dump readiness) ────────────────────────
    if db_guest and db_guest.ip_address:
        log("")
        log(f"--- E. SSH checks on {db_guest.name} (database) ---")
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

    # ── Final summary ─────────────────────────────────────────────────────────
    log("")
    status_word = "upgrade blocked" if checks_failed > 0 else "ready to upgrade"
    log(f"=== Pre-flight complete: {checks_passed}/{checks_total} checks passed — {checks_failed} failure(s), {status_word} ===")

    return checks_failed == 0, "\n".join(log_lines)


def run_mastodon_upgrade(log_callback=None, skip_protection=False):
    """Run the full Mastodon upgrade procedure.

    log_callback: optional callable(str) invoked immediately after each log line,
    enabling real-time streaming to a polling endpoint.
    skip_protection: if True, skip the snapshot/backup step (super-admin only).

    Returns (success, log_output).
    """
    from models import Credential, db

    config = _get_mastodon_config()
    log_lines = []

    def log(msg):
        logger.info(msg)
        log_lines.append(msg)
        if log_callback:
            log_callback(msg)

    # Validate config
    if not config["guest_id"]:
        return False, "Mastodon app guest not configured"
    if not config["db_guest_id"]:
        return False, "PostgreSQL guest not configured"
    if not config["pgbouncer_host"] or not config["direct_db_host"]:
        return False, "PGBouncer and direct DB host/port must be configured"

    mastodon_guest = Guest.query.get(int(config["guest_id"]))
    db_guest = Guest.query.get(int(config["db_guest_id"]))

    if not mastodon_guest:
        return False, "Mastodon app guest not found"
    if not db_guest:
        return False, "PostgreSQL guest not found"

    # Optional second Mastodon app guest
    mastodon_guest_2 = None
    guest_id_2 = config.get("guest_id_2", "")
    if guest_id_2:
        mastodon_guest_2 = Guest.query.get(int(guest_id_2))
        if not mastodon_guest_2:
            log("WARNING: Second Mastodon guest configured but not found — proceeding without it")
            mastodon_guest_2 = None
        elif mastodon_guest_2.id == mastodon_guest.id:
            log("WARNING: Second Mastodon guest is the same as the primary — skipping")
            mastodon_guest_2 = None

    user = config["user"]
    app_dir = config["app_dir"]
    branch = (config.get("branch") or "").strip()
    db_name = config["db_name"]

    # Validate shell-interpolated values to prevent command injection
    try:
        _validate_shell_param(user, "Mastodon user")
        _validate_shell_param(app_dir, "Mastodon app_dir")
        _validate_shell_param(db_name, "Database name")
        if branch:
            _validate_shell_param(branch, "Git branch")
    except ValueError as e:
        return False, str(e)

    pull_cmd = f"git pull origin {branch}" if branch else "git pull"

    # Get SSH credential here (needed for env check before snapshots)
    credential = mastodon_guest.credential
    if not credential:
        credential = Credential.query.filter_by(is_default=True).first()
    if not credential:
        return False, "No SSH credential available for Mastodon guest"

    # --- Environment compliance check (before snapshots) ---
    # Abort early if the server's Ruby/Node.js do not meet target version requirements.
    log("=== Checking environment compliance ===")
    if mastodon_guest.ip_address:
        try:
            with SSHClient.from_credential(mastodon_guest.ip_address, credential) as ssh:
                env_ok = _check_env_compliance(ssh, user, app_dir, branch, log)
            if not env_ok:
                log("ERROR: Environment does not meet requirements. Upgrade aborted.")
                log("Fix the version issues above before running the upgrade.")
                return False, "\n".join(log_lines)
            log("Environment compliance: OK")
        except Exception as e:
            log(f"WARNING: Could not run environment compliance check: {e}")
            log("Proceeding with upgrade — verify environment manually if needed.")
    else:
        log("WARNING: No IP address for Mastodon guest — skipping environment compliance check")
    log("")

    # --- Step 1: Protection (snapshot or backup) ---
    if skip_protection:
        log("=== Step 1: Skipping snapshot/backup (requested by super-admin) ===")
    else:
        protection_type = config.get("protection_type", "snapshot")
        backup_storage = config.get("backup_storage", "")

        if protection_type == "backup" and not backup_storage:
            return False, "Backup protection selected but no backup storage is configured"

        if protection_type == "backup":
            backup_mode = config.get("backup_mode", "snapshot")
            log(f"=== Step 1: Creating vzdump backups to storage '{backup_storage}' (mode: {backup_mode}) ===")
            log("(This may take several minutes — please be patient)")

            ok, msg = backup_guest(mastodon_guest, backup_storage, "mastodon", mode=backup_mode)
            log(f"Backup {mastodon_guest.name}: {msg}")
            if not ok:
                return False, "\n".join(log_lines)

            if mastodon_guest_2:
                ok, msg = backup_guest(mastodon_guest_2, backup_storage, "mastodon", mode=backup_mode)
                log(f"Backup {mastodon_guest_2.name}: {msg}")
                if not ok:
                    return False, "\n".join(log_lines)

            ok, msg = backup_guest(db_guest, backup_storage, "mastodon", mode=backup_mode)
            log(f"Backup {db_guest.name}: {msg}")
            if not ok:
                return False, "\n".join(log_lines)
        else:
            log("=== Step 1: Creating Proxmox snapshots ===")

            ok, msg = snapshot_guest(mastodon_guest, "mastodon")
            log(f"Snapshot {mastodon_guest.name}: {msg}")
            if not ok:
                return False, "\n".join(log_lines)

            if mastodon_guest_2:
                ok, msg = snapshot_guest(mastodon_guest_2, "mastodon")
                log(f"Snapshot {mastodon_guest_2.name}: {msg}")
                if not ok:
                    return False, "\n".join(log_lines)

            ok, msg = snapshot_guest(db_guest, "mastodon")
            log(f"Snapshot {db_guest.name}: {msg}")
            if not ok:
                return False, "\n".join(log_lines)

    # --- Step 2: pg_dump backup ---
    if db_guest and db_guest.ip_address:
        log("=== Step 2: PostgreSQL backup (pg_dump) ===")
        db_credential = db_guest.credential
        if not db_credential:
            db_credential = Credential.query.filter_by(is_default=True).first()

        if db_credential:
            try:
                with SSHClient.from_credential(db_guest.ip_address, db_credential) as ssh:
                    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                    dump_file = f"/tmp/mastodon_backup_{timestamp}.sql"  # nosec B108 — remote SSH path, not a local temp file
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
        log("=== Step 2: Skipping pg_dump (no DB guest IP configured) ===")
        log("")

    # --- Step 3: SSH upgrade sequence ---
    log("=== Step 3: Connecting to Mastodon guest via SSH ===")

    env_swapped = False

    try:
        with SSHClient.from_credential(mastodon_guest.ip_address, credential) as ssh:

            # Pre-check: abort before touching anything if unmerged files exist.
            # git stash silently skips unmerged files, which then causes git pull to fail.
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c 'cd {app_dir} && git ls-files --unmerged'", timeout=15
            )
            if stdout.strip():
                # git ls-files --unmerged emits 3 lines per file (stages 1/2/3); deduplicate
                seen = set()
                unique_files = []
                for line in stdout.strip().splitlines():
                    fname = line.split()[-1]
                    if fname not in seen:
                        seen.add(fname)
                        unique_files.append(f"  {fname}")
                unmerged = "\n".join(unique_files)
                log(f"ERROR: Repository has unmerged (conflicted) files:\n{unmerged}")
                log("Resolve these conflicts manually on the server before running the upgrade:")
                log(f"  ssh {user}@{mastodon_guest.ip_address}")
                log(f"  cd {app_dir}")
                log("  git merge --abort   # cancel the incomplete merge (recommended), or")
                log("  git add <file> && git commit   # if you resolved the conflict manually")
                return False, "\n".join(log_lines)

            # 2a. git stash
            log("--- git stash ---")
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c 'cd {app_dir} && git stash'", timeout=30
            )
            log(stdout or stderr or "(no output)")

            # 2b. Swap .env.production to direct DB
            log("--- Swapping .env.production to direct DB ---")
            ok, msg = _swap_env_db(ssh, app_dir, config["direct_db_host"], config["direct_db_port"])
            log(msg)
            if not ok:
                return False, "\n".join(log_lines)
            env_swapped = True

            # 2c. git pull
            log(f"--- {pull_cmd} ---")
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c 'cd {app_dir} && {pull_cmd}'", timeout=120
            )
            log(stdout or stderr or "(no output)")
            if code != 0:
                log(f"ERROR: git pull failed (exit {code})")
                _swap_env_db(ssh, app_dir, config["pgbouncer_host"], config["pgbouncer_port"])
                env_swapped = False
                return False, "\n".join(log_lines)

            # 2d. git stash pop
            log("--- git stash pop ---")
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c 'cd {app_dir} && git stash pop'", timeout=30
            )
            log(stdout or stderr or "(no output)")
            if code != 0:
                # Check whether stash pop left unmerged files (conflict).
                # If so, auto-resolve in favour of the stashed (local) version and drop the entry.
                unmerged_out, _, _ = ssh.execute_sudo(
                    f"su - {user} -c 'cd {app_dir} && git ls-files --unmerged'", timeout=15
                )
                if unmerged_out.strip():
                    conflicted = list(dict.fromkeys(
                        line.split()[-1] for line in unmerged_out.strip().splitlines()
                    ))
                    log(f"WARNING: stash pop conflict in: {', '.join(conflicted)} — auto-resolving (keeping local version)")
                    for fname in conflicted:
                        ssh.execute_sudo(
                            f"su - {user} -c 'cd {app_dir} && git checkout --theirs -- {fname}'", timeout=15
                        )
                        ssh.execute_sudo(
                            f"su - {user} -c 'cd {app_dir} && git add {fname}'", timeout=15
                        )
                    ssh.execute_sudo(
                        f"su - {user} -c 'cd {app_dir} && git stash drop'", timeout=15
                    )
                    log("  Stash conflicts resolved.")
                else:
                    log("WARNING: git stash pop returned non-zero (may be no stash to pop)")

            # 2e. Ensure correct Ruby version and Bundler are installed via rbenv.
            # Reads the target version from .ruby-version in the app dir (updated by git pull).
            # --skip-existing is a no-op if already installed; silently non-fatal if rbenv not present.
            log("--- rbenv install (ensuring correct Ruby version) ---")
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c '{_RBENV_PATH}; "
                f"cd {app_dir} && rbenv install --skip-existing && gem install bundler --no-document'",
                timeout=600,
            )
            out = ((stdout or "") + (stderr or "")).strip()
            if out:
                log(out[-500:] if len(out) > 500 else out)
            if code != 0:
                # Verify whether the required Ruby version is actually installed.
                # If not, this is a hard failure — bundle install will fail immediately.
                rv_out, _, _ = ssh.execute_sudo(
                    f"su - {user} -c 'cat {app_dir}/.ruby-version 2>/dev/null'", timeout=5
                )
                required_rv = rv_out.strip()
                ver_out, _, _ = ssh.execute_sudo(
                    f"su - {user} -c '{_RBENV_PATH}; rbenv versions --bare 2>/dev/null'", timeout=10
                )
                if required_rv and required_rv not in (ver_out or ""):
                    log(f"ERROR: rbenv install failed (exit {code}) and Ruby {required_rv} is not installed.")
                    log("ruby-build may not know about this version yet. To fix on the server:")
                    log("  cd ~/.rbenv/plugins/ruby-build && git pull")
                    log(f"  rbenv install {required_rv}")
                    _swap_env_db(ssh, app_dir, config["pgbouncer_host"], config["pgbouncer_port"])
                    env_swapped = False
                    return False, "\n".join(log_lines)
                else:
                    log(f"NOTE: rbenv/gem step exited {code} — rbenv not in use or bundler already present, continuing")

            # 2f. bundle install
            log("--- bundle install ---")
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c '{_RBENV_PATH}; cd {app_dir} && bundle install'", timeout=600
            )
            _log_cmd_output(log, stdout, stderr, code)
            if code != 0:
                log(f"ERROR: bundle install failed (exit {code})")
                _swap_env_db(ssh, app_dir, config["pgbouncer_host"], config["pgbouncer_port"])
                env_swapped = False
                return False, "\n".join(log_lines)

            # 2g. yarn install
            log("--- yarn install ---")
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c '{_RBENV_PATH}; cd {app_dir} && yarn install --frozen-lockfile'", timeout=600
            )
            _log_cmd_output(log, stdout, stderr, code)
            if code != 0:
                log(f"ERROR: yarn install failed (exit {code})")
                _swap_env_db(ssh, app_dir, config["pgbouncer_host"], config["pgbouncer_port"])
                env_swapped = False
                return False, "\n".join(log_lines)

            # 2h. Pre-deployment migrations
            log("--- Pre-deployment database migrations ---")
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c '{_RBENV_PATH}; cd {app_dir} && RAILS_ENV=production SKIP_POST_DEPLOYMENT_MIGRATIONS=true bundle exec rails db:migrate'",
                timeout=600,
            )
            _log_cmd_output(log, stdout, stderr, code)
            if code != 0:
                log(f"ERROR: pre-deployment migrations failed (exit {code})")
                _swap_env_db(ssh, app_dir, config["pgbouncer_host"], config["pgbouncer_port"])
                env_swapped = False
                return False, "\n".join(log_lines)

            # 2i. Asset precompilation
            log("--- Asset precompilation ---")
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c '{_RBENV_PATH}; cd {app_dir} && RAILS_ENV=production bundle exec rails assets:precompile'",
                timeout=900,
            )
            _log_cmd_output(log, stdout, stderr, code)
            if code != 0:
                log(f"ERROR: asset precompilation failed (exit {code})")
                _swap_env_db(ssh, app_dir, config["pgbouncer_host"], config["pgbouncer_port"])
                env_swapped = False
                return False, "\n".join(log_lines)

            # 2j. Restore .env.production to PGBouncer before the intermediate restart
            # so live traffic goes back through the connection pool, not direct PostgreSQL.
            log("--- Restoring .env.production to PGBouncer (pre-restart) ---")
            ok, msg = _swap_env_db(ssh, app_dir, config["pgbouncer_host"], config["pgbouncer_port"])
            log(msg)
            env_swapped = False

            # 2k. Restart all mastodon services (now on PGBouncer, running new code)
            log("--- Restarting mastodon services ---")
            stdout, stderr, code = ssh.execute_sudo(
                "systemctl restart mastodon-*", timeout=60
            )
            log(stdout or stderr or "(no output)")

            # 2l. Clear cache
            log("--- Clearing cache ---")
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c '{_RBENV_PATH}; cd {app_dir} && RAILS_ENV=production bin/tootctl cache clear'",
                timeout=120,
            )
            log(stdout or stderr or "(no output)")

            # 2m. Re-swap .env.production to direct DB for post-deployment migrations
            log("--- Swapping .env.production to direct DB (post-deployment migrations) ---")
            ok, msg = _swap_env_db(ssh, app_dir, config["direct_db_host"], config["direct_db_port"])
            log(msg)
            if not ok:
                return False, "\n".join(log_lines)
            env_swapped = True

            # 2n. Post-deployment migrations
            log("--- Post-deployment database migrations ---")
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c '{_RBENV_PATH}; cd {app_dir} && RAILS_ENV=production bundle exec rails db:migrate'",
                timeout=600,
            )
            _log_cmd_output(log, stdout, stderr, code)
            if code != 0:
                log(f"ERROR: post-deployment migrations failed (exit {code})")
                _swap_env_db(ssh, app_dir, config["pgbouncer_host"], config["pgbouncer_port"])
                env_swapped = False
                return False, "\n".join(log_lines)

            # 2n. Restore .env.production to PGBouncer
            log("--- Restoring .env.production to PGBouncer ---")
            ok, msg = _swap_env_db(ssh, app_dir, config["pgbouncer_host"], config["pgbouncer_port"])
            log(msg)
            env_swapped = False

            # 2o. Final service restart
            log("--- Final service restart ---")
            stdout, stderr, code = ssh.execute_sudo(
                "systemctl restart mastodon-*", timeout=60
            )
            log(stdout or stderr or "(no output)")

    except Exception as e:
        log(f"SSH ERROR: {e}")
        # Try to restore .env.production if we swapped it
        if env_swapped:
            try:
                with SSHClient.from_credential(mastodon_guest.ip_address, credential) as ssh:
                    _swap_env_db(ssh, app_dir, config["pgbouncer_host"], config["pgbouncer_port"])
                    log("Restored .env.production to PGBouncer after failure")
            except Exception:
                log("WARNING: Could not restore .env.production after failure")
        return False, "\n".join(log_lines)

    # --- Step 4: Sync code to second Mastodon app guest (if configured) ---
    if mastodon_guest_2:
        log(f"=== Step 4: Syncing code to second Mastodon guest '{mastodon_guest_2.name}' ===")
        ok = _run_second_guest_sync(mastodon_guest_2, user, app_dir, log, branch=branch)
        if not ok:
            log(f"WARNING: Code sync to '{mastodon_guest_2.name}' failed — primary upgrade was successful")

    # Success - update version tracking
    log("=== Upgrade complete! ===")
    latest = config["latest_version"] or config["current_version"]
    now = datetime.now(timezone.utc).isoformat()
    Setting.set("mastodon_current_version", latest)
    Setting.set("mastodon_update_available", "false")
    Setting.set("mastodon_last_upgrade_at", now)
    Setting.set("mastodon_last_upgrade_status", "success")
    Setting.set("mastodon_last_upgrade_log", "\n".join(log_lines))
    db.session.commit()

    return True, "\n".join(log_lines)
