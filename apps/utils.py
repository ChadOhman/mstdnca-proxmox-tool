"""Shared helpers for application upgrade automation modules."""

import base64
import contextlib
import re
import secrets
import shlex
import threading

# Shell-safe value pattern: alphanumeric, hyphens, underscores, dots, forward slashes, colons
_SHELL_SAFE_RE = re.compile(r'^[\w.\-/:~]+$')

# ---------------------------------------------------------------------------
# Allow-list patterns for settings that end up in a root shell on a remote host.
#
# Every one of these is applied twice: once in the save handler (routes/*), so a
# hostile value is never persisted, and once at the point of use (apps/*), so a
# value written by an older release, a database edit, or another code path can
# still not reach a shell.  Values are additionally quoted at the sink.
# ---------------------------------------------------------------------------

# FQDN / hostname
_HOSTNAME_RE = re.compile(
    r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
)

# IPv4 literal
_IP_RE = re.compile(r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')

# Email address (RFC-practical subset)
_EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')

# A single path component: no separators, no traversal, no shell metacharacters
_SAFE_FILENAME_RE = re.compile(r'^[\w.\-]+$')

# Absolute filesystem path (traversal is rejected separately)
_ABS_PATH_RE = re.compile(r'^/[\w.\-/]*[\w.\-]$')

# Unix account name
_USERNAME_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_.\-]{0,31}$')

# PostgreSQL identifier
_DB_NAME_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_$]{0,62}$')

# git branch / ref name (traversal is rejected separately)
_GIT_BRANCH_RE = re.compile(r'^[A-Za-z0-9][\w.\-/]{0,127}$')

# GitHub "owner/repo" slug
_GIT_REPO_RE = re.compile(r'^[\w.\-]+/[\w.\-]+$')

# Release tag as published by a GitHub release ("v1.2.3", "3.14.0-rc.1", …)
_RELEASE_TAG_RE = re.compile(r'^v?\d+(\.\d+){1,3}([-.\w]*)$')

# .ruby-version content
_RUBY_VERSION_RE = re.compile(r'^\d+\.\d+\.\d+(?:-[\w.]+)?$')

# http(s)://host[:port][/path] — no quotes, whitespace, backslash, or percent
# escapes, all of which would be corrupting or dangerous at a shell/printf sink.
_HTTP_URL_RE = re.compile(
    r'^https?://'
    r'[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*'
    r'(:\d{1,5})?'
    r'(/[\w.\-~/]*)?$'
)

# Anything a config-file value must never contain (NUL, newline, other C0, DEL).
_CONTROL_CHAR_RE = re.compile(r'[\x00-\x1f\x7f]')

# ---------------------------------------------------------------------------
# Per-app upgrade lock
#
# Manual upgrades (routes/*) and scheduled auto-upgrades (core/scheduler.py)
# both drive the same remote host.  The per-blueprint JobTracker only guards
# the manual path, so a cron-triggered upgrade could run concurrently with a
# manual one.  Both paths take this process-wide, per-app lock instead.
# ---------------------------------------------------------------------------

_UPGRADE_LOCKS: dict[str, threading.Lock] = {}
_UPGRADE_LOCKS_GUARD = threading.Lock()


def _get_upgrade_lock(app_name: str) -> threading.Lock:
    """Return (creating on first use) the upgrade lock for ``app_name``."""
    with _UPGRADE_LOCKS_GUARD:
        lock = _UPGRADE_LOCKS.get(app_name)
        if lock is None:
            lock = threading.Lock()
            _UPGRADE_LOCKS[app_name] = lock
        return lock


def acquire_upgrade_lock(app_name: str) -> bool:
    """Take the per-app upgrade lock without blocking.

    Returns True if the caller now owns the lock (and must release it), or
    False if another upgrade is already running for that app.
    """
    return _get_upgrade_lock(app_name).acquire(blocking=False)


def release_upgrade_lock(app_name: str) -> None:
    """Release the per-app upgrade lock; a double release is a no-op."""
    try:
        _get_upgrade_lock(app_name).release()
    except RuntimeError:
        pass


@contextlib.contextmanager
def upgrade_lock(app_name: str):
    """Context manager yielding True when the per-app upgrade lock was taken.

    Used by the scheduler, which can simply skip a run; the routes acquire the
    lock in the request handler (so the check-and-set is atomic) and release it
    from the background job.
    """
    acquired = acquire_upgrade_lock(app_name)
    try:
        yield acquired
    finally:
        if acquired:
            release_upgrade_lock(app_name)


def _log_cmd_output(log, stdout, stderr, code, max_chars=2000):
    """Log combined stdout+stderr, showing start+end on failure (error before stack trace)."""
    combined = ((stdout or "") + ("\n" + stderr if stderr else "")).strip()
    if not combined:
        return
    if len(combined) <= max_chars:
        log(combined)
    elif code != 0:
        # On failure the actual error is near the top; stack trace fills the bottom.
        # Show first 1500 + last 500 so both error and context are visible.
        head = combined[:1500].strip()
        tail = combined[-500:].strip()
        log(head)
        log("[... output truncated ...]")
        log(tail)
    else:
        log(combined[-max_chars:].strip())


def _validate_shell_param(value, label):
    """Raise ValueError if a config value contains shell-unsafe characters."""
    if not value:
        raise ValueError(f"{label} is empty")
    if not _SHELL_SAFE_RE.match(value):
        raise ValueError(f"{label} contains unsafe characters: {value!r}")


# ---------------------------------------------------------------------------
# Typed validators
#
# Each raises ValueError with a user-presentable message.  Save handlers catch
# it and flash the message (leaving the stored setting untouched); the app
# modules catch it and return (False, msg) before opening an SSH connection.
# ---------------------------------------------------------------------------

def _validate_no_control_chars(value, label):
    """Reject NUL/newline/other control characters in a config-file value.

    A newline is what lets a value close a heredoc early or add an extra key to
    an env/TOML/YAML file, so it is rejected for every value we write remotely.
    """
    if value is None:
        return
    if _CONTROL_CHAR_RE.search(str(value)):
        raise ValueError(f"{label} must not contain newlines or control characters")


def _validate_hostname(value, label):
    """Validate a hostname/FQDN."""
    if not value:
        raise ValueError(f"{label} is empty")
    if len(value) > 253 or not _HOSTNAME_RE.match(value):
        raise ValueError(f"{label} is not a valid hostname: {value!r}")


def _validate_ipv4(value, label):
    """Validate an IPv4 literal."""
    if not value:
        raise ValueError(f"{label} is empty")
    if not _IP_RE.match(value):
        raise ValueError(f"{label} is not a valid IPv4 address: {value!r}")


def _validate_email(value, label):
    """Validate an email address.

    Emails contain ``@`` and often ``+``, neither of which is in
    ``_SHELL_SAFE_RE`` — running _validate_shell_param over an address rejects
    every valid one, so this is the check to use for email fields.
    """
    if not value:
        raise ValueError(f"{label} is empty")
    if len(value) > 254 or not _EMAIL_RE.match(value):
        raise ValueError(f"{label} is not a valid email address: {value!r}")


def _validate_http_url(value, label):
    """Validate an http(s) URL of the form scheme://host[:port][/path]."""
    if not value:
        raise ValueError(f"{label} is empty")
    if len(value) > 2048 or not _HTTP_URL_RE.match(value):
        raise ValueError(
            f"{label} must be an http(s) URL such as https://example.com "
            f"(no quotes, spaces, '%', or '\\'): {value!r}"
        )


def _validate_abs_path(value, label):
    """Validate an absolute filesystem path.

    Rejects the filesystem root itself, relative paths, ``..`` traversal, and
    anything outside ``[A-Za-z0-9_.-/]``.
    """
    if not value:
        raise ValueError(f"{label} is empty")
    if value == "/":
        raise ValueError(f"{label} must not be the filesystem root")
    if not _ABS_PATH_RE.match(value):
        raise ValueError(f"{label} must be an absolute path without spaces or shell characters: {value!r}")
    if ".." in value.split("/"):
        raise ValueError(f"{label} must not contain '..': {value!r}")


def _validate_username(value, label):
    """Validate a Unix account name."""
    if not value:
        raise ValueError(f"{label} is empty")
    if not _USERNAME_RE.match(value):
        raise ValueError(f"{label} is not a valid user name: {value!r}")


def _validate_db_name(value, label):
    """Validate a PostgreSQL database name."""
    if not value:
        raise ValueError(f"{label} is empty")
    if not _DB_NAME_RE.match(value):
        raise ValueError(f"{label} is not a valid database name: {value!r}")


def _validate_git_branch(value, label):
    """Validate a git branch/ref name."""
    if not value:
        raise ValueError(f"{label} is empty")
    if not _GIT_BRANCH_RE.match(value) or ".." in value:
        raise ValueError(f"{label} is not a valid git branch name: {value!r}")


def _validate_git_repo(value, label):
    """Validate a GitHub ``owner/repo`` slug."""
    if not value:
        raise ValueError(f"{label} is empty")
    if not _GIT_REPO_RE.match(value) or ".." in value:
        raise ValueError(f"{label} must be of the form owner/repo: {value!r}")


def _validate_release_tag(value, label="Release tag"):
    """Validate a release tag/version taken from a third-party release feed.

    Applied immediately after parsing the GitHub API response so a compromised
    or malformed upstream tag never reaches a download URL, an extraction path,
    or an ``rm -rf``.
    """
    if not value:
        raise ValueError(f"{label} is empty")
    if len(value) > 64 or not _RELEASE_TAG_RE.match(value):
        raise ValueError(f"{label} is not a valid version: {value!r}")


def _validate_safe_filename(value, label, allow_subdir=False):
    """Validate a file name, optionally allowing a single subdirectory level.

    Jibri lists recordings as ``<dir>/<file>`` or ``<subdir>/<file>``, so one
    level of nesting is permitted when ``allow_subdir`` is set; each component
    still has to match ``_SAFE_FILENAME_RE`` (which excludes ``..``, ``/`` and
    every shell metacharacter).
    """
    if not value:
        raise ValueError(f"{label} is empty")
    parts = value.split("/")
    if len(parts) > (2 if allow_subdir else 1):
        raise ValueError(f"{label} contains too many path components: {value!r}")
    for part in parts:
        if not _SAFE_FILENAME_RE.match(part) or part in (".", ".."):
            raise ValueError(f"{label} is not a valid file name: {value!r}")


# ---------------------------------------------------------------------------
# Remote file writes
# ---------------------------------------------------------------------------

def _remote_write_cmd(path, content, mode=None, owner=None, group=None, append=False):
    """Build a shell command that writes ``content`` to ``path`` on a remote host.

    The payload is base64-encoded and the destination path is shell-quoted, so
    neither the file body nor the path can terminate the command early.  This
    replaces ``cat > file << 'EOF' … EOF``, whose terminator a body line can
    match (accidentally or deliberately) to break out into the root shell.

    When ``mode``/``owner`` are given the content is piped through ``install``,
    which creates the destination with its final mode and ownership in one step
    rather than at the shell's default umask.  ``append`` is mutually exclusive
    with ``mode``/``owner``.
    """
    b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")
    target = shlex.quote(path)
    # base64 output is [A-Za-z0-9+/=] only, so it needs no quoting of its own.
    pipe = f"echo {b64} | base64 -d"
    if append:
        return f"{pipe} >> {target}"
    if mode or owner:
        args = ""
        if mode:
            args += f" -m {shlex.quote(mode)}"
        if owner:
            args += f" -o {shlex.quote(owner)} -g {shlex.quote(group or owner)}"
        return f"{pipe} | install{args} /dev/stdin {target}"
    return f"{pipe} > {target}"


# ---------------------------------------------------------------------------
# Verified release downloads
# ---------------------------------------------------------------------------

_WORKDIR_PREFIX = "/tmp/mstdnca-rel-"  # nosec B108 — remote path on the managed guest


def _fetch_verified_tarball(ssh, log, url, asset_name, checksum_url, timeout=300):
    """Download a release tarball into a private temp dir and verify its digest.

    ``checksum_url`` must point at the checksum file published alongside
    ``asset_name`` in the same release (``sha256sums.txt`` for the Prometheus
    projects, ``<name>_<version>_checksums.txt`` for unpoller).  Only the line
    naming this asset is checked, with ``sha256sum -c``; a missing entry or a
    digest mismatch aborts before anything is extracted, let alone installed.

    The working directory is created with ``mkdir -m 700`` under a name with 128
    bits of entropy — ``mkdir`` fails rather than reusing an existing path, so a
    local user on the guest cannot pre-create it or point it elsewhere, unlike
    the predictable ``/tmp/<binary>.tar.gz`` paths this replaces.

    Returns ``(ok, workdir, error)``; the caller is responsible for
    ``rm -rf`` of ``workdir`` (see :func:`_cleanup_workdir`).
    """
    workdir = f"{_WORKDIR_PREFIX}{secrets.token_hex(16)}"
    q_dir = shlex.quote(workdir)
    q_url = shlex.quote(url)
    q_asset = shlex.quote(asset_name)
    q_sums = shlex.quote(checksum_url)
    cmd = (
        "set -e; "
        f"mkdir -m 700 {q_dir}; "
        f"cd {q_dir}; "
        f"(curl -sSfL -o {q_asset} {q_url} || wget -q -O {q_asset} {q_url}); "
        f"(curl -sSfL -o CHECKSUMS {q_sums} || wget -q -O CHECKSUMS {q_sums}); "
        f"grep -E {shlex.quote('[[:space:]][*]?' + re.escape(asset_name) + '$')} CHECKSUMS > CHECKSUMS.asset; "
        "test -s CHECKSUMS.asset; "
        "sha256sum -c CHECKSUMS.asset; "
        f"tar xzf {q_asset}"
    )
    stdout, stderr, code = ssh.execute_sudo(cmd, timeout=timeout)
    if code != 0:
        _log_cmd_output(log, stdout, stderr, code, max_chars=1000)
        _cleanup_workdir(ssh, workdir)
        return False, "", "download or SHA-256 verification failed"
    log(f"  SHA-256 verified against {checksum_url}")
    return True, workdir, ""


def _cleanup_workdir(ssh, workdir, timeout=15):
    """Remove a workdir created by :func:`_fetch_verified_tarball`."""
    if not workdir or not workdir.startswith(_WORKDIR_PREFIX):
        return
    ssh.execute_sudo(f"rm -rf {shlex.quote(workdir)}", timeout=timeout)


def _version_gt(candidate: str, current: str) -> bool:
    """True if candidate semver is strictly greater than current.

    Strips build metadata (e.g. '+glitch') before comparing so that
    '4.5.7' and '4.6.0-alpha.5+glitch' are compared by their numeric
    components only.  A stable release (no pre-release tag) sorts higher
    than a pre-release with the same major.minor.patch.
    """
    def _parse(v):
        v = v.lstrip("v").split("+")[0]
        m = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:-(.+))?$", v)
        if not m:
            return None
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4))

    pa, pb = _parse(candidate), _parse(current)
    if pa is None or pb is None:
        return False
    if pa[:3] != pb[:3]:
        return pa[:3] > pb[:3]
    # Same major.minor.patch — stable (pre=None) sorts above any pre-release
    pre_a, pre_b = pa[3], pb[3]
    if pre_a is None and pre_b is None:
        return False
    if pre_a is None:
        return True   # candidate is stable, current is pre-release → newer
    if pre_b is None:
        return False  # candidate is pre-release, current is stable → older
    return pre_a > pre_b  # both pre-release: lexicographic comparison


class JobTracker:
    """Tracks in-memory state for a background job.

    Supports dict-style access (job["running"], job["log"]) for compatibility
    with existing call sites, as well as attribute access (job.running, job.log).

    Usage:
        _upgrade_job = JobTracker()  # replaces {"running": False, "success": None, "log": []}
    """

    def __init__(self):
        self.running: bool = False
        self.success: bool | None = None
        self.log: list = []

    def reset(self) -> None:
        """Reset to initial state (call before starting a new job)."""
        self.running = False
        self.success = None
        self.log = []

    def update(self, d: dict) -> None:
        """Update multiple attributes from a dict (dict-compatibility method)."""
        for k, v in d.items():
            setattr(self, k, v)

    def __getitem__(self, key: str):
        return getattr(self, key)

    def __setitem__(self, key: str, value) -> None:
        setattr(self, key, value)
