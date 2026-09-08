"""Shared helpers for application upgrade automation modules."""

import contextlib
import re
import threading

# Shell-safe value pattern: alphanumeric, hyphens, underscores, dots, forward slashes, colons
_SHELL_SAFE_RE = re.compile(r'^[\w.\-/:~]+$')

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
