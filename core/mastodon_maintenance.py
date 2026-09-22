"""Mastodon account maintenance (disable 2FA, reset password, confirm/change email).

Runs ``bin/tootctl accounts modify`` on the Mastodon app guest over SSH, the
same shape of command the "make all accounts follow @x" job in
``routes/mastodon.py`` uses for ``tootctl accounts follow``: a non-login
``su - <user> -c '...'`` shell with the rbenv PATH prepended so ``ruby`` and
``bin/tootctl`` resolve, and every settings-derived value re-validated here
(not just at the point the setting was saved) before it reaches the shell.

Command construction (:func:`build_modify_command`) never touches the
network -- it is pure validation + string building, so it can be unit tested
without a guest, a credential, or an SSH connection, and :func:`run_maintenance`
builds the command *before* looking up the guest/credential, so a hostile
input never causes an SSH attempt.
"""

import logging
import re
import shlex
import threading

from apps.utils import _validate_email, _validate_shell_param
from clients.ssh_client import SSHClient
from core.errors import describe_exception

logger = logging.getLogger(__name__)

# Mirrors apps.mastodon._RBENV_PATH: su - creates a non-interactive login
# shell that sources .profile but not .bashrc on Debian/Ubuntu, so rbenv
# shims installed via .bashrc are otherwise absent.
_RBENV_PATH = "export PATH=$HOME/.rbenv/bin:$HOME/.rbenv/shims:$PATH"

MAINTENANCE_ACTIONS = {
    "disable_2fa": {"label": "Disable two-factor authentication", "flags": ("--disable-2fa",)},
    "reset_password": {"label": "Reset password", "flags": ("--reset-password",)},
    "confirm_email": {"label": "Confirm email", "flags": ("--confirm",)},
    "change_email": {"label": "Change email", "flags": None},  # built from email/confirm
}

# Mirrors the "account" allow-list in routes.mastodon.follow_account.
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{1,30}$")

# Output is a few lines of tootctl status text; capped generously above that
# so a runaway/hostile stream can't be held in memory indefinitely.
MAX_OUTPUT_BYTES = 64 * 1024
COMMAND_TIMEOUT = 180
INVALID_INPUT_MESSAGE = "Invalid input for this maintenance action (username, email or Mastodon settings)"

# tootctl prints the generated password on stdout, e.g. "New password: xyz".
_NEW_PASSWORD_RE = re.compile(r"^New password:\s*(\S+)", re.MULTILINE)
_REDACTED = "[redacted]"

_MAX_MESSAGE_CHARS = 300


class MaintenanceBusy(Exception):
    """Raised by :func:`maintenance_slot` when another maintenance action is running."""


def build_modify_command(username, action, *, email=None, confirm=False, user, app_dir):
    """Build the ``tootctl accounts modify`` shell command for one maintenance action.

    Raises ``ValueError`` (never opens an SSH connection, never touches the
    database) for: an unknown ``action``; a ``username`` that fails the
    allow-list regex; a ``user``/``app_dir`` setting that fails
    ``_validate_shell_param``; a missing/invalid ``email`` on
    ``change_email``; or an ``email`` supplied for any other action.
    """
    spec = MAINTENANCE_ACTIONS.get(action)
    if spec is None:
        raise ValueError(f"Unknown maintenance action: {action!r}")

    if not username or not _USERNAME_RE.match(username):
        raise ValueError(f"Invalid username: {username!r}")

    _validate_shell_param(user, "Mastodon user")
    _validate_shell_param(app_dir, "Mastodon app directory")

    if action == "change_email":
        _validate_email(email, "Email")
        flags = f"--email {shlex.quote(email)}"
        if confirm:
            flags += " --confirm"
    else:
        if email is not None:
            raise ValueError(f"email is not used by the {action!r} action")
        flags = " ".join(spec["flags"])

    return (
        f"su - {user} -c '{_RBENV_PATH}; cd {app_dir} && "
        f"RAILS_ENV=production bin/tootctl accounts modify {username} {flags}'"
    )


def _cap(text):
    if text is None:
        return ""
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= MAX_OUTPUT_BYTES:
        return text
    return encoded[:MAX_OUTPUT_BYTES].decode("utf-8", errors="ignore") + "\n[output truncated]"


def _redact_password(text, password):
    if not password or not text:
        return text
    return text.replace(password, _REDACTED)


def _first_line(text):
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:_MAX_MESSAGE_CHARS]
    return ""


def run_maintenance(action, username, *, email=None, confirm=False):
    """Run one maintenance action against ``username`` on the Mastodon app guest.

    Returns ``{"ok": bool, "message": str, "password": str | None, "output": str}``.
    The command is built (and every input validated) before any settings other
    than ``mastodon_guest_id``/``mastodon_user``/``mastodon_app_dir`` are read
    and before any guest/credential lookup or SSH connection is attempted, so a
    hostile input fails closed without ever reaching the network.
    """
    from models import Credential, Guest, Setting

    guest_id = Setting.get("mastodon_guest_id", "")
    user = Setting.get("mastodon_user", "mastodon")
    app_dir = Setting.get("mastodon_app_dir", "/home/mastodon/live")

    try:
        command = build_modify_command(username, action, email=email, confirm=confirm, user=user, app_dir=app_dir)
    except ValueError as e:
        # Our own validator text, but keep exception strings out of responses
        # (CodeQL py/stack-trace-exposure); the detail goes to the log.
        logger.warning("Maintenance input rejected for action %s: %s", action, e)
        return {"ok": False, "message": INVALID_INPUT_MESSAGE, "password": None, "output": ""}

    label = MAINTENANCE_ACTIONS[action]["label"]

    if not guest_id:
        return {"ok": False, "message": "Mastodon app guest is not configured", "password": None, "output": ""}

    try:
        guest = Guest.query.get(int(guest_id))
    except (TypeError, ValueError):
        guest = None
    if not guest:
        return {"ok": False, "message": "Mastodon app guest is not configured", "password": None, "output": ""}
    if not guest.ip_address:
        return {"ok": False, "message": "Guest has no IP address", "password": None, "output": ""}

    credential = guest.credential or Credential.query.filter_by(is_default=True).first()
    if not credential:
        return {"ok": False, "message": "No SSH credential for the Mastodon guest", "password": None, "output": ""}

    try:
        with SSHClient.from_credential(guest.ip_address, credential) as ssh:
            out, err, code = ssh.execute_sudo(command, timeout=COMMAND_TIMEOUT)
    except Exception as e:
        logger.error("Mastodon account maintenance (%s) failed for @%s", action, username, exc_info=True)
        return {"ok": False, "message": describe_exception(e), "password": None, "output": ""}

    out = _cap(out)
    err = _cap(err)

    password = None
    if action == "reset_password":
        match = _NEW_PASSWORD_RE.search(out)
        if match:
            password = match.group(1)

    combined = (out + ("\n" + err if err else "")).strip()
    output = _redact_password(combined, password)

    ok = code == 0 and "OK" in out

    if ok:
        message = f"{label} applied to @{username}"
    else:
        message = _first_line(err) or _first_line(out)
        message = _redact_password(message, password)
        if not message:
            message = f"tootctl exited with code {code}"

    return {"ok": ok, "message": message, "password": password, "output": output}


# ---------------------------------------------------------------------------
# Single-flight lock
#
# Maintenance actions modify Mastodon accounts (password resets, 2FA); only
# one is allowed to run at a time so two admins can't race tootctl on the
# same guest.
# ---------------------------------------------------------------------------

_maintenance_lock = threading.Lock()


def try_acquire() -> bool:
    """Take the maintenance lock without blocking; True if acquired."""
    return _maintenance_lock.acquire(blocking=False)


def release() -> None:
    """Release the maintenance lock; a double release is a no-op."""
    try:
        _maintenance_lock.release()
    except RuntimeError:
        pass


class _MaintenanceSlot:
    def __enter__(self):
        if not try_acquire():
            raise MaintenanceBusy("A Mastodon account maintenance action is already in progress.")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        release()
        return False


def maintenance_slot():
    """Context manager that raises :class:`MaintenanceBusy` when already held."""
    return _MaintenanceSlot()
