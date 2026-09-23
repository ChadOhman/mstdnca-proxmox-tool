"""Mastodon account maintenance (disable 2FA, reset password, confirm/change email)
and moderator status actions (delete / mark-sensitive the posts on a report).

Both run a command on the Mastodon app guest over SSH -- the same shape of
command the "make all accounts follow @x" job in ``routes/mastodon.py`` uses
for ``tootctl accounts follow``: a non-login ``su - <user> -c '...'`` shell
with the rbenv PATH prepended so ``ruby``/``bin/tootctl``/``bin/rails``
resolve, and every settings-derived value re-validated here (not just at the
point the setting was saved) before it reaches the shell.

Command construction (:func:`build_modify_command`, :func:`build_status_action_script`,
:func:`build_status_action_command`) never touches the network -- it is pure
validation + string building, so it can be unit tested without a guest, a
credential, or an SSH connection. :func:`run_maintenance` and
:func:`run_status_action` build the command *before* looking up the
guest/credential (:func:`_run_over_ssh` is only called once building has
succeeded), so a hostile input never causes an SSH attempt.

Status actions have no REST API equivalent: Mastodon's Admin API can act on
one account or one report, but "delete/mark-sensitive these specific reported
statuses" is only exposed through the web admin UI, which drives
``Admin::ModerationAction`` (Mastodon 4.6+; ``Admin::StatusBatchAction``
before that) directly. :func:`build_status_action_script` generates the same
Ruby the controller runs, executed via ``bin/rails runner`` over SSH.
"""

import base64
import json
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

# Admin::ModerationAction#type values (Admin::StatusBatchAction before
# Mastodon 4.6) this app exposes -- the report-driven moderation actions.
STATUS_ACTIONS = {"delete": "Delete", "mark_as_sensitive": "Mark as sensitive"}

# Mastodon's own admin UI batches at most a page of statuses at a time; this
# caps the Ruby array literal (and the SSH command) to a sane size regardless
# of what the browser sends.
MAX_STATUS_IDS = 50
# Matches the moderation-note length used elsewhere in the Moderation tab.
MAX_ACTION_TEXT = 2000

# Digits only -- report/actor ids and status ids are all bigint primary keys.
_DIGITS_RE = re.compile(r"^\d+$")

# bin/rails runner's exit-code-0-with-stderr-noise case (deprecation warnings,
# etc.) means success is only ever decided by this marker line, never by exit
# code alone -- see run_status_action().
_STATUS_ACTION_OK_RE = re.compile(r"^OK (\d+)$", re.MULTILINE)

RUNNER_TIMEOUT = 240

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

    if not username or not _USERNAME_RE.fullmatch(username):
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


def _run_over_ssh(command, *, timeout):
    """Resolve the configured Mastodon app guest/credential and run ``command`` over SSH.

    Shared by :func:`run_maintenance` and :func:`run_status_action` -- both
    act against the same configured Mastodon app guest
    (``mastodon_guest_id``/its credential). Returns
    ``(ok, out, err, code, error_message)``: when guest/credential resolution
    or the SSH connection itself fails, ``ok`` is False, ``error_message`` is
    a message safe to show the caller, and ``out``/``err``/``code`` are
    ``""``/``""``/``None``; otherwise ``ok`` is True, ``error_message`` is
    ``""``, and ``out``/``err``/``code`` are the command's result.
    """
    from models import Credential, Guest, Setting

    guest_id = Setting.get("mastodon_guest_id", "")
    if not guest_id:
        return False, "", "", None, "Mastodon app guest is not configured"

    try:
        guest = Guest.query.get(int(guest_id))
    except (TypeError, ValueError):
        guest = None
    if not guest:
        return False, "", "", None, "Mastodon app guest is not configured"
    if not guest.ip_address:
        return False, "", "", None, "Guest has no IP address"

    credential = guest.credential or Credential.query.filter_by(is_default=True).first()
    if not credential:
        return False, "", "", None, "No SSH credential for the Mastodon guest"

    try:
        with SSHClient.from_credential(guest.ip_address, credential) as ssh:
            out, err, code = ssh.execute_sudo(command, timeout=timeout)
    except Exception as e:
        logger.error("Mastodon SSH command failed", exc_info=True)
        return False, "", "", None, describe_exception(e)

    return True, out, err, code, ""


def run_maintenance(action, username, *, email=None, confirm=False):
    """Run one maintenance action against ``username`` on the Mastodon app guest.

    Returns ``{"ok": bool, "message": str, "password": str | None, "output": str}``.
    The command is built (and every input validated) before ``mastodon_user``/
    ``mastodon_app_dir`` are the only settings read, and before any
    guest/credential lookup or SSH connection is attempted (see
    :func:`_run_over_ssh`), so a hostile input fails closed without ever
    reaching the network.
    """
    from models import Setting

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

    ok_transport, out, err, code, error_message = _run_over_ssh(command, timeout=COMMAND_TIMEOUT)
    if not ok_transport:
        return {"ok": False, "message": error_message, "password": None, "output": ""}

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
# Status batch actions (delete / mark-sensitive the statuses on a report)
#
# Mastodon's REST API has no endpoint for this -- the web admin UI drives
# Admin::StatusBatchAction directly (app/controllers/admin/statuses_controller.rb),
# so this runs the same Ruby via `bin/rails runner` over SSH, exactly like
# build_modify_command drives tootctl for account maintenance.
# ---------------------------------------------------------------------------


def build_status_action_script(action, status_ids, report_id, actor_account_id, *, text="", send_email=False):
    """Build the Ruby script that applies one ``Admin::StatusBatchAction`` to a report.

    Raises ``ValueError`` (never touches the network) for: an unknown
    ``action`` (must be a key of :data:`STATUS_ACTIONS`); an empty
    ``status_ids``, more than :data:`MAX_STATUS_IDS` of them, or any entry
    that isn't a digits-only string; a ``report_id``/``actor_account_id``
    that isn't digits-only; or ``text`` longer than :data:`MAX_ACTION_TEXT`.

    Only integers (the validated ids) and the fixed ``action`` literal are
    interpolated into the script; ``text`` -- the only free-form,
    operator-supplied string here -- is carried as a base64 blob and decoded
    by the script itself (``Base64.strict_decode64``), so a quote, newline or
    backslash in it can never break out of the generated Ruby source. The
    script re-derives the status id set as the intersection of the report's
    own ``status_ids`` and the requested ids (``&``), so even a caller that
    got past the digits-only check can only ever act on statuses that
    actually belong to this report.
    """
    if action not in STATUS_ACTIONS:
        raise ValueError(f"Unknown status action: {action!r}")

    if not status_ids:
        raise ValueError("No statuses selected")
    deduped = []
    seen = set()
    for sid in status_ids:
        if not isinstance(sid, str) or not _DIGITS_RE.fullmatch(sid):
            raise ValueError(f"Invalid status id: {sid!r}")
        if sid not in seen:
            seen.add(sid)
            deduped.append(sid)
    if len(deduped) > MAX_STATUS_IDS:
        raise ValueError(f"Too many statuses selected (max {MAX_STATUS_IDS})")

    if report_id is None or not _DIGITS_RE.fullmatch(str(report_id)):
        raise ValueError(f"Invalid report id: {report_id!r}")
    if actor_account_id is None or not _DIGITS_RE.fullmatch(str(actor_account_id)):
        raise ValueError(f"Invalid actor account id: {actor_account_id!r}")

    text = text or ""
    if len(text) > MAX_ACTION_TEXT:
        raise ValueError(f"Text is too long (max {MAX_ACTION_TEXT} characters)")

    ids_literal = ", ".join(f"'{sid}'" for sid in deduped)
    text_b64 = base64.b64encode(text.encode("utf-8")).decode("ascii")
    send_email_literal = "true" if send_email else "false"

    # Mastodon 4.6 (mastodon/mastodon#37970) moved delete/mark_as_sensitive out
    # of Admin::StatusBatchAction into Admin::ModerationAction, which always
    # acts on *every* status (and, from 4.7, collection) on the report. Its
    # private status_ids/collections readers are overridden on the instance so
    # it only touches the statuses picked here, as StatusBatchAction did.
    # Older releases (no ModerationAction) keep the StatusBatchAction path.
    # Validation runs before save! because BaseAction#save! raises
    # RecordInvalid with an untranslated message that hides the actual error.
    return (
        "require 'base64'\n"
        f"account = Account.find({int(actor_account_id)})\n"
        f"report = Report.find({int(report_id)})\n"
        f"ids = report.status_ids.map(&:to_s) & [{ids_literal}]\n"
        "raise 'none of the selected statuses belong to this report' if ids.empty?\n"
        f"params = {{ type: '{action}', current_account: account, report_id: report.id, "
        f"send_email_notification: {send_email_literal}, "
        f"text: Base64.strict_decode64('{text_b64}').force_encoding('UTF-8') }}\n"
        "if Admin.const_defined?(:ModerationAction)\n"
        "  selected = report.status_ids & ids.map(&:to_i)\n"
        "  action = Admin::ModerationAction.new(params)\n"
        "  action.define_singleton_method(:status_ids) { selected }\n"
        "  action.define_singleton_method(:collections) { [] }\n"
        "else\n"
        "  action = Admin::StatusBatchAction.new(params.merge(status_ids: ids))\n"
        "end\n"
        "raise \"Mastodon rejected the action: #{action.errors.full_messages.join(', ')}\" unless action.valid?\n"
        "action.save!\n"
        'puts "OK #{ids.size}"\n'
    )


def build_status_action_command(script, *, user, app_dir):
    """Base64-wrap ``script`` and pipe it to ``bin/rails runner -`` via ``su -``.

    ``bin/rails runner -`` reads the Ruby program from stdin (Rails 7.x,
    ``railties/lib/rails/commands/runner/runner_command.rb``: ``code_or_file
    == "-"`` evaluates ``$stdin.read``), so the script body never sits on the
    command line or inside a nested-quoted shell string -- the same
    base64-over-stdin idiom ``core.moderation._build_mastodon_email_query_cmd``
    uses to feed SQL to ``psql``. ``user``/``app_dir`` are the same
    settings-derived values ``build_modify_command`` validates, re-checked
    here for the same reason: a value written by an older release or a direct
    database edit must still not reach the shell.
    """
    _validate_shell_param(user, "Mastodon user")
    _validate_shell_param(app_dir, "Mastodon app directory")

    script_b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")
    return (
        f"printf '%s' '{script_b64}' | base64 -d"
        f" | su - {user} -c '{_RBENV_PATH}; cd {app_dir} && RAILS_ENV=production bin/rails runner -'"
    )


def run_status_action(action, status_ids, report_id, *, text="", send_email=False):
    """Apply one ``Admin::StatusBatchAction`` to a report's statuses on the Mastodon app guest.

    Returns ``{"ok": bool, "message": str, "count": int, "output": str}``.

    The acting account is the Mastodon account behind the admin token last
    verified on the Moderation tab (``moderation_mastodon_token_account``,
    written by the Test Connection flow in ``routes/moderation.py``) --
    ``Admin::StatusBatchAction`` records who performed the action, and MCAT
    has no other Mastodon identity to attribute it to. When that setting is
    missing (Test Connection has never succeeded, or was reset), this fails
    closed before building any command.

    Like :func:`run_maintenance`, the script and command are built (every
    input validated) before any guest/credential lookup or SSH connection is
    attempted (see :func:`_run_over_ssh`), so a hostile input fails closed
    without ever reaching the network.
    """
    from models import Setting

    actor_id = None
    raw_account = Setting.get("moderation_mastodon_token_account", "")
    if raw_account:
        try:
            parsed = json.loads(raw_account)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            actor_id = parsed.get("id")
    if not actor_id:
        return {
            "ok": False,
            "message": "Run Test Connection first so MCAT knows which Mastodon account performs the action",
            "count": 0,
            "output": "",
        }

    user = Setting.get("mastodon_user", "mastodon")
    app_dir = Setting.get("mastodon_app_dir", "/home/mastodon/live")

    try:
        script = build_status_action_script(
            action, status_ids, report_id, actor_id, text=text, send_email=send_email
        )
        command = build_status_action_command(script, user=user, app_dir=app_dir)
    except ValueError as e:
        logger.warning("Status action input rejected for action %s: %s", action, e)
        return {"ok": False, "message": INVALID_INPUT_MESSAGE, "count": 0, "output": ""}

    label = STATUS_ACTIONS[action]

    ok_transport, out, err, code, error_message = _run_over_ssh(command, timeout=RUNNER_TIMEOUT)
    if not ok_transport:
        return {"ok": False, "message": error_message, "count": 0, "output": ""}

    out = _cap(out)
    err = _cap(err)
    output = (out + ("\n" + err if err else "")).strip()

    match = _STATUS_ACTION_OK_RE.search(out)
    ok = code == 0 and match is not None
    count = int(match.group(1)) if match else 0

    if ok:
        message = f"{label} applied to {count} post(s); report #{report_id} resolved"
    else:
        # A raised Ruby exception prints its message first (RuntimeError#message,
        # ActiveRecord::RecordNotFound, StatusBatchAction validation errors, ...).
        message = _first_line(err) or _first_line(out)
        if not message:
            message = f"rails runner exited with code {code}"

    return {"ok": ok, "message": message, "count": count, "output": output}


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
