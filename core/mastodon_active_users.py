"""Mastodon active-user export: local accounts that signed in recently, with email.

Feeds the admin-only "Active users" page (``routes/active_users.py``), which
exists so an administrator can pull a mailing list of monthly active users
into an external mail tool. MCAT never sends the email itself.

The query runs read-only against the Mastodon PostgreSQL guest
(``mastodon_db_guest_id``) over SSH, using the same base64-over-stdin psql
idiom as :func:`core.moderation.fetch_mastodon_emails` so no part of the SQL
is ever interpolated into a nested-quoted shell argument. The only
caller-controlled value in the SQL is the look-back window, which is coerced
to an ``int`` within :data:`MIN_DAYS`..:data:`MAX_DAYS` before it is used.

"Active" means ``users.current_sign_in_at`` falls inside the window. Mastodon
refreshes that column at most once a day per session
(``User::SIGN_IN_UPDATE_FREQUENCY``), so it is accurate to the day. Mastodon's
own dashboard MAU figure comes from a Redis activity counter rather than this
column, so the two numbers can differ slightly.
"""

import csv
import io
import json
import logging

from apps.utils import _validate_shell_param
from core.errors import describe_exception
from core.moderation import _build_mastodon_email_query_cmd

logger = logging.getLogger(__name__)

DEFAULT_DAYS = 30
MIN_DAYS = 1
MAX_DAYS = 365
QUERY_TIMEOUT = 60

CSV_COLUMNS = ("username", "email", "locale", "last_active")

# Leading characters a spreadsheet treats as a formula. An email local part
# may legitimately start with "=", "+" or "-", so these cells are prefixed
# with an apostrophe in the CSV (OWASP CSV injection guidance).
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def clamp_days(raw):
    """Coerce a look-back window from user input to an int in MIN_DAYS..MAX_DAYS."""
    try:
        days = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_DAYS
    return max(MIN_DAYS, min(MAX_DAYS, days))


def build_active_users_query(days):
    """Return the SQL selecting local, mailable accounts active within ``days`` days.

    Excludes remote accounts, unconfirmed/unapproved sign-ups, disabled logins,
    suspended accounts and memorialised accounts. The result is a single JSON
    array (one psql output line) so emails containing ``|`` or other
    separators can't corrupt the row split.
    """
    days = clamp_days(days)
    return (
        "SELECT coalesce(json_agg(r ORDER BY r.last_active DESC), '[]'::json) FROM ("  # noqa: S608 — days is an int
        "SELECT a.username, u.email, coalesce(u.locale, '') AS locale, "
        "to_char(u.current_sign_in_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS last_active "
        "FROM users u JOIN accounts a ON a.id = u.account_id "
        "WHERE a.domain IS NULL "
        f"AND u.current_sign_in_at >= now() - interval '{days} days' "
        "AND u.confirmed_at IS NOT NULL "
        "AND u.approved = true "
        "AND u.disabled = false "
        "AND a.suspended_at IS NULL "
        "AND a.memorial = false"
        ") r"
    )


def parse_active_users_output(stdout):
    """Parse psql's single-line JSON array into a list of row dicts."""
    text = (stdout or "").strip()
    if not text:
        return []
    data = json.loads(text)
    if not isinstance(data, list):
        raise ValueError("unexpected query output")
    rows = []
    for item in data:
        if not isinstance(item, dict) or not item.get("email"):
            continue
        rows.append({
            "username": str(item.get("username") or ""),
            "email": str(item["email"]).strip(),
            "locale": str(item.get("locale") or ""),
            "last_active": str(item.get("last_active") or ""),
        })
    return rows


def fetch_active_users(days=DEFAULT_DAYS):
    """Query the Mastodon DB guest for active local users.

    Returns ``(rows, None)`` on success or ``(None, message)`` on failure. The
    message is safe to show in the UI: psql's stderr and exception text go to
    the server log only.
    """
    from models import Guest, Setting, db

    db_guest_id = Setting.get("mastodon_db_guest_id", "")
    if not db_guest_id:
        return None, "Mastodon database guest is not configured (Mastodon → Settings)"
    try:
        db_guest = db.session.get(Guest, int(db_guest_id))
    except (TypeError, ValueError):
        db_guest = None
    if not db_guest:
        return None, "Mastodon database guest not found"
    if not db_guest.ip_address:
        return None, f"Mastodon database guest '{db_guest.name}' has no IP address"
    credential = db_guest.credential
    if not credential:
        return None, f"Mastodon database guest '{db_guest.name}' has no SSH credential"

    db_name = Setting.get("mastodon_db_name", "mastodon_production")
    try:
        _validate_shell_param(db_name, "Database name")
    except ValueError:
        return None, "Configured Mastodon database name is invalid"

    cmd = _build_mastodon_email_query_cmd(db_name, build_active_users_query(days))

    try:
        from clients.ssh_client import SSHClient
        with SSHClient.from_credential(db_guest.ip_address, credential) as ssh:
            stdout, stderr, code = ssh.execute_sudo(cmd, timeout=QUERY_TIMEOUT)
    except Exception as exc:
        logger.error("Active-user query: SSH to %s failed", db_guest.name, exc_info=True)
        return None, f"SSH error: {describe_exception(exc)}"

    if code != 0:
        logger.error("Active-user query failed on %s (exit %s): %s", db_guest.name, code, (stderr or "").strip()[:500])
        return None, f"Database query failed (exit {code}); see the server log"

    try:
        return parse_active_users_output(stdout), None
    except ValueError:
        # Never log stdout here: it is a list of personal email addresses.
        logger.error("Active-user query on %s returned unparseable output", db_guest.name)
        return None, "Database returned unexpected output; see the server log"


def _csv_safe(value):
    if value and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def rows_to_csv(rows):
    """Render rows as CSV text with a header line, neutralising formula cells."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    for row in rows:
        writer.writerow([_csv_safe(row.get(col, "")) for col in CSV_COLUMNS])
    return buf.getvalue()
