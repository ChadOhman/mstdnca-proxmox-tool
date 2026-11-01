"""Mastodon monthly highlights: the month's most-engaged local posts, as email HTML.

Feeds the admin-only "Monthly highlights" page (``routes/highlights.py``),
which builds a newsletter body an administrator pastes into an external mail
tool (Mailjet). MCAT never sends the email itself.

Like :mod:`core.mastodon_active_users`, the query runs read-only against the
Mastodon PostgreSQL guest over SSH with the SQL piped to psql on stdin. The
only caller-controlled values in the SQL are integers: the snowflake-ID bounds
derived from a validated ``YYYY-MM`` month, and a clamped candidate limit.

Only posts Mastodon itself would be willing to put in Trends are eligible:
public, top-level, local, no content warning or sensitive flag, from a
discoverable account that is not suspended, silenced, memorialised or a bot,
and not explicitly rejected from trends by a moderator. Being featured in an
email to every member is at least as visible as trending, so the author's
``discoverable`` opt-in is the consent signal.
"""

import json
import logging
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

from apps.utils import _validate_shell_param
from core.errors import describe_exception
from core.moderation import _build_mastodon_email_query_cmd

logger = logging.getLogger(__name__)

DEFAULT_COUNT = 5
MIN_COUNT = 1
MAX_COUNT = 20
# Posts kept per account before ranking across accounts.
DEFAULT_PER_AUTHOR = 1
# Extra rows fetched beyond the requested count so the admin can untick a post
# and still have replacements to fall back on.
CANDIDATE_EXTRA = 10
QUERY_TIMEOUT = 120
EXCERPT_CHARS = 500

# Ranking weights. A boost puts the post in front of new people, so it counts
# for more than a favourite; a reply is engagement but also where pile-ons live.
WEIGHT_FAVOURITES = 1
WEIGHT_REBLOGS = 2
WEIGHT_REPLIES = 1

_MONTH_RE = re.compile(r"^(\d{4})-(\d{2})$")
_HOST_RE = re.compile(r"^[a-z0-9.-]+(:\d+)?$")


def default_month(now=None):
    """Return the previous calendar month as ``YYYY-MM`` (the usual newsletter target)."""
    now = now or datetime.now(timezone.utc)
    year, month = (now.year, now.month - 1) if now.month > 1 else (now.year - 1, 12)
    return f"{year:04d}-{month:02d}"


def parse_month(raw):
    """Validate a ``YYYY-MM`` string; return ``(start, end)`` UTC datetimes or ``None``."""
    match = _MONTH_RE.match((raw or "").strip())
    if not match:
        return None
    year, month = int(match.group(1)), int(match.group(2))
    if not (2016 <= year <= 9999 and 1 <= month <= 12):
        return None
    start = datetime(year, month, 1, tzinfo=timezone.utc)
    end = datetime(year + (month == 12), month % 12 + 1, 1, tzinfo=timezone.utc)
    return start, end


def month_label(raw):
    bounds = parse_month(raw)
    return bounds[0].strftime("%B %Y") if bounds else raw


def clamp_per_author(raw):
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_PER_AUTHOR
    return max(1, min(MAX_COUNT, value))


def clamp_count(raw):
    try:
        count = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_COUNT
    return max(MIN_COUNT, min(MAX_COUNT, count))


def snowflake_floor(dt):
    """Lowest Mastodon status ID that can have been created at ``dt``.

    Mastodon IDs are ``milliseconds_since_epoch << 16`` plus a sequence, so a
    month maps onto a primary-key range and the query never scans by
    ``created_at`` (unindexed on ``statuses``).
    """
    return int(dt.timestamp() * 1000) << 16


def build_highlights_query(start, end, limit, per_author=DEFAULT_PER_AUTHOR):
    """Return the SQL selecting the top eligible local posts created in ``[start, end)``.

    At most ``per_author`` posts per account are kept, so one prolific poster
    can't fill the whole newsletter.
    """
    lo, hi = snowflake_floor(start), snowflake_floor(end)
    limit = max(1, min(MAX_COUNT + CANDIDATE_EXTRA, int(limit)))
    per_author = clamp_per_author(per_author)
    score = (f"({WEIGHT_FAVOURITES} * ss.favourites_count + {WEIGHT_REBLOGS} * ss.reblogs_count"
             f" + {WEIGHT_REPLIES} * ss.replies_count)")
    return (
        "SELECT coalesce(json_agg(r ORDER BY r.score DESC, r.id DESC), '[]'::json) FROM ("  # noqa: S608 — ints only
        "SELECT t.*, (SELECT count(*) FROM media_attachments m WHERE m.status_id = t.id::bigint) AS media_count "
        "FROM ("
        "SELECT s.id::text AS id, a.username, coalesce(a.display_name, '') AS display_name, "
        "s.text, coalesce(s.uri, '') AS uri, "
        "to_char(s.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS created_at, "
        "ss.favourites_count AS favourites, ss.reblogs_count AS reblogs, ss.replies_count AS replies, "
        f"{score} AS score, "
        f"row_number() OVER (PARTITION BY s.account_id ORDER BY {score} DESC, s.id DESC) AS author_rank "
        "FROM statuses s "
        "JOIN accounts a ON a.id = s.account_id "
        "JOIN status_stats ss ON ss.status_id = s.id "
        f"WHERE s.id >= {lo} AND s.id < {hi} "
        "AND a.domain IS NULL "
        "AND s.deleted_at IS NULL "
        "AND s.visibility = 0 "
        "AND s.reblog_of_id IS NULL "
        "AND s.in_reply_to_id IS NULL "
        "AND s.sensitive = false "
        "AND coalesce(s.spoiler_text, '') = '' "
        "AND s.trendable IS DISTINCT FROM false "
        "AND a.discoverable = true "
        "AND a.trendable IS DISTINCT FROM false "
        "AND a.suspended_at IS NULL "
        "AND a.silenced_at IS NULL "
        "AND a.memorial = false "
        "AND coalesce(a.actor_type, '') NOT IN ('Service', 'Application')"
        f") t WHERE t.author_rank <= {per_author} "
        "ORDER BY t.score DESC, t.id::bigint DESC "
        f"LIMIT {limit}"
        ") r"
    )


def _public_url(uri, username, status_id):
    """Build the human-facing ``https://host/@user/id`` link from the ActivityPub URI."""
    host = urlsplit(uri).netloc.lower() if uri else ""
    if not _HOST_RE.match(host):
        return ""
    return f"https://{host}/@{username}/{status_id}"


def excerpt(text, limit=EXCERPT_CHARS):
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(None, 1)[0] if " " in text[:limit] else text[:limit]
    return cut.rstrip(" .,;:") + "…"


def parse_highlights_output(stdout):
    """Parse psql's single-line JSON array into post dicts ready for the email template."""
    text = (stdout or "").strip()
    if not text:
        return []
    data = json.loads(text)
    if not isinstance(data, list):
        raise ValueError("unexpected query output")
    posts = []
    for item in data:
        if not isinstance(item, dict) or not item.get("id") or not item.get("username"):
            continue
        status_id = str(item["id"])
        if not status_id.isdigit():
            continue
        username = str(item["username"])
        uri = str(item.get("uri") or "")
        posts.append({
            "id": status_id,
            "username": username,
            "display_name": str(item.get("display_name") or "").strip() or username,
            "host": urlsplit(uri).netloc.lower() if uri else "",
            "text": excerpt(str(item.get("text") or "")),
            "created_at": str(item.get("created_at") or ""),
            "favourites": int(item.get("favourites") or 0),
            "reblogs": int(item.get("reblogs") or 0),
            "replies": int(item.get("replies") or 0),
            "media_count": int(item.get("media_count") or 0),
            "url": _public_url(uri, username, status_id),
        })
    return posts


def fetch_highlights(month, count=DEFAULT_COUNT, per_author=DEFAULT_PER_AUTHOR):
    """Query the Mastodon DB guest for the month's top posts.

    Returns ``(posts, None)`` on success or ``(None, message)`` on failure; the
    message is safe to show in the UI. ``count + CANDIDATE_EXTRA`` rows are
    returned so the page can offer replacements.
    """
    from models import Guest, Setting, db

    bounds = parse_month(month)
    if not bounds:
        return None, "Pick a month in YYYY-MM format"

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

    query = build_highlights_query(bounds[0], bounds[1], clamp_count(count) + CANDIDATE_EXTRA, per_author)
    cmd = _build_mastodon_email_query_cmd(db_name, query)

    try:
        from clients.ssh_client import SSHClient
        with SSHClient.from_credential(db_guest.ip_address, credential) as ssh:
            stdout, stderr, code = ssh.execute_sudo(cmd, timeout=QUERY_TIMEOUT)
    except Exception as exc:
        logger.error("Highlights query: SSH to %s failed", db_guest.name, exc_info=True)
        return None, f"SSH error: {describe_exception(exc)}"

    if code != 0:
        logger.error("Highlights query failed on %s (exit %s): %s", db_guest.name, code, (stderr or "").strip()[:500])
        return None, f"Database query failed (exit {code}); see the server log"

    try:
        return parse_highlights_output(stdout), None
    except (ValueError, TypeError):
        logger.error("Highlights query on %s returned unparseable output", db_guest.name)
        return None, "Database returned unexpected output; see the server log"


def text_to_html(text):
    """Escape plain post text and keep its line breaks as ``<br>`` (Outlook ignores ``white-space``)."""
    from markupsafe import Markup, escape
    return Markup("<br>\n").join(escape(line) for line in (text or "").splitlines())


def is_safe_link(url):
    """True for an absolute http(s) URL, the only kind put into the email's donate button."""
    parts = urlsplit((url or "").strip())
    return parts.scheme in ("http", "https") and bool(parts.netloc)
