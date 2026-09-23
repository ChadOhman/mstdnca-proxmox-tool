"""Watch selected Mastodon accounts for new posts, new signups, and silent logins.

Three independent checks run on each scheduled poll (see ``run_watch_poll``):

1. Watched accounts (``ModerationWatch`` rows) are polled for new statuses.
2. New local signups are discovered and, optionally, auto-watched for a
   configurable window.
3. Accounts that have never posted but recently logged back in are flagged as
   a "silent login" -- a classic sleeper-account pattern.

Every alert is deduplicated via ``ModerationAlert.dedupe_key`` before it is
persisted or notified on, so re-running the poll (or a crash mid-run) never
produces a duplicate notification.

This module never imports ``routes.moderation`` and is safe to call from the
scheduler (``core.scheduler._run_moderation_watch_poll``) as well as from
request handlers.
"""

import json
import logging
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy.exc import IntegrityError

from auth.audit import log_action
from core.mastodon_admin import parse_iso

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_WATCH_REQUESTS_PER_RUN = 100
RATE_RESERVE = 60
REQUEST_SPACING_SECONDS = 0.25
ALERT_RETENTION_DAYS = 90
SILENT_SCAN_MIN_HOURS = 24
# Cap on how many welcome DMs one poll will send, so a burst of signups (or a
# bootstrap-adjacent bug) can't turn into a wall of bot posts in one run.
MAX_WELCOMES_PER_RUN = 20
WELCOME_RENDER_ERROR = "Welcome message template is invalid or too long; fix it under Welcome message settings"
REPORT_NOTICE_RENDER_ERROR = "Report notice template is invalid or too long; fix it under Reporter notice settings"

# Settings the live-instance status-character-limit check reads/writes. Refreshed
# at most once every 24h (see ``run_watch_poll``) so it costs one extra Admin API
# call per day, not per poll.
STATUS_LIMIT_SETTING = "moderation_mastodon_max_chars"
STATUS_LIMIT_CHECKED_SETTING = "moderation_mastodon_max_chars_checked_at"
STATUS_LIMIT_REFRESH_HOURS = 24

# User-facing settings and their string defaults (see routes/settings.py for
# the form that edits these). Job-only bookkeeping keys (cursor, last-run
# timestamps/results, back-off) are not listed here: they have no sensible
# default and are only ever written by the poll itself.
WATCH_SETTING_DEFAULTS = {
    "moderation_watch_alerts_enabled": "false",
    "moderation_watch_poll_minutes": "5",
    "moderation_watch_auto_watch_days": "0",
    "moderation_watch_silent_login_days": "7",
    "moderation_watch_silent_min_age_days": "14",
    "moderation_watch_silent_scan_window_days": "90",
}


def _parse_int(raw, default, low=None, high=None):
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return default
    if low is not None and value < low:
        value = low
    if high is not None and value > high:
        value = high
    return value


def get_watch_settings():
    """Read and clamp all moderation-watch settings into a plain dict."""
    from core.scheduler import interval_setting
    from models import Setting

    return {
        "alerts_enabled": Setting.get(
            "moderation_watch_alerts_enabled", WATCH_SETTING_DEFAULTS["moderation_watch_alerts_enabled"]
        ) == "true",
        "poll_minutes": _parse_int(
            Setting.get("moderation_watch_poll_minutes", WATCH_SETTING_DEFAULTS["moderation_watch_poll_minutes"]),
            5, low=1, high=1440,
        ),
        "auto_watch_days": _parse_int(
            Setting.get("moderation_watch_auto_watch_days", WATCH_SETTING_DEFAULTS["moderation_watch_auto_watch_days"]),
            0, low=0, high=90,
        ),
        "silent_login_days": _parse_int(
            Setting.get(
                "moderation_watch_silent_login_days", WATCH_SETTING_DEFAULTS["moderation_watch_silent_login_days"]
            ),
            7, low=1,
        ),
        "silent_min_age_days": _parse_int(
            Setting.get(
                "moderation_watch_silent_min_age_days",
                WATCH_SETTING_DEFAULTS["moderation_watch_silent_min_age_days"],
            ),
            14, low=0,
        ),
        "silent_scan_window_days": _parse_int(
            Setting.get(
                "moderation_watch_silent_scan_window_days",
                WATCH_SETTING_DEFAULTS["moderation_watch_silent_scan_window_days"],
            ),
            90, low=1,
        ),
        "log_retention_days": interval_setting("moderation_log_retention_days"),
    }


def get_welcome_settings():
    """Read the welcome-bot settings into a plain dict.

    ``bot_configured`` reflects whether a bot token is stored -- it does not
    verify the token works, only that ``send_welcome`` has something to try.
    """
    from core.mastodon_admin import DEFAULT_WELCOME_TEMPLATE
    from models import Setting

    return {
        "enabled": Setting.get("moderation_welcome_enabled", "false") == "true",
        "template": Setting.get("moderation_welcome_template", DEFAULT_WELCOME_TEMPLATE),
        "bot_configured": bool(Setting.get("moderation_bot_token", "")),
    }


def get_status_limit():
    """Return the cached live-instance status character limit, clamped to a sane range.

    Backed by :data:`STATUS_LIMIT_SETTING`, written by :func:`refresh_status_limit`.
    Falls back to ``core.mastodon_admin.MAX_STATUS_CHARS`` (Mastodon's historical
    default) when the setting has never been populated or is unparseable.
    """
    from core.mastodon_admin import MAX_STATUS_CHARS, MAX_STATUS_CHARS_CEILING, MIN_STATUS_CHARS
    from models import Setting

    return _parse_int(
        Setting.get(STATUS_LIMIT_SETTING, str(MAX_STATUS_CHARS)),
        MAX_STATUS_CHARS,
        low=MIN_STATUS_CHARS,
        high=MAX_STATUS_CHARS_CEILING,
    )


def refresh_status_limit(client):
    """Ask ``client`` for the live instance's status character limit and cache it.

    Stores both :data:`STATUS_LIMIT_SETTING` (the value) and
    :data:`STATUS_LIMIT_CHECKED_SETTING` (when we last asked) and returns the
    value. On a :class:`~core.mastodon_admin.MastodonAPIError` (genuine
    connectivity/auth failure -- ``client.max_status_chars()`` itself never
    raises for a merely-missing field), logs a warning and returns the
    previously cached value without touching either setting, so a transient
    failure doesn't erase a good prior reading or reset the "last checked"
    clock (the next poll will simply try again).
    """
    from core.mastodon_admin import MastodonAPIError
    from models import Setting

    try:
        value = client.max_status_chars()
    except MastodonAPIError:
        logger.warning("Could not refresh the Mastodon status character limit", exc_info=True)
        return get_status_limit()

    Setting.set(STATUS_LIMIT_SETTING, str(value))
    Setting.set(STATUS_LIMIT_CHECKED_SETTING, datetime.now(timezone.utc).isoformat())
    return value


def build_bot_client():
    """Build a welcome-bot client from settings, or return (None, error_message).

    Mirrors :func:`build_admin_client` -- same Mastodon instance (the API
    URL setting is shared), but a separate token scoped to the bot account.
    """
    from auth.credential_store import CredentialStoreError, decrypt
    from core.mastodon_admin import MastodonBotClient
    from models import Setting

    api_url = Setting.get("moderation_mastodon_api_url", "")
    token = Setting.get("moderation_bot_token", "")
    if not api_url or not token:
        return None, "Welcome bot token not configured"
    try:
        plain = decrypt(token)
    except CredentialStoreError:
        logger.warning("Welcome bot token could not be decrypted", exc_info=True)
        return None, "Failed to decrypt the welcome bot token"
    if not plain:
        return None, "Failed to decrypt the welcome bot token"
    return MastodonBotClient(api_url, plain), None


def build_admin_client():
    """Build an Admin API client from settings, or return (None, error_message).

    Mirrors ``routes.moderation._get_mastodon_client`` -- kept as a separate
    copy here rather than imported so this module never has to import from
    ``routes``.
    """
    from auth.credential_store import CredentialStoreError, decrypt
    from core.mastodon_admin import MastodonAdminClient
    from models import Setting

    api_url = Setting.get("moderation_mastodon_api_url", "")
    token = Setting.get("moderation_mastodon_api_token", "")
    if not api_url or not token:
        return None, "Mastodon API URL or token not configured"
    try:
        plain = decrypt(token)
    except CredentialStoreError:
        logger.warning("Mastodon API token could not be decrypted", exc_info=True)
        return None, "Failed to decrypt the Mastodon API token"
    if not plain:
        return None, "Failed to decrypt the Mastodon API token"
    return MastodonAdminClient(api_url, plain), None


def _http_url_or_none(value):
    """Keep a status URL only if it is a plain http(s) URL.

    The value comes from the Fediverse (a remote status' ``url``) and ends up
    in an ``href`` on the Moderation page and in a Discord alert; a
    ``javascript:`` or ``data:`` scheme must never be stored.
    """
    if not isinstance(value, str):
        return None
    value = value.strip()
    if len(value) > 512 or not value.lower().startswith(("http://", "https://")):
        return None
    if any(ch in value for ch in " \"'<>\\") or any(ord(ch) < 32 for ch in value):
        return None
    return value


def record_alert(kind, account, status=None, *, notify=True):
    """Insert a deduplicated :class:`ModerationAlert`, or return ``None`` if it already exists.

    ``account`` is one of the account dicts returned by
    :class:`core.mastodon_admin.MastodonAdminClient` (``list_local_accounts`` /
    the account carried on a status). ``status`` is one of the dicts returned
    by ``account_statuses``, when the alert is about a specific post.
    """
    from models import ModerationAlert, db

    account_id = str(account.get("id"))
    status_id = str(status["id"]) if status else None
    dedupe_key = ModerationAlert.make_dedupe_key(kind, account_id, status_id)

    if ModerationAlert.query.filter_by(dedupe_key=dedupe_key).first():
        return None

    status_url = _http_url_or_none(status.get("url")) if status else None
    excerpt = status.get("excerpt") if status else account.get("excerpt")
    acct = account.get("acct", "")

    alert = ModerationAlert(
        kind=kind,
        dedupe_key=dedupe_key,
        mastodon_account_id=account_id,
        acct=acct,
        status_id=status_id,
        status_url=status_url,
        excerpt=excerpt,
    )
    db.session.add(alert)
    try:
        db.session.flush()
    except IntegrityError:
        db.session.rollback()
        return None

    log_action(
        f"moderation_alert_{kind}",
        "mastodon_account",
        resource_name=acct,
        details={"kind": kind, "account_id": account_id, "status_url": status_url},
        audience="moderators",
    )
    db.session.commit()

    if notify:
        try:
            from core.notifier import send_moderation_alert_notification
            send_moderation_alert_notification(kind, acct, url=status_url, excerpt=excerpt)
        except Exception:
            logger.exception("Failed to send moderation alert notification for %s", dedupe_key)

    return alert


def welcome_record(account_id):
    """Return the :class:`ModerationWelcome` row for ``account_id``, or ``None``."""
    from models import ModerationWelcome

    return ModerationWelcome.query.filter_by(mastodon_account_id=str(account_id)).first()


def get_report_notice_settings():
    """Read the report-notice settings into a plain dict."""
    from core.mastodon_admin import DEFAULT_REPORT_NOTICE_TEMPLATE
    from models import Setting

    return {
        "template": Setting.get("moderation_report_notice_template", DEFAULT_REPORT_NOTICE_TEMPLATE),
    }


def report_notice_record(report_id):
    """Return the :class:`ModerationReportNotice` row for ``report_id``, or ``None``."""
    from models import ModerationReportNotice

    return ModerationReportNotice.query.filter_by(report_id=str(report_id)).first()


def send_welcome(bot_client, account, *, sent_by_user_id=None, force=False, template=None):
    """Send a welcome DM to ``account`` via ``bot_client``. Returns ``(record, error)``.

    Refuses (returning ``(None, "already welcomed")``) when a
    :class:`ModerationWelcome` row already exists for this account and
    ``force`` is not set. On success, the row is inserted (or, when forcing,
    updated) and audited under ``audience="moderators"``; ``sent_by_user_id``
    left as ``None`` marks the send as automatic (from the poll) rather than
    a moderator's manual action.
    """
    from core.mastodon_admin import MastodonAPIError, render_welcome
    from models import ModerationWelcome, db

    account_id = str(account.get("id"))
    acct = account.get("acct", "")

    existing = welcome_record(account_id)
    if existing and not force:
        return None, "already welcomed"

    from core.mastodon_admin import DEFAULT_WELCOME_TEMPLATE
    from models import Setting

    template = template or Setting.get("moderation_welcome_template", DEFAULT_WELCOME_TEMPLATE)

    try:
        text = render_welcome(template, account, max_chars=get_status_limit())
    except (ValueError, KeyError, IndexError):
        # Our own render error (over budget) or a malformed template: keep the
        # exception text in the log, hand the caller a fixed message.
        logger.warning("Welcome message could not be rendered for %s", account.get("acct"), exc_info=True)
        return None, WELCOME_RENDER_ERROR

    try:
        status = bot_client.post_direct(text, idempotency_key=f"welcome-{account_id}")
    except MastodonAPIError as exc:
        db.session.rollback()
        return None, exc.message

    status_id = status.get("id")
    if existing:
        existing.sent_at = datetime.now(timezone.utc)
        existing.sent_by_user_id = sent_by_user_id
        existing.status_id = status_id
        existing.acct = acct
        record = existing
    else:
        record = ModerationWelcome(
            mastodon_account_id=account_id,
            acct=acct,
            sent_by_user_id=sent_by_user_id,
            status_id=status_id,
        )
        db.session.add(record)

    log_action(
        "mastodon_welcome_send",
        "mastodon_account",
        resource_name=acct,
        details={"account_id": account_id, "status_id": status_id, "automatic": sent_by_user_id is None},
        audience="moderators",
    )
    db.session.commit()
    return record, None


def send_report_notice(bot_client, report_id, reporter, *, text=None, sent_by_user_id=None, force=False):
    """Send a "thanks for reporting" DM to a report's reporter. Returns ``(record, error)``.

    Mirrors :func:`send_welcome`: refuses (``(None, "already notified")``) when
    a :class:`ModerationReportNotice` row already exists for ``report_id`` and
    ``force`` is not set. ``text``, when given, is a moderator's own edited
    message -- used verbatim (just prefixed with the reporter's ``@mention``)
    instead of rendering the configured template, and a too-long edit is
    reported with its own fixed-format message rather than the template
    renderer's exception text. ``reporter`` is the reporting account's dict
    (has ``id``/``acct``, possibly on a remote instance); the mention always
    uses ``acct`` so a remote reporter is actually reachable.
    """
    from core.mastodon_admin import (
        DEFAULT_REPORT_NOTICE_TEMPLATE,
        MastodonAPIError,
        compose_direct,
        render_report_notice_body,
    )
    from models import ModerationReportNotice, Setting, db

    report_id = str(report_id)
    reporter_account_id = str(reporter.get("id")) if reporter.get("id") is not None else None
    reporter_acct = reporter.get("acct", "")
    mention = reporter["acct"]

    existing = report_notice_record(report_id)
    if existing and not force:
        return None, "already notified"

    limit = get_status_limit()

    if text is not None:
        body = text.strip()
        full = f"@{mention} {body}"
        if len(full) > limit:
            return None, f"Message would be {len(full)} characters; this instance allows {limit}"
    else:
        template = Setting.get("moderation_report_notice_template", DEFAULT_REPORT_NOTICE_TEMPLATE)
        try:
            body = render_report_notice_body(template, reporter, report_id)
            full = compose_direct(mention, body, label="Report notice", max_chars=limit)
        except (ValueError, KeyError, IndexError):
            # Our own render error (over budget) or a malformed template: keep the
            # exception text in the log, hand the caller a fixed message.
            logger.warning("Report notice could not be rendered for report %s", report_id, exc_info=True)
            return None, REPORT_NOTICE_RENDER_ERROR

    idempotency_key = f"report-notice-{report_id}"
    if force:
        idempotency_key = f"{idempotency_key}-r{int(time.time())}"

    try:
        status = bot_client.post_direct(full, idempotency_key=idempotency_key)
    except MastodonAPIError as exc:
        db.session.rollback()
        return None, exc.message

    status_id = status.get("id")
    if existing:
        existing.sent_at = datetime.now(timezone.utc)
        existing.sent_by_user_id = sent_by_user_id
        existing.status_id = status_id
        existing.reporter_account_id = reporter_account_id
        existing.reporter_acct = reporter_acct
        record = existing
    else:
        record = ModerationReportNotice(
            report_id=report_id,
            reporter_account_id=reporter_account_id,
            reporter_acct=reporter_acct,
            sent_by_user_id=sent_by_user_id,
            status_id=status_id,
        )
        db.session.add(record)

    log_action(
        "mastodon_report_notice_send",
        "mastodon_report",
        resource_name=f"report {report_id}",
        details={
            "report_id": report_id,
            "reporter_account_id": reporter_account_id,
            "reporter_acct": reporter_acct,
            "status_id": status_id,
            "remote": "@" in reporter_acct,
            "forced": force,
        },
        audience="moderators",
    )
    db.session.commit()
    return record, None


# ---------------------------------------------------------------------------
# Poll steps
# ---------------------------------------------------------------------------


def _prune(now):
    """Delete expired watches and old, acknowledged alerts."""
    from models import ModerationAlert, ModerationWatch, db

    ModerationWatch.query.filter(
        ModerationWatch.expires_at.isnot(None),
        ModerationWatch.expires_at < now,
    ).delete(synchronize_session=False)

    cutoff = now - timedelta(days=ALERT_RETENTION_DAYS)
    ModerationAlert.query.filter(
        ModerationAlert.acknowledged_at.isnot(None),
        ModerationAlert.acknowledged_at < cutoff,
    ).delete(synchronize_session=False)

    # Alerts nobody acknowledged used to live forever, each carrying a post
    # excerpt and URL. They follow the moderation log's retention setting.
    from core.scheduler import interval_setting
    unacked_cutoff = now - timedelta(days=interval_setting("moderation_log_retention_days"))
    ModerationAlert.query.filter(
        ModerationAlert.acknowledged_at.is_(None),
        ModerationAlert.created_at < unacked_cutoff,
    ).delete(synchronize_session=False)

    db.session.commit()


def _check_watched(client, now, result, sleep):
    """Poll watched accounts for new statuses, oldest-checked first."""
    from models import ModerationWatch, db

    watches = (
        ModerationWatch.query.order_by(
            ModerationWatch.last_checked_at.is_(None).desc(),
            ModerationWatch.last_checked_at.asc(),
            ModerationWatch.id.asc(),
        )
        .limit(MAX_WATCH_REQUESTS_PER_RUN)
        .all()
    )
    result["watch_total"] = ModerationWatch.query.count()

    checked = 0
    for watch in watches:
        if not client.budget_ok(RATE_RESERVE):
            result["deferred"] = True
            break

        if watch.last_status_id is None:
            # First time we've ever looked at this account: seed the cursor
            # without alerting on pre-existing history.
            statuses = client.account_statuses(watch.mastodon_account_id, limit=1)
            if statuses:
                watch.last_status_id = statuses[0]["id"]
                acct = statuses[0].get("account_acct")
                if acct:
                    watch.acct = acct
        else:
            statuses = client.account_statuses(watch.mastodon_account_id, since_id=watch.last_status_id)
            if statuses:
                newest_id = statuses[0]["id"]  # newest-first
                for status in reversed(statuses):  # oldest-first for alerting
                    alert = record_alert(
                        "watched_post",
                        {"id": watch.mastodon_account_id, "acct": status.get("account_acct") or watch.acct},
                        status,
                    )
                    if alert:
                        result["alerts"]["watched_post"] += 1
                    acct = status.get("account_acct")
                    if acct:
                        watch.acct = acct
                watch.last_status_id = newest_id

        watch.last_checked_at = now
        checked += 1
        db.session.commit()
        sleep(REQUEST_SPACING_SECONDS)

    result["checked"] = checked


def _discover_new_accounts(client, now, result, settings):
    """Alert on (and optionally auto-watch) newly registered local accounts."""
    from models import ModerationWatch, Setting, db

    if not client.budget_ok(RATE_RESERVE):
        result["deferred"] = True
        return

    cursor_raw = Setting.get("moderation_watch_new_account_cursor")
    if not cursor_raw:
        # First run ever: establish a cursor without alerting on the entire
        # pre-existing user base.
        accounts = client.list_local_accounts(max_pages=1)
        if accounts:
            newest = accounts[0].get("created_at")
            if newest:
                Setting.set("moderation_watch_new_account_cursor", newest)
        result["bootstrapped"] = True
        return

    since = parse_iso(cursor_raw)
    accounts = client.list_local_accounts(newer_than=since)
    if not accounts:
        return

    newest_cursor = accounts[0].get("created_at") or cursor_raw  # newest-first
    new_accounts_out = []
    for acct in reversed(accounts):  # oldest-first
        alert = record_alert("new_account", acct)
        if alert:
            result["alerts"]["new_account"] += 1
        new_accounts_out.append(acct)

        if settings["auto_watch_days"] > 0:
            account_id = str(acct.get("id"))
            already = ModerationWatch.query.filter_by(mastodon_account_id=account_id).first()
            if not already:
                db.session.add(ModerationWatch(
                    mastodon_account_id=account_id,
                    acct=acct.get("acct", ""),
                    auto_added=True,
                    expires_at=now + timedelta(days=settings["auto_watch_days"]),
                    last_status_id=None,
                    reason="Auto-watch: new account",
                ))
                db.session.commit()

    Setting.set("moderation_watch_new_account_cursor", newest_cursor)
    result["new_accounts"] = new_accounts_out


def _send_welcomes(bot_client, accounts, now, result):
    """Send welcome DMs for freshly discovered ``accounts``, oldest-first.

    Skipped entirely on a bootstrap run (``result["bootstrapped"]``), since
    those accounts pre-date watching and shouldn't get a belated welcome.
    """
    from core.mastodon_admin import MastodonAPIError

    if result["bootstrapped"] or not accounts:
        return

    bot_account_id = None
    try:
        bot_account_id = str(bot_client.verify().get("id"))
    except MastodonAPIError:
        logger.warning("Welcome bot token verification failed; continuing without self-exclusion")

    welcomed = 0
    for account in sorted(accounts, key=lambda a: a.get("created_at") or ""):
        if welcomed >= MAX_WELCOMES_PER_RUN:
            break
        account_id = str(account.get("id"))
        if bot_account_id and account_id == bot_account_id:
            continue
        if welcome_record(account_id):
            continue
        if not bot_client.budget_ok(RATE_RESERVE):
            result["deferred"] = True
            break

        _, error = send_welcome(bot_client, account)
        if error:
            result["errors"].append(f"send_welcome: {error}")
            continue
        welcomed += 1

    result["welcomed"] = welcomed


def _scan_silent_logins(client, now, result, settings):
    """Flag accounts that have never posted but recently logged back in."""
    from models import Setting

    last_scan_raw = Setting.get("moderation_watch_silent_last_scan_at")
    last_scan = parse_iso(last_scan_raw) if last_scan_raw else None
    if last_scan and (now - last_scan) < timedelta(hours=SILENT_SCAN_MIN_HOURS):
        return

    if not client.budget_ok(RATE_RESERVE + 10):
        result["deferred"] = True
        return

    window_days = settings["silent_scan_window_days"]
    login_days = settings["silent_login_days"]
    min_age_days = settings["silent_min_age_days"]

    accounts = client.list_local_accounts(newer_than=now - timedelta(days=window_days), max_pages=10)

    newly_inserted = []
    for acct in accounts:
        if (acct.get("statuses_count") or 0) != 0:
            continue
        created_at = parse_iso(acct.get("created_at"))
        last_login = parse_iso(acct.get("last_login_at"))
        if created_at is None or last_login is None:
            continue
        if created_at > now - timedelta(days=min_age_days):
            continue
        if last_login < now - timedelta(days=login_days):
            continue

        excerpt = (
            f"Created {created_at.date().isoformat()}, "
            f"last login {last_login.date().isoformat()}, 0 posts"
        )
        acct_with_excerpt = dict(acct)
        acct_with_excerpt["excerpt"] = excerpt
        alert = record_alert("silent_login", acct_with_excerpt, notify=False)
        if alert:
            newly_inserted.append(acct)
            result["alerts"]["silent_login"] += 1

    if newly_inserted:
        try:
            from core.notifier import send_moderation_silent_login_summary
            send_moderation_silent_login_summary(
                len(newly_inserted), [a.get("acct", "") for a in newly_inserted[:5]]
            )
        except Exception:
            logger.exception("Failed to send silent-login summary notification")

    Setting.set("moderation_watch_silent_last_scan_at", now.isoformat())


def _maybe_refresh_status_limit(client, now, result):
    """Refresh the cached live-instance status-length limit if it's stale.

    At most once every :data:`STATUS_LIMIT_REFRESH_HOURS` hours, and only
    when there's rate-limit budget to spare -- this is a "nice to have"
    background check, never worth spending the rest of the poll's budget on.
    Wrapped so it can never raise or otherwise fail the run: a broken
    response here should never stop watches, signups or the silent-login
    scan from running.
    """
    from models import Setting

    try:
        checked_raw = Setting.get(STATUS_LIMIT_CHECKED_SETTING)
        checked_at = parse_iso(checked_raw) if checked_raw else None
        stale = checked_at is None or (now - checked_at) >= timedelta(hours=STATUS_LIMIT_REFRESH_HOURS)
        if not stale or not client.budget_ok(RATE_RESERVE):
            return
        result["status_limit"] = refresh_status_limit(client)
    except Exception:
        logger.exception("Failed to refresh the Mastodon status character limit")


def run_watch_poll(client, *, bot_client=None, now=None, sleep=time.sleep, log=None):
    """Run one poll cycle: prune, check watches, discover signups, scan for silent logins.

    Every step is independent and wrapped in its own ``try/except
    MastodonAPIError`` so one failing call never blocks the others. A 429
    aborts any remaining steps for this run and records ``backoff_until``.
    Returns the summary dict, which is also persisted to
    ``moderation_watch_last_run_result``.

    ``bot_client`` (a :class:`core.mastodon_admin.MastodonBotClient`), when
    given, sends welcome DMs to accounts discovered this run -- provided the
    welcome feature is enabled in settings. Pass ``None`` (the default) to
    skip welcomes entirely, e.g. when the bot token isn't configured.
    """
    from core.mastodon_admin import MastodonAPIError
    from models import Setting

    now = now or datetime.now(timezone.utc)
    emit = log if callable(log) else logger.info
    settings = get_watch_settings()

    result = {
        "checked": 0,
        "watch_total": 0,
        "alerts": {"watched_post": 0, "new_account": 0, "silent_login": 0},
        "deferred": False,
        "bootstrapped": False,
        "backoff_until": None,
        "errors": [],
        "rate_limit": None,
        "welcomed": 0,
        "status_limit": None,
    }

    def _note_error(step, exc):
        message = getattr(exc, "message", None) or str(exc)
        result["errors"].append(f"{step}: {message}")
        if getattr(exc, "http_status", None) == 429:
            retry_after = exc.retry_after if getattr(exc, "retry_after", None) is not None else 60
            result["backoff_until"] = (now + timedelta(seconds=retry_after)).isoformat()
            return True
        return False

    _maybe_refresh_status_limit(client, now, result)

    aborted = False

    try:
        _prune(now)
    except MastodonAPIError as exc:
        aborted = _note_error("prune", exc)

    if not aborted:
        try:
            _check_watched(client, now, result, sleep)
        except MastodonAPIError as exc:
            aborted = _note_error("check_watched", exc)

    if not aborted:
        try:
            _discover_new_accounts(client, now, result, settings)
        except MastodonAPIError as exc:
            aborted = _note_error("discover_new_accounts", exc)

    if not aborted and bot_client is not None and result.get("new_accounts"):
        welcome_settings = get_welcome_settings()
        if welcome_settings["enabled"]:
            try:
                _send_welcomes(bot_client, result["new_accounts"], now, result)
            except MastodonAPIError as exc:
                aborted = _note_error("send_welcomes", exc)

    if not aborted:
        try:
            _scan_silent_logins(client, now, result, settings)
        except MastodonAPIError as exc:
            aborted = _note_error("scan_silent_logins", exc)

    if aborted:
        emit("Moderation watch poll hit a rate limit; backing off until %s" % result["backoff_until"])
    elif result["deferred"]:
        emit("Moderation watch poll deferred remaining work: rate-limit budget exhausted")

    rate_limit = getattr(client, "rate_limit", None)
    if rate_limit:
        result["rate_limit"] = {
            "limit": rate_limit.limit,
            "remaining": rate_limit.remaining,
            "reset_at": rate_limit.reset_at.isoformat() if rate_limit.reset_at else None,
        }

    persisted = {
        "checked": result["checked"],
        "watch_total": result["watch_total"],
        "alerts": result["alerts"],
        "deferred": result["deferred"],
        "bootstrapped": result["bootstrapped"],
        "backoff_until": result["backoff_until"],
        "errors": result["errors"],
        "rate_limit": result["rate_limit"],
        "welcomed": result.get("welcomed", 0),
        "status_limit": result.get("status_limit"),
    }
    Setting.set("moderation_watch_last_run_at", now.isoformat())
    Setting.set("moderation_watch_last_run_result", json.dumps(persisted))

    return result
