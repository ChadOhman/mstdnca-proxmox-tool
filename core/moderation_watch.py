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
    except CredentialStoreError as exc:
        return None, str(exc)
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

    status_url = status.get("url") if status else None
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
        text = render_welcome(template, account)
    except ValueError as exc:
        return None, str(exc)

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
    }

    def _note_error(step, exc):
        message = getattr(exc, "message", None) or str(exc)
        result["errors"].append(f"{step}: {message}")
        if getattr(exc, "http_status", None) == 429:
            retry_after = exc.retry_after if getattr(exc, "retry_after", None) is not None else 60
            result["backoff_until"] = (now + timedelta(seconds=retry_after)).isoformat()
            return True
        return False

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
    }
    Setting.set("moderation_watch_last_run_at", now.isoformat())
    Setting.set("moderation_watch_last_run_result", json.dumps(persisted))

    return result
