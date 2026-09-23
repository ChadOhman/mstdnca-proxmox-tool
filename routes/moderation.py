"""Moderation blueprint: cross-platform user email verification."""

import ipaddress
import json
import logging
import re
import threading as _threading
from collections import deque
from datetime import datetime, timedelta, timezone

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import or_

from auth.audit import log_action
from core.mastodon_admin import (
    ACCOUNT_ACTION_TYPES,
    ACCOUNT_LIFT_ACTIONS,
    DOMAIN_BLOCK_SEVERITIES,
    MastodonAdminClient,
    MastodonAPIError,
    validate_domain,
)
from core.mastodon_maintenance import (
    INVALID_INPUT_MESSAGE,
    MAINTENANCE_ACTIONS,
    MAX_STATUS_IDS,
    STATUS_ACTIONS,
    MaintenanceBusy,
    build_modify_command,
    build_status_action_script,
    maintenance_slot,
    run_maintenance,
    run_status_action,
)
from core.moderation_log import KIND_FILTERS, MODERATION_ACTION_PREFIXES, moderation_log_filter
from models import AuditLog, ModerationAlert, ModerationWatch, Setting, User, db


def _audit(action, resource_type, **kwargs):
    """log_action for this blueprint: moderators-only real-time broadcast.

    Moderation events name Fediverse accounts and actions such as "reset
    password" or "disable 2FA"; the activity toast must reach connected
    moderators only, not every logged-in user (GHSA-qq45-f2h2-9j4q).
    """
    kwargs.setdefault("audience", "moderators")
    return log_action(action, resource_type, **kwargs)


def _clean_api_url(raw, label):
    """Normalise an integration API base URL from a form. Returns (value, error).

    A stored bearer token is sent to this URL on every poll, so it must be
    well-formed and https; an empty value clears the setting.
    """
    from apps.utils import _validate_http_url

    value = (raw or "").strip().rstrip("/")
    if not value:
        return "", None
    try:
        _validate_http_url(value, label)
    except ValueError as exc:
        return None, str(exc)
    if not value.startswith("https://"):
        return None, f"{label} must start with https://"
    return value, None

logger = logging.getLogger(__name__)

# Upper bound on free-text fields (reasons, comments) forwarded to Mastodon.
_MAX_TEXT_LEN = 2000

# Shown when a moderator without can_moderate_staff tries to act on an
# account holding a Mastodon staff role.
STAFF_TARGET_ERROR = "This account holds a Mastodon staff role; your MCAT role may not act on it"

bp = Blueprint("moderation", __name__)

# Cap the in-memory log so a very chatty/long-running check can't grow this
# unboundedly. "log_total" is a monotonically increasing count of every line
# ever appended for the current run (independent of how many the deque has
# room for), so /status's offset-based polling still lines up correctly even
# after old entries have been evicted from the deque.
_MODERATION_LOG_MAXLEN = 2000

# In-memory job state — mirrors the pattern from routes/peertube.py.
# ``result`` holds the full (email-bearing) result of the most recent run so the
# live admin view can render emails that are deliberately NOT persisted to the
# Setting store (see core.moderation._scrub_result_for_storage).
_moderation_job = {
    "running": False,
    "success": None,
    "log": deque(maxlen=_MODERATION_LOG_MAXLEN),
    "log_total": 0,
    "result": None,
}


def _append_moderation_log(msg):
    """Append a line to the capped in-memory log and bump the running total
    used for offset-based /status polling."""
    _moderation_job["log"].append(msg)
    _moderation_job["log_total"] += 1

# Guards the check-then-set on _moderation_job["running"] (TOCTOU): without it,
# two concurrent /run requests could both observe running=False and start.
_moderation_job_lock = _threading.Lock()


def _parse_iso(value):
    """Parse an ISO 8601 string into a timezone-aware datetime, or return None."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


# Endpoints that change moderation configuration (API URLs, tokens, the
# PeerTube auto-ban switch). Moderators may operate the tools but only
# administrators may reconfigure them.
_ADMIN_ONLY_ENDPOINTS = frozenset({
    "moderation.save",
    "moderation.mastodon_save",
    "moderation.mastodon_test",
    "moderation.mastodon_watch_save",
    "moderation.mastodon_welcome_save",
    "moderation.mastodon_welcome_test",
    "moderation.mastodon_report_notice_save",
    "moderation.mastodon_account_delete",
})

# Guards the check-then-set on the manual "run poll now" job (TOCTOU): without
# it, two concurrent /watch/poll requests could both observe running=False.
_watch_poll_lock = _threading.Lock()
_watch_poll_state = {"running": False}


@bp.before_request
@login_required
def _require_login():
    # can_moderate is only grantable by a super_admin on the Roles tab, so it
    # is itself the access gate for the operational moderation surface. Like
    # Mastodon's own moderator role, that surface includes account emails and
    # IPs in the live cards (account lookup, reports, pending approvals) — a
    # moderator needs those to do the job. Reconfiguring where those tools
    # point (API URLs, tokens, the PeerTube auto-ban switch) stays admin-tier,
    # enforced below via _ADMIN_ONLY_ENDPOINTS.
    if not current_user.can_moderate:
        flash("You don't have permission to access moderation.", "error")
        return redirect(url_for("dashboard.index"))
    if request.endpoint in _ADMIN_ONLY_ENDPOINTS and not current_user.is_admin:
        flash("Administrator access is required to change moderation settings.", "error")
        return redirect(url_for("moderation.index"))


def _get_moderation_settings():
    return {
        "peertube_api_url": Setting.get("moderation_peertube_api_url", ""),
        "peertube_api_token": Setting.get("moderation_peertube_api_token", ""),
        "mastodon_api_url": Setting.get("moderation_mastodon_api_url", ""),
        "mastodon_api_token": Setting.get("moderation_mastodon_api_token", ""),
        "check_interval_hours": Setting.get("moderation_check_interval_hours", "24"),
        "auto_ban_enabled": Setting.get("moderation_auto_ban_enabled", "false") == "true",
        "last_check_at": _parse_iso(Setting.get("moderation_last_check_at", "")),
        "last_check_result": Setting.get("moderation_last_check_result", ""),
    }


def _page_context():
    """Context shared by every page rendering ``templates/moderation.html``.

    Centralised so a field added for one tab (e.g. the activity log) can never
    be silently missing from another -- ``index()`` and ``log()`` both start
    from this and only add what's specific to their own tab.
    """
    settings = _get_moderation_settings()

    # Prefer the transient in-memory result from the most recent run: it carries
    # emails for the live admin view. The persisted Setting is PII-scrubbed
    # (no emails) and is only used as a fallback after a process restart.
    last_result = _moderation_job.get("result")
    if last_result is None and settings["last_check_result"]:
        try:
            last_result = json.loads(settings["last_check_result"])
        except (json.JSONDecodeError, TypeError):
            pass

    from core.moderation_watch import (
        get_report_notice_settings,
        get_status_limit,
        get_watch_settings,
        get_welcome_settings,
    )

    return {
        "settings": settings,
        "last_result": last_result,
        "job": _moderation_job,
        "can_configure": current_user.is_admin,
        "watch_settings": get_watch_settings(),
        "welcome_settings": get_welcome_settings(),
        "report_notice_settings": get_report_notice_settings(),
        "status_limit": get_status_limit(),
        "token_account": _get_token_account(),
        "can_moderate_staff": current_user.can_moderate_staff,
        "can_maintain_accounts": current_user.can_maintain_mastodon_accounts,
        "maintenance_available": bool(Setting.get("mastodon_guest_id", "")),
    }


@bp.route("/")
def index():
    if request.args.get("tab") == "log":
        return redirect(url_for("moderation.log"))

    active_tab = "mastodon" if request.args.get("tab") == "mastodon" else "peertube"
    context = _page_context()
    context["active_tab"] = active_tab
    return render_template("moderation.html", **context)


# ---------------------------------------------------------------------------
# Activity log: a moderator-facing view over the AuditLog rows that MCAT's
# moderation surface already writes (see core/moderation_log.py for exactly
# which rows qualify). Unlike the Security page's audit tab, this is scoped
# to can_moderate rather than can_manage_users.
# ---------------------------------------------------------------------------

# Detail keys that must never be rendered, even though ``details`` JSON is
# otherwise app-controlled (never user-supplied) -- belt-and-suspenders so a
# future call site that starts stashing something sensitive in ``details``
# doesn't silently leak it onto a page every moderator can see.
_SENSITIVE_DETAIL_KEYS = frozenset({"password", "token", "email"})

_TRAILING_DIGITS_RE = re.compile(r"(\d+)\s*$")


def _humanize_action(action):
    """``mastodon_account_suspend`` -> ``account suspend``."""
    for prefix in MODERATION_ACTION_PREFIXES:
        if action.startswith(prefix):
            return action[len(prefix):].replace("_", " ")
    return action.replace("_", " ")


def _resource_admin_link(row, mastodon_api_url):
    """Return a link into the Mastodon web admin for a report/account row, or None."""
    if not mastodon_api_url:
        return None
    details = row.details if isinstance(row.details, dict) else {}
    if row.resource_type == "mastodon_report":
        report_id = details.get("report_id")
        if not report_id and row.resource_name:
            m = _TRAILING_DIGITS_RE.search(row.resource_name)
            if m:
                report_id = m.group(1)
        if report_id:
            return f"{mastodon_api_url}/admin/reports/{report_id}"
    elif row.resource_type == "mastodon_account":
        account_id = details.get("account_id")
        if account_id:
            return f"{mastodon_api_url}/admin/accounts/{account_id}"
    return None


def _moderation_log_query(q=None, actor=None, kind=None):
    """Return a SQLAlchemy query over moderation-related AuditLog rows, newest first."""
    query = AuditLog.query.filter(moderation_log_filter())

    if kind in KIND_FILTERS:
        patterns = KIND_FILTERS[kind]
        query = query.filter(or_(*(AuditLog.action.like(p) for p in patterns)))

    if q:
        q = q.strip()[:100]
        if q:
            like = f"%{q}%"
            query = query.filter(or_(AuditLog.resource_name.ilike(like), AuditLog.action.ilike(like)))

    if actor:
        actor = actor.strip()
        if actor.lower() == "system":
            query = query.filter(AuditLog.user_id.is_(None))
        elif actor:
            query = query.join(User, AuditLog.user_id == User.id).filter(User.username == actor)

    return query.order_by(AuditLog.timestamp.desc())


@bp.route("/log")
def log():
    page = request.args.get("page", 1, type=int) or 1
    if page < 1:
        page = 1
    q = (request.args.get("q", "") or "").strip()[:100]
    actor = (request.args.get("actor", "") or "").strip()
    kind = (request.args.get("kind", "") or "").strip()
    if kind not in KIND_FILTERS:
        kind = ""

    log_pagination = _moderation_log_query(q=q or None, actor=actor or None, kind=kind or None).paginate(
        page=page, per_page=50, error_out=False
    )

    row_details = []
    for row in log_pagination.items:
        details = row.details if isinstance(row.details, dict) else {}
        badges = {k: v for k, v in details.items() if v is not None and k not in _SENSITIVE_DETAIL_KEYS}
        row_details.append({
            "badges": badges,
            "label": _humanize_action(row.action),
            "link": _resource_admin_link(row, Setting.get("moderation_mastodon_api_url", "")),
        })

    actor_rows = (
        db.session.query(User.username)
        .join(AuditLog, AuditLog.user_id == User.id)
        .filter(moderation_log_filter())
        .distinct()
        .order_by(User.username)
        .limit(50)
        .all()
    )
    log_actors = ["system"] + [u for (u,) in actor_rows]

    context = _page_context()
    context.update(
        active_tab="log",
        log_pagination=log_pagination,
        log_filters={"q": q, "actor": actor, "kind": kind},
        log_actors=log_actors,
        row_details=row_details,
        show_ip=current_user.is_admin,
    )
    return render_template("moderation.html", **context)


@bp.route("/save", methods=["POST"])
def save():
    from auth.credential_store import encrypt

    peertube_api_url, err = _clean_api_url(request.form.get("peertube_api_url", ""), "PeerTube API URL")
    if err:
        flash(err, "error")
        return redirect(url_for("moderation.index"))
    Setting.set("moderation_peertube_api_url", peertube_api_url)

    # Only update token if a new one was provided (not the placeholder)
    new_token = request.form.get("peertube_api_token", "").strip()
    if new_token:
        Setting.set("moderation_peertube_api_token", encrypt(new_token))

    Setting.set("moderation_check_interval_hours", request.form.get("check_interval_hours", "24").strip())
    Setting.set("moderation_auto_ban_enabled", "true" if request.form.get("auto_ban_enabled") else "false")

    _audit("moderation_config_save", "moderation")
    db.session.commit()
    flash("Moderation settings saved.", "success")
    return redirect(url_for("moderation.index"))


@bp.route("/run", methods=["POST"])
def run():
    from flask import current_app
    app = current_app._get_current_object()

    # Atomically claim the running slot: check-then-set under a lock so two
    # concurrent /run requests can't both start a job (TOCTOU).
    with _moderation_job_lock:
        if _moderation_job["running"]:
            flash("A moderation check is already running.", "warning")
            return redirect(url_for("moderation.index"))
        _moderation_job["running"] = True
        _moderation_job["success"] = None
        _moderation_job["log"] = deque(maxlen=_MODERATION_LOG_MAXLEN)
        _moderation_job["log_total"] = 0

    def _worker():
        with app.app_context():
            try:
                from core.moderation import run_moderation_check
                ok, result = run_moderation_check(log_callback=_append_moderation_log)
                _moderation_job["success"] = ok
                # Retain the full (email-bearing) result in memory only.
                _moderation_job["result"] = result if ok else None
            except Exception as exc:
                logger.exception("Moderation check failed")
                _append_moderation_log(f"ERROR: {exc}")
                _moderation_job["success"] = False
            finally:
                _moderation_job["running"] = False

    t = _threading.Thread(target=_worker, daemon=True)
    t.start()

    flash("Moderation check started.", "info")
    return redirect(url_for("moderation.index"))


@bp.route("/status")
def status():
    """JSON job status. Pass ?offset=<log_offset from a previous response> to
    receive only log lines appended since then, instead of re-serialising the
    whole (capped) log on every poll.
    """
    offset = request.args.get("offset", type=int, default=0)
    if offset < 0:
        offset = 0

    log_total = _moderation_job["log_total"]
    log_list = list(_moderation_job["log"])
    # Absolute index of log_list[0] -- entries before this have been evicted
    # by the deque's maxlen and can no longer be returned.
    first_index = log_total - len(log_list)
    new_lines = log_list if offset < first_index else log_list[offset - first_index:]

    return jsonify({
        "running": _moderation_job["running"],
        "success": _moderation_job["success"],
        "log": new_lines,
        "log_offset": log_total,
    })


# ---------------------------------------------------------------------------
# Mastodon moderation (Admin REST API)
# ---------------------------------------------------------------------------
# Every endpoint below returns JSON and is driven by fetch() from the Mastodon
# tab. Mutations write an AuditLog row. Failures never carry raw exception
# text: MastodonAPIError.message is built from the HTTP status and the API's
# own ``error`` field, or a type-derived description for transport errors.


def _get_mastodon_client():
    """Build an Admin API client from settings, or return (None, error_message)."""
    from auth.credential_store import decrypt

    api_url = Setting.get("moderation_mastodon_api_url", "")
    token = Setting.get("moderation_mastodon_api_token", "")
    if not api_url or not token:
        return None, "Mastodon API URL or token not configured"
    plain = decrypt(token)
    if not plain:
        return None, "Failed to decrypt the Mastodon API token"
    return MastodonAdminClient(api_url, plain), None


def _mastodon_json(fn, *, audit=None):
    """Run ``fn(client)`` and wrap the outcome as a JSON response.

    ``audit`` is an optional ``(action, resource_type, resource_name, details)``
    tuple written to the audit log (and committed) only if the call succeeds.
    """
    client, err = _get_mastodon_client()
    if err:
        return jsonify({"ok": False, "error": err}), 400
    try:
        payload = fn(client)
    except MastodonAPIError as exc:
        return jsonify({"ok": False, "error": exc.message}), 502
    except ValueError as exc:  # validate_domain
        return jsonify({"ok": False, "error": str(exc)}), 400
    if audit:
        action, resource_type, resource_name, details = audit
        _audit(action, resource_type, resource_name=resource_name, details=details)
        db.session.commit()
    body = {"ok": True}
    if isinstance(payload, dict):
        body.update(payload)
    return jsonify(body)


def _get_bot_client():
    """Build a welcome-bot client from settings, or return (None, error_message).

    Thin wrapper over ``core.moderation_watch.build_bot_client`` kept as its own
    function (rather than called inline) so tests can patch
    ``routes.moderation._get_bot_client`` the same way they patch
    ``_get_mastodon_client``.
    """
    from core.moderation_watch import build_bot_client

    return build_bot_client()


def _bot_json(fn, *, audit=None):
    """Run ``fn(client)`` against the welcome-bot client and wrap the outcome as JSON.

    Mirrors ``_mastodon_json`` but builds its client via ``_get_bot_client()``.
    """
    client, err = _get_bot_client()
    if err:
        return jsonify({"ok": False, "error": err}), 400
    try:
        payload = fn(client)
    except MastodonAPIError as exc:
        return jsonify({"ok": False, "error": exc.message}), 502
    if audit:
        action, resource_type, resource_name, details = audit
        _audit(action, resource_type, resource_name=resource_name, details=details)
        db.session.commit()
    body = {"ok": True}
    if isinstance(payload, dict):
        body.update(payload)
    return jsonify(body)


def _form_text(name):
    return (request.form.get(name, "") or "").strip()[:_MAX_TEXT_LEN]


def _form_flag(name):
    return request.form.get(name, "").lower() in ("1", "true", "on", "yes")


def _arg_flag(name):
    return request.args.get(name, "").lower() in ("1", "true", "on", "yes")



def _utc_iso(value):
    """Serialise a DB datetime as ISO 8601 with an explicit UTC offset.

    SQLite hands naive datetimes back even though every row is written in UTC;
    without the offset the browser would parse them as local time.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _serialize_watch(watch):
    return {
        "id": watch.id,
        "account_id": watch.mastodon_account_id,
        "acct": watch.acct,
        "reason": watch.reason or "",
        "added_by": watch.added_by.display_name if watch.added_by else "system",
        "added_at": _utc_iso(watch.added_at),
        "expires_at": _utc_iso(watch.expires_at),
        "auto_added": bool(watch.auto_added),
        "last_checked_at": _utc_iso(watch.last_checked_at),
    }


def _serialize_alert(alert, watched_ids):
    return {
        "id": alert.id,
        "kind": alert.kind,
        "account_id": alert.mastodon_account_id,
        "acct": alert.acct,
        "status_id": alert.status_id,
        "status_url": alert.status_url,
        "excerpt": alert.excerpt or "",
        "created_at": _utc_iso(alert.created_at),
        "acknowledged_at": _utc_iso(alert.acknowledged_at),
        "watched": alert.mastodon_account_id in watched_ids,
    }


def _watched_account_ids(account_ids):
    """Return the subset of ``account_ids`` that has an active ModerationWatch row."""
    account_ids = [a for a in account_ids if a]
    if not account_ids:
        return set()
    rows = (
        db.session.query(ModerationWatch.mastodon_account_id)
        .filter(ModerationWatch.mastodon_account_id.in_(account_ids))
        .all()
    )
    return {row[0] for row in rows}


@bp.route("/mastodon/save", methods=["POST"])
def mastodon_save():
    from auth.credential_store import encrypt

    api_url, err = _clean_api_url(request.form.get("mastodon_api_url", ""), "Mastodon API URL")
    if err:
        flash(err, "error")
        return redirect(url_for("moderation.index", tab="mastodon"))

    previous_api_url = Setting.get("moderation_mastodon_api_url", "")
    Setting.set("moderation_mastodon_api_url", api_url)

    # Only update the token if a new one was provided (not the placeholder)
    new_token = request.form.get("mastodon_api_token", "").strip()
    if new_token:
        from core.moderation_watch import refresh_status_limit

        Setting.set("moderation_mastodon_api_token", encrypt(new_token))
        try:
            client = MastodonAdminClient(api_url, new_token)
            account = client.verify()
            _store_token_account(account)
            refresh_status_limit(client)
        except MastodonAPIError as exc:
            Setting.set("moderation_mastodon_token_account", "")
            flash(f"Token saved but could not be verified: {exc.message}", "warning")
    elif api_url != previous_api_url:
        # The token stayed the same but the URL changed -- the previously
        # verified identity may no longer apply.
        Setting.set("moderation_mastodon_token_account", "")

    _audit("moderation_mastodon_config_save", "moderation")
    db.session.commit()
    flash("Mastodon moderation settings saved.", "success")
    return redirect(url_for("moderation.index", tab="mastodon"))


def _store_token_account(account):
    """Persist the verified token identity, tagged with when it was checked."""
    checked_at = datetime.now(timezone.utc).isoformat()
    Setting.set("moderation_mastodon_token_account", json.dumps({**account, "checked_at": checked_at}))
    return checked_at


def _get_token_account():
    """Return the stored token-identity dict, or None if unset/unparseable."""
    raw = Setting.get("moderation_mastodon_token_account", "")
    if not raw:
        return None
    try:
        account = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(account, dict):
        return None
    # Parsed copy for the template's local_dt filter; the ISO string stays for JSON consumers.
    account["checked_at_dt"] = _parse_iso(account.get("checked_at"))
    return account


@bp.route("/mastodon/test", methods=["POST"])
def mastodon_test():
    from core.moderation_watch import refresh_status_limit

    def _do(c):
        account = c.verify()
        checked_at = _store_token_account(account)
        max_chars = refresh_status_limit(c)
        return {"account": account, "checked_at": checked_at, "max_chars": max_chars}

    return _mastodon_json(_do)


def _report_notice_by_report_id(report_ids):
    """Return {report_id: iso} for the given report ids that have a
    :class:`ModerationReportNotice` row, in a single query.
    """
    from models import ModerationReportNotice

    report_ids = [str(r) for r in report_ids if r is not None]
    if not report_ids:
        return {}
    rows = (
        ModerationReportNotice.query
        .filter(ModerationReportNotice.report_id.in_(report_ids))
        .all()
    )
    return {row.report_id: _utc_iso(row.sent_at) for row in rows}


# -- reports ---------------------------------------------------------------

@bp.route("/mastodon/reports")
def mastodon_reports():
    resolved = request.args.get("resolved", "false") == "true"

    def _do(c):
        reports = c.list_reports(resolved=resolved)
        notified = _report_notice_by_report_id([r.get("id") for r in reports])
        for r in reports:
            r["reporter_notified_at"] = notified.get(str(r.get("id")))
        return {"reports": reports}

    return _mastodon_json(_do)


@bp.route("/mastodon/reports/<int:report_id>/resolve", methods=["POST"])
def mastodon_report_resolve(report_id):
    def _do(c):
        c.resolve_report(report_id)
        return {"report_id": str(report_id)}

    return _mastodon_json(
        _do,
        audit=("mastodon_report_resolve", "mastodon_report", f"report {report_id}", {"report_id": str(report_id)}),
    )


@bp.route("/mastodon/reports/<int:report_id>/reopen", methods=["POST"])
def mastodon_report_reopen(report_id):
    def _do(c):
        c.reopen_report(report_id)
        return {"report_id": str(report_id)}

    return _mastodon_json(
        _do,
        audit=("mastodon_report_reopen", "mastodon_report", f"report {report_id}", {"report_id": str(report_id)}),
    )


@bp.route("/mastodon/reports/<int:report_id>/notify/preview")
def mastodon_report_notice_preview(report_id):
    """Render a preview of the configured reporter-notice template for one report.

    Read-only: never touches ``ModerationReportNotice`` other than to look up
    whether the reporter has already been notified, so a moderator can open
    the modal repeatedly without side effects.
    """
    from core.mastodon_admin import DEFAULT_REPORT_NOTICE_TEMPLATE, render_report_notice_body, report_notice_mention
    from core.moderation_watch import REPORT_NOTICE_RENDER_ERROR, get_status_limit, report_notice_record

    acct = (request.args.get("reporter_acct", "") or "").strip()[:320]
    if not acct:
        return jsonify({"ok": False, "error": "reporter_acct is required"}), 400
    display_name = (request.args.get("display_name", "") or "").strip()[:320]

    reporter = {
        "id": None,
        "acct": acct.lstrip("@"),
        "username": acct.split("@")[0].lstrip("@"),
        "display_name": display_name or None,
    }

    template = Setting.get("moderation_report_notice_template", DEFAULT_REPORT_NOTICE_TEMPLATE)
    try:
        text = render_report_notice_body(template, reporter, report_id)
    except (KeyError, IndexError, ValueError):
        return jsonify({"ok": False, "error": REPORT_NOTICE_RENDER_ERROR}), 400

    existing = report_notice_record(report_id)
    return jsonify({
        "ok": True,
        "mention": report_notice_mention(reporter),
        "text": text,
        "max_chars": get_status_limit(),
        "already_notified_at": _utc_iso(existing.sent_at) if existing else None,
    })


@bp.route("/mastodon/reports/<int:report_id>/notify", methods=["POST"])
def mastodon_report_notify(report_id):
    from core.moderation_watch import REPORT_NOTICE_RENDER_ERROR, send_report_notice

    reporter_id_raw = (request.form.get("reporter_id", "") or "").strip()
    reporter_id = reporter_id_raw if reporter_id_raw.isdigit() else None
    acct = _form_text("reporter_acct")
    if not acct:
        return jsonify({"ok": False, "error": "reporter_acct is required"}), 400
    display_name = _form_text("display_name")
    text = _form_text("text")
    if not text:
        return jsonify({"ok": False, "error": "text is required"}), 400
    force = _form_flag("force")

    client, err = _get_bot_client()
    if err:
        return jsonify({"ok": False, "error": "Welcome bot is not configured"}), 400

    reporter = {
        "id": reporter_id,
        "acct": acct.lstrip("@"),
        "username": acct.split("@")[0].lstrip("@"),
        "display_name": display_name or None,
    }

    # send_report_notice already audits (audience="moderators") on success, so
    # nothing further is logged here.
    rec, error = send_report_notice(
        client, report_id, reporter, text=text, sent_by_user_id=current_user.id, force=force
    )

    if error == "already notified":
        return jsonify({"ok": False, "error": error}), 409
    if error == REPORT_NOTICE_RENDER_ERROR or (error and error.startswith("Message would be")):
        return jsonify({"ok": False, "error": error}), 400
    if error:
        return jsonify({"ok": False, "error": error}), 502

    return jsonify({
        "ok": True,
        "notice": {
            "sent_at": _utc_iso(rec.sent_at),
            "status_id": rec.status_id,
        },
    })


@bp.route("/mastodon/reports/<int:report_id>/statuses/action", methods=["POST"])
def mastodon_report_statuses_action(report_id):
    """Delete or mark-sensitive the reported posts on one report (Admin::StatusBatchAction).

    See ``core/mastodon_maintenance.py`` for why this runs over SSH instead of
    the REST API. Every input is re-validated (and status ids restricted to
    those actually on the report) before any SSH attempt, exactly like
    ``mastodon_account_maintenance`` does for account maintenance.
    """
    action = request.form.get("type", "")
    if action not in STATUS_ACTIONS:
        return jsonify({"ok": False, "error": "Unknown post action"}), 400
    status_ids = [s.strip() for s in request.form.getlist("status_ids") if s.strip()]
    if not status_ids:
        return jsonify({"ok": False, "error": "Select at least one post"}), 400
    if len(status_ids) > MAX_STATUS_IDS:
        return jsonify({"ok": False, "error": f"Too many posts selected (max {MAX_STATUS_IDS})"}), 400
    text = _form_text("text")
    send_email = _form_flag("send_email_notification")

    client, err = _get_mastodon_client()
    if err:
        return jsonify({"ok": False, "error": err}), 400
    try:
        report = client.get_report(report_id)
    except MastodonAPIError as exc:
        return jsonify({"ok": False, "error": exc.message}), 502
    if report.get("action_taken"):
        return jsonify({"ok": False, "error": "This report is already resolved; reopen it first"}), 400

    report_status_ids = {s["id"] for s in report.get("statuses") or [] if s.get("id")}
    status_ids = [sid for sid in status_ids if sid in report_status_ids]
    if not status_ids:
        return jsonify({"ok": False, "error": "None of the selected posts belong to this report"}), 400

    target = report.get("target_account") or {}
    if target.get("is_staff") and not current_user.can_moderate_staff:
        _audit("mastodon_account_action_refused", "mastodon_account",
                   resource_name=target.get("acct") or str(target.get("id") or ""),
                   details={"account_id": str(target.get("id") or ""), "type": f"posts:{action}",
                            "target_role": target.get("role_name", ""), "report_id": str(report_id)})
        db.session.commit()
        return jsonify({"ok": False, "error": STAFF_TARGET_ERROR}), 403

    # A remote target's home instance is the one actually notifying them --
    # sending our own "you have a new notice from staff" DM makes no sense
    # (and reuses the same rule mastodon_account_maintenance would apply).
    if target.get("domain"):
        send_email = False

    token_account = _get_token_account()
    if not token_account or not token_account.get("id"):
        return jsonify({
            "ok": False,
            "error": "Run Test Connection first so MCAT knows which Mastodon account performs the action",
        }), 400
    if not Setting.get("mastodon_guest_id", ""):
        return jsonify({"ok": False, "error": "Configure the Mastodon app guest first"}), 400

    # Pre-validate with the same inputs run_status_action() will use, so a bad
    # input maps to 400 before the maintenance lock or any SSH attempt --
    # run_status_action() itself swallows this same ValueError into an
    # ok=False result, which is the wrong status code for a client error.
    try:
        build_status_action_script(
            action, status_ids, str(report_id), token_account["id"], text=text, send_email=send_email
        )
    except ValueError as exc:
        logger.warning("Status action input rejected for report %s action %s: %s", report_id, action, exc)
        return jsonify({"ok": False, "error": INVALID_INPUT_MESSAGE}), 400

    try:
        with maintenance_slot():
            result = run_status_action(action, status_ids, str(report_id), text=text, send_email=send_email)
    except MaintenanceBusy:
        return jsonify({"ok": False, "error": "Another server-side action is running"}), 409

    _audit(
        f"mastodon_report_posts_{action}",
        "mastodon_report",
        resource_name=f"report {report_id}",
        details={
            "report_id": str(report_id),
            "status_count": len(status_ids),
            "acted": result.get("count"),
            "ok": result["ok"],
            "target": target.get("acct") or "",
            "text_len": len(text),
            "email": send_email,
        },
    )
    db.session.commit()

    if not result["ok"]:
        return jsonify({"ok": False, "error": result["message"]}), 502

    return jsonify({"ok": True, "message": result["message"], "count": result.get("count")})


# -- pending approvals -----------------------------------------------------

@bp.route("/mastodon/pending")
def mastodon_pending():
    return _mastodon_json(lambda c: {"accounts": c.list_pending_accounts()})


@bp.route("/mastodon/accounts/<int:account_id>/approve", methods=["POST"])
def mastodon_account_approve(account_id):
    acct = _form_text("acct")

    def _do(c):
        c.approve_account(account_id)
        return {"account_id": str(account_id)}

    return _mastodon_json(
        _do,
        audit=("mastodon_account_approve", "mastodon_account", acct or str(account_id),
               {"account_id": str(account_id)}),
    )


@bp.route("/mastodon/accounts/<int:account_id>/reject", methods=["POST"])
def mastodon_account_reject(account_id):
    acct = _form_text("acct")

    def _do(c):
        c.reject_account(account_id)
        return {"account_id": str(account_id)}

    return _mastodon_json(
        _do,
        audit=("mastodon_account_reject", "mastodon_account", acct or str(account_id),
               {"account_id": str(account_id)}),
    )


# -- account lookup and actions --------------------------------------------

@bp.route("/mastodon/accounts/lookup")
def mastodon_account_lookup():
    acct = (request.args.get("acct", "") or "").strip()[:320]
    if not acct:
        return jsonify({"ok": False, "error": "Enter an account handle to look up"}), 400
    return _mastodon_json(lambda c: {"account": c.lookup_account(acct)})


@bp.route("/mastodon/accounts/search")
def mastodon_account_search():
    email = (request.args.get("email", "") or "").strip()[:320]
    ip = (request.args.get("ip", "") or "").strip()[:64]
    username = (request.args.get("username", "") or "").strip()[:64]
    display_name = (request.args.get("display_name", "") or "").strip()[:128]

    if not (email or ip or username or display_name):
        return jsonify({"ok": False, "error": "Provide an email, IP, username or display name"}), 400

    if ip:
        try:
            ipaddress.ip_network(ip, strict=False)
        except ValueError:
            return jsonify({"ok": False, "error": "invalid IP or CIDR"}), 400

    filters = {}
    if email:
        filters["email"] = email
    if ip:
        filters["ip"] = ip
    if username:
        filters["username"] = username
    if display_name:
        filters["display_name"] = display_name

    def _do(c):
        accounts = c.search_accounts(**filters, limit=25)
        watched_ids = _watched_account_ids([a.get("id") for a in accounts])
        for a in accounts:
            a["watched"] = a.get("id") in watched_ids
        return {"accounts": accounts}

    return _mastodon_json(
        _do,
        audit=("mastodon_account_search", "mastodon_account", None, {"filters": sorted(filters)}),
    )


@bp.route("/mastodon/accounts/<int:account_id>/context")
def mastodon_account_context(account_id):
    client, err = _get_mastodon_client()
    if err:
        return jsonify({"ok": False, "error": err}), 400
    try:
        target = client.get_admin_account(account_id)
    except MastodonAPIError as exc:
        return jsonify({"ok": False, "error": exc.message}), 502

    errors = {}

    try:
        reports_about = client.reports_for_account(account_id, as_target=True)[:10]
    except MastodonAPIError as exc:
        reports_about = None
        errors["reports_about"] = exc.message

    try:
        reports_by = client.reports_for_account(account_id, as_target=False)[:10]
    except MastodonAPIError as exc:
        reports_by = None
        errors["reports_by"] = exc.message

    try:
        recent_statuses = client.account_statuses(account_id, limit=10)
    except MastodonAPIError as exc:
        recent_statuses = None
        errors["recent_statuses"] = exc.message

    if target.get("ip"):
        try:
            same_ip = client.accounts_sharing_ip(target["ip"], exclude_id=str(account_id), limit=10)
        except MastodonAPIError as exc:
            same_ip = None
            errors["same_ip"] = exc.message
        except ValueError:
            same_ip = []
    else:
        same_ip = []

    account_id_str = str(account_id)
    watched_ids = _watched_account_ids([account_id_str])
    welcomed_at = _welcomed_at_by_account_id([account_id_str])

    return jsonify({
        "ok": True,
        "reports_about": reports_about,
        "reports_by": reports_by,
        "recent_statuses": recent_statuses,
        "same_ip": same_ip,
        "errors": errors,
        "watched": account_id_str in watched_ids,
        "welcomed_at": welcomed_at.get(account_id_str),
    })


@bp.route("/mastodon/accounts/<int:account_id>/action", methods=["POST"])
def mastodon_account_action(account_id):
    action_type = _form_text("type")
    if action_type not in ACCOUNT_ACTION_TYPES:
        return jsonify({"ok": False, "error": "Unknown account action"}), 400
    text = _form_text("text")
    acct = _form_text("acct")
    report_id = request.form.get("report_id", type=int)
    notify = _form_flag("send_email_notification")

    client, err = _get_mastodon_client()
    if err:
        return jsonify({"ok": False, "error": err}), 400
    try:
        target = client.get_admin_account(account_id)
    except MastodonAPIError as exc:
        return jsonify({"ok": False, "error": exc.message}), 502
    if target.get("is_staff") and not current_user.can_moderate_staff:
        _audit("mastodon_account_action_refused", "mastodon_account",
                   resource_name=acct or target.get("acct") or str(account_id),
                   details={"account_id": str(account_id), "type": action_type,
                            "target_role": target.get("role_name", ""),
                            **({"report_id": str(report_id)} if report_id else {})})
        db.session.commit()
        return jsonify({"ok": False, "error": STAFF_TARGET_ERROR}), 403

    def _do(c):
        c.account_action(account_id, action_type, text=text, report_id=report_id, send_email_notification=notify)
        return {"account": c.get_admin_account(account_id)}

    details = {"account_id": str(account_id), "type": action_type, "notify": notify}
    if report_id:
        details["report_id"] = str(report_id)
    return _mastodon_json(_do, audit=(f"mastodon_account_{action_type}", "mastodon_account",
                                      acct or str(account_id), details))


@bp.route("/mastodon/accounts/<int:account_id>/delete", methods=["POST"])
def mastodon_account_delete(account_id):
    acct = _form_text("acct")
    if not acct:
        return jsonify({"ok": False, "error": "acct is required"}), 400
    confirm = _form_text("confirm")
    if confirm != acct:
        return jsonify({"ok": False, "error": "Type the account handle to confirm"}), 400

    client, err = _get_mastodon_client()
    if err:
        return jsonify({"ok": False, "error": err}), 400
    try:
        target = client.get_admin_account(account_id)
    except MastodonAPIError as exc:
        return jsonify({"ok": False, "error": exc.message}), 502

    if not target.get("suspended"):
        return jsonify({"ok": False, "error": "Suspend the account before deleting it"}), 400

    if target.get("is_staff") and not current_user.can_moderate_staff:
        _audit("mastodon_account_action_refused", "mastodon_account",
                   resource_name=acct or target.get("acct") or str(account_id),
                   details={"account_id": str(account_id), "type": "delete",
                            "target_role": target.get("role_name", "")})
        db.session.commit()
        return jsonify({"ok": False, "error": STAFF_TARGET_ERROR}), 403

    return _mastodon_json(
        lambda c: {"deleted": c.delete_account(account_id)},
        audit=("mastodon_account_delete", "mastodon_account", acct,
               {"account_id": str(account_id), "domain": target.get("domain")}),
    )


@bp.route("/mastodon/accounts/<int:account_id>/maintenance", methods=["POST"])
def mastodon_account_maintenance(account_id):
    if not current_user.can_maintain_mastodon_accounts:
        _audit("mastodon_maintenance_refused", "mastodon_account",
                   resource_name=str(account_id),
                   details={"account_id": str(account_id), "action": _form_text("action"), "reason": "permission"})
        db.session.commit()
        return jsonify({"ok": False, "error": "Your role may not run account maintenance"}), 403

    action = request.form.get("action", "")
    if action not in MAINTENANCE_ACTIONS:
        return jsonify({"ok": False, "error": "Unknown maintenance action"}), 400
    acct = _form_text("acct")
    email = _form_text("email") or None
    confirm = _form_flag("confirm")

    client, err = _get_mastodon_client()
    if err:
        return jsonify({"ok": False, "error": err}), 400
    try:
        target = client.get_admin_account(account_id)
    except MastodonAPIError as exc:
        return jsonify({"ok": False, "error": exc.message}), 502

    if target.get("domain"):
        return jsonify({"ok": False, "error": "Maintenance actions apply to local accounts only"}), 400

    if target.get("is_staff") and not current_user.can_moderate_staff:
        _audit("mastodon_account_action_refused", "mastodon_account",
                   resource_name=acct or target.get("acct") or str(account_id),
                   details={"account_id": str(account_id), "type": f"maintenance:{action}",
                            "target_role": target.get("role_name", "")})
        db.session.commit()
        return jsonify({"ok": False, "error": STAFF_TARGET_ERROR}), 403

    username = target.get("username")

    # Pre-validate with the same settings run_maintenance() will use, so a bad
    # input (e.g. an invalid email) maps to 400 before the maintenance lock or
    # any SSH attempt -- run_maintenance() itself swallows this same ValueError
    # into an ok=False result, which is the wrong status code for a client error.
    user_setting = Setting.get("mastodon_user", "mastodon")
    app_dir_setting = Setting.get("mastodon_app_dir", "/home/mastodon/live")
    try:
        build_modify_command(
            username, action, email=email, confirm=confirm, user=user_setting, app_dir=app_dir_setting
        )
    except ValueError as exc:
        # Our own validator text, but keep exception strings out of JSON
        # (CodeQL py/stack-trace-exposure); the detail goes to the log.
        logger.warning("Maintenance input rejected for %s on account %s: %s", action, account_id, exc)
        return jsonify({"ok": False, "error": INVALID_INPUT_MESSAGE}), 400

    try:
        with maintenance_slot():
            result = run_maintenance(action, username, email=email, confirm=confirm)
    except MaintenanceBusy:
        return jsonify({"ok": False, "error": "Another maintenance action is running"}), 409

    _audit(
        f"mastodon_maintenance_{action}",
        "mastodon_account",
        resource_name=acct or username,
        details={
            "account_id": str(account_id),
            "ok": result["ok"],
            "email_changed": action == "change_email" and result["ok"],
        },
    )
    db.session.commit()

    if not result["ok"]:
        return jsonify({"ok": False, "error": result["message"]}), 502

    return jsonify({
        "ok": True,
        "message": result["message"],
        "password": result["password"] if action == "reset_password" else None,
    })


@bp.route("/mastodon/accounts/<int:account_id>/<lift>", methods=["POST"])
def mastodon_account_lift(account_id, lift):
    if lift not in ACCOUNT_LIFT_ACTIONS:
        return jsonify({"ok": False, "error": "Unknown account action"}), 404
    acct = _form_text("acct")

    def _do(c):
        c.lift_account_action(account_id, lift)
        return {"account": c.get_admin_account(account_id)}

    return _mastodon_json(_do, audit=(f"mastodon_account_{lift}", "mastodon_account",
                                      acct or str(account_id), {"account_id": str(account_id)}))


# -- domain blocks ---------------------------------------------------------

@bp.route("/mastodon/domain_blocks")
def mastodon_domain_blocks():
    return _mastodon_json(lambda c: {"blocks": c.list_domain_blocks()})


@bp.route("/mastodon/domain_blocks", methods=["POST"])
def mastodon_domain_block_create():
    try:
        domain = validate_domain(request.form.get("domain", ""))
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    severity = _form_text("severity") or "silence"
    if severity not in DOMAIN_BLOCK_SEVERITIES:
        return jsonify({"ok": False, "error": "Unknown domain block severity"}), 400
    opts = {
        "severity": severity,
        "reject_media": _form_flag("reject_media"),
        "reject_reports": _form_flag("reject_reports"),
        "obfuscate": _form_flag("obfuscate"),
        "public_comment": _form_text("public_comment"),
        "private_comment": _form_text("private_comment"),
    }
    return _mastodon_json(
        lambda c: {"block": c.create_domain_block(domain, **opts)},
        audit=("mastodon_domain_block_create", "mastodon_domain_block", domain,
               {"severity": severity, "reject_media": opts["reject_media"], "reject_reports": opts["reject_reports"]}),
    )


@bp.route("/mastodon/domain_blocks/<int:block_id>/delete", methods=["POST"])
def mastodon_domain_block_delete(block_id):
    domain = _form_text("domain")

    def _do(c):
        c.delete_domain_block(block_id)
        return {"block_id": str(block_id)}

    return _mastodon_json(
        _do,
        audit=("mastodon_domain_block_delete", "mastodon_domain_block", domain or str(block_id),
               {"block_id": str(block_id)}),
    )


# ---------------------------------------------------------------------------
# Moderation watch: watched accounts, deduplicated alerts, new-signup and
# silent-login discovery. See core/moderation_watch.py for the poll itself.
# ---------------------------------------------------------------------------


@bp.route("/mastodon/watch")
def mastodon_watch_list():
    watches = ModerationWatch.query.order_by(ModerationWatch.added_at.desc()).all()

    last_run = None
    raw_result = Setting.get("moderation_watch_last_run_result", "")
    if raw_result:
        try:
            last_run = json.loads(raw_result)
        except (json.JSONDecodeError, TypeError):
            last_run = None
    if last_run is not None:
        last_run["at"] = Setting.get("moderation_watch_last_run_at", "") or None

    return jsonify({
        "ok": True,
        "watches": [_serialize_watch(w) for w in watches],
        "last_run": last_run,
        "backoff_until": Setting.get("moderation_watch_backoff_until", "") or None,
    })


@bp.route("/mastodon/watch", methods=["POST"])
def mastodon_watch_add():
    account_id = _form_text("account_id")
    if not account_id.isdigit():
        return jsonify({"ok": False, "error": "A numeric account_id is required"}), 400
    acct = _form_text("acct")
    if not acct:
        return jsonify({"ok": False, "error": "acct is required"}), 400
    reason = _form_text("reason")
    days = request.form.get("days", 0, type=int) or 0
    days = max(0, min(365, days))

    if ModerationWatch.query.filter_by(mastodon_account_id=account_id).first():
        return jsonify({"ok": False, "error": "Already watched"}), 409

    def _do(c):
        statuses = c.account_statuses(account_id, limit=1)
        last_status_id = statuses[0]["id"] if statuses else None
        watch = ModerationWatch(
            mastodon_account_id=account_id,
            acct=acct,
            reason=reason or None,
            added_by_user_id=current_user.id,
            expires_at=(datetime.now(timezone.utc) + timedelta(days=days)) if days else None,
            last_status_id=last_status_id,
        )
        db.session.add(watch)
        db.session.flush()
        return {"watch": _serialize_watch(watch)}

    return _mastodon_json(
        _do,
        audit=("mastodon_watch_add", "mastodon_account", acct, {"account_id": account_id, "days": days}),
    )


@bp.route("/mastodon/watch/<int:watch_id>/delete", methods=["POST"])
def mastodon_watch_remove(watch_id):
    watch = db.session.get(ModerationWatch, watch_id)
    if not watch:
        return jsonify({"ok": False, "error": "Watch not found"}), 404
    acct = watch.acct
    db.session.delete(watch)
    _audit("mastodon_watch_remove", "mastodon_account", resource_name=acct,
               details={"watch_id": watch_id, "account_id": watch.mastodon_account_id})
    db.session.commit()
    return jsonify({"ok": True})


@bp.route("/mastodon/alerts")
def mastodon_alerts():
    kind = request.args.get("kind", "")
    if kind and kind not in ModerationAlert.KINDS:
        return jsonify({"ok": False, "error": "Unknown alert kind"}), 400
    include_acked = _arg_flag("include_acked")
    limit = request.args.get("limit", 50, type=int) or 50
    limit = max(1, min(200, limit))

    query = ModerationAlert.query
    if kind:
        query = query.filter_by(kind=kind)
    if not include_acked:
        query = query.filter(ModerationAlert.acknowledged_at.is_(None))
    alerts = query.order_by(ModerationAlert.created_at.desc()).limit(limit).all()

    watched_ids = _watched_account_ids([a.mastodon_account_id for a in alerts])
    return jsonify({"ok": True, "alerts": [_serialize_alert(a, watched_ids) for a in alerts]})


@bp.route("/mastodon/alerts/<int:alert_id>/ack", methods=["POST"])
def mastodon_alert_ack(alert_id):
    alert = db.session.get(ModerationAlert, alert_id)
    if not alert:
        return jsonify({"ok": False, "error": "Alert not found"}), 404
    if alert.acknowledged_at is None:
        alert.acknowledged_at = datetime.now(timezone.utc)
        alert.acknowledged_by_user_id = current_user.id
        db.session.commit()
    return jsonify({"ok": True})


@bp.route("/mastodon/alerts/ack_all", methods=["POST"])
def mastodon_alerts_ack_all():
    kind = _form_text("kind")
    if kind and kind not in ModerationAlert.KINDS:
        return jsonify({"ok": False, "error": "Unknown alert kind"}), 400

    query = ModerationAlert.query.filter(ModerationAlert.acknowledged_at.is_(None))
    if kind:
        query = query.filter_by(kind=kind)
    count = query.update(
        {
            "acknowledged_at": datetime.now(timezone.utc),
            "acknowledged_by_user_id": current_user.id,
        },
        synchronize_session=False,
    )
    _audit("mastodon_alerts_ack_all", "moderation", details={"kind": kind or None, "count": count})
    db.session.commit()
    return jsonify({"ok": True, "count": count})


def _welcomed_at_by_account_id(account_ids):
    """Return {account_id: welcomed_at ISO string} for the given account ids that have a
    :class:`ModerationWelcome` row, in a single query.
    """
    from models import ModerationWelcome

    account_ids = [a for a in account_ids if a]
    if not account_ids:
        return {}
    rows = (
        ModerationWelcome.query
        .filter(ModerationWelcome.mastodon_account_id.in_(account_ids))
        .all()
    )
    return {row.mastodon_account_id: _utc_iso(row.sent_at) for row in rows}


@bp.route("/mastodon/new_accounts")
def mastodon_new_accounts():
    days = request.args.get("days", 7, type=int) or 7
    days = max(1, min(30, days))

    def _do(c):
        since = datetime.now(timezone.utc) - timedelta(days=days)
        accounts = c.list_local_accounts(newer_than=since, max_pages=3)
        watched_ids = _watched_account_ids([a.get("id") for a in accounts])
        welcomed_at = _welcomed_at_by_account_id([a.get("id") for a in accounts])
        for a in accounts:
            a["watched"] = a.get("id") in watched_ids
            a["welcomed_at"] = welcomed_at.get(a.get("id"))
        return {"accounts": accounts}

    return _mastodon_json(_do)


# ---------------------------------------------------------------------------
# Welcome bot: automatic/manual welcome DMs to newly discovered accounts.
# See core/moderation_watch.py for send_welcome/build_bot_client/get_welcome_settings.
# ---------------------------------------------------------------------------


@bp.route("/mastodon/accounts/<int:account_id>/welcome", methods=["POST"])
def mastodon_welcome_send(account_id):
    from core.moderation_watch import send_welcome

    acct = _form_text("acct")
    if not acct:
        return jsonify({"ok": False, "error": "acct is required"}), 400
    force = request.form.get("force") == "1"

    client, err = _get_bot_client()
    if err:
        return jsonify({"ok": False, "error": "Welcome bot is not configured"}), 400

    account = {
        "id": str(account_id),
        "username": acct.split("@")[0].lstrip("@"),
        "acct": acct.lstrip("@"),
        "display_name": _form_text("display_name") or None,
    }

    # send_welcome never raises MastodonAPIError itself -- a post failure comes
    # back as (None, exc.message) -- so no try/except is needed here.
    rec, error = send_welcome(client, account, sent_by_user_id=current_user.id, force=force)

    if error == "already welcomed":
        return jsonify({"ok": False, "error": error}), 409
    if error:
        return jsonify({"ok": False, "error": error}), 502

    return jsonify({
        "ok": True,
        "welcome": {
            "sent_at": _utc_iso(rec.sent_at),
            "status_id": rec.status_id,
            "automatic": rec.sent_by_user_id is None,
        },
    })


@bp.route("/mastodon/welcome/save", methods=["POST"])
def mastodon_welcome_save():
    from auth.credential_store import encrypt
    from core.mastodon_admin import validate_welcome_template
    from core.moderation_watch import get_status_limit

    template = request.form.get("welcome_template", "")
    err = validate_welcome_template(template, max_chars=get_status_limit())
    if err:
        flash(err, "error")
        return redirect(url_for("moderation.index", tab="mastodon"))

    new_token = request.form.get("bot_token", "").strip()
    token_changed = bool(new_token)
    if new_token:
        Setting.set("moderation_bot_token", encrypt(new_token))

    Setting.set("moderation_welcome_template", template.strip())
    enabled = _form_flag("welcome_enabled")
    Setting.set("moderation_welcome_enabled", "true" if enabled else "false")

    _audit(
        "moderation_welcome_config_save",
        "moderation",
        details={"enabled": enabled, "template_len": len(template.strip()), "token_changed": token_changed},
    )
    db.session.commit()

    flash("Welcome message settings saved.", "success")
    return redirect(url_for("moderation.index", tab="mastodon"))


@bp.route("/mastodon/welcome/test", methods=["POST"])
def mastodon_welcome_test():
    from core.moderation_watch import refresh_status_limit

    def _do(c):
        account = c.verify()
        # The bot token also reads /api/v2/instance, so this is a convenient
        # second opportunity (besides the admin token's own /mastodon/test)
        # to refresh the cached status-length limit.
        refresh_status_limit(c)
        return {"account": account}

    return _bot_json(_do, audit=("mastodon_welcome_test", "moderation", None, None))


@bp.route("/mastodon/report_notice/save", methods=["POST"])
def mastodon_report_notice_save():
    from core.mastodon_admin import validate_report_notice_template
    from core.moderation_watch import get_status_limit

    template = request.form.get("report_notice_template", "")
    err = validate_report_notice_template(template, max_chars=get_status_limit())
    if err:
        flash(err, "error")
        return redirect(url_for("moderation.index", tab="mastodon"))

    Setting.set("moderation_report_notice_template", template.strip())
    _audit(
        "moderation_report_notice_config_save",
        "moderation",
        details={"template_len": len(template.strip())},
    )
    db.session.commit()

    flash("Reporter notice settings saved.", "success")
    return redirect(url_for("moderation.index", tab="mastodon"))


@bp.route("/mastodon/watch/poll", methods=["POST"])
def mastodon_watch_poll_now():
    from flask import current_app

    from core.moderation_watch import build_admin_client, run_watch_poll

    client, err = build_admin_client()
    if err:
        return jsonify({"ok": False, "error": err}), 400

    with _watch_poll_lock:
        if _watch_poll_state["running"]:
            return jsonify({"ok": False, "error": "A poll is already running"}), 409
        _watch_poll_state["running"] = True

    app = current_app._get_current_object()

    def _worker():
        with app.app_context():
            try:
                run_watch_poll(client)
            except Exception:
                logger.exception("Manual moderation watch poll failed")
            finally:
                _watch_poll_state["running"] = False

    t = _threading.Thread(target=_worker, daemon=True)
    t.start()

    _audit("mastodon_watch_poll_now", "moderation")
    db.session.commit()
    return jsonify({"ok": True, "started": True})


@bp.route("/mastodon/summary")
def mastodon_summary():
    configured = bool(
        Setting.get("moderation_mastodon_api_url", "") and Setting.get("moderation_mastodon_api_token", "")
    )

    unacked = {}
    for kind in ModerationAlert.KINDS:
        unacked[kind] = (
            ModerationAlert.query.filter_by(kind=kind).filter(ModerationAlert.acknowledged_at.is_(None)).count()
        )
    unacked_total = sum(unacked.values())
    watch_total = ModerationWatch.query.count()

    recent = (
        ModerationAlert.query.filter(ModerationAlert.acknowledged_at.is_(None))
        .order_by(ModerationAlert.created_at.desc())
        .limit(5)
        .all()
    )
    watched_ids = _watched_account_ids([a.mastodon_account_id for a in recent])

    open_reports = None
    pending_accounts = None
    live_error = None
    if configured:
        client, err = _get_mastodon_client()
        if err:
            live_error = err
        else:
            try:
                count, more = client.open_report_count()
                open_reports = {"count": count, "more": more}
                count2, more2 = client.pending_account_count()
                pending_accounts = {"count": count2, "more": more2}
            except MastodonAPIError as exc:
                live_error = exc.message

    return jsonify({
        "ok": True,
        "configured": configured,
        "unacked": unacked,
        "unacked_total": unacked_total,
        "watch_total": watch_total,
        "recent_alerts": [_serialize_alert(a, watched_ids) for a in recent],
        "last_run_at": Setting.get("moderation_watch_last_run_at", "") or None,
        "open_reports": open_reports,
        "pending_accounts": pending_accounts,
        "live_error": live_error,
    })


@bp.route("/mastodon/watch/save", methods=["POST"])
def mastodon_watch_save():
    from core.scheduler import parse_interval, reschedule_moderation_watch

    poll_minutes, error = parse_interval("moderation_watch_poll_minutes", request.form.get("poll_minutes", "5"))
    if error:
        flash(f"Poll interval {error}", "error")
        return redirect(url_for("moderation.index", tab="mastodon"))

    log_retention_days, error = parse_interval(
        "moderation_log_retention_days", request.form.get("log_retention_days", "365")
    )
    if error:
        flash(f"Activity log retention {error}", "error")
        return redirect(url_for("moderation.index", tab="mastodon"))

    def _clamp(name, default, low, high):
        raw = request.form.get(name, str(default))
        try:
            value = int(str(raw).strip())
        except (TypeError, ValueError):
            value = default
        return max(low, min(high, value))

    alerts_enabled = _form_flag("alerts_enabled")
    auto_watch_days = _clamp("auto_watch_days", 0, 0, 90)
    silent_login_days = _clamp("silent_login_days", 7, 1, 90)
    silent_min_age_days = _clamp("silent_min_age_days", 14, 0, 365)
    silent_scan_window_days = _clamp("silent_scan_window_days", 90, 7, 365)

    Setting.set("moderation_watch_alerts_enabled", "true" if alerts_enabled else "false")
    Setting.set("moderation_watch_poll_minutes", str(poll_minutes))
    Setting.set("moderation_watch_auto_watch_days", str(auto_watch_days))
    Setting.set("moderation_watch_silent_login_days", str(silent_login_days))
    Setting.set("moderation_watch_silent_min_age_days", str(silent_min_age_days))
    Setting.set("moderation_watch_silent_scan_window_days", str(silent_scan_window_days))
    Setting.set("moderation_log_retention_days", str(log_retention_days))

    _audit("moderation_watch_config_save", "moderation")
    db.session.commit()

    reschedule_moderation_watch(poll_minutes)

    flash("Moderation watch settings saved.", "success")
    return redirect(url_for("moderation.index", tab="mastodon"))
