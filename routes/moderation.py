"""Moderation blueprint: cross-platform user email verification."""

import json
import logging
import threading as _threading
from collections import deque
from datetime import datetime

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from auth.audit import log_action
from core.mastodon_admin import (
    ACCOUNT_ACTION_TYPES,
    ACCOUNT_LIFT_ACTIONS,
    DOMAIN_BLOCK_SEVERITIES,
    MastodonAdminClient,
    MastodonAPIError,
    validate_domain,
)
from models import Setting, db

logger = logging.getLogger(__name__)

# Upper bound on free-text fields (reasons, comments) forwarded to Mastodon.
_MAX_TEXT_LEN = 2000

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
})


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


@bp.route("/")
def index():
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

    active_tab = "mastodon" if request.args.get("tab") == "mastodon" else "peertube"
    return render_template(
        "moderation.html",
        settings=settings,
        last_result=last_result,
        job=_moderation_job,
        active_tab=active_tab,
        can_configure=current_user.is_admin,
    )


@bp.route("/save", methods=["POST"])
def save():
    from auth.credential_store import encrypt

    Setting.set("moderation_peertube_api_url", request.form.get("peertube_api_url", "").strip())

    # Only update token if a new one was provided (not the placeholder)
    new_token = request.form.get("peertube_api_token", "").strip()
    if new_token:
        Setting.set("moderation_peertube_api_token", encrypt(new_token))

    Setting.set("moderation_check_interval_hours", request.form.get("check_interval_hours", "24").strip())
    Setting.set("moderation_auto_ban_enabled", "true" if request.form.get("auto_ban_enabled") else "false")

    log_action("moderation_config_save", "moderation")
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
        log_action(action, resource_type, resource_name=resource_name, details=details)
        db.session.commit()
    body = {"ok": True}
    if isinstance(payload, dict):
        body.update(payload)
    return jsonify(body)


def _form_text(name):
    return (request.form.get(name, "") or "").strip()[:_MAX_TEXT_LEN]


def _form_flag(name):
    return request.form.get(name, "").lower() in ("1", "true", "on", "yes")


@bp.route("/mastodon/save", methods=["POST"])
def mastodon_save():
    from auth.credential_store import encrypt

    api_url = request.form.get("mastodon_api_url", "").strip().rstrip("/")
    if api_url and not (api_url.startswith("https://") or api_url.startswith("http://")):
        flash("Mastodon API URL must start with https://", "error")
        return redirect(url_for("moderation.index", tab="mastodon"))
    Setting.set("moderation_mastodon_api_url", api_url)

    # Only update the token if a new one was provided (not the placeholder)
    new_token = request.form.get("mastodon_api_token", "").strip()
    if new_token:
        Setting.set("moderation_mastodon_api_token", encrypt(new_token))

    log_action("moderation_mastodon_config_save", "moderation")
    db.session.commit()
    flash("Mastodon moderation settings saved.", "success")
    return redirect(url_for("moderation.index", tab="mastodon"))


@bp.route("/mastodon/test", methods=["POST"])
def mastodon_test():
    return _mastodon_json(lambda c: {"account": c.verify()})


# -- reports ---------------------------------------------------------------

@bp.route("/mastodon/reports")
def mastodon_reports():
    resolved = request.args.get("resolved", "false") == "true"
    return _mastodon_json(lambda c: {"reports": c.list_reports(resolved=resolved)})


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


@bp.route("/mastodon/accounts/<int:account_id>/action", methods=["POST"])
def mastodon_account_action(account_id):
    action_type = _form_text("type")
    if action_type not in ACCOUNT_ACTION_TYPES:
        return jsonify({"ok": False, "error": "Unknown account action"}), 400
    text = _form_text("text")
    acct = _form_text("acct")
    report_id = request.form.get("report_id", type=int)
    notify = _form_flag("send_email_notification")

    def _do(c):
        c.account_action(account_id, action_type, text=text, report_id=report_id, send_email_notification=notify)
        return {"account": c.get_admin_account(account_id)}

    details = {"account_id": str(account_id), "type": action_type, "notify": notify}
    if report_id:
        details["report_id"] = str(report_id)
    return _mastodon_json(_do, audit=(f"mastodon_account_{action_type}", "mastodon_account",
                                      acct or str(account_id), details))


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
