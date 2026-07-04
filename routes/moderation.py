"""Moderation blueprint: cross-platform user email verification."""

import json
import logging
import threading as _threading
from datetime import datetime

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from auth.audit import log_action
from models import Setting, db

logger = logging.getLogger(__name__)

bp = Blueprint("moderation", __name__)

# In-memory job state — mirrors the pattern from routes/peertube.py.
# ``result`` holds the full (email-bearing) result of the most recent run so the
# live admin view can render emails that are deliberately NOT persisted to the
# Setting store (see core.moderation._scrub_result_for_storage).
_moderation_job = {"running": False, "success": None, "log": [], "result": None}

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


@bp.before_request
@login_required
def _require_login():
    # Moderation exposes user PII (emails) and an auto-ban surface, so it is
    # gated at the admin tier in addition to the grantable can_moderate flag —
    # can_moderate alone must not unlock this feature for a non-admin (H2).
    # current_user.is_admin is role_level >= 3 (admin / super_admin).
    if not (current_user.is_admin and current_user.can_moderate):
        flash("You don't have permission to access moderation.", "error")
        return redirect(url_for("dashboard.index"))


def _get_moderation_settings():
    return {
        "peertube_api_url": Setting.get("moderation_peertube_api_url", ""),
        "peertube_api_token": Setting.get("moderation_peertube_api_token", ""),
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

    return render_template(
        "moderation.html",
        settings=settings,
        last_result=last_result,
        job=_moderation_job,
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
        _moderation_job["log"] = []

    def _worker():
        with app.app_context():
            try:
                from core.moderation import run_moderation_check
                ok, result = run_moderation_check(
                    log_callback=lambda msg: _moderation_job["log"].append(msg)
                )
                _moderation_job["success"] = ok
                # Retain the full (email-bearing) result in memory only.
                _moderation_job["result"] = result if ok else None
            except Exception as exc:
                logger.exception("Moderation check failed")
                _moderation_job["log"].append(f"ERROR: {exc}")
                _moderation_job["success"] = False
            finally:
                _moderation_job["running"] = False

    t = _threading.Thread(target=_worker, daemon=True)
    t.start()

    flash("Moderation check started.", "info")
    return redirect(url_for("moderation.index"))


@bp.route("/status")
def status():
    return jsonify({
        "running": _moderation_job["running"],
        "success": _moderation_job["success"],
        "log": _moderation_job["log"],
    })
