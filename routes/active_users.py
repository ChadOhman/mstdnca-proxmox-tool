"""Admin-only Mastodon active-user list and CSV export for mailing campaigns."""

from datetime import datetime, timezone

from flask import Blueprint, Response, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from auth.audit import log_action
from core.mastodon_active_users import (
    DEFAULT_DAYS,
    MAX_DAYS,
    MIN_DAYS,
    clamp_days,
    fetch_active_users,
    rows_to_csv,
)
from models import db

bp = Blueprint("active_users", __name__)

# Rows shown on the page; the CSV always carries the full list.
PREVIEW_LIMIT = 100


@bp.before_request
@login_required
def _require_admin():
    # Every response from this blueprint can carry the email address of each
    # active user, so it is admin-tier only (not can_moderate / can_update).
    if not current_user.is_admin:
        flash("Administrator access is required to view active users.", "error")
        return redirect(url_for("dashboard.index"))


@bp.after_request
def _no_store(response):
    response.headers["Cache-Control"] = "no-store"
    return response


def _audit(action, days, count):
    log_action(action, "mastodon_active_users", resource_name=f"last {days} days",
               details={"days": days, "count": count}, audience="moderators")
    db.session.commit()


@bp.route("/", methods=["GET"])
def index():
    return render_template("active_users.html", days=DEFAULT_DAYS, min_days=MIN_DAYS, max_days=MAX_DAYS,
                           rows=None, total=None, preview_limit=PREVIEW_LIMIT)


@bp.route("/preview", methods=["POST"])
def preview():
    days = clamp_days(request.form.get("days"))
    rows, err = fetch_active_users(days)
    if err:
        flash(err, "error")
        return redirect(url_for("active_users.index"))
    _audit("mastodon_active_users_view", days, len(rows))
    return render_template("active_users.html", days=days, min_days=MIN_DAYS, max_days=MAX_DAYS,
                           rows=rows[:PREVIEW_LIMIT], total=len(rows), preview_limit=PREVIEW_LIMIT)


@bp.route("/export.csv", methods=["POST"])
def export_csv():
    days = clamp_days(request.form.get("days"))
    rows, err = fetch_active_users(days)
    if err:
        flash(err, "error")
        return redirect(url_for("active_users.index"))
    _audit("mastodon_active_users_export", days, len(rows))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    return Response(
        rows_to_csv(rows),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="mastodon-active-users-{days}d-{stamp}.csv"'},
    )
