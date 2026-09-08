from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from auth.audit import log_action
from core.scheduler import VALID_WINDOW_DAYS, parse_window_time
from models import MaintenanceWindow, db

bp = Blueprint("schedules", __name__)


@bp.before_request
@login_required
def _require_login():
    if not current_user.is_admin:
        flash("Admin access required.", "error")
        return redirect(url_for("dashboard.index"))


@bp.route("/")
def index():
    schedules = MaintenanceWindow.query.order_by(MaintenanceWindow.name).all()
    return render_template("schedules.html", schedules=schedules)


@bp.route("/add", methods=["POST"])
def add():
    name = request.form.get("name", "").strip()
    day_of_week = request.form.get("day_of_week", "sunday")
    start_time = request.form.get("start_time", "02:00")
    end_time = request.form.get("end_time", "05:00")
    update_type = request.form.get("update_type", "upgrade")

    if not name:
        flash("Name is required.", "error")
        return redirect(url_for("schedules.index"))

    # Validate before persisting: _run_auto_updates parses these into
    # datetime.time, so a malformed value would silently disable the window.
    day_of_week = (day_of_week or "").strip().lower()
    if day_of_week not in VALID_WINDOW_DAYS:
        flash("Day must be 'daily' or a weekday name.", "error")
        return redirect(url_for("schedules.index"))

    if parse_window_time(start_time) is None or parse_window_time(end_time) is None:
        flash("Start and end times must be in zero-padded 24-hour HH:MM format.", "error")
        return redirect(url_for("schedules.index"))

    window = MaintenanceWindow(
        name=name,
        day_of_week=day_of_week,
        start_time=start_time.strip(),
        end_time=end_time.strip(),
        update_type=update_type,
    )
    db.session.add(window)
    db.session.flush()
    log_action("schedule_create", "schedule", resource_id=window.id, resource_name=name)
    db.session.commit()

    flash(f"Maintenance schedule '{name}' created.", "success")
    return redirect(url_for("schedules.index"))


@bp.route("/<int:schedule_id>/toggle", methods=["POST"])
def toggle(schedule_id):
    window = MaintenanceWindow.query.get_or_404(schedule_id)
    window.enabled = not window.enabled
    log_action("schedule_toggle", "schedule", resource_id=window.id, resource_name=window.name)
    db.session.commit()
    state = "enabled" if window.enabled else "disabled"
    flash(f"Schedule '{window.name}' {state}.", "success")
    return redirect(url_for("schedules.index"))


@bp.route("/<int:schedule_id>/delete", methods=["POST"])
def delete(schedule_id):
    window = MaintenanceWindow.query.get_or_404(schedule_id)
    name = window.name
    log_action("schedule_delete", "schedule", resource_id=window.id, resource_name=name)
    db.session.delete(window)
    db.session.commit()
    flash(f"Schedule '{name}' deleted.", "warning")
    return redirect(url_for("schedules.index"))
