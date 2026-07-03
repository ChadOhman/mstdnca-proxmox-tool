"""Update history / trends page.

Shows update-apply activity over time, a "chronically behind" ranking of
guests with long-outstanding pending updates, and per-guest apply timelines.
Read access mirrors the dashboard/guests pages: any authenticated user, with
guest data scoped to the tags they can access (no dedicated permission flag
exists for "view guests", so none is introduced here either).
"""

from flask import Blueprint, render_template, request
from flask_login import current_user, login_required

from core.update_trends import DEFAULT_TREND_DAYS, chronically_behind, guest_history, weekly_apply_series
from models import Guest

bp = Blueprint("trends", __name__)


@bp.route("/")
@login_required
def index():
    guests = current_user.accessible_guests()
    guest_ids = [g.id for g in guests]

    guest_filter_id = request.args.get("guest_id", type=int)
    selected_guest = None
    if guest_filter_id is not None:
        selected_guest = next((g for g in guests if g.id == guest_filter_id), None)
        # Fall back to a direct lookup + access check so a valid-but-not-yet-loaded
        # guest still resolves (accessible_guests() already excludes disabled/
        # inaccessible guests, so an unmatched id just means "no access / not found").
        if selected_guest is None:
            candidate = Guest.query.get(guest_filter_id)
            if candidate and (current_user.is_admin or current_user.can_access_guest(candidate)):
                selected_guest = candidate

    series = weekly_apply_series(guest_ids, days=DEFAULT_TREND_DAYS)
    behind = chronically_behind(guests)

    history = []
    if selected_guest is not None:
        history = guest_history(selected_guest.id)

    return render_template(
        "trends.html",
        series=series,
        behind=behind,
        guests=guests,
        selected_guest=selected_guest,
        history=history,
        trend_days=DEFAULT_TREND_DAYS,
    )
