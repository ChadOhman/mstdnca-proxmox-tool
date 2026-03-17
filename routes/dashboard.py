from flask import Blueprint, current_app, render_template, request, session
from flask_login import current_user, login_required

from core.dashboard_stats import get_dashboard_stats
from models import ProxmoxHost, Setting, Tag

bp = Blueprint("dashboard", __name__)


@bp.route("/")
@login_required
def index():
    # Tag filter (shared with guests/terminal pages via session)
    tag_filter = request.args.get("tag", None)
    user_tags = current_user.allowed_tags
    user_tag_names = [t.name for t in user_tags]

    if tag_filter is not None:
        session["guest_tag_filter"] = tag_filter
    elif "guest_tag_filter" in session:
        tag_filter = session["guest_tag_filter"]
    elif user_tag_names:
        tag_filter = "__my_tags__"
    else:
        tag_filter = ""

    result = get_dashboard_stats(current_user, tag_filter=tag_filter)
    stats = result["stats"]
    guests_with_updates = result["guests_with_updates"]
    reboot_required = result["guests_needing_reboot"]

    hosts_for_updates = (
        ProxmoxHost.query.order_by(ProxmoxHost.name).all()
        if (current_user.can_view_hosts or current_user.can_manage_hosts)
        else []
    )

    tags = Tag.query.order_by(Tag.name).all()

    # Check for app update availability (for admins)
    app_update_available = None
    if current_user.is_admin:
        latest_version = Setting.get("latest_app_version")
        current_version = current_app.config.get("APP_VERSION", "unknown")
        is_stale = current_app.config.get("APP_VERSION_STALE", False)
        if latest_version and latest_version != current_version:
            app_update_available = latest_version
        elif is_stale and latest_version:
            app_update_available = latest_version

    return render_template(
        "dashboard.html",
        stats=stats,
        guests_with_updates=guests_with_updates,
        guests_needing_reboot=reboot_required,
        app_update_available=app_update_available,
        tags=tags,
        current_tag=tag_filter,
        user_tag_names=user_tag_names,
        hosts_for_updates=hosts_for_updates,
    )
