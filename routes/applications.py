from flask import Blueprint, flash, redirect, render_template, url_for
from flask_login import current_user, login_required

from models import Setting

bp = Blueprint("applications", __name__)


@bp.before_request
@login_required
def _require_login():
    if not current_user.can_update:
        flash("Permission denied.", "error")
        return redirect(url_for("dashboard.index"))


@bp.route("/")
def index():
    apps = {
        "mastodon": {
            "auto_upgrade": Setting.get("mastodon_auto_upgrade", "false") == "true",
            "update_available": Setting.get("mastodon_update_available", "false") == "true",
            "current_version": Setting.get("mastodon_current_version", ""),
            "latest_version": Setting.get("mastodon_latest_version", ""),
        },
        "ghost": {
            "auto_upgrade": Setting.get("ghost_auto_upgrade", "false") == "true",
            "update_available": Setting.get("ghost_update_available", "false") == "true",
            "current_version": Setting.get("ghost_current_version", ""),
            "latest_version": Setting.get("ghost_latest_version", ""),
        },
        "peertube": {
            "auto_upgrade": Setting.get("peertube_auto_upgrade", "false") == "true",
            "update_available": Setting.get("peertube_update_available", "false") == "true",
            "current_version": Setting.get("peertube_current_version", ""),
            "latest_version": Setting.get("peertube_latest_version", ""),
            "installed": Setting.get("peertube_installed", "false") == "true",
        },
        "elk": {
            "auto_upgrade": Setting.get("elk_auto_upgrade", "false") == "true",
            "update_available": Setting.get("elk_update_available", "false") == "true",
            "current_version": Setting.get("elk_current_version", ""),
            "latest_version": Setting.get("elk_latest_version", ""),
            "installed": Setting.get("elk_installed", "false") == "true",
        },
        "jitsi": {
            "auto_upgrade": Setting.get("jitsi_auto_upgrade", "false") == "true",
            "update_available": Setting.get("jitsi_update_available", "false") == "true",
            "current_version": Setting.get("jitsi_current_version", ""),
            "latest_version": Setting.get("jitsi_latest_version", ""),
            "installed": Setting.get("jitsi_installed", "false") == "true",
        },
        "jibri": {
            "installed": Setting.get("jibri_installed", "false") == "true",
            "enabled": Setting.get("jibri_enabled", "false") == "true",
        },
        "prometheus": {
            "auto_upgrade": Setting.get("prometheus_auto_upgrade", "false") == "true",
            "update_available": Setting.get("prometheus_update_available", "false") == "true",
            "current_version": Setting.get("prometheus_current_version", ""),
            "latest_version": Setting.get("prometheus_latest_version", ""),
            "installed": Setting.get("prometheus_installed", "false") == "true",
        },
        "unpoller": {
            "auto_upgrade": Setting.get("unpoller_auto_upgrade", "false") == "true",
            "update_available": Setting.get("unpoller_update_available", "false") == "true",
            "current_version": Setting.get("unpoller_current_version", ""),
            "latest_version": Setting.get("unpoller_latest_version", ""),
            "installed": Setting.get("unpoller_installed", "false") == "true",
        },
    }
    return render_template("applications.html", apps=apps)
