"""Admin-only Mastodon monthly highlights: top posts + donate prompt as paste-ready email HTML."""

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from auth.audit import log_action
from core.mastodon_active_users import DEFAULT_DAYS, MAX_DAYS, MIN_DAYS
from core.mastodon_highlights import (
    DEFAULT_COUNT,
    DEFAULT_PER_AUTHOR,
    MAX_COUNT,
    MIN_COUNT,
    clamp_count,
    clamp_per_author,
    default_month,
    fetch_highlights,
    is_safe_link,
    month_label,
    parse_month,
    text_to_html,
)
from models import Setting, db

bp = Blueprint("highlights", __name__)

DEFAULT_DONATE_HEADING = "Help keep our community running"
DEFAULT_DONATE_MESSAGE = (
    "This community is run by volunteers and paid entirely by members like you. "
    "If the community made your month a little better, please consider chipping in."
)
DEFAULT_DONATE_BUTTON = "Donate"
MAX_TEXT = 2000


@bp.before_request
@login_required
def _require_admin():
    # Same tier as the active-user mailing list this email is sent to.
    if not current_user.is_admin:
        flash("Administrator access is required to build the monthly highlights email.", "error")
        return redirect(url_for("dashboard.index"))


def _saved_form():
    return {
        "month": default_month(),
        "count": DEFAULT_COUNT,
        "per_author": DEFAULT_PER_AUTHOR,
        "intro": "",
        "donate_url": Setting.get("mastodon_highlights_donate_url", ""),
        "donate_heading": Setting.get("mastodon_highlights_donate_heading", DEFAULT_DONATE_HEADING),
        "donate_message": Setting.get("mastodon_highlights_donate_message", DEFAULT_DONATE_MESSAGE),
        "donate_button": Setting.get("mastodon_highlights_donate_button", DEFAULT_DONATE_BUTTON),
        "unsubscribe": True,
    }


def _render(form, **extra):
    return render_template("highlights.html", form=form, min_count=MIN_COUNT, max_count=MAX_COUNT,
                           recipient_days=DEFAULT_DAYS, recipient_min_days=MIN_DAYS, recipient_max_days=MAX_DAYS,
                           **extra)


@bp.route("/", methods=["GET"])
def index():
    return _render(_saved_form(), posts=None)


@bp.route("/build", methods=["POST"])
def build():
    def text(name, default=""):
        return (request.form.get(name) or default).strip()[:MAX_TEXT]

    form = {
        "month": text("month"),
        "count": clamp_count(request.form.get("count")),
        "per_author": clamp_per_author(request.form.get("per_author")),
        "intro": text("intro"),
        "donate_url": text("donate_url"),
        "donate_heading": text("donate_heading", DEFAULT_DONATE_HEADING),
        "donate_message": text("donate_message", DEFAULT_DONATE_MESSAGE),
        "donate_button": text("donate_button", DEFAULT_DONATE_BUTTON),
        "unsubscribe": request.form.get("unsubscribe") == "on",
    }
    if not parse_month(form["month"]):
        flash("Pick a month in YYYY-MM format.", "error")
        return _render(form, posts=None)
    if form["donate_url"] and not is_safe_link(form["donate_url"]):
        flash("The donate link must be a full http:// or https:// URL.", "error")
        return _render(form, posts=None)

    # The donate block rarely changes month to month, so remember it.
    for key in ("donate_url", "donate_heading", "donate_message", "donate_button"):
        Setting.set(f"mastodon_highlights_{key}", form[key])

    posts, err = fetch_highlights(form["month"], form["count"], form["per_author"])
    if err:
        flash(err, "error")
        return _render(form, posts=None)

    label = month_label(form["month"])
    host = next((p["host"] for p in posts if p["host"]), "")
    email = {
        "label": label,
        "host": host,
        "intro": form["intro"] or f"Here are the posts the community loved most in {label}.",
    }
    blocks = [
        render_template("partials/highlights_email_post.html", post=post, text_html=text_to_html(post["text"]))
        for post in posts
    ]
    fragments = {
        "wrapper": render_template("partials/highlights_email_wrapper.html"),
        "header": render_template("partials/highlights_email_header.html", email=email),
        "footer": render_template("partials/highlights_email_footer.html", email=email, form=form),
    }

    log_action("mastodon_highlights_build", "mastodon_highlights", resource_name=label,
               details={"month": form["month"], "candidates": len(posts)})
    db.session.commit()
    return _render(form, posts=list(zip(posts, blocks, strict=True)), fragments=fragments, email=email)
