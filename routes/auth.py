import collections
import logging
import os
import threading
import time
import zoneinfo
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from flask import Blueprint, current_app, flash, g, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from flask_login.signals import user_loaded_from_cookie
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from auth.audit import log_action
from auth.jwt_auth import credential_epoch
from auth.local_network import _get_client_ip as _client_ip
from auth.session_manager import SESSION_KEY, revoke_current_session, start_session
from models import User, UserSession, db

logger = logging.getLogger(__name__)

bp = Blueprint("auth", __name__)

# ---------------------------------------------------------------------------
# "Remember me" hardening
# ---------------------------------------------------------------------------
# Flask-Login's remember cookie carries nothing but the user id, so on its own
# it restores a login without consulting UserSession and with no way to tell
# whether the credentials it stands for have since been rotated.  Alongside it
# we set a signed, non-forgeable marker recording when the remember cookie was
# issued; a restore is refused when that marker is missing, expired, bound to a
# different account, or predates the user's last password change.  Accepted
# restores get a tracked UserSession row so they show up on /profile and can be
# revoked like any other login.
REMEMBER_MARKER_COOKIE = "remember_ctx"
_REMEMBER_MARKER_SALT = "mstdnca-remember-marker"

# Endpoints reachable while an account still owes a forced password change.
_FORCED_CHANGE_EXEMPT = frozenset({
    "static", "auth.login", "auth.logout", "auth.change_password", "health_check",
})


def _remember_serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt=_REMEMBER_MARKER_SALT)


def _remember_duration():
    return current_app.config.get("REMEMBER_COOKIE_DURATION") or timedelta(days=14)


def _set_remember_marker(response, user):
    """Attach the signed marker that accompanies the remember cookie.

    It records which account the remember cookie belongs to and which password
    generation it was issued under; itsdangerous supplies the signature and the
    issued-at timestamp that bounds its lifetime.
    """
    duration = _remember_duration()
    response.set_cookie(
        REMEMBER_MARKER_COOKIE,
        _remember_serializer().dumps({"uid": user.id, "pwd": credential_epoch(user)}),
        max_age=int(duration.total_seconds()),
        httponly=True,
        secure=bool(current_app.config.get("REMEMBER_COOKIE_SECURE", True)),
        samesite=current_app.config.get("REMEMBER_COOKIE_SAMESITE", "Lax"),
    )


def _remember_marker_payload():
    """Return this request's verified remember-marker payload, or None."""
    raw = request.cookies.get(REMEMBER_MARKER_COOKIE)
    if not raw:
        return None
    try:
        payload = _remember_serializer().loads(
            raw, max_age=int(_remember_duration().total_seconds()),
        )
    except (BadSignature, SignatureExpired):
        return None
    return payload if isinstance(payload, dict) else None


def remember_restore_refusal(user):
    """Return a reason string when a remember-cookie restore must be refused."""
    if user is None or not user.is_active:
        return "inactive"
    payload = _remember_marker_payload()
    if payload is None or payload.get("uid") != user.id:
        return "missing_marker"
    if payload.get("pwd") != credential_epoch(user):
        return "credentials_rotated"
    return None


def _on_user_loaded_from_cookie(sender, user=None, **extra):
    """Vet and track logins restored from the "remember me" cookie.

    Flask-Login has already decided to accept the cookie by the time this runs
    and the signal cannot veto it, so a refusal is recorded on ``g`` and acted
    on by ``_enforce_remember_and_password_change`` below.
    """
    g._remember_restore_rejected = None
    if user is None:
        return
    # Publish the user early so log_action() does not re-enter the user loader.
    g._login_user = user

    reason = remember_restore_refusal(user)
    if reason:
        g._remember_restore_rejected = reason
        return

    try:
        start_session(user)
        user.last_login_at = datetime.now(timezone.utc)
        log_action("login_remembered", "user", resource_id=user.id, resource_name=user.username)
        db.session.commit()
    except Exception:
        db.session.rollback()
        logger.warning("Could not record a session for a remembered login", exc_info=True)


user_loaded_from_cookie.connect(_on_user_loaded_from_cookie)


@bp.before_app_request
def _enforce_remember_and_password_change():
    """Reject vetoed remember-cookie restores and force pending password changes."""
    if request.path.startswith(("/static/", "/api/v1/")):
        return
    if not current_user.is_authenticated:
        return

    if getattr(g, "_remember_restore_rejected", None):
        logger.info("Refused a remember-cookie login for user %s: %s",
                    current_user.id, g._remember_restore_rejected)
        logout_user()  # also clears the remember cookie on this response
        session.pop(SESSION_KEY, None)
        response = redirect(url_for("auth.login"))
        response.delete_cookie(REMEMBER_MARKER_COOKIE)
        flash("Your saved login is no longer valid. Please sign in again.", "warning")
        return response

    if getattr(current_user, "must_change_password", False) and request.endpoint not in _FORCED_CHANGE_EXEMPT:
        flash("You must change your password before continuing.", "warning")
        return redirect(url_for("auth.change_password"))


# ---------------------------------------------------------------------------
# Login rate-limiting (in-process; works with single gunicorn worker / gthread)
# ---------------------------------------------------------------------------
_FAIL_WINDOW = 300   # 5-minute sliding window
_FAIL_LIMIT = 10     # failed attempts before lockout
_FAIL_MAX_KEYS = 4096  # hard cap so a flood of distinct IPs cannot grow the dict

_failed_attempts: dict = collections.defaultdict(list)
_failed_lock = threading.Lock()


def _prune_failed_attempts(cutoff: float) -> None:
    """Drop buckets with no attempt newer than ``cutoff``. Caller holds the lock.

    Without this the dict only ever grows: every distinct source IP that fails a
    login leaves a permanent (eventually empty) entry behind.
    """
    for key in [k for k, v in _failed_attempts.items() if not v or v[-1] <= cutoff]:
        del _failed_attempts[key]
    if len(_failed_attempts) > _FAIL_MAX_KEYS:
        # Still over the cap after pruning: evict the least recently active keys.
        stale = sorted(_failed_attempts, key=lambda k: _failed_attempts[k][-1])
        for key in stale[: len(_failed_attempts) - _FAIL_MAX_KEYS]:
            del _failed_attempts[key]


def _check_rate_limit(ip: str) -> bool:
    """Return True if this IP is currently locked out."""
    cutoff = time.time() - _FAIL_WINDOW
    with _failed_lock:
        _prune_failed_attempts(cutoff)
        recent = [t for t in _failed_attempts.get(ip, []) if t > cutoff]
        if recent:
            _failed_attempts[ip] = recent
        else:
            _failed_attempts.pop(ip, None)
        return len(recent) >= _FAIL_LIMIT


def _record_failed_login(ip: str) -> None:
    with _failed_lock:
        _failed_attempts[ip].append(time.time())
        _prune_failed_attempts(time.time() - _FAIL_WINDOW)


def _get_client_ip() -> str:
    """Return the client IP used as the rate-limit key.

    Delegates to the single app-wide implementation in ``auth.local_network`` so
    the limiter, the audit log and the local-network bypass can never disagree
    about who the caller is.  Forwarded headers are only ever honoured when
    ``TRUSTED_PROXY_COUNT`` is configured, so they cannot be used to rotate the
    rate-limit key.
    """
    return _client_ip() or "unknown"


def _is_safe_next_url(target):
    """Allow redirects only to local paths."""
    if not target:
        return False
    parsed = urlparse(target)
    return parsed.scheme == "" and parsed.netloc == "" and target.startswith("/")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        ip = _get_client_ip()
        if _check_rate_limit(ip):
            flash("Too many failed login attempts. Please try again later.", "error")
            return render_template("login.html")

        # Usernames are stored lower-cased (see security.add_user), so
        # normalise here too or "Admin" can never log in as "admin".
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password) and user.is_active:
            remember = "remember" in request.form
            # Regenerate session to prevent session fixation attacks
            session.clear()
            login_user(user, remember=remember)
            user.last_login_at = datetime.now(timezone.utc)
            start_session(user)
            log_action("login", "user", resource_id=user.id, resource_name=user.username)
            db.session.commit()
            next_page = request.args.get("next")
            if user.must_change_password:
                target = url_for("auth.change_password")
            elif _is_safe_next_url(next_page):
                target = next_page
            else:
                target = url_for("dashboard.index")
            response = redirect(target)
            if remember:
                _set_remember_marker(response, user)
            return response

        _record_failed_login(ip)
        log_action("login_failed", "user",
                   resource_id=user.id if user else None,
                   resource_name=username,
                   details={"reason": "inactive" if user and not user.is_active else "bad_credentials"})
        db.session.commit()
        flash("Invalid username or password.", "error")

    return render_template("login.html")


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    log_action("logout", "user", resource_id=current_user.id, resource_name=current_user.username)
    revoke_current_session()
    db.session.commit()
    is_cf_user = current_user.created_via == "cloudflare"
    logout_user()
    if is_cf_user:
        from auth.cloudflare_access import _is_valid_team_domain
        from models import Setting
        team_domain = Setting.get("cf_access_team_domain", "")
        # Strict match (not .endswith()) -- a suffix check would accept
        # "evil.com#.cloudflareaccess.com" and turn this into an open redirect.
        if _is_valid_team_domain(team_domain):
            return redirect(f"https://{team_domain}/cdn-cgi/access/logout")
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


@bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if current_user.created_via == "cloudflare":
        flash("Password management is not available for Cloudflare-authenticated accounts.", "error")
        return redirect(url_for("auth.profile"))

    if request.method == "POST":
        current_pw = request.form.get("current_password", "")
        new_pw = request.form.get("new_password", "")
        confirm_pw = request.form.get("confirm_password", "")

        if not current_user.check_password(current_pw):
            flash("Current password is incorrect.", "error")
        elif new_pw != confirm_pw:
            flash("New passwords do not match.", "error")
        elif len(new_pw) < 8:
            flash("New password must be at least 8 characters.", "error")
        else:
            was_forced = bool(current_user.must_change_password)
            # set_password() also stamps tokens_valid_after, which invalidates
            # every JWT and every remember cookie issued before this moment.
            current_user.set_password(new_pw)
            log_action("password_change", "user", resource_id=current_user.id, resource_name=current_user.username)
            db.session.commit()
            if was_forced:
                _remove_initial_admin_password_file()
            flash("Password changed. Saved logins and API tokens issued earlier have been invalidated.",
                  "success")
            response = redirect(url_for("dashboard.index"))
            # Keep this browser's "remember me" working: it just proved the old
            # password, so re-stamp its marker past the new invalidation point.
            if request.cookies.get(REMEMBER_MARKER_COOKIE):
                _set_remember_marker(response, current_user)
            return response

    return render_template("change_password.html",
                           must_change=bool(current_user.must_change_password))


def _remove_initial_admin_password_file():
    """Delete the bootstrap password file once the admin has rotated it."""
    from app import initial_admin_password_path
    try:
        os.unlink(initial_admin_password_path())
    except FileNotFoundError:
        pass
    except OSError:
        logger.warning("Could not remove the initial admin password file", exc_info=True)


@bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        tz = request.form.get("timezone", "").strip()
        if tz and tz not in zoneinfo.available_timezones():
            flash("Invalid timezone.", "error")
            return redirect(url_for("auth.profile"))
        current_user.timezone = tz or None
        db.session.commit()
        flash("Profile saved.", "success")
        return redirect(url_for("auth.profile"))

    from auth.session_manager import current_session_record

    current_record = current_session_record()
    current_session_id = current_record.id if current_record else None
    sessions = (
        UserSession.query
        .filter_by(user_id=current_user.id, revoked=False)
        .order_by(UserSession.last_seen_at.desc())
        .all()
    )
    return render_template(
        "profile.html",
        sessions=sessions,
        current_session_id=current_session_id,
    )


@bp.route("/sessions/<int:session_pk>/revoke", methods=["POST"])
@login_required
def revoke_session(session_pk):
    """Revoke one of the current user's own sessions."""
    record = UserSession.query.get_or_404(session_pk)
    if record.user_id != current_user.id:
        flash("You can only revoke your own sessions.", "error")
        return redirect(url_for("auth.profile"))

    if not record.revoked:
        record.revoked = True
        log_action("session_revoke", "user_session", resource_id=record.id,
                   resource_name=current_user.username)
        db.session.commit()
        flash("Session revoked.", "success")
    return redirect(url_for("auth.profile"))


@bp.route("/sessions/revoke-others", methods=["POST"])
@login_required
def revoke_other_sessions():
    """Revoke all of the current user's sessions except the current one."""
    from auth.session_manager import current_session_record

    current_record = current_session_record()
    current_id = current_record.id if current_record else None

    others = UserSession.query.filter_by(user_id=current_user.id, revoked=False)
    if current_id is not None:
        others = others.filter(UserSession.id != current_id)
    count = 0
    for record in others.all():
        record.revoked = True
        count += 1
    if count:
        log_action("session_revoke_others", "user_session",
                   resource_id=current_user.id, resource_name=current_user.username,
                   details={"count": count})
        db.session.commit()
    flash(f"Revoked {count} other session(s)." if count else "No other sessions to revoke.", "success")
    return redirect(url_for("auth.profile"))
