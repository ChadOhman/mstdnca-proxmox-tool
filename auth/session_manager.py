"""Server-side session tracking so users/admins can see and revoke active logins.

Flask-Login stores auth state in a signed cookie; on its own the server keeps no
list of active sessions and cannot revoke one without rotating the secret key.
This module records a ``UserSession`` row per browser login (keyed by an opaque
id whose hash is stored) and installs a ``before_app_request`` hook that:

  * forces logout if the current session's row is missing or revoked, and
  * refreshes ``last_seen_at`` at most once per minute.

The hook is deliberately tolerant of sessions established by auth paths that do
not go through the web login form (Cloudflare Access, local-network bypass) and
never runs for the JWT mobile API (``/api/v1``), which has no cookie session.
"""

import hashlib
import secrets
from datetime import datetime, timezone

from flask import request, session
from flask_login import current_user, logout_user

from models import UserSession, db

# Key under which the opaque session id is stored in the Flask session cookie.
SESSION_KEY = "_usession"

# Throttle window for last_seen_at writes (seconds).
_LAST_SEEN_THROTTLE = 60


def _hash_session_id(raw_id: str) -> str:
    """Return the SHA-256 hex digest of an opaque session id."""
    return hashlib.sha256(raw_id.encode("utf-8")).hexdigest()


def _client_ip() -> str | None:
    """Best-effort real client IP, reusing the trusted-proxy logic in audit."""
    try:
        from auth.local_network import _get_client_ip
        return _get_client_ip()
    except Exception:
        return request.remote_addr


def start_session(user) -> None:
    """Create a UserSession for ``user`` and store its opaque id in the cookie.

    Call this immediately after ``login_user()`` (and after ``session.clear()``,
    which callers do to prevent session fixation).  Does not commit; the caller
    commits alongside its own changes.
    """
    raw_id = secrets.token_urlsafe(32)
    session[SESSION_KEY] = raw_id
    ua = (request.headers.get("User-Agent") or "")[:256]
    record = UserSession(
        user_id=user.id,
        session_id_hash=_hash_session_id(raw_id),
        ip_address=_client_ip(),
        user_agent=ua or None,
    )
    db.session.add(record)


def current_session_record():
    """Return the UserSession row for the current cookie, or None."""
    raw_id = session.get(SESSION_KEY)
    if not raw_id:
        return None
    return UserSession.query.filter_by(session_id_hash=_hash_session_id(raw_id)).first()


def revoke_current_session() -> None:
    """Mark the current cookie's session revoked (used on logout). No commit."""
    record = current_session_record()
    if record and not record.revoked:
        record.revoked = True


def init_session_tracking(app):
    """Install the before_app_request hook that enforces revocation."""

    @app.before_request
    def _enforce_session_state():
        # Never touch the JWT mobile API (no cookie session) or static assets.
        if request.path.startswith(("/api/v1/", "/static/")):
            return
        if not current_user.is_authenticated:
            return

        raw_id = session.get(SESSION_KEY)
        if not raw_id:
            # Authenticated without a tracked web session: this is a session
            # established by Cloudflare Access or local-network bypass (they call
            # session.clear() and login_user() without start_session()).  Leave
            # those alone -- they re-authenticate on every request anyway.
            return

        record = UserSession.query.filter_by(session_id_hash=_hash_session_id(raw_id)).first()
        if record is None or record.revoked:
            # Session was revoked (or the row vanished): force logout.
            logout_user()
            session.pop(SESSION_KEY, None)
            return

        # Throttled last_seen_at refresh (at most once per _LAST_SEEN_THROTTLE s).
        now = datetime.now(timezone.utc)
        last = record.last_seen_at
        if last is not None and last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        if last is None or (now - last).total_seconds() >= _LAST_SEEN_THROTTLE:
            record.last_seen_at = now
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()
