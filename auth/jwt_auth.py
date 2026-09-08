"""JWT authentication for the mobile API.

Issues short-lived access tokens (15 min) and long-lived refresh tokens (30 days).
Tokens are signed with HS256 using the Flask SECRET_KEY.
"""

import collections
import logging
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import current_app, g, jsonify, request

from models import User, db

logger = logging.getLogger(__name__)

ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
REFRESH_TOKEN_EXPIRES = timedelta(days=30)

# ---------------------------------------------------------------------------
# Rate limiting for API login/refresh (in-process; single gunicorn worker)
# ---------------------------------------------------------------------------
_API_FAIL_WINDOW = 300  # 5-minute sliding window
_API_FAIL_LIMIT = 5     # stricter than web login (10)
_API_FAIL_MAX_KEYS = 4096  # hard cap so a flood of distinct IPs cannot grow the dict

_api_failed_attempts: dict = collections.defaultdict(list)
_api_failed_lock = threading.Lock()


def _prune_api_failed_attempts(cutoff: float) -> None:
    """Drop buckets with no attempt newer than ``cutoff``. Caller holds the lock.

    Without this the dict only ever grows: every distinct source IP that fails an
    API login leaves a permanent (eventually empty) entry behind.
    """
    for key in [k for k, v in _api_failed_attempts.items() if not v or v[-1] <= cutoff]:
        del _api_failed_attempts[key]
    if len(_api_failed_attempts) > _API_FAIL_MAX_KEYS:
        # Still over the cap after pruning: evict the least recently active keys.
        stale = sorted(_api_failed_attempts, key=lambda k: _api_failed_attempts[k][-1])
        for key in stale[: len(_api_failed_attempts) - _API_FAIL_MAX_KEYS]:
            del _api_failed_attempts[key]


def check_api_rate_limit(ip: str) -> bool:
    """Return True if this IP is currently locked out."""
    cutoff = time.time() - _API_FAIL_WINDOW
    with _api_failed_lock:
        _prune_api_failed_attempts(cutoff)
        recent = [t for t in _api_failed_attempts.get(ip, []) if t > cutoff]
        if recent:
            _api_failed_attempts[ip] = recent
        else:
            _api_failed_attempts.pop(ip, None)
        return len(recent) >= _API_FAIL_LIMIT


def record_api_failed_login(ip: str) -> None:
    with _api_failed_lock:
        _api_failed_attempts[ip].append(time.time())
        _prune_api_failed_attempts(time.time() - _API_FAIL_WINDOW)


# ---------------------------------------------------------------------------
# Password-change invalidation
# ---------------------------------------------------------------------------

def tokens_valid_after(user):
    """Return the user's ``tokens_valid_after`` as an aware UTC datetime, or None.

    SQLite hands back naive datetimes; everything stored in this column is UTC.
    """
    value = getattr(user, "tokens_valid_after", None)
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value


def credential_epoch(user):
    """Integer stamp of the user's last password change, or None if never.

    Tokens and "remember me" markers carry the epoch that was current when they
    were minted.  Comparing epochs for equality avoids the one-second ambiguity
    an ``iat``-vs-timestamp comparison would have (a JWT ``iat`` has only second
    resolution, so a token minted in the same second as a password change could
    not otherwise be told apart from one minted just before it).
    """
    floor = tokens_valid_after(user)
    if floor is None:
        return None
    return int(floor.timestamp())


def token_predates_password_change(user, payload) -> bool:
    """True when this token was issued before the user's last password change."""
    epoch = credential_epoch(user)
    if epoch is None:
        # The account has never changed its password since the column existed:
        # there is nothing to invalidate against.
        return False
    return payload.get("pwd") != epoch


# ---------------------------------------------------------------------------
# Token creation
# ---------------------------------------------------------------------------

def create_access_token(user):
    """Create a short-lived access token for the given user."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "role": user.role,
        "type": "access",
        "pwd": credential_epoch(user),
        "iat": now,
        "exp": now + ACCESS_TOKEN_EXPIRES,
    }
    return jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")


def create_refresh_token(user):
    """Create a long-lived refresh token with a unique JTI for revocation."""
    now = datetime.now(timezone.utc)
    jti = str(uuid.uuid4())
    payload = {
        "sub": str(user.id),
        "type": "refresh",
        "jti": jti,
        "pwd": credential_epoch(user),
        "iat": now,
        "exp": now + REFRESH_TOKEN_EXPIRES,
    }
    token = jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")
    return token, jti


# ---------------------------------------------------------------------------
# Token validation
# ---------------------------------------------------------------------------

def decode_token(token_str):
    """Decode and validate a JWT token. Returns the payload dict.

    Raises jwt.ExpiredSignatureError or jwt.InvalidTokenError on failure.
    """
    return jwt.decode(
        token_str,
        current_app.config["SECRET_KEY"],
        algorithms=["HS256"],
        options={"require": ["sub", "type", "exp", "iat"]},
    )


# ---------------------------------------------------------------------------
# Token revocation (database-backed)
# ---------------------------------------------------------------------------

def revoke_token(jti, expires_at):
    """Add a token's JTI to the revocation table."""
    from models import RevokedToken
    if not RevokedToken.query.filter_by(jti=jti).first():
        db.session.add(RevokedToken(jti=jti, expires_at=expires_at))
        db.session.commit()


def is_token_revoked(jti):
    """Check whether a token has been revoked."""
    from models import RevokedToken
    return RevokedToken.query.filter_by(jti=jti).first() is not None


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------

def jwt_required(f):
    """Decorator that requires a valid access token in the Authorization header.

    On success the authenticated user is published for the duration of the
    request through Flask-Login's request-scoped slot (``g._login_user``), which
    is what ``current_user`` resolves to, so existing permission checks and
    audit logging work unchanged.  It deliberately does NOT call ``login_user``:
    that wrote ``_user_id`` into the Flask session and made every bearer-token
    request emit ``Set-Cookie: session=...``, upgrading a 15-minute token into a
    durable, untracked browser session that outlived it.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": {"code": "UNAUTHORIZED", "message": "Missing or invalid Authorization header"}}), 401

        token_str = auth_header[7:]
        try:
            payload = decode_token(token_str)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": {"code": "TOKEN_EXPIRED", "message": "Access token has expired"}}), 401
        except jwt.InvalidTokenError as e:
            logger.debug("JWT validation failed: %s", e)
            return jsonify({"error": {"code": "INVALID_TOKEN", "message": "Invalid token"}}), 401

        if payload.get("type") != "access":
            return jsonify({"error": {"code": "INVALID_TOKEN", "message": "Not an access token"}}), 401

        user = db.session.get(User, int(payload["sub"]))
        if not user or not user.is_active:
            return jsonify({"error": {"code": "UNAUTHORIZED", "message": "User not found or inactive"}}), 401

        if token_predates_password_change(user, payload):
            return jsonify({"error": {"code": "TOKEN_REVOKED",
                                      "message": "Token was issued before the last password change"}}), 401

        # Publish the user for this request only -- no session, no cookie.
        g._login_user = user

        return f(*args, **kwargs)
    return decorated
