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
from flask import current_app, jsonify, request
from flask_login import login_user

from models import User, db

logger = logging.getLogger(__name__)

ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
REFRESH_TOKEN_EXPIRES = timedelta(days=30)

# ---------------------------------------------------------------------------
# Rate limiting for API login/refresh (in-process; single gunicorn worker)
# ---------------------------------------------------------------------------
_API_FAIL_WINDOW = 300  # 5-minute sliding window
_API_FAIL_LIMIT = 5     # stricter than web login (10)

_api_failed_attempts: dict = collections.defaultdict(list)
_api_failed_lock = threading.Lock()


def check_api_rate_limit(ip: str) -> bool:
    """Return True if this IP is currently locked out."""
    cutoff = time.time() - _API_FAIL_WINDOW
    with _api_failed_lock:
        _api_failed_attempts[ip] = [t for t in _api_failed_attempts[ip] if t > cutoff]
        return len(_api_failed_attempts[ip]) >= _API_FAIL_LIMIT


def record_api_failed_login(ip: str) -> None:
    with _api_failed_lock:
        _api_failed_attempts[ip].append(time.time())


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
        options={"require": ["sub", "type", "exp"]},
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

    On success, sets current_user via login_user() so that existing permission
    checks and audit logging work unchanged.
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

        # Set current_user for the request so existing permission checks work
        login_user(user, remember=False)

        return f(*args, **kwargs)
    return decorated
