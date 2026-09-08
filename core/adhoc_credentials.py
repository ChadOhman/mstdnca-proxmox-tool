"""Short-lived, single-use server-side store for ad-hoc SSH credentials.

The terminal lets an operator type one-off SSH credentials for a guest that has
no stored Credential row.  Those used to be Fernet-encrypted and parked in the
Flask session cookie, which the WebSocket handler then tried to ``session.pop``
-- but a WebSocket upgrade writes its 101 response straight to the hijacked
socket, so the modified session never reached the browser.  The blob therefore
survived in the cookie and was replayed on every later connection to that guest,
overriding any least-privilege credential assigned in the meantime.

The cookie now carries only an opaque random token; the credentials themselves
live here, scoped to the issuing user and guest, expire after ``TTL_SECONDS``
and can be consumed exactly once.  The store is per-process, which matches the
rest of the terminal/collaboration machinery (single worker or gthread).
"""

import secrets
import threading
import time

# How long an unused ad-hoc credential stays available.
TTL_SECONDS = 300
# Hard cap so a script hammering connect-adhoc cannot grow the store unbounded.
_MAX_ENTRIES = 256

_entries: dict[str, dict] = {}
_lock = threading.Lock()


def _prune_locked(now: float) -> None:
    expired = [tok for tok, e in _entries.items() if e["expires_at"] <= now]
    for tok in expired:
        _entries.pop(tok, None)
    # If still over the cap, drop the oldest entries first.
    while len(_entries) > _MAX_ENTRIES:
        oldest = min(_entries, key=lambda t: _entries[t]["expires_at"])
        _entries.pop(oldest, None)


def store_credentials(user_id, guest_id, username, password) -> str:
    """Park one set of ad-hoc credentials and return its opaque token."""
    token = secrets.token_urlsafe(32)
    now = time.monotonic()
    with _lock:
        _prune_locked(now)
        _entries[token] = {
            "user_id": user_id,
            "guest_id": guest_id,
            "username": username,
            "password": password,
            "expires_at": now + TTL_SECONDS,
        }
    return token


def take_credentials(token, user_id, guest_id):
    """Consume the credentials for ``token``; returns a dict or None.

    Returns None when the token is unknown, already consumed, expired, or was
    issued to a different user or guest.  A token is removed on the first call
    whether or not it matched, so a guess cannot be probed twice.
    """
    if not token:
        return None
    now = time.monotonic()
    with _lock:
        _prune_locked(now)
        entry = _entries.pop(token, None)
    if entry is None:
        return None
    if entry["expires_at"] <= now:
        return None
    if entry["user_id"] != user_id or entry["guest_id"] != guest_id:
        return None
    return {"username": entry["username"], "password": entry["password"]}


def discard(token) -> None:
    """Drop a token without consuming it (best effort)."""
    if not token:
        return
    with _lock:
        _entries.pop(token, None)


def clear() -> None:
    """Empty the store (tests / shutdown)."""
    with _lock:
        _entries.clear()
