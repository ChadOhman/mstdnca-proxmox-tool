from flask import has_request_context
from flask_login import current_user

from auth.local_network import _get_client_ip
from models import AuditLog, db

# Username recorded on the collaboration feed for actions taken outside a
# request context (scheduler jobs, CLI, maintenance tasks).
BACKGROUND_ACTOR = "system"


def log_action(action, resource_type, resource_id=None, resource_name=None, details=None, actor=None):
    """Add an AuditLog entry to the current db.session.

    Call before db.session.commit() so the log entry is committed atomically
    with the main change.  Also broadcasts the action to the real-time
    collaboration hub so connected users see it instantly.

    Safe to call outside a request context (e.g. from scheduler jobs, which run
    under an app context only): ``user_id`` and ``ip_address`` are then left
    NULL and the broadcast is attributed to ``actor`` (default ``"system"``).
    """
    in_request = has_request_context()
    user = current_user if in_request and current_user.is_authenticated else None

    db.session.add(AuditLog(
        user_id=user.id if user else None,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_name=resource_name,
        details=details,
        ip_address=_get_client_ip() if in_request else None,
    ))

    if user:
        username = user.display_name or user.username
    elif in_request:
        username = "anonymous"
    else:
        username = actor or BACKGROUND_ACTOR

    # Broadcast to collaboration hub (best-effort — never breaks the audit write)
    try:
        import datetime as _dt

        from core.collaboration import collab_hub
        collab_hub.broadcast({
            "type": "activity",
            "action": action,
            "resource_type": resource_type,
            "resource_name": resource_name or "",
            "username": username,
            "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        })
    except Exception:
        pass
