"""Dispatch push notifications to registered mobile webhook endpoints.

Called from the scanner after detecting alertable state changes (new security
updates, service failures, reboot requirements).  Failures are logged but
never block the scan.
"""

import json
import logging

import requests as http_requests

from core.url_safety import validate_webhook_url
from models import PushWebhook

logger = logging.getLogger(__name__)

_TIMEOUT = 5  # seconds

# Alias mapping: service_failed also matches subscriptions to service_down
_EVENT_ALIASES = {"service_failed": "service_down"}


def dispatch_push_alerts(guest, event_type, details=None):
    """Send push notifications to all users who registered for *event_type*
    and have tag-based access to *guest*.

    Args:
        guest: The Guest model instance that triggered the alert.
        event_type: One of PushWebhook.VALID_EVENTS.
        details: Optional dict with extra context (e.g. service name).
    """
    if event_type not in PushWebhook.VALID_EVENTS:
        return

    webhooks = PushWebhook.query.all()
    if not webhooks:
        return

    guest_tag_ids = {t.id for t in guest.tags}

    for wh in webhooks:
        # Check the webhook is subscribed to this event type
        try:
            subscribed_events = json.loads(wh.events)
        except (json.JSONDecodeError, TypeError):
            continue
        alias = _EVENT_ALIASES.get(event_type)
        if event_type not in subscribed_events and (alias is None or alias not in subscribed_events):
            continue

        # Check tag-based access: user must have access to this guest
        user = wh.user
        if not user or not user.is_active:
            continue
        if not user.is_super_admin:
            if not guest.tags:
                continue  # untagged guests are admin-only
            user_tag_ids = {t.id for t in user.allowed_tags}
            if not (user_tag_ids & guest_tag_ids):
                continue

        # Re-validate the stored URL right before dispatch: blocks any webhook
        # persisted before this guard existed and mitigates DNS rebinding
        # between registration and now (SSRF).
        ok, reason = validate_webhook_url(wh.url)
        if not ok:
            logger.warning(
                "Skipping push webhook %d for user %s: unsafe url (%s)",
                wh.id, user.username, reason,
            )
            continue

        payload = {
            "event": event_type,
            "guest_id": guest.id,
            "guest_name": guest.name,
            "guest_type": guest.guest_type,
            "details": details or {},
            "device_token": wh.device_token,
        }

        try:
            resp = http_requests.post(
                wh.url,
                json=payload,
                timeout=_TIMEOUT,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code >= 400:
                logger.warning(
                    "Push webhook %d returned %d for user %s",
                    wh.id, resp.status_code, user.username,
                )
        except http_requests.RequestException as e:
            logger.warning("Push webhook %d failed for user %s: %s", wh.id, user.username, e)
