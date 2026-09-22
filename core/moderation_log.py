"""Shared definition of "a moderation-related AuditLog row".

Used by both the Moderation page's activity log (``routes/moderation.py``)
and the scheduled audit-log purge (``core/scheduler.py``) so the two never
drift apart -- a row that shows up on the Activity log tab is exactly a row
that gets the longer, moderation-specific retention window.

Kept dependency-free of ``routes.moderation`` (imports only ``models`` and
``sqlalchemy``) so it is safe to import from the scheduler.
"""

from sqlalchemy import or_

# Every moderation/Mastodon action written via auth.audit.log_action() starts
# with one of these prefixes (see routes/moderation.py, core/moderation.py,
# core/moderation_watch.py). Kept as the primary match; resource_type below is
# a backstop for any row that doesn't follow the naming convention.
MODERATION_ACTION_PREFIXES = ("mastodon_", "moderation_")

# resource_type values written by the moderation surface. "peertube_user" is
# included for forward-compatibility (a future per-user PeerTube ban audit
# entry) even though no current call site uses it.
MODERATION_RESOURCE_TYPES = frozenset({
    "mastodon_account",
    "mastodon_report",
    "mastodon_domain_block",
    "moderation",
    "peertube_user",
})

# kind -> action LIKE pattern(s) (SQL LIKE wildcards: % and _) used to narrow
# the activity log to one category. Unknown kinds are ignored by the caller.
KIND_FILTERS = {
    "accounts": ("mastodon_account_%",),
    "reports": ("mastodon_report%",),
    "watch": ("mastodon_watch%", "mastodon_alert%", "mastodon_welcome%"),
    "domains": ("mastodon_domain%",),
    "peertube": ("moderation_check", "peertube%"),
    "config": ("%_config_save",),
}


def moderation_log_filter():
    """Return the SQLAlchemy criterion selecting moderation-related AuditLog rows.

    A row matches when its action starts with one of ``MODERATION_ACTION_PREFIXES``
    or its resource_type is one of ``MODERATION_RESOURCE_TYPES``.
    """
    from models import AuditLog

    return or_(
        *(AuditLog.action.like(f"{prefix}%") for prefix in MODERATION_ACTION_PREFIXES),
        AuditLog.resource_type.in_(MODERATION_RESOURCE_TYPES),
    )
