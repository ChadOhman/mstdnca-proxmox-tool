"""Tag-scope helpers for guests that are chosen indirectly.

Per-guest routes (``/guests/<id>/...``) check ``User.may_access_guest``
themselves. Two other paths reach a guest without an id in the URL and used
to skip the check (GHSA-hjq8-j54x-c7rr):

* **App settings** — every app page stores a ``*_guest_id`` Setting chosen
  from a form, and its install/upgrade/preflight routes then run root
  commands on that guest. ``resolve_guest_selection`` validates a submitted
  choice against the current user's tags, and ``require_configured_guest_scope``
  refuses any state-changing request on an app blueprint whose configured
  target guest is outside the user's tags.
* **Presence** — the collaboration hub tells every user which page every
  other user is on, and ``/guests/<id>`` paths reveal guests across the tag
  boundary. ``page_tag_ids`` resolves a page to the guest's tag ids while a
  request context exists, so the hub can redact it per recipient later
  without touching the database.
"""

import re

from flask import flash, redirect, request, url_for
from flask_login import current_user

from models import Guest, GuestService, Setting, db

_PAGE_GUEST_RE = re.compile(r"^/(?:guests|terminal)/(\d+)(?:[/?#]|$)")
_PAGE_SERVICE_RE = re.compile(r"^/services/(\d+)(?:[/?#]|$)")


# ---------------------------------------------------------------------------
# Pages → guests (presence redaction)
# ---------------------------------------------------------------------------

def guest_for_page(page):
    """Return the Guest a page path is about, or None for non-guest pages."""
    if not isinstance(page, str):
        return None
    m = _PAGE_GUEST_RE.match(page)
    if m:
        return db.session.get(Guest, int(m.group(1)))
    m = _PAGE_SERVICE_RE.match(page)
    if m:
        svc = db.session.get(GuestService, int(m.group(1)))
        return svc.guest if svc is not None else None
    return None


def page_tag_ids(page):
    """Tag ids of the guest a page is about.

    Returns None when the page is not guest-specific (visible to everyone) and
    an empty list for an untagged guest (admin-only), mirroring the
    ``guest_tag_ids`` routing key used for activity events.
    """
    guest = guest_for_page(page)
    if guest is None:
        return None
    return [t.id for t in guest.tags]


def page_visible_to(tag_ids, viewer_is_admin, viewer_tag_ids):
    """Whether a page with ``tag_ids`` (from ``page_tag_ids``) may be shown."""
    if tag_ids is None or viewer_is_admin:
        return True
    return bool(set(tag_ids) & set(viewer_tag_ids or ()))


# ---------------------------------------------------------------------------
# App settings → guests
# ---------------------------------------------------------------------------

def resolve_guest_selection(raw, setting_key, label):
    """Validate a ``*_guest_id`` form value for the current user.

    Returns ``(value, error)``. An empty value clears the selection; for a
    tag-scoped user any other value must name an existing guest inside their
    tags. Admin-tier users may select any guest (they pass
    ``may_access_guest`` for every guest), so their input is stored as before.
    """
    raw = (raw or "").strip()
    if not raw or current_user.is_admin:
        return raw, None
    if not raw.isdigit():
        return None, f"{label}: invalid guest id."
    guest = db.session.get(Guest, int(raw))
    if guest is None:
        return None, f"{label}: guest not found."
    if not current_user.may_access_guest(guest):
        return None, f"{label}: you don't have permission to select that guest."
    return raw, None


def configured_guests_out_of_scope(setting_keys):
    """Names of configured target guests the current user may not act on."""
    blocked = []
    for key in setting_keys:
        raw = (Setting.get(key, "") or "").strip()
        if not raw.isdigit():
            continue
        guest = db.session.get(Guest, int(raw))
        if guest is not None and not current_user.may_access_guest(guest):
            blocked.append(guest.name)
    return blocked


def require_configured_guest_scope(setting_keys, redirect_endpoint):
    """``before_request`` body for an app blueprint.

    Every POST on the blueprint acts on the guest(s) named by ``setting_keys``
    (install, upgrade, preflight, configure, save). If any of them is outside
    the current user's tags the request is refused, regardless of the
    ``can_update`` flag that let the user reach the page.
    """
    if request.method != "POST":
        return None
    if not getattr(current_user, "is_authenticated", False):
        return None  # the blueprint's login guard answers this one
    blocked = configured_guests_out_of_scope(setting_keys)
    if not blocked:
        return None
    flash(
        "You don't have permission to act on the configured target guest "
        f"({', '.join(blocked)}).",
        "error",
    )
    return redirect(url_for(redirect_endpoint))
