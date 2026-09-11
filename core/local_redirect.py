"""Open-redirect guard for redirect targets taken from the request.

``request.referrer`` and ``?next=`` are attacker-controlled.  Instead of
string-checking them and then redirecting to the raw value, resolve the path
against the app's own URL map and rebuild the target with ``url_for``.  The
redirect can then only ever point at a route this app serves, on this host,
and the value handed to ``redirect()`` is one we generated rather than one
the client supplied.
"""

from urllib.parse import parse_qsl, unquote, urlsplit

from flask import current_app, redirect, request, url_for
from werkzeug.exceptions import HTTPException
from werkzeug.routing import BuildError, RequestRedirect

# url_for() keyword arguments that must never be populated from a query string.
_RESERVED_URL_FOR_KWARGS = frozenset({"_external", "_anchor", "_method", "_scheme"})


def _match_route(path):
    """Return ``(endpoint, values)`` for *path*, or ``None`` if no GET route serves it.

    Follows at most one of werkzeug's canonical-slash redirects (``/hosts`` ->
    ``/hosts/``) so the caller still ends up building the URL via ``url_for``.
    """
    adapter = current_app.url_map.bind_to_environ(request.environ)
    for _ in range(2):
        try:
            return adapter.match(path_info=path, method="GET")
        except RequestRedirect as canonical:
            path = unquote(urlsplit(canonical.new_url).path)
        except HTTPException:
            return None
    return None


def resolve_local_url(target):
    """Return a ``url_for``-built URL equivalent to *target*, or ``None``.

    *target* may be a path (``/guests/3?tab=services``) or an absolute URL on
    this request's host.  Anything else -- another host, a scheme-relative
    ``//host`` URL, a path that matches no GET route -- yields ``None`` so the
    caller falls back to a known-good destination.
    """
    if not target or not isinstance(target, str):
        return None
    target = target.strip()
    if not target:
        return None
    try:
        parts = urlsplit(target)
    except ValueError:
        return None

    if parts.scheme or parts.netloc:
        if parts.scheme.lower() not in ("http", "https"):
            return None
        if parts.netloc.lower() != request.host.lower():
            return None

    path = unquote(parts.path) or "/"
    if not path.startswith("/") or path.startswith("//"):
        return None

    # Strip the mount point so the path matches the URL map the same way the
    # WSGI PATH_INFO for that page would.
    script_root = request.script_root
    if script_root:
        if path == script_root:
            path = "/"
        elif path.startswith(script_root + "/"):
            path = path[len(script_root):]

    matched = _match_route(path)
    if matched is None:
        return None
    endpoint, values = matched
    if endpoint == "static":
        return None

    query = {}
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if key in values or key in _RESERVED_URL_FOR_KWARGS or key in query:
            continue
        query[key] = value

    try:
        return url_for(endpoint, **values, **query)
    except BuildError:
        return None


def redirect_back(fallback_endpoint, **values):
    """Redirect to the page the request came from, if it is one of our own.

    Falls back to ``url_for(fallback_endpoint, **values)`` when the Referer
    is missing, points at another host, or does not name a route of this app.
    """
    return redirect(resolve_local_url(request.referrer) or url_for(fallback_endpoint, **values))
