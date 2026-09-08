"""SSRF guard for outbound, user-supplied URLs (webhooks, integrations).

Mobile clients register a push-notification webhook URL that the server later
POSTs to, and admins configure outbound integrations (Discord webhooks,
Cloudflare Access) whose hostnames are attacker-influenceable in various ways.
Because these URLs are effectively attacker-controlled, they must be validated
before any request is made so a low-privileged user (or a misconfigured
setting) can't coerce the server into reaching internal/metadata endpoints it
shouldn't (SSRF).

We enforce an https/http scheme, a standard web port (80/443 by default),
no embedded userinfo credentials, and reject any URL whose hostname resolves
to a private, loopback, link-local, multicast, reserved or unspecified
address. Resolution happens at registration/save time (reject obviously-
internal targets) and again immediately before dispatch (mitigating DNS-
rebinding between the two) wherever that matters.
"""

import ipaddress
import socket
from urllib.parse import urlparse

# Schemes we are willing to make outbound requests with.
_ALLOWED_SCHEMES = ("https", "http")

# Ports we are willing to connect to by default. Restricting to the standard
# web ports closes off SSRF targets such as internal management UIs, databases
# or the Proxmox API (8006) that would otherwise be reachable via a
# user-supplied URL.
_ALLOWED_PORTS = (80, 443)

_DEFAULT_PORT_FOR_SCHEME = {"http": 80, "https": 443}


def _ip_is_blocked(ip_str):
    """True if *ip_str* is in a range we must never reach via an outbound request."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable -> treat as unsafe
    # Map IPv4-mapped IPv6 (::ffff:a.b.c.d) back to IPv4 for accurate checks.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_outbound_url(url, allowed_hosts=None, allowed_schemes=_ALLOWED_SCHEMES, allowed_ports=_ALLOWED_PORTS):
    """Validate a user-supplied outbound URL before the server requests it.

    Returns ``(True, None)`` if the URL is safe to request, otherwise
    ``(False, reason)``. Never raises for a malformed URL (e.g. an
    out-of-range port) -- that always yields ``(False, "malformed url")``.

    Args:
        url: The URL to validate.
        allowed_hosts: Optional iterable of exact hostnames (case-insensitive)
            the URL's host must match. ``None`` (default) allows any public
            host, subject to the other checks.
        allowed_schemes: Schemes permitted for this URL. Defaults to http/https.
        allowed_ports: Ports permitted for this URL (after resolving the
            scheme's default port when none is given explicitly). Pass
            ``None`` to skip the port check entirely.
    """
    if not url or not isinstance(url, str):
        return False, "url is required"

    try:
        parsed = urlparse(url.strip())
        port = parsed.port
    except ValueError:
        # e.g. urlparse(...).port raises ValueError for an out-of-range port.
        return False, "malformed url"

    scheme = parsed.scheme.lower()
    if scheme not in allowed_schemes:
        return False, f"url must use {' or '.join(allowed_schemes)}"

    if parsed.username or parsed.password:
        return False, "url must not contain userinfo credentials"

    hostname = parsed.hostname
    if not hostname:
        return False, "url must include a hostname"

    if allowed_hosts is not None and hostname.lower() not in allowed_hosts:
        return False, "url host is not allowed"

    if allowed_ports is not None:
        effective_port = port or _DEFAULT_PORT_FOR_SCHEME.get(scheme)
        if effective_port not in allowed_ports:
            return False, "url port is not allowed"

    # Resolve every address the hostname maps to; reject if any is internal.
    try:
        infos = socket.getaddrinfo(hostname, port or 0, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False, "url hostname could not be resolved"
    except UnicodeError:
        return False, "malformed url"

    resolved = {info[4][0] for info in infos}
    if not resolved:
        return False, "url hostname could not be resolved"
    for ip_str in resolved:
        if _ip_is_blocked(ip_str):
            return False, "url resolves to a non-public address"

    return True, None


def validate_webhook_url(url):
    """Validate a user-supplied outbound webhook URL.

    Thin, backward-compatible wrapper around :func:`validate_outbound_url`
    with the default (any public host, standard ports, http/https) policy.
    """
    return validate_outbound_url(url)
