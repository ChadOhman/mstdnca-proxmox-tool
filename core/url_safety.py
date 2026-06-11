"""SSRF guard for outbound, user-supplied webhook URLs.

Mobile clients register a push-notification webhook URL that the server later
POSTs to.  Because the URL is fully attacker-controlled, it must be validated
before any request is made so a low-privileged user cannot coerce the server
into reaching internal/metadata endpoints it shouldn't (SSRF).

We enforce an https/http scheme and reject any URL whose hostname resolves to a
private, loopback, link-local, multicast, reserved or unspecified address.
Resolution happens at registration time (reject obviously-internal targets) and
again immediately before dispatch (mitigating DNS-rebinding between the two).
"""

import ipaddress
import socket
from urllib.parse import urlparse

# Schemes we are willing to make outbound requests with.
_ALLOWED_SCHEMES = ("https", "http")


def _ip_is_blocked(ip_str):
    """True if *ip_str* is in a range we must never reach via a webhook."""
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


def validate_webhook_url(url):
    """Validate a user-supplied outbound webhook URL.

    Returns ``(True, None)`` if the URL is safe to request, otherwise
    ``(False, reason)``.  Every hostname resolution result must be a public
    address; if any resolved IP is internal the URL is rejected.
    """
    if not url or not isinstance(url, str):
        return False, "url is required"

    parsed = urlparse(url.strip())
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        return False, "url must use http or https"

    hostname = parsed.hostname
    if not hostname:
        return False, "url must include a hostname"

    # Resolve every address the hostname maps to; reject if any is internal.
    try:
        infos = socket.getaddrinfo(hostname, parsed.port or 0, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False, "url hostname could not be resolved"

    resolved = {info[4][0] for info in infos}
    if not resolved:
        return False, "url hostname could not be resolved"
    for ip_str in resolved:
        if _ip_is_blocked(ip_str):
            return False, "url resolves to a non-public address"

    return True, None
