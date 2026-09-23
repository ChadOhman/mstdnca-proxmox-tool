"""Reverse-proxy header trust, keyed on *which peer* sent the request.

``TRUSTED_PROXY_COUNT`` says how many proxy hops to unwind from
``X-Forwarded-For``; on its own it trusts those headers from *any* TCP peer.
With the default ``0.0.0.0:5000`` bind that let a client that connects
directly (bypassing the proxy) forge ``X-Forwarded-For: 10.0.0.5`` and pick
up the local-network bypass (GHSA-w9wf-pqr9-26m8, residual).

:class:`TrustedPeerProxyFix` applies Werkzeug's ``ProxyFix`` only when the
connection's peer is a proxy we trust; every other request keeps its real
``REMOTE_ADDR``, scheme and host, exactly as if ``TRUSTED_PROXY_COUNT`` were 0.

Which peers count is ``TRUSTED_PROXY_PEERS``: a comma-separated list of
addresses or CIDR ranges. When it is unset, loopback and private (RFC 1918 /
ULA) peers are trusted, which covers cloudflared or nginx on the same host or
LAN. When it is set, only the listed ranges are trusted; a value that parses to
nothing trusts no peer at all (fail closed).
"""

import ipaddress
import logging

from werkzeug.middleware.proxy_fix import ProxyFix

logger = logging.getLogger(__name__)


def parse_trusted_proxy_peers(raw):
    """Parse ``TRUSTED_PROXY_PEERS``. Returns None (unset: default policy) or a list of networks."""
    if raw is None:
        return None
    if not isinstance(raw, str):
        raw = ",".join(str(item) for item in raw)
    if not raw.strip():
        return None
    networks = []
    for position, entry in enumerate(raw.split(","), start=1):
        entry = entry.strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            logger.warning("Ignoring invalid TRUSTED_PROXY_PEERS entry #%d", position)
    if not networks:
        logger.warning("TRUSTED_PROXY_PEERS is set but contains no valid address or range; "
                       "forwarded headers will be ignored from every peer")
    return networks


def peer_is_trusted(addr, peers):
    """Whether the TCP peer ``addr`` may set forwarded headers.

    ``peers`` is the result of :func:`parse_trusted_proxy_peers`: None means
    the default policy (loopback or private), a list means an explicit allowlist.
    """
    if not addr:
        return False
    try:
        parsed = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
        parsed = parsed.ipv4_mapped
    if peers is None:
        return parsed.is_loopback or parsed.is_private
    return any(parsed in net for net in peers)


class TrustedPeerProxyFix(ProxyFix):
    """``ProxyFix`` that only unwinds forwarded headers sent by a trusted peer."""

    def __init__(self, app, peers=None, **kwargs):
        super().__init__(app, **kwargs)
        self.peers = peers

    def __call__(self, environ, start_response):
        if not peer_is_trusted(environ.get("REMOTE_ADDR"), self.peers):
            # Untrusted peer: no header is honoured, and no
            # ``werkzeug.proxy_fix.orig`` is set, so CF-Connecting-IP is
            # ignored downstream as well.
            return self.app(environ, start_response)
        return super().__call__(environ, start_response)
