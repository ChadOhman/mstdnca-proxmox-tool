"""
Local network authentication bypass.

Requests originating from trusted subnets are automatically authenticated
as the admin user without requiring login. This allows seamless local
access from the datacenter LAN while still requiring CF Access / login
for external connections.

No subnets are trusted by default. Trusted subnets must be explicitly
configured via the Settings UI.
"""

import ipaddress
import logging
from datetime import datetime, timezone

from flask import g, request, session
from flask_login import current_user, login_user

from models import Role, Setting, User

logger = logging.getLogger(__name__)

DEFAULT_TRUSTED_SUBNETS = ""


def _get_trusted_networks():
    """Parse trusted subnets from settings into a list of IPv4/IPv6 networks."""
    raw = Setting.get("trusted_subnets", DEFAULT_TRUSTED_SUBNETS)
    networks = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            logger.warning(f"Invalid trusted subnet: {entry}")
    return networks


def _get_client_ip():
    """Get the real client IP, respecting proxy headers.

    Order of preference:
      1. CF-Connecting-IP  (set by Cloudflare)
      2. X-Real-IP         (set by nginx / reverse proxies)
      3. First entry in X-Forwarded-For
      4. request.remote_addr (direct connection)
    """
    remote_addr = request.remote_addr
    if not remote_addr:
        return None

    # Only trust forwarded headers when traffic is coming from local/private
    # infrastructure (e.g. reverse proxy). This prevents direct clients from
    # spoofing X-Forwarded-For / X-Real-IP / CF-Connecting-IP.
    try:
        remote_ip = ipaddress.ip_address(remote_addr)
        trust_forwarded = remote_ip.is_loopback or remote_ip.is_private
    except ValueError:
        trust_forwarded = False

    if trust_forwarded:
        cf_ip = request.headers.get("CF-Connecting-IP")
        if cf_ip:
            return cf_ip.strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()

    return remote_addr


def _is_trusted(client_ip, networks):
    """Check if client_ip falls within any trusted network."""
    try:
        addr = ipaddress.ip_address(client_ip)
        return any(addr in net for net in networks)
    except ValueError:
        return False


def init_local_bypass(app):
    """Register the local-network auto-auth middleware."""

    @app.before_request
    def _local_network_bypass():
        # Skip for static assets and mobile API (API uses its own JWT auth)
        if request.path.startswith(("/static/", "/api/v1/")):
            return

        # Already authenticated -- nothing to do
        if current_user.is_authenticated:
            return

        # Check if bypass is enabled
        if Setting.get("local_bypass_enabled", "false") == "false":
            return

        client_ip = _get_client_ip()
        networks = _get_trusted_networks()

        if not _is_trusted(client_ip, networks):
            return

        # Auto-login as admin
        admin = User.query.join(Role).filter(
            User.username == "admin",
            Role.name.in_(("super_admin", "admin")),
        ).first()
        if admin and admin.is_active:
            safety = session.get("safety_mode", False)
            session.clear()
            login_user(admin)
            admin.last_login_at = datetime.now(timezone.utc)
            if safety:
                session["safety_mode"] = True
            g.local_bypass = True
            logger.debug(f"Local bypass: auto-authenticated {client_ip} as admin")

    @app.context_processor
    def _local_bypass_context():
        return {"local_bypass": getattr(g, "local_bypass", False)}
