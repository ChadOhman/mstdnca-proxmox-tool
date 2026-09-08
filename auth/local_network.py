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
from flask_login import current_user, login_user, logout_user

from models import Role, Setting, User, db

logger = logging.getLogger(__name__)

DEFAULT_TRUSTED_SUBNETS = ""

# Flask-session flag marking a session that was established by this bypass (as
# opposed to a real login), so it can be re-validated on every request.
BYPASS_SESSION_KEY = "_local_bypass"


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
    """Return the client IP.  Single source of truth for the whole app.

    ``request.remote_addr`` is the real TCP peer unless ``TRUSTED_PROXY_COUNT``
    is greater than 0, in which case ``ProxyFix`` (installed in ``create_app``)
    has already resolved it from ``X-Forwarded-For``.  This function therefore
    never parses ``X-Forwarded-For`` / ``X-Real-IP`` itself: doing so would let
    a direct client pick its own source IP, which is what the trust decisions
    built on top of this value (local bypass, rate limiting, audit) rely on.

    The one extra header honoured is Cloudflare's ``CF-Connecting-IP``, and only
    when ProxyFix actually ran *and* the pre-ProxyFix TCP peer is loopback or
    private -- i.e. the request really did arrive through local proxy
    infrastructure rather than straight off the network.
    """
    remote_addr = request.remote_addr

    orig = request.environ.get("werkzeug.proxy_fix.orig")
    if orig and _is_proxy_peer(orig.get("REMOTE_ADDR")):
        cf_ip = (request.headers.get("CF-Connecting-IP") or "").strip()
        if cf_ip and _is_ip_address(cf_ip):
            return cf_ip

    return remote_addr or None


def _is_ip_address(value):
    """True when ``value`` parses as an IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _is_proxy_peer(addr):
    """True when ``addr`` is loopback/private, i.e. plausible proxy infrastructure."""
    if not addr:
        return False
    try:
        parsed = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return parsed.is_loopback or parsed.is_private


def _is_trusted(client_ip, networks):
    """Check if client_ip falls within any trusted network."""
    try:
        addr = ipaddress.ip_address(client_ip)
        return any(addr in net for net in networks)
    except ValueError:
        return False


def _bypass_enabled():
    """True when the local-network auto-login feature is switched on."""
    return Setting.get("local_bypass_enabled", "false") != "false"


def _bypass_session_still_valid():
    """Re-validate an already-established bypass session against live settings.

    A bypass session carries no credentials, so it must not outlive the
    conditions that created it: turning ``local_bypass_enabled`` off or
    narrowing ``trusted_subnets`` has to invalidate it on the very next request.
    """
    if not _bypass_enabled():
        return False
    return _is_trusted(_get_client_ip(), _get_trusted_networks())


def _warn_if_proxy_trust_missing(app):
    """Warn when header-dependent auth is enabled but no proxy hop is trusted."""
    if app.config.get("TRUSTED_PROXY_COUNT", 0):
        return
    try:
        with app.app_context():
            cf_enabled = Setting.get("cf_access_enabled", "false") == "true"
            bypass_enabled = _bypass_enabled()
    except Exception:  # pragma: no cover - settings table not ready yet
        return
    if not (cf_enabled or bypass_enabled):
        return
    logger.warning(
        "TRUSTED_PROXY_COUNT is 0 while %s enabled: forwarded headers "
        "(X-Forwarded-For / CF-Connecting-IP) are ignored and every trust decision uses the "
        "direct TCP peer. If a reverse proxy (cloudflared, nginx) fronts this app, set "
        "TRUSTED_PROXY_COUNT to the number of proxy hops you operate (usually 1) so client "
        "IPs resolve correctly; leave it at 0 when clients connect directly.",
        "Cloudflare Access is" if cf_enabled else "local-network bypass is",
    )


def init_local_bypass(app):
    """Register the local-network auto-auth middleware."""
    _warn_if_proxy_trust_missing(app)

    @app.before_request
    def _local_network_bypass():
        # Skip for static assets and mobile API (API uses its own JWT auth)
        if request.path.startswith(("/static/", "/api/v1/")):
            return

        # Already authenticated -- nothing to do, except that a session created
        # by this bypass must be re-checked while it is in use.
        if current_user.is_authenticated:
            if session.get(BYPASS_SESSION_KEY):
                if _bypass_session_still_valid():
                    g.local_bypass = True
                else:
                    from auth.session_manager import revoke_current_session
                    revoke_current_session()
                    db.session.commit()
                    logout_user()
                    session.clear()
                    logger.info("Local bypass session invalidated (settings changed or IP no longer trusted)")
            return

        # Check if bypass is enabled
        if not _bypass_enabled():
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
            from auth.audit import log_action
            from auth.session_manager import start_session

            safety = session.get("safety_mode", False)
            session.clear()
            login_user(admin)
            admin.last_login_at = datetime.now(timezone.utc)
            if safety:
                session["safety_mode"] = True
            # Track the session server-side so it is listed and revocable, and
            # mark it as bypass-established so it can be re-validated per request.
            start_session(admin)
            session[BYPASS_SESSION_KEY] = True
            log_action("login_local_bypass", "user", resource_id=admin.id,
                       resource_name=admin.username, details={"client_ip": client_ip})
            db.session.commit()
            g.local_bypass = True
            logger.debug(f"Local bypass: auto-authenticated {client_ip} as admin")

    @app.context_processor
    def _local_bypass_context():
        return {"local_bypass": getattr(g, "local_bypass", False)}
