import logging
import os
from urllib.parse import urlparse

from flask import Flask
from flask_login import LoginManager

from config import BASE_DIR, DATA_DIR, Config
from models import DEFAULT_ROLES, Role, User, db

logger = logging.getLogger(__name__)


def create_app(test_config=None):
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(Config)

    # Trust one layer of reverse-proxy headers (nginx, Cloudflare, etc.).
    # This makes request.remote_addr reflect the real client IP.
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    if test_config:
        app.config.update(test_config)

    # Ensure data directory exists
    os.makedirs(DATA_DIR, exist_ok=True)

    db.init_app(app)

    # Setup Flask-Login
    login_manager = LoginManager()
    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "warning"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.options(db.joinedload(User.role_obj)).get(int(user_id))

    with app.app_context():
        db.create_all()
        _migrate_ipmi_columns()
        _migrate_smcipmi_to_ipmi_exporter()
        _seed_roles()
        _ensure_default_admin()

    # Read version from file
    file_version = "unknown"
    if os.path.exists(Config.VERSION_FILE):
        with open(Config.VERSION_FILE) as f:
            file_version = f.read().strip()

    # Read git info for branch-based deployments
    import subprocess
    git_commit = ""
    git_branch = ""
    version_matches_tag = False
    try:
        git_commit = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=BASE_DIR, stderr=subprocess.DEVNULL, timeout=5
        ).decode().strip()
        git_branch = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=BASE_DIR, stderr=subprocess.DEVNULL, timeout=5
        ).decode().strip()
        # Check if current commit is tagged with the VERSION file's version
        if file_version != "unknown":
            try:
                tag_commit = subprocess.check_output(
                    ["git", "rev-parse", "--short", f"v{file_version}"],
                    cwd=BASE_DIR, stderr=subprocess.DEVNULL, timeout=5
                ).decode().strip()
                version_matches_tag = (tag_commit == git_commit)
            except Exception:
                version_matches_tag = False
    except Exception:
        pass

    # If current commit doesn't match the VERSION tag, we're ahead of the release
    if version_matches_tag:
        app.config["APP_VERSION"] = file_version
    else:
        app.config["APP_VERSION"] = file_version  # keep for reference
        app.config["APP_VERSION_STALE"] = True
    app.config["GIT_COMMIT"] = git_commit
    app.config["GIT_BRANCH"] = git_branch

    # Register blueprints
    from routes.api import bp as api_bp
    from routes.api_v1 import bp as api_v1_bp
    from routes.applications import bp as applications_bp
    from routes.auth import bp as auth_bp
    from routes.credentials import bp as credentials_bp
    from routes.dashboard import bp as dashboard_bp
    from routes.elk import bp as elk_bp
    from routes.ghost import bp as ghost_bp
    from routes.guests import bp as guests_bp
    from routes.hosts import bp as hosts_bp
    from routes.ipmi import bp as ipmi_bp
    from routes.jibri import bp as jibri_bp
    from routes.jitsi import bp as jitsi_bp
    from routes.mastodon import bp as mastodon_bp
    from routes.peertube import bp as peertube_bp
    from routes.prometheus_app import bp as prometheus_app_bp
    from routes.prometheus_metrics import bp as prometheus_metrics_bp
    from routes.schedules import bp as schedules_bp
    from routes.security import bp as security_bp
    from routes.services import bp as services_bp
    from routes.settings import bp as settings_bp
    from routes.terminal import bp as terminal_bp
    from routes.unifi import bp as unifi_bp
    from routes.unpoller import bp as unpoller_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(hosts_bp, url_prefix="/hosts")
    app.register_blueprint(guests_bp, url_prefix="/guests")
    app.register_blueprint(credentials_bp, url_prefix="/credentials")
    app.register_blueprint(settings_bp, url_prefix="/settings")
    app.register_blueprint(schedules_bp, url_prefix="/schedules")
    app.register_blueprint(security_bp, url_prefix="/security")
    app.register_blueprint(terminal_bp, url_prefix="/terminal")
    app.register_blueprint(mastodon_bp, url_prefix="/mastodon")
    app.register_blueprint(ghost_bp, url_prefix="/ghost")
    app.register_blueprint(peertube_bp, url_prefix="/peertube")
    app.register_blueprint(elk_bp, url_prefix="/elk")
    app.register_blueprint(jibri_bp, url_prefix="/jibri")
    app.register_blueprint(jitsi_bp, url_prefix="/jitsi")
    app.register_blueprint(services_bp, url_prefix="/services")
    app.register_blueprint(unifi_bp, url_prefix="/unifi")
    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(applications_bp, url_prefix="/applications")
    app.register_blueprint(prometheus_metrics_bp)
    app.register_blueprint(prometheus_app_bp, url_prefix="/prometheus")
    app.register_blueprint(ipmi_bp, url_prefix="/ipmi")
    app.register_blueprint(unpoller_bp, url_prefix="/unpoller")
    app.register_blueprint(api_v1_bp, url_prefix="/api/v1")

    # Initialize WebSocket for terminal
    from routes.terminal import init_websocket
    init_websocket(app)

    # Start background scheduler (discovery, scans, UniFi event polling, etc.).
    # Must run in create_app() so gunicorn picks it up; skip in test mode.
    if not test_config:
        from core.scheduler import init_scheduler
        init_scheduler(app)

    # Warn if running with multiple workers, which breaks in-process collaboration
    _web_concurrency = int(os.environ.get("WEB_CONCURRENCY", "1"))
    if _web_concurrency > 1:
        logger.warning(
            "WEB_CONCURRENCY=%d: the collaboration/presence system uses in-process state "
            "and will NOT work correctly with multiple gunicorn workers. "
            "Use a single worker (-w 1) or switch to threaded workers (--worker-class gthread).",
            _web_concurrency,
        )

    # Local network bypass (must run before CF Access so local IPs are already authed)
    from auth.local_network import init_local_bypass
    init_local_bypass(app)

    # Initialize Cloudflare Zero Trust integration
    from auth.cloudflare_access import init_cf_access
    init_cf_access(app)

    # Custom Jinja filters
    import zoneinfo
    from datetime import datetime
    from datetime import timezone as tz

    from markupsafe import Markup

    def _tz_span(dt, fmt):
        """Return a Markup <span data-utc="ISO"> with server-side tz conversion."""
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=tz.utc)
        iso = dt.isoformat()
        user_tz = None
        try:
            from flask_login import current_user
            if current_user.is_authenticated and current_user.timezone:
                user_tz = zoneinfo.ZoneInfo(current_user.timezone)
        except Exception:
            pass
        if user_tz:
            display = dt.astimezone(user_tz).strftime(fmt)
        else:
            display = dt.strftime(fmt)
        return Markup('<span data-utc="{}">{}</span>').format(iso, display)

    @app.template_filter("timestamp_to_datetime")
    def timestamp_to_datetime(epoch):
        """Convert a Unix epoch to a timezone-aware <span data-utc> element."""
        try:
            dt = datetime.fromtimestamp(int(epoch), tz=tz.utc)
            return _tz_span(dt, "%Y-%m-%d %H:%M")
        except (ValueError, TypeError, OSError):
            return Markup("")

    @app.template_filter("local_dt")
    def local_dt_filter(dt, fmt="%m/%d %H:%M"):
        """Render a datetime as a <span data-utc="ISO"> element.

        Server-side conversion uses zoneinfo (IANA/eggert tz database) when
        the user has a saved timezone.  The data-utc attribute is kept so
        client-side JS can refine or handle users without a saved timezone.
        """
        if dt is None:
            return Markup("")
        return _tz_span(dt, fmt)

    # Security headers
    @app.before_request
    def _csrf_origin_check():
        """Basic CSRF defense for state-changing browser requests.

        Accept only same-origin requests for unsafe HTTP methods.
        """
        from flask import abort, request

        if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return
        if request.path.startswith("/static/"):
            return

        # Prefer Origin; fallback to Referer for older browser/form behavior.
        source = request.headers.get("Origin") or request.headers.get("Referer")
        if not source:
            return  # No origin header -- non-browser client; allow

        src = urlparse(source)
        req = urlparse(request.host_url)
        if (src.scheme, src.netloc) != (req.scheme, req.netloc):
            logger.warning("CSRF origin mismatch: source=%s expected=%s path=%s",
                           source, request.host_url, request.path)
            abort(403, description="Cross-site request blocked")

    @app.after_request
    def _security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if not app.debug:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        # CSP: allows CDN-hosted Bootstrap/HTMX/Chart.js plus inline scripts and styles.
        # Tighten by migrating inline JS to nonces or external files in a future pass.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "connect-src 'self' ws: wss:; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "object-src 'none'; "
            "base-uri 'self';"
        )
        return response

    @app.context_processor
    def inject_globals():
        from flask import session
        from flask_login import current_user
        if current_user.is_authenticated:
            return {
                "safety_mode": session.get("safety_mode", False),
                "user_timezone": current_user.timezone,
            }
        return {"safety_mode": False, "user_timezone": None}

    @app.route("/toggle-safety-mode", methods=["POST"])
    def toggle_safety_mode():
        from flask import redirect, request, session
        from flask_login import current_user
        if not current_user.is_authenticated:
            from flask import abort
            abort(403)
        session["safety_mode"] = not session.get("safety_mode", False)
        return redirect(request.referrer or "/")

    @app.route("/health")
    def health_check():
        """Lightweight health check for load balancers and monitoring."""
        from flask import jsonify
        try:
            db.session.execute(db.text("SELECT 1"))
            return jsonify({"status": "ok"}), 200
        except Exception:
            return jsonify({"status": "error", "detail": "database unreachable"}), 503

    return app


def _add_column_if_missing(table, column, col_type="BOOLEAN DEFAULT 0"):
    """Add a column to an existing SQLite table if it doesn't exist yet."""
    try:
        existing = {row[1] for row in db.session.execute(db.text(f"PRAGMA table_info({table})")).fetchall()}
        if column not in existing:
            db.session.execute(db.text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"))
            db.session.commit()
            logger.info("Added column %s.%s", table, column)
    except Exception as e:
        db.session.rollback()
        logger.debug("Migration check for %s.%s: %s", table, column, e)


def _migrate_ipmi_columns():
    """Add IPMI-related columns to existing tables that were created before this feature."""
    # Role permissions
    _add_column_if_missing("roles", "can_view_ipmi", "BOOLEAN DEFAULT 0")
    _add_column_if_missing("roles", "can_manage_ipmi", "BOOLEAN DEFAULT 0")
    # ProxmoxHost IPMI config
    _add_column_if_missing("proxmox_hosts", "ipmi_enabled", "BOOLEAN DEFAULT 0")
    _add_column_if_missing("proxmox_hosts", "ipmi_address", "VARCHAR(256)")
    _add_column_if_missing("proxmox_hosts", "ipmi_username", "VARCHAR(128)")
    _add_column_if_missing("proxmox_hosts", "ipmi_password", "TEXT")
    _add_column_if_missing("proxmox_hosts", "ipmi_verify_ssl", "BOOLEAN DEFAULT 0")


def _migrate_smcipmi_to_ipmi_exporter():
    """Migrate any existing smcipmi_exporter instances to ipmi_exporter."""
    try:
        from models import HostExporterInstance
        rows = HostExporterInstance.query.filter_by(exporter_type="smcipmi_exporter").all()
        for row in rows:
            row.exporter_type = "ipmi_exporter"
            row.port = 9290
            row.status = "pending"
            row.version = None
        if rows:
            db.session.commit()
            logger.info("Migrated %d smcipmi_exporter instance(s) to ipmi_exporter.", len(rows))
    except Exception:
        pass  # Table may not exist yet on fresh installs


def _seed_roles():
    """Seed the default roles if the roles table is empty."""
    if Role.query.count() > 0:
        return
    logger.info("Seeding default roles...")
    for role_data in DEFAULT_ROLES:
        role = Role(**role_data)
        db.session.add(role)
    db.session.commit()
    logger.info(f"Seeded {len(DEFAULT_ROLES)} default roles.")


def _ensure_default_admin():
    """Create default admin user if no users exist."""
    if User.query.count() == 0:
        sa_role = Role.query.filter_by(name="super_admin").first()
        if not sa_role:
            return
        import secrets
        default_password = secrets.token_urlsafe(16)
        admin = User(
            username="admin",
            display_name="Administrator",
            role_id=sa_role.id,
        )
        admin.set_password(default_password)
        db.session.add(admin)
        db.session.commit()
        logger.warning("=" * 60)
        logger.warning("  DEFAULT ADMIN ACCOUNT CREATED")
        logger.warning("  Username: admin")
        logger.warning("  Password: %s", default_password)
        logger.warning("  Please change this password immediately!")
        logger.warning("=" * 60)
        print("=" * 60)
        print("  DEFAULT ADMIN ACCOUNT CREATED")
        print("  Username: admin")
        print(f"  Password: {default_password}")
        print("  Please change this password immediately!")
        print("=" * 60)


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=os.environ.get("FLASK_DEBUG", "0") == "1")
