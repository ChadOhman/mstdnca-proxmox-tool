import logging
import os
import sqlite3
from urllib.parse import urlparse

from flask import Flask
from flask_login import LoginManager
from sqlalchemy import event
from sqlalchemy.engine import Engine

from config import BASE_DIR, DATA_DIR, Config
from models import DEFAULT_ROLES, GUEST_VMID_UNIQUE_INDEX, Role, User, db

logger = logging.getLogger(__name__)


@event.listens_for(Engine, "connect")
def _set_sqlite_pragmas(dbapi_connection, connection_record):
    """Apply per-connection SQLite tuning.

    * ``foreign_keys=ON`` makes the ``ondelete="CASCADE"`` clauses in models.py
      actually do something -- SQLite does not enforce foreign keys by default.
    * ``journal_mode=WAL`` lets scheduler threads read while a request writes.
      It is a persistent, file-level setting, so it is skipped for in-memory
      databases where it is meaningless.
    * ``busy_timeout`` replaces the 5s default so a slow writer produces a wait
      rather than an immediate "database is locked".
    """
    if not isinstance(dbapi_connection, sqlite3.Connection):
        return
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=30000")
        row = cursor.execute("PRAGMA database_list").fetchone()
        main_file = row[2] if row and len(row) > 2 else ""
        if main_file:  # empty for :memory: and temporary databases
            cursor.execute("PRAGMA journal_mode=WAL")
    except Exception:
        logger.warning("Failed to apply SQLite connection pragmas", exc_info=True)
    finally:
        cursor.close()


def create_app(test_config=None):
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(Config)

    if test_config:
        app.config.update(test_config)

    # Reverse-proxy header trust is opt-in.  ProxyFix rewrites REMOTE_ADDR from
    # the client-supplied X-Forwarded-For header, so installing it when nothing
    # trustworthy sits in front of the app would let any client choose its own
    # source IP.  With TRUSTED_PROXY_COUNT=0 (the default) it is not installed at
    # all and request.remote_addr stays the real TCP peer everywhere.
    proxy_count = app.config.get("TRUSTED_PROXY_COUNT", 0) or 0
    if proxy_count > 0:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=proxy_count,
            x_proto=proxy_count,
            x_host=proxy_count,
            x_prefix=proxy_count,
        )

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
        _migrate_moderation_columns()
        _migrate_ai_columns()
        _migrate_smcipmi_to_ipmi_exporter()
        _migrate_guest_lock_column()
        _migrate_user_security_columns()
        _ensure_guest_vmid_unique_index()
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
    from routes.ai_chat import bp as ai_chat_bp
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
    from routes.moderation import bp as moderation_bp
    from routes.peertube import bp as peertube_bp
    from routes.prometheus_app import bp as prometheus_app_bp
    from routes.prometheus_metrics import bp as prometheus_metrics_bp
    from routes.schedules import bp as schedules_bp
    from routes.security import bp as security_bp
    from routes.services import bp as services_bp
    from routes.settings import bp as settings_bp
    from routes.terminal import bp as terminal_bp
    from routes.trends import bp as trends_bp
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
    app.register_blueprint(moderation_bp, url_prefix="/moderation")
    app.register_blueprint(prometheus_metrics_bp)
    app.register_blueprint(prometheus_app_bp, url_prefix="/prometheus")
    app.register_blueprint(ipmi_bp, url_prefix="/ipmi")
    app.register_blueprint(unpoller_bp, url_prefix="/unpoller")
    app.register_blueprint(api_v1_bp, url_prefix="/api/v1")
    app.register_blueprint(trends_bp, url_prefix="/trends")
    app.register_blueprint(ai_chat_bp, url_prefix="/ai")

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

    # Server-side session tracking (revocation + last-seen). Registered after the
    # bypass/CF hooks so those may authenticate first; the hook ignores sessions
    # they establish (no tracked session id) and never runs for /api/v1.
    from auth.session_manager import init_session_tracking
    init_session_tracking(app)

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
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "img-src 'self' data:; "
            "connect-src 'self' ws: wss:; "
            "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com; "
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
        from core.local_redirect import resolve_local_url
        return redirect(resolve_local_url(request.referrer) or "/")

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
    """Add a column to an existing SQLite table if it doesn't exist yet.

    Returns True when the column was actually added so callers can run a
    one-time backfill.  Failures are logged at WARNING (they used to be
    invisible at DEBUG) but never re-raised: a failed migration must not stop
    the app from booting.
    """
    try:
        existing = {row[1] for row in db.session.execute(db.text(f"PRAGMA table_info({table})")).fetchall()}
        if column not in existing:
            db.session.execute(db.text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"))
            db.session.commit()
            logger.info("Added column %s.%s", table, column)
            return True
    except Exception:
        db.session.rollback()
        logger.warning("Migration check for %s.%s failed", table, column, exc_info=True)
    return False


def _migrate_moderation_columns():
    """Add the moderation permission column to roles created before this feature.

    Grants can_moderate to the admin-tier built-in roles (super_admin, admin) so
    existing deployments match the DEFAULT_ROLES seed.
    """
    try:
        existing = {row[1] for row in db.session.execute(db.text("PRAGMA table_info(roles)")).fetchall()}
        if "can_moderate" not in existing:
            logger.info("Adding column roles.can_moderate")
            db.session.execute(db.text("ALTER TABLE roles ADD COLUMN can_moderate BOOLEAN DEFAULT 0"))
            db.session.execute(db.text("UPDATE roles SET can_moderate = 1 WHERE name IN ('super_admin', 'admin')"))
            db.session.commit()
    except Exception:
        db.session.rollback()
        logger.warning("Migration check for roles.can_moderate failed", exc_info=True)


def _migrate_ai_columns():
    """Add AI-related columns to existing tables that were created before this feature."""
    _add_column_if_missing("roles", "can_use_ai", "BOOLEAN DEFAULT 0")


def _migrate_ipmi_columns():
    """Add IPMI-related columns to tables created before this feature.

    When the role permission columns are newly added, grant them to the
    admin-tier built-in roles so upgraded deployments match DEFAULT_ROLES --
    the same one-time backfill _migrate_moderation_columns performs.  It runs
    only on the upgrade that adds the column, so later customisation of a
    built-in role is never reverted.
    """
    # Role permissions
    added_view = _add_column_if_missing("roles", "can_view_ipmi", "BOOLEAN DEFAULT 0")
    added_manage = _add_column_if_missing("roles", "can_manage_ipmi", "BOOLEAN DEFAULT 0")
    if added_view or added_manage:
        try:
            if added_view:
                db.session.execute(
                    db.text("UPDATE roles SET can_view_ipmi = 1 WHERE name IN ('super_admin', 'admin')")
                )
            if added_manage:
                db.session.execute(
                    db.text("UPDATE roles SET can_manage_ipmi = 1 WHERE name IN ('super_admin', 'admin')")
                )
            db.session.commit()
            logger.info("Backfilled IPMI permissions on the built-in admin roles")
        except Exception:
            db.session.rollback()
            logger.warning("Failed to backfill IPMI role permissions", exc_info=True)
    # ProxmoxHost IPMI config
    _add_column_if_missing("proxmox_hosts", "ipmi_enabled", "BOOLEAN DEFAULT 0")
    _add_column_if_missing("proxmox_hosts", "ipmi_address", "VARCHAR(256)")
    _add_column_if_missing("proxmox_hosts", "ipmi_username", "VARCHAR(128)")
    _add_column_if_missing("proxmox_hosts", "ipmi_password", "TEXT")
    _add_column_if_missing("proxmox_hosts", "ipmi_verify_ssl", "BOOLEAN DEFAULT 0")


def _migrate_guest_lock_column():
    """Add the guests.lock_reason column to databases created before lock display."""
    _add_column_if_missing("guests", "lock_reason", "VARCHAR(32)")


def _migrate_user_security_columns():
    """Add the credential-invalidation columns to pre-existing user rows.

    Both default to "nothing to enforce" so existing accounts are unaffected:
    ``tokens_valid_after`` stays NULL until the next password change and
    ``must_change_password`` defaults to 0.
    """
    _add_column_if_missing("users", "tokens_valid_after", "DATETIME")
    _add_column_if_missing("users", "must_change_password", "BOOLEAN DEFAULT 0")


def _ensure_guest_vmid_unique_index():
    """Create the (proxmox_host_id, vmid) unique index on pre-existing databases.

    create_all() does not add indexes to tables it did not create, so this
    mirrors the model-level index for upgraded installs.  If the database
    already holds duplicate host/VMID pairs the CREATE fails; that is logged at
    WARNING and the app still boots so an admin can clean the rows up.
    """
    try:
        db.session.execute(db.text(
            f"CREATE UNIQUE INDEX IF NOT EXISTS {GUEST_VMID_UNIQUE_INDEX} "
            "ON guests (proxmox_host_id, vmid) WHERE vmid IS NOT NULL"
        ))
        db.session.commit()
    except Exception:
        db.session.rollback()
        logger.warning(
            "Could not create the unique index %s on guests(proxmox_host_id, vmid); "
            "duplicate rows probably exist and must be removed manually",
            GUEST_VMID_UNIQUE_INDEX,
            exc_info=True,
        )


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
        # The table may not exist yet on fresh installs; log it so a genuine
        # failure is visible instead of silently swallowed.
        db.session.rollback()
        logger.warning("Migration of smcipmi_exporter instances failed", exc_info=True)


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


INITIAL_ADMIN_PASSWORD_FILE = "initial-admin-password"


def initial_admin_password_path():
    """Absolute path of the one-time bootstrap password file."""
    return os.path.join(DATA_DIR, INITIAL_ADMIN_PASSWORD_FILE)


def _write_initial_admin_password(password):
    """Write the bootstrap password to a 0600 file and return its path.

    The file is created with ``O_CREAT | O_EXCL | O_WRONLY`` so the mode is
    applied atomically at creation rather than after a umask-widened open, and
    so an existing path (including a symlink planted by another user) is never
    followed.  Returns None when the file could not be written.
    """
    path = initial_admin_password_path()
    try:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(fd, (password + "\n").encode("utf-8"))
        finally:
            os.close(fd)
        return path
    except OSError:
        logger.warning("Could not write the initial admin password file at %s", path, exc_info=True)
        return None


def _ensure_default_admin():
    """Create default admin user if no users exist.

    The generated password is never printed or logged -- it used to go to both
    stdout and the logger, which put it in journald forever.  It is written to
    a 0600 file under DATA_DIR instead and the account is flagged
    ``must_change_password``, so the first login is forced through
    /change-password (which then deletes the file).
    """
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
        admin.must_change_password = True
        db.session.add(admin)
        db.session.commit()
        path = _write_initial_admin_password(default_password)
        location = path or "(could not be written -- reset the password manually)"
        banner = (
            "=" * 60
            + "\n  DEFAULT ADMIN ACCOUNT CREATED"
            + "\n  Username: admin"
            + f"\n  Password file (mode 0600): {location}"
            + "\n  You must change this password at first login."
            + "\n" + "=" * 60
        )
        logger.warning("%s", banner)
        print(banner)


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=os.environ.get("FLASK_DEBUG", "0") == "1")
