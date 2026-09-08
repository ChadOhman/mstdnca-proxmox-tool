# Architecture

## App Factory

`app.py::create_app()` — initializes DB, runs schema migrations, registers 26 blueprints, starts APScheduler, sets up auth middleware (Cloudflare Access + local network bypass), CSRF origin check, and security headers.

**Single-worker constraint:** The collaboration system (`core/collaboration.py`) uses in-process state for presence tracking and terminal sharing. Must run with gunicorn `-w 1` or `--worker-class gthread`. Multi-worker deployments silently break collaboration features.

The production worker class is `gevent` (`scripts/setup.sh` gunicorn `ExecStart`, pinned in `requirements.txt`); it's imported directly by seven `routes/*` modules to spawn background greenlets for long-running SSH/upgrade work.

## Directory Structure

```
(root)
├── app.py                  # Flask app factory
├── config.py               # Configuration (BASE_DIR, DATA_DIR, SECRET_KEY_PATH)
├── models.py               # SQLAlchemy models + DB instance
├── auth/                   # Authentication & security
│   ├── audit.py            # log_action() audit logging
│   ├── cloudflare_access.py # CF Access JWT validation
│   ├── local_network.py    # Local network auto-login bypass
│   └── credential_store.py # Fernet symmetric encryption
├── clients/                # External service clients
│   ├── ssh_client.py       # SSH wrapper (paramiko)
│   ├── proxmox_api.py      # Proxmox VE API client
│   ├── pbs_client.py       # Proxmox Backup Server client
│   ├── unifi_client.py     # UniFi network integration
│   └── unifi_geoip.py      # GeoIP lookup for UniFi
├── core/                   # Business logic
│   ├── scanner.py          # Guest/package scanning via SSH
│   ├── scheduler.py        # APScheduler background jobs
│   ├── collaboration.py    # Presence tracking, terminal sharing
│   └── notifier.py         # Webhook notifications
├── apps/                   # Application upgrade automation
│   ├── utils.py            # Shared helpers (_log_cmd_output, _validate_shell_param, _version_gt)
│   ├── mastodon.py         # Mastodon/glitch-soc upgrades
│   ├── ghost.py            # Ghost CMS upgrades
│   ├── peertube.py         # PeerTube upgrades
│   ├── elk.py              # Elk (Mastodon web client) upgrades
│   ├── jitsi.py            # Jitsi Meet install/upgrades
│   ├── jibri.py            # Jibri (Jitsi recording) upgrades
│   ├── exporters.py        # Prometheus exporter upgrades
│   ├── prometheus_app.py   # Prometheus server upgrades
│   ├── unpoller.py         # UnPoller upgrades
│   └── backup.py           # App database backup
├── routes/                 # Flask blueprints (one per feature)
├── templates/              # Jinja2 templates
├── static/                 # CSS (style.css)
├── scripts/                # Shell scripts (setup.sh, update.sh, create-ct.sh)
└── tests/                  # Test suite
```

## Blueprints

One file per feature area in `routes/`:
- `auth.py` — login/logout/change-password
- `guests.py` — VM/CT CRUD with tag-based access filtering
- `hosts.py` — PVE/PBS host management
- `terminal.py` — WebSocket SSH terminal (Flask-Sock), 1800s idle timeout
- `security.py` — user/role/tag/session management, audit log, `_safe_int()` helper
- `services.py` — service monitoring (mastodon, sidekiq, postgres, redis)
- `mastodon.py`, `ghost.py`, `peertube.py`, `elk.py`, `jitsi.py`, `jibri.py`, `prometheus_app.py`, `unpoller.py` — application upgrade routes
- `moderation.py` — PeerTube/Mastodon email cross-check
- `trends.py` — update history and trends
- `ipmi.py` — IPMI sensor/power monitoring
- `api.py`, `api_v1.py` — REST API endpoints
- `prometheus_metrics.py` — Prometheus metrics endpoint
- `dashboard.py`, `credentials.py`, `settings.py`, `schedules.py`, `unifi.py`, `applications.py`

## Database

SQLite via SQLAlchemy. Schema migrations run at startup in `_migrate_schema()` (ALTER TABLE for new columns since `create_all()` doesn't alter existing tables). Models in `models.py`.

## Auth Layers

Local login → Cloudflare Access JWT (`auth/cloudflare_access.py`) → Local network auto-login (`auth/local_network.py`, trusted CIDRs). Role-based permissions: super_admin > admin > operator > viewer; see `Role.PERMISSION_FIELDS` for the full flag list.

**Client IP / proxy trust.** `auth/local_network._get_client_ip()` is the single source of truth for the caller's address — the local bypass, login and API rate limiting (`routes/auth.py`, `auth/jwt_auth.py`) and `auth/audit.log_action()` all go through it. It returns `request.remote_addr` and never parses forwarded headers itself. `ProxyFix` is installed in `create_app()` **only** when `Config.TRUSTED_PROXY_COUNT` (env `TRUSTED_PROXY_COUNT`, default `0`) is greater than 0, so with the default no client-supplied header can influence `remote_addr`. When ProxyFix is active, `CF-Connecting-IP` is additionally honoured, but only if the pre-ProxyFix peer (`environ["werkzeug.proxy_fix.orig"]["REMOTE_ADDR"]`) is loopback/private. Deployments behind cloudflared or nginx must set `TRUSTED_PROXY_COUNT=1`; a startup WARNING is logged when CF Access or the local bypass is enabled while it is 0.

**Session tracking.** All three auth paths call `auth/session_manager.start_session()`, so bypass and CF Access sessions get a `UserSession` row and are listed/revocable. Bypass sessions carry a `_local_bypass` flag in the Flask session and are re-validated against `local_bypass_enabled` + `trusted_subnets` on every request.

## Credentials

Fernet symmetric encryption (`auth/credential_store.py`), key at `/etc/mstdnca/secret.key`. Fernet instance cached at module level with thread-safe double-checked locking.

## Frontend

Jinja2 templates with Bootstrap 5.3.3 dark theme + xterm.js, all from CDN. Single `static/style.css` plus `static/esc.js` (shared `escHtml` helper).