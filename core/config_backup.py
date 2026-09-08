"""Config export/import and app-database backup helpers.

This module handles the tool's own configuration — NOT the guest data it backs
up elsewhere.  It produces a JSON snapshot of hosts, guests (config fields),
tags, roles, and application settings, and can re-apply that snapshot.

SECURITY-CRITICAL:
- Export redaction is RULE-BASED, not a denylist: any Setting whose key looks
  secret-shaped (``_SECRET_KEY_PATTERN``) or whose value looks like Fernet
  ciphertext is redacted, on top of an explicit extra set. New secret-bearing
  settings are caught automatically without needing a code change here.
- Import uses an ALLOWLIST-style blocklist for auth-critical settings
  (``_AUTH_CRITICAL_SETTING_KEYS``) so a tampered/shared export can never
  disable auth, and interval settings are bounds-checked rather than trusted.
- Importing role permissions and host connection fields is opt-in
  (``import_roles`` / ``import_hosts``); when unchecked those sections are
  left untouched.  Overwriting an existing host's connection fields always
  clears its stored credential so a repointed host can't leak the old secret.
- Secrets are never restored — administrators must re-enter credentials.
- The whole import is applied atomically: writes go through the session
  without per-row commits, and the caller commits once (or not at all, on
  error).
"""

import re
import sqlite3
import tempfile

from sqlalchemy import inspect as sa_inspect

from models import (
    Guest,
    ProxmoxHost,
    Role,
    Setting,
    Tag,
    TagUnifiNetwork,
    db,
)

# Schema version for the exported document.  Bump when the shape changes in a
# backward-incompatible way.
EXPORT_VERSION = 1

# Any Setting key matching this pattern is treated as secret-bearing and is
# redacted on export / never written on import, regardless of what the key is
# called by future features. Catches *_password, *_passwd, *_secret, *_token,
# *_api_key/apikey, *_private_key, and anything with "webhook" in it.
_SECRET_KEY_PATTERN = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|private[_-]?key|webhook)", re.IGNORECASE
)

# Explicit extra keys to redact even if a future rename dodges the pattern
# above. Kept as a belt-and-suspenders backstop, not the primary mechanism.
_EXTRA_SECRET_SETTING_KEYS = frozenset()

# Fernet tokens are urlsafe-base64 and always start with a version byte that
# encodes as "gAAAAA..." — used as a second, value-based redaction signal so
# an encrypted setting is caught even if its key doesn't look secret-shaped.
_FERNET_LIKE_RE = re.compile(r"^gAAAAA[A-Za-z0-9_=-]{20,}$")


def _looks_like_secret_key(key):
    return bool(_SECRET_KEY_PATTERN.search(key)) or key in _EXTRA_SECRET_SETTING_KEYS


def _looks_like_secret_value(value):
    return isinstance(value, str) and bool(_FERNET_LIKE_RE.match(value))


# Settings that gate or drive authentication, network trust, or the app's own
# self-update mechanism. These are never written by import even though they
# don't match the secret pattern — a tampered export must not be able to
# disable auth, widen the trusted-proxy list, or repoint self-update.
_AUTH_CRITICAL_SETTING_KEYS = frozenset({
    "trusted_subnets",
    "local_bypass_enabled",
    "cf_access_enabled",
    "cf_access_bypass_local_auth",
    "cf_access_audience",
    "cf_access_auto_provision",
    "cf_access_team_domain",
    "app_auto_update",
    "app_update_branch",
})

# Interval-type settings: validated against core.scheduler.INTERVAL_BOUNDS
# rather than blanket-skipped, since they're legitimate to import but an
# out-of-range value could otherwise wedge a background job.
_INTERVAL_SETTING_KEYS = frozenset({
    "scan_interval", "discovery_interval", "service_check_interval",
    "unifi_api_poll_interval", "prometheus_collect_interval",
    "moderation_check_interval_hours",
})

# Host config fields that are safe to export (no secrets).  Explicitly EXCLUDES
# encrypted_password, api_token_secret, and ipmi_password.
_HOST_FIELDS = (
    "name", "hostname", "port", "auth_type", "username", "api_token_id",
    "verify_ssl", "host_type", "ipmi_enabled", "ipmi_address", "ipmi_username",
    "ipmi_verify_ssl",
)

# Host fields that carry a stored secret, cleared whenever an existing host's
# connection fields are overwritten by import so a repointed host can never
# send the old credential to a new endpoint.
_HOST_SECRET_FIELDS = ("encrypted_password", "api_token_secret", "ipmi_password")

# Guest config fields that are safe to export.  Guests hold no secrets directly
# (credentials live in the Credential table, referenced by id which we do not
# export because credentials themselves are not exported).
_GUEST_FIELDS = (
    "vmid", "name", "guest_type", "ip_address", "connection_method",
    "auto_update", "status", "enabled", "replication_target", "mac_address",
    "power_state", "reboot_required", "require_snapshot", "backup_storage",
    "backup_mode", "backup_compress",
)

_ROLE_FIELDS = ("name", "display_name", "level", "is_builtin", "base_tier", *Role.PERMISSION_FIELDS)


class ImportError_(ValueError):
    """Raised when an uploaded config document is structurally invalid."""


def _model_to_dict(obj, fields):
    return {f: getattr(obj, f) for f in fields}


def build_export():
    """Build the export document (a JSON-serializable dict).

    Never includes decrypted secrets.  Encrypted columns are omitted at the
    model-field-allowlist level (see ``_HOST_FIELDS`` / ``_GUEST_FIELDS``);
    settings are redacted by rule (see ``_looks_like_secret_key`` /
    ``_looks_like_secret_value``) rather than a fixed denylist, so a new
    secret-bearing setting is caught automatically. Redacted keys are replaced
    with a placeholder so importers can see that a value existed without
    leaking it — this also covers Fernet ciphertext, which is treated as a
    secret even when the key name doesn't look secret-shaped.
    """
    hosts = [
        _model_to_dict(h, _HOST_FIELDS)
        for h in ProxmoxHost.query.order_by(ProxmoxHost.name).all()
    ]

    tags = [
        {"name": t.name, "color": t.color,
         "unifi_networks": [n.network_name for n in t.unifi_networks]}
        for t in Tag.query.order_by(Tag.name).all()
    ]

    guests = []
    for g in Guest.query.order_by(Guest.name).all():
        row = _model_to_dict(g, _GUEST_FIELDS)
        # Reference host by name (stable across imports) rather than id.
        row["host_name"] = g.proxmox_host.name if g.proxmox_host else None
        row["tags"] = [t.name for t in g.tags]
        guests.append(row)

    roles = [
        _model_to_dict(r, _ROLE_FIELDS)
        for r in Role.query.order_by(Role.level.desc(), Role.name).all()
    ]

    settings = {}
    for s in Setting.query.order_by(Setting.key).all():
        if _looks_like_secret_key(s.key) or _looks_like_secret_value(s.value):
            # Record that a secret exists, but never its value.
            settings[s.key] = "***REDACTED***"
        else:
            settings[s.key] = s.value

    return {
        "version": EXPORT_VERSION,
        "hosts": hosts,
        "tags": tags,
        "guests": guests,
        "roles": roles,
        "settings": settings,
    }


def _require(cond, msg):
    if not cond:
        raise ImportError_(msg)


def _validate_document(doc):
    """Strictly validate the top-level structure of an import document."""
    _require(isinstance(doc, dict), "Top-level JSON must be an object.")
    _require(doc.get("version") == EXPORT_VERSION,
             f"Unsupported export version (expected {EXPORT_VERSION}).")
    for key in ("hosts", "tags", "guests", "roles", "settings"):
        _require(key in doc, f"Missing required section: '{key}'.")
    for key in ("hosts", "tags", "guests", "roles"):
        _require(isinstance(doc[key], list), f"Section '{key}' must be a list.")
    _require(isinstance(doc["settings"], dict), "Section 'settings' must be an object.")
    for section in ("hosts", "tags", "guests", "roles"):
        for i, item in enumerate(doc[section]):
            _require(isinstance(item, dict), f"{section}[{i}] must be an object.")


def apply_import(doc, import_roles=False, import_hosts=False):
    """Validate ``doc`` and upsert tags, guests, hosts, roles, and settings.

    Secrets are NEVER imported.  Auth-critical settings (trusted subnets,
    local-bypass, Cloudflare Access, self-update source) are always skipped
    regardless of ``import_roles``/``import_hosts``, and interval settings are
    bounds-checked rather than trusted verbatim.

    ``import_roles`` and ``import_hosts`` are opt-in and default to False:
    - When ``import_roles`` is False, the roles section is ignored entirely
      (no role is created or modified).
    - When ``import_hosts`` is False, existing hosts are left untouched (their
      connection fields are never overwritten); new hosts may still be
      created with connection fields, since a new host has no stored
      credential to leak. When ``import_hosts`` is True and an existing host's
      connection fields are overwritten, that host's stored credential is
      cleared in the same transaction so it can't be repointed to a new
      endpoint while still holding the old secret.

    Writes go through the session without per-row commits — the caller is
    responsible for committing once, and for rolling back the whole session on
    any exception, so an import either fully applies or leaves no changes.

    Returns a summary dict: counts of applied items plus lists of settings
    skipped (secret/auth-critical/invalid-interval) and hosts skipped because
    ``import_hosts`` was not set, for the caller to report to the user.

    Raises ImportError_ on malformed input; the caller is responsible for
    rolling back the session on error.
    """
    _validate_document(doc)

    counts = {"hosts": 0, "tags": 0, "guests": 0, "settings": 0, "roles": 0}
    skipped_settings = []
    skipped_hosts = []
    skipped_roles = 0

    # --- Tags first (guests reference them by name) ---
    for item in doc["tags"]:
        name = (item.get("name") or "").strip()
        if not name:
            continue
        color = item.get("color") or "#6c757d"
        tag = Tag.query.filter_by(name=name).first()
        if tag is None:
            tag = Tag(name=name, color=color)
            db.session.add(tag)
            db.session.flush()
        else:
            tag.color = color
        # Replace unifi network links
        networks = item.get("unifi_networks") or []
        if isinstance(networks, list):
            TagUnifiNetwork.query.filter_by(tag_id=tag.id).delete()
            for net in networks:
                if isinstance(net, str) and net.strip():
                    db.session.add(TagUnifiNetwork(tag_id=tag.id, network_name=net.strip()))
        counts["tags"] += 1

    # --- Hosts (referenced by guests via name) ---
    # New hosts may always be created with connection fields (no stored
    # credential exists yet to leak). Overwriting an EXISTING host's
    # connection fields requires the import_hosts opt-in, and always clears
    # that host's stored credential so it can't be repointed to a new
    # endpoint while still carrying the old secret.
    valid_host_cols = {c.key for c in sa_inspect(ProxmoxHost).columns}
    for item in doc["hosts"]:
        name = (item.get("name") or "").strip()
        hostname = (item.get("hostname") or "").strip()
        if not name or not hostname:
            continue
        host = ProxmoxHost.query.filter_by(name=name).first()
        if host is None:
            host = ProxmoxHost(name=name, hostname=hostname)
            db.session.add(host)
            for field in _HOST_FIELDS:
                if field in item and field in valid_host_cols:
                    setattr(host, field, item[field])
            db.session.flush()
            counts["hosts"] += 1
            continue

        if not import_hosts:
            skipped_hosts.append(name)
            continue

        for secret_field in _HOST_SECRET_FIELDS:
            setattr(host, secret_field, None)
        for field in _HOST_FIELDS:
            if field in item and field in valid_host_cols:
                setattr(host, field, item[field])
        db.session.flush()
        counts["hosts"] += 1

    # --- Guests ---
    for item in doc["guests"]:
        name = (item.get("name") or "").strip()
        guest_type = (item.get("guest_type") or "").strip()
        if not name or guest_type not in ("vm", "ct"):
            continue
        host = None
        host_name = item.get("host_name")
        if host_name:
            host = ProxmoxHost.query.filter_by(name=host_name).first()

        vmid = item.get("vmid")
        guest = None
        if host and vmid is not None:
            guest = Guest.query.filter_by(proxmox_host_id=host.id, vmid=vmid).first()
        if guest is None:
            guest = Guest.query.filter_by(name=name, guest_type=guest_type).first()
        if guest is None:
            guest = Guest(name=name, guest_type=guest_type)
            db.session.add(guest)

        for field in _GUEST_FIELDS:
            if field in item:
                setattr(guest, field, item[field])
        guest.name = name
        guest.guest_type = guest_type
        if host is not None:
            guest.proxmox_host_id = host.id

        tag_names = item.get("tags") or []
        if isinstance(tag_names, list):
            resolved = Tag.query.filter(Tag.name.in_([t for t in tag_names if isinstance(t, str)])).all()
            guest.tags = resolved
        db.session.flush()
        counts["guests"] += 1

    # --- Roles: opt-in only; only custom (non-builtin) roles get upserted ---
    if import_roles:
        for item in doc["roles"]:
            rname = (item.get("name") or "").strip()
            if not rname:
                continue
            role = Role.query.filter_by(name=rname).first()
            if role is not None and role.is_builtin:
                continue  # never mutate builtin roles on import
            if role is None:
                if item.get("is_builtin"):
                    continue  # do not create phantom builtin roles
                role = Role(
                    name=rname,
                    display_name=(item.get("display_name") or rname),
                    level=int(item.get("level") or 1),
                    is_builtin=False,
                    base_tier=item.get("base_tier"),
                )
                db.session.add(role)
            else:
                if item.get("display_name"):
                    role.display_name = item["display_name"]
                if item.get("base_tier"):
                    role.base_tier = item["base_tier"]
                if isinstance(item.get("level"), int):
                    role.level = item["level"]
            for perm in Role.PERMISSION_FIELDS:
                if perm in item:
                    setattr(role, perm, bool(item[perm]))
            db.session.flush()
            counts["roles"] += 1
    else:
        skipped_roles = len(doc["roles"])

    # --- Settings: secrets and auth-critical keys are always skipped;
    # interval settings are bounds-checked rather than trusted verbatim ---
    from core.scheduler import parse_interval

    for key, value in doc["settings"].items():
        if not isinstance(key, str):
            continue
        if _looks_like_secret_key(key) or _looks_like_secret_value(value):
            continue  # never import secrets
        if key in _AUTH_CRITICAL_SETTING_KEYS:
            skipped_settings.append(key)
            continue  # never let import touch auth/trust/self-update config
        if value is not None and not isinstance(value, str):
            continue  # settings are stored as text
        if key in _INTERVAL_SETTING_KEYS:
            parsed, err = parse_interval(key, value)
            if err is not None:
                skipped_settings.append(key)
                continue
            value = str(parsed)
        Setting.set_no_commit(key, value)
        counts["settings"] += 1

    counts["skipped_settings"] = skipped_settings
    counts["skipped_hosts"] = skipped_hosts
    counts["skipped_roles"] = skipped_roles
    return counts


def _database_file_path():
    """Return the on-disk path of the app's SQLite database, or None.

    Returns None for in-memory databases (e.g. the test suite) where there is
    no file to back up.
    """
    engine = db.engine
    if engine.dialect.name != "sqlite":
        return None
    path = engine.url.database
    if not path or path == ":memory:":
        return None
    return path


def backup_database_to(dest_path):
    """Write a consistent snapshot of the app's SQLite DB to ``dest_path``.

    Uses the SQLite online backup API (sqlite3.Connection.backup) so a
    running/writing database is copied atomically rather than by copying the
    live file.  Returns True on success, False if there is no file-backed DB
    (e.g. in-memory test database).
    """
    src_path = _database_file_path()
    if src_path is None:
        return False

    # Read the live DB and stream it into the destination via the backup API.
    src = sqlite3.connect(src_path)
    try:
        dst = sqlite3.connect(dest_path)
        try:
            with dst:
                src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()
    return True


def make_backup_tempfile():
    """Create a secure temp file, back up the DB into it, and return its path.

    Returns None when there is no file-backed database to snapshot.  The caller
    owns the returned file and must delete it after use.
    """
    fd, tmp_path = tempfile.mkstemp(suffix=".sqlite3", prefix="mstdnca-dbbackup-")
    import os
    os.close(fd)
    try:
        if not backup_database_to(tmp_path):
            os.remove(tmp_path)
            return None
    except Exception:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise
    return tmp_path
