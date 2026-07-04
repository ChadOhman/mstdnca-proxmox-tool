"""Config export/import and app-database backup helpers.

This module handles the tool's own configuration — NOT the guest data it backs
up elsewhere.  It produces a JSON snapshot of hosts, guests (config fields),
tags, roles, and application settings, and can re-apply that snapshot.

SECURITY-CRITICAL: decrypted secrets are NEVER exported.  Encrypted secret
columns and secret-bearing settings are excluded entirely (see
``_SECRET_SETTING_KEYS`` and the per-model field allowlists below).  On import,
secrets are never restored — administrators must re-enter credentials.
"""

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

# Setting keys that hold secrets (encrypted values or credential-bearing URLs).
# These are excluded from export and never written on import.
_SECRET_SETTING_KEYS = frozenset({
    "unifi_password",        # Fernet-encrypted
    "github_token",          # Fernet-encrypted
    "discord_webhook_url",   # URL embeds the webhook secret token
})

# Host config fields that are safe to export (no secrets).  Explicitly EXCLUDES
# encrypted_password, api_token_secret, and ipmi_password.
_HOST_FIELDS = (
    "name", "hostname", "port", "auth_type", "username", "api_token_id",
    "verify_ssl", "host_type", "ipmi_enabled", "ipmi_address", "ipmi_username",
    "ipmi_verify_ssl",
)

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

    Never includes decrypted secrets.  Encrypted columns and secret settings
    are omitted; the ``settings`` map has secret keys replaced with a
    placeholder so importers can see that a value existed without leaking it.
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
        if s.key in _SECRET_SETTING_KEYS:
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


def apply_import(doc):
    """Validate ``doc`` and upsert hosts, tags, guests, and settings.

    Secrets are NEVER imported.  Roles are validated but only their permission
    flags / display fields are upserted for non-builtin roles (builtin roles are
    left untouched to avoid privilege drift).  Returns a summary dict of counts.

    Raises ImportError_ on malformed input; the caller is responsible for
    rolling back the session on error.
    """
    _validate_document(doc)

    counts = {"hosts": 0, "tags": 0, "guests": 0, "settings": 0, "roles": 0}

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

    # --- Roles: only custom (non-builtin) roles get upserted ---
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

    # --- Settings (secrets skipped) ---
    for key, value in doc["settings"].items():
        if not isinstance(key, str):
            continue
        if key in _SECRET_SETTING_KEYS:
            continue  # never import secrets
        if value is not None and not isinstance(value, str):
            continue  # settings are stored as text
        Setting.set(key, value)
        counts["settings"] += 1

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
