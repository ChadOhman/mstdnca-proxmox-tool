from datetime import datetime, timezone

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash


def _in_request_context() -> bool:
    try:
        from flask import has_request_context
        return has_request_context()
    except RuntimeError:
        return False

db = SQLAlchemy()

# Package name prefixes that typically require a reboot on Debian/Ubuntu.
# Used to predict whether pending updates will need one before they are applied.
_REBOOT_PKG_PREFIXES = (
    "linux-image",
    "linux-modules",
    "linux-headers",
    "libc6",
    "libc-bin",
    "systemd",
    "udev",
    "initramfs-tools",
    "grub-",
    "shim-",
)

# Association table: which tags a user has access to
user_tags = db.Table(
    "user_tags",
    db.Column("user_id", db.Integer, db.ForeignKey("users.id"), primary_key=True),
    db.Column("tag_id", db.Integer, db.ForeignKey("tags.id"), primary_key=True),
)

# Association table: which tags a guest has
guest_tags = db.Table(
    "guest_tags",
    db.Column("guest_id", db.Integer, db.ForeignKey("guests.id"), primary_key=True),
    db.Column("tag_id", db.Integer, db.ForeignKey("tags.id"), primary_key=True),
)


class Role(db.Model):
    __tablename__ = "roles"

    PERMISSION_FIELDS = [
        "can_ssh", "can_update", "can_manage_users", "can_manage_settings",
        "can_manage_credentials", "can_view_hosts", "can_manage_hosts",
        "can_manage_guests", "can_restart_unifi", "can_view_audit_log",
        "can_view_services",
        "can_edit_services",
        "can_view_unifi",
        "can_view_ipmi",
        "can_manage_ipmi",
    ]

    PERMISSION_LABELS = {
        "can_ssh": "SSH Terminal Access",
        "can_update": "Apply Updates",
        "can_manage_users": "Manage Users",
        "can_manage_settings": "Manage Settings",
        "can_manage_credentials": "Manage Credentials",
        "can_view_hosts": "View Host Statistics",
        "can_manage_hosts": "Manage Hosts",
        "can_manage_guests": "Manage Guests",
        "can_restart_unifi": "Restart UniFi Devices",
        "can_view_audit_log": "View Audit Log",
        "can_view_services": "View Services",
        "can_edit_services": "Edit Services",
        "can_view_unifi": "View Network (UniFi)",
        "can_view_ipmi": "View IPMI (Hardware Health)",
        "can_manage_ipmi": "Manage IPMI (Power Control)",
    }

    BASE_TIER_LEVELS = {"viewer": 1, "operator": 2, "admin": 3}

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    display_name = db.Column(db.String(128), nullable=False)
    level = db.Column(db.Integer, nullable=False, default=1)
    is_builtin = db.Column(db.Boolean, default=False)
    base_tier = db.Column(db.String(16), nullable=True)

    # Permission flags
    can_ssh = db.Column(db.Boolean, default=False)
    can_update = db.Column(db.Boolean, default=False)
    can_manage_users = db.Column(db.Boolean, default=False)
    can_manage_settings = db.Column(db.Boolean, default=False)
    can_manage_credentials = db.Column(db.Boolean, default=False)
    can_view_hosts = db.Column(db.Boolean, default=False)
    can_manage_hosts = db.Column(db.Boolean, default=False)
    can_manage_guests = db.Column(db.Boolean, default=False)
    can_restart_unifi = db.Column(db.Boolean, default=False)
    can_view_audit_log = db.Column(db.Boolean, default=False)
    can_view_services = db.Column(db.Boolean, default=False)
    can_edit_services = db.Column(db.Boolean, default=False)
    can_view_unifi = db.Column(db.Boolean, default=False)
    can_view_ipmi = db.Column(db.Boolean, default=False)
    can_manage_ipmi = db.Column(db.Boolean, default=False)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    users = db.relationship("User", backref="role_obj", lazy=True)

    def __getitem__(self, key):
        """Allow dict-style access for Jinja templates (e.g. role[perm])."""
        return getattr(self, key)

    def __repr__(self):
        return f"<Role {self.name}>"


# Default role definitions for seeding
DEFAULT_ROLES = [
    {"name": "super_admin", "display_name": "Super Admin", "level": 4, "is_builtin": True,
     "can_ssh": True, "can_update": True, "can_manage_users": True,
     "can_manage_settings": True, "can_manage_credentials": True,
     "can_view_hosts": True, "can_manage_hosts": True, "can_manage_guests": True,
     "can_restart_unifi": True, "can_view_audit_log": True, "can_view_services": True, "can_edit_services": True,
     "can_view_unifi": True, "can_view_ipmi": True, "can_manage_ipmi": True},
    {"name": "admin", "display_name": "Admin", "level": 3, "is_builtin": True,
     "can_ssh": True, "can_update": True, "can_manage_users": True,
     "can_manage_settings": False, "can_manage_credentials": False,
     "can_view_hosts": True, "can_manage_hosts": True, "can_manage_guests": True,
     "can_restart_unifi": True, "can_view_audit_log": True, "can_view_services": True, "can_edit_services": True,
     "can_view_unifi": True, "can_view_ipmi": True, "can_manage_ipmi": True},
    {"name": "operator", "display_name": "Operator", "level": 2, "is_builtin": True,
     "can_ssh": True, "can_update": True, "can_manage_users": False,
     "can_manage_settings": False, "can_manage_credentials": False,
     "can_view_hosts": True, "can_manage_hosts": False, "can_manage_guests": False,
     "can_restart_unifi": False, "can_view_audit_log": False, "can_view_services": False, "can_edit_services": False,
     "can_view_unifi": False, "can_view_ipmi": True, "can_manage_ipmi": False},
    {"name": "viewer", "display_name": "Viewer", "level": 1, "is_builtin": True,
     "can_ssh": False, "can_update": False, "can_manage_users": False,
     "can_manage_settings": False, "can_manage_credentials": False,
     "can_view_hosts": False, "can_manage_hosts": False, "can_manage_guests": False,
     "can_restart_unifi": False, "can_view_audit_log": False, "can_view_services": False, "can_edit_services": False,
     "can_view_unifi": False, "can_view_ipmi": False, "can_manage_ipmi": False},
]


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    display_name = db.Column(db.String(128))
    password_hash = db.Column(db.String(256), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)
    created_via = db.Column(db.String(32), default="local")  # local, cloudflare, local_bypass
    is_active_user = db.Column(db.Boolean, default=True)
    timezone = db.Column(db.String(64), nullable=True)  # IANA tz name, e.g. "America/Chicago"; None = browser auto-detect
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login_at = db.Column(db.DateTime, nullable=True)

    # Tags this user has access to
    allowed_tags = db.relationship("Tag", secondary=user_tags, backref="users")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_active(self):
        return self.is_active_user

    @property
    def role(self):
        """Backward-compatible: returns the role name string."""
        return self.role_obj.name if self.role_obj else "viewer"

    @property
    def role_level(self):
        return self.role_obj.level if self.role_obj else 1

    @property
    def is_super_admin(self):
        return self.role_obj.name == "super_admin" if self.role_obj else False

    @property
    def is_admin(self):
        return self.role_level >= 3

    @property
    def can_ssh(self):
        if self.is_super_admin:
            return True
        return self.role_obj.can_ssh if self.role_obj else False

    @property
    def can_update(self):
        if self.is_super_admin:
            return True
        return self.role_obj.can_update if self.role_obj else False

    @property
    def can_manage_users(self):
        if self.is_super_admin:
            return True
        return self.role_obj.can_manage_users if self.role_obj else False

    @property
    def can_manage_settings(self):
        if self.is_super_admin:
            return True
        return self.role_obj.can_manage_settings if self.role_obj else False

    @property
    def can_manage_credentials(self):
        if self.is_super_admin:
            return True
        return self.role_obj.can_manage_credentials if self.role_obj else False

    @property
    def can_view_hosts(self):
        if self.is_super_admin:
            return True
        return self.role_obj.can_view_hosts if self.role_obj else False

    @property
    def can_manage_hosts(self):
        if self.is_super_admin:
            return True
        return self.role_obj.can_manage_hosts if self.role_obj else False

    @property
    def can_manage_guests(self):
        if self.is_super_admin:
            return True
        return self.role_obj.can_manage_guests if self.role_obj else False

    @property
    def can_restart_unifi(self):
        if self.is_super_admin:
            return True
        return self.role_obj.can_restart_unifi if self.role_obj else False

    @property
    def can_view_audit_log(self):
        if self.is_super_admin:
            return True
        return self.role_obj.can_view_audit_log if self.role_obj else False

    @property
    def can_view_services(self):
        if self.is_super_admin:
            return True
        return self.role_obj.can_view_services if self.role_obj else False

    @property
    def can_edit_services(self):
        if self.is_super_admin:
            return True
        return self.role_obj.can_edit_services if self.role_obj else False

    @property
    def can_view_unifi(self):
        if self.is_super_admin:
            return True
        return self.role_obj.can_view_unifi if self.role_obj else False

    @property
    def can_view_ipmi(self):
        if self.is_super_admin:
            return True
        return self.role_obj.can_view_ipmi if self.role_obj else False

    @property
    def can_manage_ipmi(self):
        if self.is_super_admin:
            return True
        return self.role_obj.can_manage_ipmi if self.role_obj else False

    @property
    def role_display(self):
        return self.role_obj.display_name if self.role_obj else "Viewer"

    def can_access_guest(self, guest):
        """Check if user can access a guest based on tag permissions."""
        if self.is_super_admin:
            return True
        if not guest.tags:
            return False  # untagged guests are admin-only
        user_tag_ids = {t.id for t in self.allowed_tags}
        guest_tag_ids = {t.id for t in guest.tags}
        return bool(user_tag_ids & guest_tag_ids)

    def accessible_guests(self):
        """Return list of guests this user can access."""
        if self.is_super_admin:
            return Guest.query.filter_by(enabled=True).all()
        user_tag_ids = [t.id for t in self.allowed_tags]
        if not user_tag_ids:
            return []
        return (
            Guest.query.filter_by(enabled=True)
            .filter(Guest.tags.any(Tag.id.in_(user_tag_ids)))
            .all()
        )

    def can_edit_user(self, other_user):
        """Check if this user can edit another user."""
        if self.id == other_user.id:
            return True
        if self.is_super_admin:
            return True
        return self.role_level > other_user.role_level

    def __repr__(self):
        return f"<User {self.username}>"


class Tag(db.Model):
    __tablename__ = "tags"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    color = db.Column(db.String(7), default="#6c757d")  # hex color for UI
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    unifi_networks = db.relationship(
        "TagUnifiNetwork", backref="tag", cascade="all, delete-orphan", passive_deletes=True
    )

    def __repr__(self):
        return f"<Tag {self.name}>"


class TagUnifiNetwork(db.Model):
    """Links a tag to one or more UniFi network names for access control filtering."""
    __tablename__ = "tag_unifi_networks"

    tag_id = db.Column(db.Integer, db.ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True)
    network_name = db.Column(db.String(64), primary_key=True)


class ProxmoxHost(db.Model):
    __tablename__ = "proxmox_hosts"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    hostname = db.Column(db.String(256), nullable=False)
    port = db.Column(db.Integer, default=8006)
    auth_type = db.Column(db.String(32), default="token")  # token or password
    username = db.Column(db.String(128))  # e.g. root@pam
    encrypted_password = db.Column(db.Text)
    api_token_id = db.Column(db.String(128))
    api_token_secret = db.Column(db.Text)  # encrypted
    verify_ssl = db.Column(db.Boolean, default=False)
    host_type = db.Column(db.String(16), default="pve")  # "pve" or "pbs"
    ssh_credential_id = db.Column(db.Integer, db.ForeignKey("credentials.id"), nullable=True)
    ipmi_enabled = db.Column(db.Boolean, default=False)
    ipmi_address = db.Column(db.String(256), nullable=True)  # BMC IP/hostname
    ipmi_username = db.Column(db.String(128), nullable=True)
    ipmi_password = db.Column(db.Text, nullable=True)  # Fernet encrypted
    ipmi_verify_ssl = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    guests = db.relationship("Guest", backref="proxmox_host", lazy=True, cascade="all, delete-orphan")
    ssh_credential = db.relationship("Credential", foreign_keys=[ssh_credential_id])
    host_update_packages = db.relationship(
        "HostUpdatePackage", backref="host", lazy=True, cascade="all, delete-orphan"
    )

    @property
    def is_pbs(self):
        return self.host_type == "pbs"

    def pending_updates(self):
        return [u for u in self.host_update_packages if u.status == "pending"]

    def security_updates(self):
        return [u for u in self.host_update_packages if u.status == "pending" and u.severity == "critical"]

    def __repr__(self):
        return f"<ProxmoxHost {self.name} ({self.hostname}) [{self.host_type}]>"


class Credential(db.Model):
    __tablename__ = "credentials"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    username = db.Column(db.String(128), nullable=False, default="root")
    auth_type = db.Column(db.String(32), default="password")  # password or key
    encrypted_value = db.Column(db.Text, nullable=False)  # encrypted password or private key
    encrypted_sudo_password = db.Column(db.Text, nullable=True)  # optional sudo password
    is_default = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    guests = db.relationship("Guest", backref="credential", lazy=True)

    def __repr__(self):
        return f"<Credential {self.name}>"


class MaintenanceWindow(db.Model):
    __tablename__ = "maintenance_windows"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    day_of_week = db.Column(db.String(32), nullable=False)  # e.g. "monday" or "daily"
    start_time = db.Column(db.String(8), nullable=False)  # HH:MM
    end_time = db.Column(db.String(8), nullable=False)  # HH:MM
    update_type = db.Column(db.String(32), default="upgrade")  # upgrade or dist-upgrade
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    guests = db.relationship("Guest", backref="maintenance_window", lazy=True)

    def __repr__(self):
        return f"<MaintenanceWindow {self.name}>"


class Guest(db.Model):
    __tablename__ = "guests"

    id = db.Column(db.Integer, primary_key=True)
    proxmox_host_id = db.Column(db.Integer, db.ForeignKey("proxmox_hosts.id"), nullable=True)
    vmid = db.Column(db.Integer, nullable=True)
    name = db.Column(db.String(128), nullable=False)
    guest_type = db.Column(db.String(16), nullable=False)  # vm or ct
    ip_address = db.Column(db.String(64))
    connection_method = db.Column(db.String(16), default="ssh")  # ssh, agent, or auto
    credential_id = db.Column(db.Integer, db.ForeignKey("credentials.id"), nullable=True)
    auto_update = db.Column(db.Boolean, default=False)
    maintenance_window_id = db.Column(db.Integer, db.ForeignKey("maintenance_windows.id"), nullable=True)
    last_scan = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(32), default="unknown", index=True)  # unknown, up-to-date, updates-available, error
    enabled = db.Column(db.Boolean, default=True)
    replication_target = db.Column(db.String(128), nullable=True)  # node name if replicated
    mac_address = db.Column(db.String(17), nullable=True)  # MAC from Proxmox config (for UniFi matching)
    power_state = db.Column(db.String(16), default="unknown")  # running, stopped, paused, unknown
    reboot_required = db.Column(db.Boolean, default=False)
    require_snapshot = db.Column(db.String(16), default="inherit")  # inherit, yes, no
    backup_storage = db.Column(db.String(128), nullable=True)  # per-guest backup storage override
    backup_mode = db.Column(db.String(32), nullable=True)       # per-guest backup mode override
    backup_compress = db.Column(db.String(32), nullable=True)   # per-guest compression override
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    updates = db.relationship("UpdatePackage", backref="guest", lazy=True, cascade="all, delete-orphan")
    scan_results = db.relationship("ScanResult", backref="guest", lazy=True, cascade="all, delete-orphan")
    services = db.relationship("GuestService", backref="guest", lazy=True, cascade="all, delete-orphan")
    exporters = db.relationship("ExporterInstance", backref="guest", lazy=True, cascade="all, delete-orphan")
    tags = db.relationship("Tag", secondary=guest_tags, backref="guests")

    def pending_updates(self):
        return [u for u in self.updates if u.status == "pending"]

    def security_updates(self):
        return [u for u in self.updates if u.status == "pending" and u.severity == "critical"]

    def reboot_updates(self):
        """Return pending updates whose package names suggest a reboot will be needed."""
        return [u for u in self.pending_updates() if u.package_name.startswith(_REBOOT_PKG_PREFIXES)]

    def clear_stale_data(self):
        """Remove scan results, update packages, and services. Reset scan state.

        Used when VMID reuse is detected or when an admin manually resets a guest.
        """
        for sr in list(self.scan_results):
            db.session.delete(sr)
        for up in list(self.updates):
            db.session.delete(up)
        for svc in list(self.services):
            db.session.delete(svc)
        for exp in list(self.exporters):
            db.session.delete(exp)
        self.last_scan = None
        self.status = "unknown"
        self.reboot_required = False

    def __repr__(self):
        return f"<Guest {self.name} ({self.guest_type})>"


db.Index("ix_guest_host_vmid", Guest.proxmox_host_id, Guest.vmid)


class UpdatePackage(db.Model):
    __tablename__ = "update_packages"

    id = db.Column(db.Integer, primary_key=True)
    guest_id = db.Column(db.Integer, db.ForeignKey("guests.id"), nullable=False)
    package_name = db.Column(db.String(256), nullable=False)
    current_version = db.Column(db.String(128))
    available_version = db.Column(db.String(128))
    severity = db.Column(db.String(32), default="normal")  # critical, important, normal
    discovered_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    applied_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(32), default="pending")  # pending, applied, skipped

    @property
    def requires_reboot(self):
        """True if this package typically requires a reboot to take effect."""
        return self.package_name.startswith(_REBOOT_PKG_PREFIXES)

    def __repr__(self):
        return f"<UpdatePackage {self.package_name} on guest {self.guest_id}>"


db.Index("ix_update_pkg_guest_status", UpdatePackage.guest_id, UpdatePackage.status)


class HostUpdatePackage(db.Model):
    """APT package update available on a Proxmox host."""

    __tablename__ = "host_update_package"

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey("proxmox_hosts.id", ondelete="CASCADE"), nullable=False)
    package_name = db.Column(db.String(256))
    current_version = db.Column(db.String(128))
    available_version = db.Column(db.String(128))
    severity = db.Column(db.String(32), default="normal")
    discovered_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    applied_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(32), default="pending")


db.Index("ix_host_update_pkg_host_status", HostUpdatePackage.host_id, HostUpdatePackage.status)


class ScanResult(db.Model):
    __tablename__ = "scan_results"

    id = db.Column(db.Integer, primary_key=True)
    guest_id = db.Column(db.Integer, db.ForeignKey("guests.id"), nullable=False, index=True)
    scanned_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    total_updates = db.Column(db.Integer, default=0)
    security_updates = db.Column(db.Integer, default=0)
    status = db.Column(db.String(32), default="success")  # success, error
    error_message = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f"<ScanResult guest={self.guest_id} total={self.total_updates}>"


class GuestService(db.Model):
    __tablename__ = "guest_services"

    # Known service definitions: (display_name, unit_name, default_port)
    KNOWN_SERVICES = {
        "elasticsearch": ("Elasticsearch", "elasticsearch.service", 9200),
        "postgresql": ("PostgreSQL", "postgresql.service", 5432),
        "redis": ("Redis", "redis-server.service", 6379),
        "libretranslate": ("LibreTranslate", "libretranslate.service", 5000),
        "puma": ("Puma", "mastodon-web.service", 3000),
        "sidekiq": ("Sidekiq", "mastodon-sidekiq*.service", None),
        "jitsi-videobridge2": ("Jitsi Videobridge", "jitsi-videobridge2.service", 8080),
        "jicofo": ("Jicofo", "jicofo.service", None),
        "prosody": ("Prosody", "prosody.service", None),
        "prometheus": ("Prometheus", "prometheus.service", 9090),
    }

    id = db.Column(db.Integer, primary_key=True)
    guest_id = db.Column(db.Integer, db.ForeignKey("guests.id"), nullable=False, index=True)
    service_name = db.Column(db.String(64), nullable=False)  # e.g. "elasticsearch"
    unit_name = db.Column(db.String(128), nullable=False)  # e.g. "elasticsearch.service"
    port = db.Column(db.Integer, nullable=True)
    status = db.Column(db.String(32), default="unknown")  # running, stopped, failed, unknown
    last_checked = db.Column(db.DateTime, nullable=True)
    auto_detected = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"<GuestService {self.service_name} on guest {self.guest_id}>"


class ServiceMetricSnapshot(db.Model):
    """Time-series snapshots of key scalar metrics for a service (currently PostgreSQL)."""
    __tablename__ = "service_metric_snapshots"

    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey("guest_services.id", ondelete="CASCADE"), nullable=False, index=True)
    captured_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    # JSON blob: {"total_connections": 5, "cache_hit_ratio": 99.2, "active_queries": 1, ...}
    data = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f"<ServiceMetricSnapshot service={self.service_id} at={self.captured_at}>"


# Composite index speeds up the per-service prune query (ORDER BY captured_at DESC OFFSET N)
db.Index(
    "ix_svc_metric_service_captured",
    ServiceMetricSnapshot.service_id,
    ServiceMetricSnapshot.captured_at,
)


class ExporterInstance(db.Model):
    """Tracks a Prometheus exporter installed on a guest."""
    __tablename__ = "exporter_instances"

    id = db.Column(db.Integer, primary_key=True)
    guest_id = db.Column(db.Integer, db.ForeignKey("guests.id"), nullable=False, index=True)
    exporter_type = db.Column(db.String(64), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    version = db.Column(db.String(32), nullable=True)
    status = db.Column(db.String(32), default="pending")
    config = db.Column(db.JSON, nullable=True)
    installed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<ExporterInstance {self.exporter_type} on guest={self.guest_id} status={self.status}>"


class HostExporterInstance(db.Model):
    """Tracks a Prometheus exporter installed on a Proxmox host (host-level exporters like SMCIPMI)."""
    __tablename__ = "host_exporter_instances"

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey("proxmox_hosts.id", ondelete="CASCADE"), nullable=False, index=True)
    exporter_type = db.Column(db.String(64), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    version = db.Column(db.String(32), nullable=True)
    status = db.Column(db.String(32), default="pending")
    config = db.Column(db.JSON, nullable=True)
    installed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    host = db.relationship("ProxmoxHost", backref="host_exporter_instances")

    def __repr__(self):
        return f"<HostExporterInstance {self.exporter_type} on host={self.host_id} status={self.status}>"


class Setting(db.Model):
    __tablename__ = "settings"

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(128), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=True)

    @staticmethod
    def get(key, default=None):
        if _in_request_context():
            from flask import g
            cache = g.get("_settings_cache")
            if cache is None:
                g._settings_cache = {}
                cache = g._settings_cache
            if key in cache:
                return cache[key]
            s = Setting.query.filter_by(key=key).first()
            value = s.value if s else default
            cache[key] = value
            return value
        s = Setting.query.filter_by(key=key).first()
        return s.value if s else default

    @staticmethod
    def set(key, value):
        s = Setting.query.filter_by(key=key).first()
        if s:
            s.value = value
        else:
            s = Setting(key=key, value=value)
            db.session.add(s)
        db.session.commit()
        if _in_request_context():
            from flask import g
            g.pop("_settings_cache", None)
        return s


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id            = db.Column(db.Integer, primary_key=True)
    timestamp     = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    user_id       = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    user          = db.relationship("User", backref="audit_logs")
    action        = db.Column(db.String(64),  nullable=False, index=True)
    resource_type = db.Column(db.String(32),  nullable=False, index=True)
    resource_id   = db.Column(db.Integer,     nullable=True,  index=True)
    resource_name = db.Column(db.String(256), nullable=True)
    details       = db.Column(db.JSON,        nullable=True)
    ip_address    = db.Column(db.String(45),  nullable=True)

    def __repr__(self):
        return f"<AuditLog {self.action} by user_id={self.user_id}>"


class HostMetricSnapshot(db.Model):
    """Time-series snapshots of IPMI sensor data for a host (temps, fans, power)."""
    __tablename__ = "host_metric_snapshots"

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey("proxmox_hosts.id", ondelete="CASCADE"), nullable=False, index=True)
    captured_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    # JSON blob: {"cpu_temp": 42, "system_temp": 35, "fans": [...], "power_watts": 180, ...}
    data = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f"<HostMetricSnapshot host={self.host_id} at={self.captured_at}>"


db.Index(
    "ix_host_metric_host_captured",
    HostMetricSnapshot.host_id,
    HostMetricSnapshot.captured_at,
)


class UnifiLogEntry(db.Model):
    __tablename__ = "unifi_log_entries"

    id           = db.Column(db.Integer, primary_key=True)
    timestamp    = db.Column(db.DateTime, nullable=False, index=True)
    source       = db.Column(db.String(16))                    # 'api'
    log_type     = db.Column(db.String(16), index=True)        # firewall|dhcp|wifi|dns|system
    action       = db.Column(db.String(16))                    # allow|block|drop
    direction    = db.Column(db.String(16))                    # inbound|outbound|inter_vlan|local
    src_ip       = db.Column(db.String(64), index=True)
    dst_ip       = db.Column(db.String(64), index=True)
    src_port     = db.Column(db.Integer)
    dst_port     = db.Column(db.Integer)
    protocol     = db.Column(db.String(8))
    interface    = db.Column(db.String(32))
    rule_id      = db.Column(db.String(64))
    mac          = db.Column(db.String(17))
    country      = db.Column(db.String(64))                    # from GeoIP
    country_code = db.Column(db.String(4))
    city         = db.Column(db.String(64))
    msg          = db.Column(db.String(512))                   # human-readable summary
    raw          = db.Column(db.Text)                          # raw event data for debugging
    created_at   = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<UnifiLogEntry {self.log_type} {self.action} {self.src_ip}->{self.dst_ip}>"


class RevokedToken(db.Model):
    """Revoked JWT refresh tokens.  Pruned daily by the scheduler."""
    __tablename__ = "revoked_tokens"

    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False)

    def __repr__(self):
        return f"<RevokedToken jti={self.jti}>"


class UserSession(db.Model):
    """A server-side record of a browser login session (Flask-Login cookie session).

    Lets users and admins see and revoke active sessions.  Only a hash of the
    opaque session id is stored; the plaintext id lives in the Flask session
    cookie.  A session is considered active when ``revoked`` is False.
    """
    __tablename__ = "user_sessions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    # SHA-256 hex digest of the opaque session id (never store the raw id).
    session_id_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(256), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    revoked = db.Column(db.Boolean, default=False, nullable=False, index=True)

    user = db.relationship("User", backref=db.backref("sessions", cascade="all, delete-orphan"))

    def __repr__(self):
        return f"<UserSession user={self.user_id} revoked={self.revoked}>"


class PushWebhook(db.Model):
    """Mobile push notification webhook registration."""
    __tablename__ = "push_webhooks"

    VALID_EVENTS = {"security_update", "service_down", "service_failed", "service_recovered", "reboot_required", "guest_error"}

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    url = db.Column(db.String(512), nullable=False)
    device_token = db.Column(db.String(512), nullable=False)
    platform = db.Column(db.String(10), nullable=False)   # ios, android
    events = db.Column(db.Text, nullable=False)            # JSON array
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user = db.relationship("User", backref="push_webhooks")

    def __repr__(self):
        return f"<PushWebhook user={self.user_id} platform={self.platform}>"
