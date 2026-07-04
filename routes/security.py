import re

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from auth.audit import log_action
from models import AuditLog, Credential, Role, ScanResult, Setting, Tag, TagUnifiNetwork, User, UserSession, db

# Strict hex-color validation: #RRGGBB only
_HEX_COLOR_RE = re.compile(r'^#[0-9a-fA-F]{6}$')

bp = Blueprint("security", __name__)


def _safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_int_list(values):
    parsed = []
    for v in values:
        iv = _safe_int(v)
        if iv is None:
            return None
        parsed.append(iv)
    return parsed


@bp.before_request
@login_required
def _require_access():
    # Roles, tags, and access management: super_admin only
    if request.path.startswith("/security/roles") or request.path.startswith("/security/tags") or request.path.startswith("/security/access"):
        if not current_user.is_super_admin:
            flash("Super admin access required.", "error")
            return redirect(url_for("dashboard.index"))
    # Users management: can_manage_users permission
    elif not current_user.can_manage_users:
        flash("Admin access required.", "error")
        return redirect(url_for("dashboard.index"))


def _get_access_settings():
    """Settings needed for the Access tab."""
    return {
        "cf_access_enabled": Setting.get("cf_access_enabled", "false"),
        "cf_access_team_domain": Setting.get("cf_access_team_domain", ""),
        "cf_access_audience": Setting.get("cf_access_audience", ""),
        "cf_access_auto_provision": Setting.get("cf_access_auto_provision", "true"),
        "cf_access_bypass_local_auth": Setting.get("cf_access_bypass_local_auth", "false"),
        "local_bypass_enabled": Setting.get("local_bypass_enabled", "false"),
        "local_bypass_explicitly_set": Setting.query.filter_by(key="local_bypass_enabled").first() is not None,
        "trusted_subnets": Setting.get("trusted_subnets", "10.0.0.0/8"),
        "require_snapshot_before_action": Setting.get("require_snapshot_before_action", "false"),
    }


@bp.route("/")
def index():
    users = User.query.options(db.joinedload(User.role_obj)).order_by(User.username).all()
    roles = Role.query.order_by(Role.level.desc(), Role.name).all()
    tags = Tag.query.options(db.joinedload(Tag.unifi_networks)).order_by(Tag.name).all()
    settings = _get_access_settings() if current_user.is_super_admin else {}

    audit_pagination = None
    if current_user.can_view_audit_log:
        page = request.args.get("audit_page", 1, type=int)
        audit_pagination = (AuditLog.query
                            .order_by(AuditLog.timestamp.desc())
                            .paginate(page=page, per_page=50, error_out=False))

    # Fetch available UniFi networks for the tag-network link UI (super_admin only)
    unifi_networks_available = []
    if current_user.is_super_admin and Setting.get("unifi_enabled", "false") == "true":
        try:
            from routes.unifi import _get_unifi_client
            client = _get_unifi_client()
            if client:
                unifi_networks_available = client.get_networks()
        except Exception:
            pass

    credentials = []
    if current_user.is_super_admin:
        credentials = Credential.query.order_by(Credential.is_default.desc(), Credential.name).all()

    recent_scans = (
        ScanResult.query
        .order_by(ScanResult.scanned_at.desc())
        .limit(50)
        .all()
    )

    # Active login sessions across all users (user-management permission is
    # already enforced by _require_access for the users view).
    active_sessions = (
        UserSession.query
        .options(db.joinedload(UserSession.user))
        .filter_by(revoked=False)
        .order_by(UserSession.last_seen_at.desc())
        .all()
    )

    return render_template("security.html", users=users, roles=roles, tags=tags,
                           settings=settings, audit_pagination=audit_pagination,
                           unifi_networks_available=unifi_networks_available,
                           credentials=credentials, recent_scans=recent_scans,
                           active_sessions=active_sessions)


@bp.route("/sessions/<int:session_pk>/revoke", methods=["POST"])
def revoke_user_session(session_pk):
    """Admins with user-management permission may revoke any user's session."""
    record = UserSession.query.get_or_404(session_pk)
    target_user = record.user
    if not record.revoked:
        record.revoked = True
        log_action("session_revoke", "user_session", resource_id=record.id,
                   resource_name=target_user.username if target_user else None,
                   details={"target_user_id": record.user_id})
        db.session.commit()
        flash("Session revoked.", "success")
    return redirect(url_for("security.index"))


# --- User management ---

@bp.route("/users/add", methods=["POST"])
def add_user():
    username = request.form.get("username", "").strip().lower()
    display_name = request.form.get("display_name", "").strip()
    password = request.form.get("password", "")
    role_id = request.form.get("role_id", "")
    tag_ids = request.form.getlist("tag_ids")

    if not username or not password:
        flash("Username and password are required.", "error")
        return redirect(url_for("security.index"))

    if User.query.filter_by(username=username).first():
        flash(f"Username '{username}' already exists.", "error")
        return redirect(url_for("security.index"))

    if len(password) < 8:
        flash("Password must be at least 8 characters.", "error")
        return redirect(url_for("security.index"))

    # Resolve role
    parsed_role_id = _safe_int(role_id) if role_id else None
    if role_id and parsed_role_id is None:
        flash("Invalid role selection.", "error")
        return redirect(url_for("security.index"))

    target_role = Role.query.get(parsed_role_id) if parsed_role_id else None
    if not target_role:
        target_role = Role.query.filter_by(name="viewer").first()

    # Cannot assign a role with equal or higher level (unless super_admin)
    if target_role.level >= current_user.role_level and not current_user.is_super_admin:
        flash("You cannot create a user with an equal or higher role.", "error")
        return redirect(url_for("security.index"))

    user = User(
        username=username,
        display_name=display_name or username,
        role_id=target_role.id,
    )
    user.set_password(password)

    if tag_ids:
        parsed_tag_ids = _safe_int_list(tag_ids)
        if parsed_tag_ids is None:
            flash("Invalid tag selection.", "error")
            return redirect(url_for("security.index"))
        tags = Tag.query.filter(Tag.id.in_(parsed_tag_ids)).all()
        user.allowed_tags = tags

    db.session.add(user)
    db.session.flush()
    log_action("user_add", "user", resource_id=user.id, resource_name=username,
               details={"role": target_role.name})
    db.session.commit()

    flash(f"User '{username}' created.", "success")
    return redirect(url_for("security.index"))


@bp.route("/users/<int:user_id>/edit", methods=["POST"])
def edit_user(user_id):
    user = User.query.get_or_404(user_id)

    if not current_user.can_edit_user(user):
        flash("You cannot edit a user with an equal or higher role.", "error")
        return redirect(url_for("security.index"))

    user.display_name = request.form.get("display_name", user.display_name).strip()
    if user.id != current_user.id:
        user.is_active_user = "is_active" in request.form

    # Role change (only if not editing self)
    new_role_id = request.form.get("role_id", "")
    if new_role_id and user.id != current_user.id:
        parsed_new_role_id = _safe_int(new_role_id)
        if parsed_new_role_id is None:
            flash("Invalid role selection.", "error")
            return redirect(url_for("security.index"))
        target_role = Role.query.get(parsed_new_role_id)
        if target_role:
            if target_role.level >= current_user.role_level and not current_user.is_super_admin:
                flash("You cannot assign a role equal to or higher than your own.", "error")
                return redirect(url_for("security.index"))
            user.role_id = target_role.id

    tag_ids = request.form.getlist("tag_ids")
    if tag_ids:
        parsed_tag_ids = _safe_int_list(tag_ids)
        if parsed_tag_ids is None:
            flash("Invalid tag selection.", "error")
            return redirect(url_for("security.index"))
        tags = Tag.query.filter(Tag.id.in_(parsed_tag_ids)).all()
    else:
        tags = []
    user.allowed_tags = tags

    new_password = request.form.get("new_password", "").strip()
    if new_password:
        if user.created_via == "cloudflare":
            flash("Cannot set a password for a Cloudflare-authenticated user.", "error")
            return redirect(url_for("security.index"))
        if len(new_password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return redirect(url_for("security.index"))
        user.set_password(new_password)

    log_action("user_edit", "user", resource_id=user.id, resource_name=user.username)
    db.session.commit()
    flash(f"User '{user.username}' updated.", "success")
    return redirect(url_for("security.index"))


@bp.route("/users/<int:user_id>/delete", methods=["POST"])
def delete_user(user_id):
    if user_id == current_user.id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("security.index"))

    user = User.query.get_or_404(user_id)

    if not current_user.can_edit_user(user):
        flash("You cannot delete a user with an equal or higher role.", "error")
        return redirect(url_for("security.index"))

    username = user.username
    log_action("user_delete", "user", resource_id=user.id, resource_name=username)
    db.session.delete(user)
    db.session.commit()
    flash(f"User '{username}' deleted.", "warning")
    return redirect(url_for("security.index"))


# --- Role management (super_admin only, enforced by before_request) ---

@bp.route("/roles/add", methods=["POST"])
def add_role():
    name = request.form.get("name", "").strip().lower().replace(" ", "_")
    display_name = request.form.get("display_name", "").strip()
    base_tier = request.form.get("base_tier", "viewer")

    if not name or not display_name:
        flash("Role name and display name are required.", "error")
        return redirect(url_for("security.index"))

    if Role.query.filter_by(name=name).first():
        flash(f"Role '{name}' already exists.", "error")
        return redirect(url_for("security.index"))

    level = Role.BASE_TIER_LEVELS.get(base_tier, 1)

    role = Role(
        name=name,
        display_name=display_name,
        level=level,
        is_builtin=False,
        base_tier=base_tier,
    )

    # Set permissions from form checkboxes
    for perm in Role.PERMISSION_FIELDS:
        setattr(role, perm, perm in request.form)

    db.session.add(role)
    db.session.flush()
    log_action("role_add", "role", resource_id=role.id, resource_name=display_name)
    db.session.commit()

    flash(f"Role '{display_name}' created.", "success")
    return redirect(url_for("security.index"))


@bp.route("/roles/<int:role_id>/edit", methods=["POST"])
def edit_role(role_id):
    role = Role.query.get_or_404(role_id)

    if role.name == "super_admin":
        flash("The Super Admin role cannot be edited.", "error")
        return redirect(url_for("security.index"))

    # For custom roles, allow editing display_name and base_tier
    if not role.is_builtin:
        new_display = request.form.get("display_name", "").strip()
        if new_display:
            role.display_name = new_display

        new_tier = request.form.get("base_tier", "")
        if new_tier and new_tier in Role.BASE_TIER_LEVELS:
            role.base_tier = new_tier
            role.level = Role.BASE_TIER_LEVELS[new_tier]

    # Update permissions from checkboxes
    for perm in Role.PERMISSION_FIELDS:
        setattr(role, perm, perm in request.form)

    log_action("role_edit", "role", resource_id=role.id, resource_name=role.display_name)
    db.session.commit()
    flash(f"Role '{role.display_name}' updated.", "success")
    return redirect(url_for("security.index"))


@bp.route("/roles/<int:role_id>/delete", methods=["POST"])
def delete_role(role_id):
    role = Role.query.get_or_404(role_id)

    if role.is_builtin:
        flash("Built-in roles cannot be deleted.", "error")
        return redirect(url_for("security.index"))

    if role.users:
        flash(f"Cannot delete role '{role.display_name}' — {len(role.users)} user(s) are assigned to it. Reassign them first.", "error")
        return redirect(url_for("security.index"))

    name = role.display_name
    log_action("role_delete", "role", resource_id=role.id, resource_name=name)
    db.session.delete(role)
    db.session.commit()
    flash(f"Role '{name}' deleted.", "warning")
    return redirect(url_for("security.index"))


# --- Tag management (super_admin only, enforced by before_request) ---

@bp.route("/tags/add", methods=["POST"])
def add_tag():
    name = request.form.get("name", "").strip()
    color = request.form.get("color", "#6c757d").strip()

    if not name:
        flash("Tag name is required.", "error")
        return redirect(url_for("security.index"))

    if not _HEX_COLOR_RE.match(color):
        color = "#6c757d"  # fallback to default grey for invalid colors

    if Tag.query.filter_by(name=name).first():
        flash(f"Tag '{name}' already exists.", "error")
        return redirect(url_for("security.index"))

    tag = Tag(name=name, color=color)
    db.session.add(tag)
    db.session.flush()
    log_action("tag_add", "tag", resource_id=tag.id, resource_name=name)
    db.session.commit()

    flash(f"Tag '{name}' created.", "success")
    return redirect(url_for("security.index"))


@bp.route("/tags/<int:tag_id>/delete", methods=["POST"])
def delete_tag(tag_id):
    tag = Tag.query.get_or_404(tag_id)
    name = tag.name
    log_action("tag_delete", "tag", resource_id=tag.id, resource_name=name)
    db.session.delete(tag)
    db.session.commit()
    flash(f"Tag '{name}' deleted.", "warning")
    return redirect(url_for("security.index"))


@bp.route("/tags/<int:tag_id>/networks", methods=["POST"])
def set_tag_networks(tag_id):
    tag = Tag.query.get_or_404(tag_id)
    network_names = request.form.getlist("network_names")
    # Validate: names must be non-empty strings, no SQL injection via ORM
    network_names = [n.strip() for n in network_names if n.strip()]

    TagUnifiNetwork.query.filter_by(tag_id=tag_id).delete()
    for name in network_names:
        db.session.add(TagUnifiNetwork(tag_id=tag_id, network_name=name))

    log_action("tag_networks_update", "tag", resource_id=tag.id, resource_name=tag.name,
               details={"networks": network_names})
    db.session.commit()
    flash(f"Network links updated for tag '{tag.name}'.", "success")
    return redirect(url_for("security.index"))


# --- Access settings (super_admin only, enforced by before_request) ---

@bp.route("/access/cloudflare", methods=["POST"])
def save_cloudflare():
    cf_enabled = "cf_access_enabled" in request.form
    team_domain = request.form.get("cf_access_team_domain", "").strip()
    audience = request.form.get("cf_access_audience", "").strip()
    auto_provision = "cf_access_auto_provision" in request.form
    bypass_local = "cf_access_bypass_local_auth" in request.form

    if bypass_local and cf_enabled:
        if not team_domain or not audience:
            flash("Team domain and audience tag are required to enable CF Access-only mode.", "error")
            return redirect(url_for("security.index"))

    Setting.set("cf_access_enabled", "true" if cf_enabled else "false")
    Setting.set("cf_access_team_domain", team_domain)
    Setting.set("cf_access_audience", audience)
    Setting.set("cf_access_auto_provision", "true" if auto_provision else "false")
    Setting.set("cf_access_bypass_local_auth", "true" if bypass_local else "false")

    log_action("settings_cloudflare_save", "settings", resource_name="cloudflare_access")
    db.session.commit()
    flash("Cloudflare Zero Trust settings saved.", "success")
    return redirect(url_for("security.index"))


@bp.route("/access/local-bypass", methods=["POST"])
def save_local_bypass():
    import ipaddress

    enabled = "local_bypass_enabled" in request.form
    subnets = request.form.get("trusted_subnets", "10.0.0.0/8").strip()

    if subnets:
        for entry in subnets.split(","):
            entry = entry.strip()
            if not entry:
                continue
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError:
                flash(f"Invalid subnet: {entry}", "error")
                return redirect(url_for("security.index"))

    Setting.set("local_bypass_enabled", "true" if enabled else "false")
    Setting.set("trusted_subnets", subnets)

    log_action("settings_local_bypass_save", "settings", resource_name="local_bypass",
               details={"enabled": enabled})
    db.session.commit()
    flash("Local network access settings saved.", "success")
    return redirect(url_for("security.index"))


@bp.route("/access/dismiss-bypass-notice", methods=["POST"])
def dismiss_bypass_notice():
    """Explicitly record that the user has acknowledged the default change."""
    Setting.set("local_bypass_enabled", "false")
    log_action("bypass_notice_dismiss", "settings", resource_name="local_bypass")
    db.session.commit()
    return redirect(url_for("security.index"))


@bp.route("/access/snapshots", methods=["POST"])
def save_snapshots():
    require_snapshot = "require_snapshot_before_action" in request.form
    Setting.set("require_snapshot_before_action", "true" if require_snapshot else "false")

    log_action("settings_snapshots_save", "settings", resource_name="snapshots",
               details={"require_snapshot": require_snapshot})
    db.session.commit()
    flash("Snapshot settings saved.", "success")
    return redirect(url_for("security.index"))
