"""Tests for the startup schema migrations in app.py.

The migration branches only run against a database whose tables predate a
feature, which ``db.create_all()`` in the normal test fixture never produces.
These tests therefore build a legacy-shaped SQLite file with raw SQL *before*
calling ``create_app()``, so the ALTER TABLE / backfill paths actually execute.
"""
import os
import sqlite3
import tempfile

import pytest

# Column set of the ``roles`` table as it existed before the IPMI and
# moderation permissions were added.
_LEGACY_ROLES_DDL = """
CREATE TABLE roles (
    id INTEGER NOT NULL PRIMARY KEY,
    name VARCHAR(64) NOT NULL UNIQUE,
    display_name VARCHAR(128) NOT NULL,
    level INTEGER NOT NULL,
    is_builtin BOOLEAN,
    base_tier VARCHAR(16),
    can_ssh BOOLEAN,
    can_update BOOLEAN,
    can_manage_users BOOLEAN,
    can_manage_settings BOOLEAN,
    can_manage_credentials BOOLEAN,
    can_view_hosts BOOLEAN,
    can_manage_hosts BOOLEAN,
    can_manage_guests BOOLEAN,
    can_restart_unifi BOOLEAN,
    can_view_audit_log BOOLEAN,
    can_view_services BOOLEAN,
    can_edit_services BOOLEAN,
    can_view_unifi BOOLEAN,
    created_at DATETIME
)
"""

_LEGACY_ROLE_ROWS = [
    ("super_admin", "Super Admin", 4),
    ("admin", "Admin", 3),
    ("operator", "Operator", 2),
    ("viewer", "Viewer", 1),
]


def _write_legacy_roles(db_path):
    """Create a pre-IPMI ``roles`` table with the four built-in roles."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(_LEGACY_ROLES_DDL)
        for name, display_name, level in _LEGACY_ROLE_ROWS:
            conn.execute(
                "INSERT INTO roles (name, display_name, level, is_builtin) VALUES (?, ?, ?, 1)",
                (name, display_name, level),
            )
        conn.commit()
    finally:
        conn.close()


def _boot(db_path):
    """Run create_app() against the given SQLite file and return the app."""
    from app import create_app

    return create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_path}",
        "SECRET_KEY": "test-secret-key",
        "WTF_CSRF_ENABLED": False,
    })


def _role_perms(app, name):
    from models import Role

    with app.app_context():
        role = Role.query.filter_by(name=name).first()
        assert role is not None, f"role {name} missing"
        return {f: getattr(role, f) for f in Role.PERMISSION_FIELDS}


@pytest.fixture()
def legacy_db():
    """Path to a throwaway SQLite file holding a pre-IPMI schema."""
    tmp_dir = tempfile.mkdtemp(prefix="mstdnca-migration-")
    db_path = os.path.join(tmp_dir, "legacy.db").replace("\\", "/")
    _write_legacy_roles(db_path)

    yield db_path

    for name in os.listdir(tmp_dir):  # -wal / -shm may exist once WAL is on
        try:
            os.remove(os.path.join(tmp_dir, name))
        except OSError:
            pass
    try:
        os.rmdir(tmp_dir)
    except OSError:
        pass


class TestIpmiPermissionBackfill:
    def test_admin_roles_get_ipmi_permissions(self, legacy_db):
        """Upgrading must grant the new IPMI perms to the admin-tier roles."""
        app = _boot(legacy_db)

        for role_name in ("super_admin", "admin"):
            perms = _role_perms(app, role_name)
            assert perms["can_view_ipmi"], f"{role_name} lost can_view_ipmi on upgrade"
            assert perms["can_manage_ipmi"], f"{role_name} lost can_manage_ipmi on upgrade"

    def test_non_admin_roles_are_untouched(self, legacy_db):
        app = _boot(legacy_db)

        for role_name in ("operator", "viewer"):
            perms = _role_perms(app, role_name)
            assert not perms["can_view_ipmi"]
            assert not perms["can_manage_ipmi"]

    def test_moderation_backfill_still_applies(self, legacy_db):
        """The pre-existing can_moderate backfill must keep working."""
        app = _boot(legacy_db)

        assert _role_perms(app, "admin")["can_moderate"]
        assert not _role_perms(app, "viewer")["can_moderate"]

    def test_backfill_is_one_time_and_does_not_revert_customisation(self, legacy_db):
        """An admin who removes a builtin role's IPMI perm keeps it removed."""
        from models import Role, db

        app = _boot(legacy_db)
        with app.app_context():
            role = Role.query.filter_by(name="admin").first()
            role.can_manage_ipmi = False
            db.session.commit()

        app2 = _boot(legacy_db)
        assert not _role_perms(app2, "admin")["can_manage_ipmi"]


class TestSqlitePragmas:
    def test_file_database_gets_wal_and_foreign_keys(self, legacy_db):
        from models import db

        app = _boot(legacy_db)
        with app.app_context():
            fk = db.session.execute(db.text("PRAGMA foreign_keys")).scalar()
            journal = db.session.execute(db.text("PRAGMA journal_mode")).scalar()
            busy = db.session.execute(db.text("PRAGMA busy_timeout")).scalar()

        assert fk == 1
        assert str(journal).lower() == "wal"
        assert busy == 30000

    def test_in_memory_database_skips_wal(self):
        """WAL is meaningless for :memory:; the other pragmas still apply."""
        from app import create_app
        from models import db

        app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
                          "SECRET_KEY": "test-secret-key"})
        with app.app_context():
            fk = db.session.execute(db.text("PRAGMA foreign_keys")).scalar()
            journal = db.session.execute(db.text("PRAGMA journal_mode")).scalar()

        assert fk == 1
        assert str(journal).lower() != "wal"


class TestGuestVmidIndexMigration:
    def test_index_is_created_on_an_existing_database(self, legacy_db):
        from models import db

        app = _boot(legacy_db)
        with app.app_context():
            names = {
                row[1]
                for row in db.session.execute(db.text("PRAGMA index_list(guests)")).fetchall()
            }
        assert "uq_guest_host_vmid" in names

    def test_boot_survives_pre_existing_duplicates(self, legacy_db):
        """Duplicate host/VMID rows must produce a warning, not a failed boot."""
        from models import Guest, ProxmoxHost, db

        app = _boot(legacy_db)
        with app.app_context():
            # Drop the index so duplicates can be inserted, as they could be on
            # a database that predates it.
            db.session.execute(db.text("DROP INDEX uq_guest_host_vmid"))
            host = ProxmoxHost(name="dup-host", hostname="10.0.0.1", host_type="pve")
            db.session.add(host)
            db.session.commit()
            db.session.add_all([
                Guest(name="dup-a", guest_type="ct", proxmox_host_id=host.id, vmid=101),
                Guest(name="dup-b", guest_type="ct", proxmox_host_id=host.id, vmid=101),
            ])
            db.session.commit()

        app2 = _boot(legacy_db)  # must not raise
        with app2.app_context():
            names = {
                row[1]
                for row in db.session.execute(db.text("PRAGMA index_list(guests)")).fetchall()
            }
        assert "uq_guest_host_vmid" not in names


class TestGuestViewPermissionAndModeratorRole:
    def test_legacy_builtin_roles_get_can_view_guests(self, legacy_db):
        """Every pre-existing builtin role must gain the new permission."""
        app = _boot(legacy_db)

        for role_name in ("super_admin", "admin", "operator", "viewer"):
            assert _role_perms(app, role_name)["can_view_guests"], (
                f"{role_name} did not get can_view_guests on upgrade"
            )

    def test_legacy_custom_role_gets_can_view_guests(self, legacy_db):
        """A custom (non-builtin) legacy role must also be backfilled."""
        conn = sqlite3.connect(legacy_db)
        try:
            conn.execute(
                "INSERT INTO roles (name, display_name, level, is_builtin) VALUES (?, ?, ?, ?)",
                ("custom_ops", "Custom Ops", 2, 0),
            )
            conn.commit()
        finally:
            conn.close()

        app = _boot(legacy_db)
        assert _role_perms(app, "custom_ops")["can_view_guests"]

    def test_moderator_role_is_inserted(self, legacy_db):
        """The moderator role must be created with can_view_guests left False."""
        from models import Role

        app = _boot(legacy_db)
        with app.app_context():
            role = Role.query.filter_by(name="moderator").first()
            assert role is not None
            assert role.is_builtin
            assert role.level == 2
            assert role.can_moderate
            assert not role.can_view_guests
            for field in Role.PERMISSION_FIELDS:
                if field in ("can_moderate", "can_view_guests"):
                    continue
                assert not getattr(role, field), f"moderator.{field} should be False"

    def test_can_view_guests_backfill_is_one_time(self, legacy_db):
        """An admin who removes the permission from a builtin role keeps it removed."""
        from models import Role, db

        app = _boot(legacy_db)
        with app.app_context():
            role = Role.query.filter_by(name="viewer").first()
            role.can_view_guests = False
            db.session.commit()

        app2 = _boot(legacy_db)
        assert not _role_perms(app2, "viewer")["can_view_guests"]

    def test_pre_existing_custom_moderator_role_is_not_overwritten(self, legacy_db):
        """A pre-existing custom role literally named 'moderator' must be left alone."""
        conn = sqlite3.connect(legacy_db)
        try:
            conn.execute(
                "INSERT INTO roles (name, display_name, level, is_builtin) VALUES (?, ?, ?, ?)",
                ("moderator", "Custom Moderator", 1, 0),
            )
            conn.commit()
        finally:
            conn.close()

        from models import Role

        app = _boot(legacy_db)
        with app.app_context():
            role = Role.query.filter_by(name="moderator").first()
            assert role is not None
            assert role.level == 1
            assert not role.is_builtin
            assert not role.can_moderate


class TestFreshDatabaseRoleSeeding:
    def test_fresh_database_seeds_five_roles_including_moderator(self, app):
        from models import Role

        with app.app_context():
            # The session-scoped ``app`` fixture is shared with other test
            # modules, some of which add their own custom roles -- so this
            # asserts the five builtins are present rather than requiring an
            # exact set (which would be order-dependent on the whole suite).
            names = {role.name for role in Role.query.all()}
            assert {"super_admin", "admin", "operator", "viewer", "moderator"} <= names

            moderator = Role.query.filter_by(name="moderator").first()
            assert moderator.is_builtin
            assert moderator.level == 2
            assert moderator.can_moderate
            assert not moderator.can_view_guests
            assert not moderator.can_use_ai

    def test_can_view_guests_property_by_role(self, app):
        from models import Role, User, db

        with app.app_context():
            def _make_user(username, role_name):
                role = Role.query.filter_by(name=role_name).first()
                user = User.query.filter_by(username=username).first()
                if user is None:
                    user = User(username=username, display_name=username, role_id=role.id)
                    user.set_password("test-only-" + username)
                    db.session.add(user)
                    db.session.commit()
                return user

            admin_user = _make_user("_perm_check_admin", "admin")
            operator_user = _make_user("_perm_check_operator", "operator")
            viewer_user = _make_user("_perm_check_viewer", "viewer")
            moderator_user = _make_user("_perm_check_moderator", "moderator")
            super_admin_user = _make_user("_perm_check_super_admin", "super_admin")

            assert admin_user.can_view_guests
            assert operator_user.can_view_guests
            assert viewer_user.can_view_guests
            assert not moderator_user.can_view_guests
            assert super_admin_user.can_view_guests
