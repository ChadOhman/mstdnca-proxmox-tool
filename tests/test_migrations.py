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
