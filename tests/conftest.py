import os
import shutil
import tempfile

import pytest

from app import create_app
from models import Role, User
from models import db as _db

_TEST_ADMIN_PASSWORD = "TestPass123!"
_TEST_MODERATOR_PASSWORD = "test-only-ModeratorPass123!"

# The suite uses a file-backed SQLite database in a per-session temp directory
# rather than ``sqlite:///:memory:``.  An in-memory database is served through
# a single shared connection (StaticPool) that is not safe to use from several
# threads at once, and the app legitimately starts background threads (scan and
# update jobs) that touch the DB -- with ``:memory:`` those raced against the
# test that spawned them and produced intermittent ObjectDeletedError /
# StaleDataError / "no such row" failures.  A real file gets one connection per
# thread plus the WAL + busy_timeout pragmas applied by app.py, exactly like
# production.
_TEST_DB_DIR = tempfile.mkdtemp(prefix="mstdnca-testdb-")
_TEST_DB_PATH = os.path.join(_TEST_DB_DIR, "test.sqlite3")

_TEST_CONFIG = {
    "TESTING": True,
    "SQLALCHEMY_DATABASE_URI": "sqlite:///" + _TEST_DB_PATH.replace(os.sep, "/"),
    "SECRET_KEY": "test-secret-key",
    "WTF_CSRF_ENABLED": False,
}


@pytest.fixture(autouse=True, scope="session")
def _isolate_credential_store():
    """Redirect credential_store key to a temp file so tests never touch /etc/mstdnca."""
    import auth.credential_store as credential_store
    import config as cfg

    tmp_dir = tempfile.mkdtemp(prefix="mstdnca-test-")
    key_path = os.path.join(tmp_dir, "secret.key")
    original_path = cfg.SECRET_KEY_PATH
    original_fernet = credential_store._fernet

    cfg.SECRET_KEY_PATH = key_path
    os.environ["MSTDNCA_SECRET_KEY"] = key_path
    credential_store._fernet = None

    yield

    cfg.SECRET_KEY_PATH = original_path
    os.environ.pop("MSTDNCA_SECRET_KEY", None)
    credential_store._fernet = original_fernet

    # Clean up temp key file
    if os.path.exists(key_path):
        os.remove(key_path)
    if os.path.exists(tmp_dir):
        os.rmdir(tmp_dir)


@pytest.fixture(scope="session")
def app():
    application = create_app(_TEST_CONFIG)
    with application.app_context():
        admin = User.query.filter_by(username="admin").first()
        if admin:
            admin.set_password(_TEST_ADMIN_PASSWORD)
            _db.session.commit()
    yield application
    # Release every pooled connection before deleting the file (Windows refuses
    # to remove an open database), then drop the per-session directory.
    with application.app_context():
        _db.session.remove()
        _db.engine.dispose()
    shutil.rmtree(_TEST_DB_DIR, ignore_errors=True)


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def auth_client(app):
    """A test client pre-authenticated as the admin user."""
    with app.test_client() as c:
        c.post(
            "/login",
            data={"username": "admin", "password": _TEST_ADMIN_PASSWORD},
            follow_redirects=False,
        )
        yield c


@pytest.fixture(scope="session")
def moderator_user(app):
    """A user in the builtin moderator role, created once per test session."""
    with app.app_context():
        user = User.query.filter_by(username="_moderator_fixture").first()
        if user is None:
            role = Role.query.filter_by(name="moderator").first()
            user = User(username="_moderator_fixture", display_name="Moderator Fixture", role_id=role.id)
            user.set_password(_TEST_MODERATOR_PASSWORD)
            _db.session.add(user)
            _db.session.commit()
        return user.id


@pytest.fixture()
def moderator_client(app, moderator_user):
    """A test client pre-authenticated as the builtin moderator-role user."""
    with app.test_client() as c:
        c.post(
            "/login",
            data={"username": "_moderator_fixture", "password": _TEST_MODERATOR_PASSWORD},
            follow_redirects=False,
        )
        yield c
