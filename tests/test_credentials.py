"""Tests for credentials routes and credential_store encrypt/decrypt helpers."""
import pytest

from models import Credential, db

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def credential(app):
    """Seed a single Credential row; clean up after the test."""
    cred_id = None
    with app.app_context():
        import auth.credential_store as credential_store
        cred = Credential(
            name="_test-cred",
            username="root",
            auth_type="password",
            encrypted_value=credential_store.encrypt("hunter2"),
            is_default=False,
        )
        db.session.add(cred)
        db.session.commit()
        cred_id = cred.id

    yield cred_id

    with app.app_context():
        c = Credential.query.get(cred_id)
        if c:
            db.session.delete(c)
            db.session.commit()


@pytest.fixture()
def default_credential(app):
    """Seed a Credential already marked as default; clean up after the test."""
    cred_id = None
    with app.app_context():
        import auth.credential_store as credential_store
        # Unset any pre-existing defaults to keep state predictable.
        Credential.query.filter_by(is_default=True).update({"is_default": False})
        db.session.commit()

        cred = Credential(
            name="_test-default-cred",
            username="admin",
            auth_type="password",
            encrypted_value=credential_store.encrypt("s3cr3t"),
            is_default=True,
        )
        db.session.add(cred)
        db.session.commit()
        cred_id = cred.id

    yield cred_id

    with app.app_context():
        c = Credential.query.get(cred_id)
        if c:
            db.session.delete(c)
            db.session.commit()
        # Restore: no default needed after cleanup.


# ---------------------------------------------------------------------------
# Route: GET /credentials/ — should redirect to /security/
# ---------------------------------------------------------------------------


class TestCredentialsIndex:
    def test_redirects_to_security(self, auth_client):
        resp = auth_client.get("/credentials/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/security/" in resp.headers["Location"]

    def test_unauthenticated_redirects_to_login(self, client):
        resp = client.get("/credentials/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


# ---------------------------------------------------------------------------
# Route: POST /credentials/add
# ---------------------------------------------------------------------------


class TestCredentialAdd:
    def test_add_password_type_happy_path(self, app, auth_client):
        cred_id = None
        try:
            resp = auth_client.post(
                "/credentials/add",
                data={
                    "name": "_test-add-password",
                    "username": "deploy",
                    "auth_type": "password",
                    "password": "MySecretPass!",
                },
                follow_redirects=False,
            )
            assert resp.status_code == 302

            with app.app_context():
                cred = Credential.query.filter_by(name="_test-add-password").first()
                assert cred is not None
                assert cred.username == "deploy"
                assert cred.auth_type == "password"
                assert cred.encrypted_value is not None
                cred_id = cred.id
        finally:
            if cred_id is not None:
                with app.app_context():
                    c = Credential.query.get(cred_id)
                    if c:
                        db.session.delete(c)
                        db.session.commit()

    def test_add_key_type_happy_path(self, app, auth_client):
        cred_id = None
        try:
            resp = auth_client.post(
                "/credentials/add",
                data={
                    "name": "_test-add-key",
                    "username": "ubuntu",
                    "auth_type": "key",
                    "private_key": "not-a-real-key-just-test-data",
                },
                follow_redirects=False,
            )
            assert resp.status_code == 302

            with app.app_context():
                cred = Credential.query.filter_by(name="_test-add-key").first()
                assert cred is not None
                assert cred.auth_type == "key"
                assert cred.encrypted_value is not None
                cred_id = cred.id
        finally:
            if cred_id is not None:
                with app.app_context():
                    c = Credential.query.get(cred_id)
                    if c:
                        db.session.delete(c)
                        db.session.commit()

    def test_add_missing_name_redirects_with_flash(self, app, auth_client):
        resp = auth_client.post(
            "/credentials/add",
            data={
                "name": "",
                "auth_type": "password",
                "password": "something",
            },
            follow_redirects=False,
        )
        # Validation failure: redirect back to security page, no new row
        assert resp.status_code == 302
        with app.app_context():
            assert Credential.query.filter_by(name="").count() == 0

    def test_add_missing_value_redirects_with_flash(self, app, auth_client):
        resp = auth_client.post(
            "/credentials/add",
            data={
                "name": "_test-no-value",
                "auth_type": "password",
                "password": "",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302
        with app.app_context():
            assert Credential.query.filter_by(name="_test-no-value").count() == 0

    def test_add_with_is_default_clears_other_defaults(self, app, auth_client, default_credential):
        new_id = None
        try:
            resp = auth_client.post(
                "/credentials/add",
                data={
                    "name": "_test-add-becomes-default",
                    "username": "root",
                    "auth_type": "password",
                    "password": "newdefaultpass",
                    "is_default": "1",
                },
                follow_redirects=False,
            )
            assert resp.status_code == 302

            with app.app_context():
                new_cred = Credential.query.filter_by(name="_test-add-becomes-default").first()
                assert new_cred is not None
                assert new_cred.is_default is True
                new_id = new_cred.id

                # The previously-default credential must no longer be default.
                old_cred = Credential.query.get(default_credential)
                assert old_cred is not None
                assert old_cred.is_default is False
        finally:
            if new_id is not None:
                with app.app_context():
                    c = Credential.query.get(new_id)
                    if c:
                        db.session.delete(c)
                        db.session.commit()


# ---------------------------------------------------------------------------
# Route: POST /credentials/<id>/edit
# ---------------------------------------------------------------------------


class TestCredentialEdit:
    def test_edit_name_and_username(self, app, auth_client, credential):
        resp = auth_client.post(
            f"/credentials/{credential}/edit",
            data={
                "name": "_test-cred-renamed",
                "username": "newuser",
                "auth_type": "",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            cred = Credential.query.get(credential)
            assert cred.name == "_test-cred-renamed"
            assert cred.username == "newuser"

    def test_edit_missing_name_does_not_update(self, app, auth_client, credential):
        resp = auth_client.post(
            f"/credentials/{credential}/edit",
            data={
                "name": "",
                "username": "ignored",
                "auth_type": "",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            cred = Credential.query.get(credential)
            # Name must be unchanged from the seeded value (or whatever the
            # test_edit_name_and_username test may have set it to — fixture
            # provides a fresh row per-test so the original name is "_test-cred").
            assert cred.name != ""

    def test_edit_updates_password_value(self, app, auth_client, credential):
        resp = auth_client.post(
            f"/credentials/{credential}/edit",
            data={
                "name": "_test-cred",
                "username": "root",
                "auth_type": "password",
                "password": "NewPassword99!",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            import auth.credential_store as credential_store
            cred = Credential.query.get(credential)
            decrypted = credential_store.decrypt(cred.encrypted_value)
            assert decrypted == "NewPassword99!"

    def test_edit_nonexistent_returns_404(self, auth_client):
        resp = auth_client.post(
            "/credentials/999999/edit",
            data={"name": "ghost", "username": "root", "auth_type": ""},
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Route: POST /credentials/<id>/set-default
# ---------------------------------------------------------------------------


class TestCredentialSetDefault:
    def test_set_default_marks_credential(self, app, auth_client, credential):
        resp = auth_client.post(
            f"/credentials/{credential}/set-default",
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            cred = Credential.query.get(credential)
            assert cred.is_default is True

    def test_set_default_unsets_previous_default(self, app, auth_client, credential, default_credential):
        resp = auth_client.post(
            f"/credentials/{credential}/set-default",
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            old = Credential.query.get(default_credential)
            assert old.is_default is False
            new = Credential.query.get(credential)
            assert new.is_default is True

    def test_set_default_nonexistent_returns_404(self, auth_client):
        resp = auth_client.post("/credentials/999999/set-default")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Route: POST /credentials/<id>/delete
# ---------------------------------------------------------------------------


class TestCredentialDelete:
    def test_delete_removes_row(self, app, auth_client, credential):
        resp = auth_client.post(
            f"/credentials/{credential}/delete",
            follow_redirects=False,
        )
        assert resp.status_code == 302

        with app.app_context():
            assert Credential.query.get(credential) is None

    def test_delete_nonexistent_returns_404(self, auth_client):
        resp = auth_client.post("/credentials/999999/delete")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Unit tests: credential_store encrypt / decrypt
# ---------------------------------------------------------------------------


class TestCredentialStore:
    """Pure unit tests for encrypt() and decrypt() — no Flask context required."""

    @pytest.fixture(autouse=True)
    def _isolated_key(self, monkeypatch, tmp_path):
        """
        Point MSTDNCA_SECRET_KEY at a temporary file and reset the cached
        Fernet instance so every test starts with a fresh, known key.
        """
        import auth.credential_store as credential_store

        key_path = str(tmp_path / "test_secret.key")
        monkeypatch.setenv("MSTDNCA_SECRET_KEY", key_path)

        # Patch SECRET_KEY_PATH in config and credential_store together.
        import config as cfg
        monkeypatch.setattr(cfg, "SECRET_KEY_PATH", key_path)
        monkeypatch.setattr(credential_store, "_fernet", None)

        yield

        # Reset cache after each test so a subsequent test's monkeypatch takes effect.
        credential_store._fernet = None

    def test_encrypt_decrypt_roundtrip(self):
        from auth.credential_store import decrypt, encrypt

        plaintext = "super-secret-value-42"
        ciphertext = encrypt(plaintext)
        assert ciphertext is not None
        assert ciphertext != plaintext
        assert decrypt(ciphertext) == plaintext

    def test_encrypt_none_returns_none(self):
        from auth.credential_store import encrypt

        assert encrypt(None) is None

    def test_encrypt_empty_string_returns_none(self):
        """encrypt() treats empty string the same as None (falsy check)."""
        from auth.credential_store import encrypt

        assert encrypt("") is None

    def test_decrypt_none_returns_none(self):
        from auth.credential_store import decrypt

        assert decrypt(None) is None

    def test_decrypt_empty_string_returns_none(self):
        from auth.credential_store import decrypt

        assert decrypt("") is None

    def test_ciphertext_differs_each_call(self):
        """Fernet produces a unique ciphertext on every call (random IV)."""
        from auth.credential_store import encrypt

        plaintext = "same-input"
        ct1 = encrypt(plaintext)
        ct2 = encrypt(plaintext)
        assert ct1 != ct2


# ---------------------------------------------------------------------------
# Delete guard and auth_type validation (issue #127)
# ---------------------------------------------------------------------------


class TestCredentialDeleteInUse:
    def test_delete_refused_while_a_guest_uses_it(self, auth_client, app, credential):
        from models import Guest

        with app.app_context():
            guest = Guest(name="_cred-inuse-guest", guest_type="ct", credential_id=credential)
            db.session.add(guest)
            db.session.commit()
            guest_id = guest.id

        try:
            resp = auth_client.post(f"/credentials/{credential}/delete", follow_redirects=True)
            assert resp.status_code == 200
            assert b"still used by" in resp.data
            with app.app_context():
                assert Credential.query.get(credential) is not None
        finally:
            with app.app_context():
                g = Guest.query.get(guest_id)
                if g:
                    db.session.delete(g)
                    db.session.commit()

    def test_delete_refused_while_a_host_uses_it(self, auth_client, app, credential):
        from models import ProxmoxHost

        with app.app_context():
            host = ProxmoxHost(name="_cred-inuse-host", hostname="10.8.0.1",
                               host_type="pve", ssh_credential_id=credential)
            db.session.add(host)
            db.session.commit()
            host_id = host.id

        try:
            resp = auth_client.post(f"/credentials/{credential}/delete", follow_redirects=True)
            assert resp.status_code == 200
            assert b"host(s)" in resp.data
            with app.app_context():
                assert Credential.query.get(credential) is not None
        finally:
            with app.app_context():
                h = ProxmoxHost.query.get(host_id)
                if h:
                    db.session.delete(h)
                    db.session.commit()

    def test_delete_succeeds_when_unreferenced(self, auth_client, app, credential):
        resp = auth_client.post(f"/credentials/{credential}/delete", follow_redirects=True)
        assert resp.status_code == 200
        with app.app_context():
            assert Credential.query.get(credential) is None


class TestCredentialAuthTypeValidation:
    def test_add_rejects_unknown_auth_type(self, auth_client, app):
        resp = auth_client.post(
            "/credentials/add",
            data={"name": "_bad-authtype", "username": "root",
                  "auth_type": "kerberos", "password": "test-only-password"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        with app.app_context():
            assert Credential.query.filter_by(name="_bad-authtype").first() is None

    def test_add_accepts_key_auth_type(self, auth_client, app):
        resp = auth_client.post(
            "/credentials/add",
            data={"name": "_good-authtype", "username": "root",
                  "auth_type": "key", "private_key": "test-only-key-material"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        with app.app_context():
            cred = Credential.query.filter_by(name="_good-authtype").first()
            assert cred is not None
            assert cred.auth_type == "key"
            db.session.delete(cred)
            db.session.commit()

    def test_edit_rejects_unknown_auth_type(self, auth_client, app, credential):
        resp = auth_client.post(
            f"/credentials/{credential}/edit",
            data={"name": "_test-cred", "username": "root",
                  "auth_type": "kerberos", "password": "test-only-password"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        with app.app_context():
            assert Credential.query.get(credential).auth_type == "password"
