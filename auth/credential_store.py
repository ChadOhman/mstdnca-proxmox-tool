import logging
import os
import threading

from cryptography.fernet import Fernet, InvalidToken

from config import SECRET_KEY_PATH

logger = logging.getLogger(__name__)

_fernet: "Fernet | None" = None
_fernet_lock = threading.Lock()


class CredentialStoreError(Exception):
    """Base class for credential-store failures."""


class CredentialKeyMissingError(CredentialStoreError):
    """The Fernet key file is gone but encrypted data still references it.

    Silently generating a replacement would leave every stored secret
    permanently undecryptable behind an opaque ``InvalidToken``, so the store
    refuses to start instead and asks for the original key to be restored.
    """


class CredentialDecryptError(CredentialStoreError):
    """A stored ciphertext could not be decrypted with the current key."""


def _ciphertext_exists() -> bool:
    """True when the database already holds secrets encrypted with some key.

    Returns False when the question cannot be answered (no app context, tables
    not created yet, database unreachable) -- a fresh install must still be able
    to generate its first key.
    """
    try:
        from flask import has_app_context
        if not has_app_context():
            return False
        from models import Credential, ProxmoxHost, db

        has_credential = db.session.query(
            Credential.query.filter(Credential.encrypted_value.isnot(None)).exists()
        ).scalar()
        if has_credential:
            return True
        return bool(db.session.query(
            ProxmoxHost.query.filter(
                db.or_(
                    ProxmoxHost.encrypted_password.isnot(None),
                    ProxmoxHost.api_token_secret.isnot(None),
                )
            ).exists()
        ).scalar())
    except Exception:
        logger.debug("Could not check for existing ciphertext before key generation", exc_info=True)
        return False


def _get_or_create_key():
    key_dir = os.path.dirname(SECRET_KEY_PATH)
    if key_dir and not os.path.exists(key_dir):
        os.makedirs(key_dir, mode=0o700, exist_ok=True)

    if os.path.exists(SECRET_KEY_PATH):
        with open(SECRET_KEY_PATH, "rb") as f:
            return f.read()

    if _ciphertext_exists():
        raise CredentialKeyMissingError(
            f"The credential encryption key {SECRET_KEY_PATH} is missing but encrypted "
            "credentials are still stored in the database. Restore the key file from "
            "backup (mode 0600) instead of letting a new one be generated -- generating "
            "one would orphan every stored secret. If the key is unrecoverable, delete "
            "the affected credentials/hosts and re-enter them."
        )

    key = Fernet.generate_key()
    # O_EXCL so the mode is applied atomically at creation instead of through a
    # umask-widened open followed by chmod, and so an existing path (including a
    # symlink planted by another user) is never followed.
    fd = os.open(SECRET_KEY_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    return key


def get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        with _fernet_lock:
            if _fernet is None:
                _fernet = Fernet(_get_or_create_key())
    return _fernet


def encrypt(plaintext):
    if not plaintext:
        return None
    f = get_fernet()
    return f.encrypt(plaintext.encode()).decode()


def decrypt(ciphertext):
    if not ciphertext:
        return None
    f = get_fernet()
    try:
        return f.decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise CredentialDecryptError(
            f"Stored secret could not be decrypted with the key at {SECRET_KEY_PATH}. "
            "The key was most likely replaced or restored from a different backup than "
            "the database; restore the matching key file, or re-enter this credential."
        ) from exc
