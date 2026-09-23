"""Settings that hold a secret, encrypted at rest with the credential-store key.

Use these helpers instead of ``Setting.get``/``Setting.set`` for any setting
whose value is a password, token, API key, or webhook URL. Values written here
are Fernet ciphertext in the database, which also means the config export
redacts them by value even if the key name were ever to dodge the secret
pattern (see ``core.config_backup``).

Reads tolerate one legacy plaintext value per key: a stored value that is not
Fernet ciphertext at all is returned as-is and re-encrypted in place, so a
setting that predates encryption migrates the first time it is read. A value
that *is* Fernet ciphertext but does not decrypt is a real key problem and is
raised as ``CredentialDecryptError`` rather than silently re-encrypted.
"""

import logging
import re

from auth.credential_store import decrypt, encrypt
from models import Setting

logger = logging.getLogger(__name__)

# Fernet tokens are urlsafe-base64 with a fixed version byte ("gAAAAA...").
_FERNET_LIKE_RE = re.compile(r"^gAAAAA[A-Za-z0-9_=-]{20,}$")


def looks_encrypted(value):
    return isinstance(value, str) and bool(_FERNET_LIKE_RE.match(value))


def get_secret_setting(key, default=""):
    """Return the decrypted value of ``key``, or ``default`` when unset."""
    raw = Setting.get(key, "")
    if not raw:
        return default
    if looks_encrypted(raw):
        return decrypt(raw) or default
    # Legacy plaintext from before this key was encrypted: migrate once.
    logger.info("Migrating legacy plaintext setting %s to encrypted storage", key)
    set_secret_setting(key, raw)
    return raw


def set_secret_setting(key, value):
    """Store ``value`` for ``key`` encrypted; an empty value clears it."""
    Setting.set(key, encrypt(value) if value else "")


def set_secret_setting_no_commit(key, value):
    """Like ``set_secret_setting`` but leaves the commit to the caller."""
    Setting.set_no_commit(key, encrypt(value) if value else "")
