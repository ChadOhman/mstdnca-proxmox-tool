import os
from datetime import timedelta

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("MSTDNCA_DATA_DIR", "/var/lib/mstdnca")
SECRET_KEY_PATH = os.environ.get("MSTDNCA_SECRET_KEY", "/etc/mstdnca/secret.key")


def _load_flask_secret():
    """Load Flask secret key from file or environment, generating one if needed."""
    key_file = os.environ.get("FLASK_SECRET_KEY_FILE", "/etc/mstdnca/flask_secret")
    if os.path.exists(key_file):
        with open(key_file) as f:
            key = f.read().strip()
            if key:
                return key

    env_key = os.environ.get("FLASK_SECRET_KEY", "")
    if env_key:
        return env_key

    # Generate and persist a secure random key
    import secrets
    generated = secrets.token_hex(32)
    try:
        key_dir = os.path.dirname(key_file)
        if key_dir and not os.path.exists(key_dir):
            os.makedirs(key_dir, mode=0o700, exist_ok=True)
        with open(key_file, "w") as f:
            f.write(generated)
        os.chmod(key_file, 0o600)
    except OSError:
        pass  # Dev/test environment without write access to /etc
    return generated


class Config:
    SECRET_KEY = _load_flask_secret()
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(DATA_DIR, 'mstdnca.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session cookie hardening.
    # SESSION_COOKIE_SECURE defaults to True in production (FLASK_DEBUG != "1").
    # Set SESSION_COOKIE_SECURE=0 in the environment when the app is accessed
    # directly over HTTP (e.g. local network without TLS termination) — otherwise
    # browsers will never send the session cookie back and session state (including
    # safety mode) will be lost on every request.
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    _debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "0" if _debug else "1") == "1"

    # "Remember me" cookie hardening.  Flask-Login's defaults are a 365-day
    # cookie with Secure=False and no SameSite, which lets a stolen cookie
    # restore a login for a year over plain HTTP and across sites.  Mirror the
    # session cookie's transport flags and cut the lifetime to 14 days.  The
    # cookie is additionally bound to a signed issued-at marker and a tracked
    # UserSession row -- see routes/auth.py.
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE
    REMEMBER_COOKIE_DURATION = timedelta(days=int(os.environ.get("REMEMBER_COOKIE_DAYS", "14")))

    # Default scan interval in hours
    SCAN_INTERVAL_HOURS = int(os.environ.get("SCAN_INTERVAL_HOURS", "6"))

    # App info
    VERSION_FILE = os.path.join(BASE_DIR, "VERSION")
    GITHUB_REPO = "ChadOhman/mstdnca-proxmox-tool"
