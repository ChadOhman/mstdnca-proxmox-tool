import os

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


def _trusted_proxy_count():
    """Parse TRUSTED_PROXY_COUNT from the environment, defaulting to 0 (no trust).

    Anything unparseable or negative is treated as 0 so a typo can never widen
    trust; the resulting value is the number of proxy hops ProxyFix may honour.
    """
    raw = os.environ.get("TRUSTED_PROXY_COUNT", "0").strip()
    try:
        count = int(raw)
    except ValueError:
        return 0
    return max(count, 0)


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

    # Reverse-proxy trust.
    # Number of reverse proxies you operate directly in front of this app.
    # 0 (the default) means the app is reached directly by clients and NO
    # forwarded header (X-Forwarded-For / X-Real-IP / CF-Connecting-IP) is
    # trusted anywhere: request.remote_addr is always the real TCP peer.
    # Set TRUSTED_PROXY_COUNT=1 when exactly one proxy you control (cloudflared,
    # nginx) terminates connections and appends X-Forwarded-For. Setting it
    # higher than the real number of hops lets clients forge their own IP.
    TRUSTED_PROXY_COUNT = _trusted_proxy_count()

    # Default scan interval in hours
    SCAN_INTERVAL_HOURS = int(os.environ.get("SCAN_INTERVAL_HOURS", "6"))

    # App info
    VERSION_FILE = os.path.join(BASE_DIR, "VERSION")
    GITHUB_REPO = "ChadOhman/mstdnca-proxmox-tool"
