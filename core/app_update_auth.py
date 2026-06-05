"""Shared GitHub-token helpers for the app self-update (manual + scheduled paths).

The token is stored encrypted as the `github_token` Setting. Imports are done
INSIDE the functions so callers that patch `sys.modules['models']` in tests
resolve the mock at call time."""


def github_auth_headers():
    """Return an Authorization header dict for GitHub API calls, or {} if no
    token is configured."""
    from auth.credential_store import decrypt
    from models import Setting
    enc = Setting.get("github_token", "")
    if not enc:
        return {}
    token = decrypt(enc)
    return {"Authorization": f"Bearer {token}"} if token else {}


def github_token_env():
    """Return a copy of os.environ with GITHUB_TOKEN set when a token is
    configured (else unchanged), for passing to the update.sh subprocess."""
    import os

    from auth.credential_store import decrypt
    from models import Setting
    env = os.environ.copy()
    enc = Setting.get("github_token", "")
    if enc:
        token = decrypt(enc)
        if token:
            env["GITHUB_TOKEN"] = token
    return env
