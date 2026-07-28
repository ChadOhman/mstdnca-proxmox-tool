# Private-Repo Self-Update Authentication — Design

**Date:** 2026-06-05
**Status:** Approved (design). **Historical note (2026-07-28):** the repo is
now public again, so the GitHub token is no longer required for self-update —
the token remains supported but optional.
**Components:** `routes/settings.py`, `templates/settings.html`, `scripts/update.sh`

## Problem

The repo `ChadOhman/mstdnca-proxmox-tool` was made private. The app's
self-update feature queries GitHub anonymously, and GitHub returns **404** for
private repos to anonymous callers. The user sees:

```
Could not check branch 'main': HTTP Error 404: Not Found
```

Two call sites break on a private repo:

1. **`check_update`** (`routes/settings.py`) — unauthenticated `urllib`
   requests to `api.github.com/repos/{repo}/branches/{branch}` and
   `.../releases/latest`.
2. **`scripts/update.sh`** — `git fetch origin` (and the subsequent
   `git reset --hard origin/main`) cannot pull a private repo over HTTPS without
   credentials.

Fixing only the check would let the UI detect an update but the actual apply
would still fail at `git fetch`.

## Goal

Let the self-update **check** and **apply** authenticate to the private repo
using a GitHub token the operator configures in Settings.

## Decision (from brainstorming)

Store the token as an encrypted DB Setting entered via a masked Settings field
(mirroring the existing `unifi_password`). The Flask check uses it as an API
auth header; `apply_update` injects it into the `update.sh` subprocess
environment so the script authenticates `git fetch` without touching the DB.

## Architecture

### Token storage (mirrors `unifi_password`)

- DB Setting `github_token`, **encrypted** at rest via the existing
  `encrypt()` / `decrypt()` helpers already used for `unifi_password`.
- `_get_settings_dict()` includes `github_token` (the encrypted blob) so the
  template can show a placeholder when one is set. The blob is never rendered
  into a value attribute.
- Save logic mirrors UniFi: **only overwrite when a non-blank value is
  submitted**; a blank submit preserves the existing token. The token is saved
  wherever `app_auto_update` / `app_update_branch` are persisted (the
  update-settings save path), and `check_update` (which also persists those
  fields from the same form) saves it too, so submitting either form keeps the
  token in sync.

### Template (`templates/settings.html`, Application-updates section)

Add near the `app_update_branch` input (~line 717) a masked field:

```html
<input type="password" class="form-control" name="github_token"
       placeholder="{{ '********' if settings.github_token else '' }}"
       autocomplete="new-password">
<div class="form-text">
  Required for a private repository. Use a fine-grained personal access token
  with read-only <strong>Contents</strong> permission on this repo.
</div>
```

The `value` attribute is intentionally omitted so the secret never reaches the
HTML — identical to `unifiPassword`.

### Flask check (`check_update`)

A helper:

```python
def _github_auth_headers():
    """Return an Authorization header dict for GitHub API calls, or {} if no
    token is configured."""
    enc = Setting.get("github_token", "")
    if not enc:
        return {}
    token = decrypt(enc)
    return {"Authorization": f"Bearer {token}"} if token else {}
```

Both `urllib.request.Request(...)` calls in `check_update` merge this with the
existing `{"User-Agent": "MCAT"}` header. With a valid token the private repo
returns 200 instead of 404.

On `HTTPError` with status 401/403, the flash message appends a hint:
`— check the GitHub access token in Settings`.

### Bash apply (`apply_update` → `update.sh`)

`apply_update` decrypts the token and injects it into the subprocess env:

```python
env = os.environ.copy()
enc = Setting.get("github_token", "")
if enc:
    token = decrypt(enc)
    if token:
        env["GITHUB_TOKEN"] = token
proc = subprocess.Popen(cmd, cwd=BASE_DIR, env=env)
```

The token is **never** interpolated into the command string — it rides in
`env` only.

In `update.sh`, the fetch becomes token-aware:

```bash
if [ -n "$GITHUB_TOKEN" ]; then
    # GitHub git-over-HTTPS needs Basic auth (token as password), NOT Bearer.
    _gh_basic=$(printf 'x-access-token:%s' "$GITHUB_TOKEN" | base64 | tr -d '\n')
    git -c http.extraheader="Authorization: Basic $_gh_basic" fetch origin 2>&1 | sed 's/^/    /'
else
    git fetch origin 2>&1 | sed 's/^/    /'
fi
```

`git reset --hard origin/main` is local and needs no auth. Using
`-c http.extraheader` (rather than embedding the token in the remote URL) keeps
the token out of `.git/config`. The script does not run `set -x` and git does
not echo header values, so the token does not appear in the update log.

## Security

- Token encrypted at rest; never rendered into HTML; never written to the
  update log; never embedded in a git remote URL; passed to the script only via
  process environment.
- `app_update_branch` is already regex-validated before reaching `update.sh`.
- No new shell interpolation of secrets in Python.

## Edge cases

- **No token** → unchanged behavior (fine for public repos / dev; a private
  repo still 404s, as today).
- **Invalid/expired token** → 401/403 surfaced in the flash with a
  check-the-token hint.
- **Blank submit** → existing token preserved, not wiped.

## Testing (`tests/test_settings.py`, mocking `urllib.request.urlopen` and `subprocess.Popen`)

- `_github_auth_headers()` → `{}` when unset; `{"Authorization": "Bearer <decrypted>"}` when set.
- `check_update` attaches the `Authorization` header when a token is set; omits it when not (assert on the mocked `Request`).
- Token save: stored encrypted (value in DB ≠ plaintext, `decrypt` round-trips); updated only when provided; blank submit keeps the existing value.
- `apply_update` calls `Popen` with `env` containing `GITHUB_TOKEN` equal to the decrypted token (and without it when no token is set).
- Existing "Could not check branch" 404 test remains valid (simulated API failure).
- `update.sh` uses `http.extraheader` when `GITHUB_TOKEN` is set — a lightweight
  assertion (e.g. `grep` for the guarded fetch plus `bash -n` syntax check),
  since the repo has no harness for executing `update.sh` end-to-end.

## Out of scope

- Token rotation UI beyond set/replace; OAuth flows.
- Switching the git remote to SSH / deploy keys.
- Authenticating the unrelated public `mastodon/mastodon` GitHub calls in
  `apps/mastodon.py` (a different repo, unaffected by this change).
