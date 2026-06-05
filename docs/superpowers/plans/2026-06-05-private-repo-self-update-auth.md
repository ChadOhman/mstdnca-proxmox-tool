# Private-Repo Self-Update Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the app's self-update check and apply authenticate to the now-private GitHub repo using an operator-configured GitHub token.

**Architecture:** Store an optional GitHub token as an encrypted DB Setting (`github_token`) entered via a masked Settings field, mirroring the existing `unifi_password`. The Flask update-check sends it as an `Authorization: Bearer` header; `apply_update` injects it into the `update.sh` subprocess environment so the script's `git fetch` can pull the private repo.

**Tech Stack:** Python 3.13, Flask, pytest, `unittest.mock`. Secrets use the existing `auth.credential_store.encrypt`/`decrypt`. Bash for `scripts/update.sh`.

---

## File Structure

- **Modify:** `routes/settings.py` — add `decrypt` import; `_github_auth_headers()` and `_update_check_hint()` helpers; a `_save_github_token_from_form()` helper; wire token into `_get_settings_dict()`, `check_update`, `save_update_mode` (the `/app-update-mode` route), and `apply_update`.
- **Modify:** `templates/settings.html` — masked `github_token` field in the Application-updates form.
- **Modify:** `scripts/update.sh` — token-aware `git fetch`.
- **Modify:** `tests/test_settings.py` — tests for helpers, header attachment, token save, env injection, template field.
- **Create:** `tests/test_update_script.py` — shell-script assertions for `update.sh`.

Existing facts this plan relies on (verified in the current tree):
- `routes/settings.py:11` — `from auth.credential_store import encrypt`
- `routes/settings.py:39-89` — `_get_settings_dict()` (UniFi password at line 73 is the masked-secret template precedent)
- `routes/settings.py:358,372` — `decrypt` is currently imported **locally** inside the UniFi test route
- `routes/settings.py:578-588` — `@bp.route("/app-update-mode")` save route (`save_update_mode`)
- `routes/settings.py:591-644` — `check_update` (branch path 606-629, release path 631-644)
- `routes/settings.py:647-679` — `apply_update` (`subprocess.Popen(cmd, cwd=BASE_DIR)` at line 664)
- `templates/settings.html:187` — UniFi masked password field (the pattern to copy)
- `templates/settings.html:709-726` — Application-updates `<form action="/settings/app-update-mode">` (branch input at 717; both Save and "Check for Updates" submit this form)
- `tests/test_settings.py:477-484` — `TestCheckUpdate._make_fake_urlopen` helper

---

## Task 1: `_github_auth_headers()` helper + `decrypt` import

**Files:**
- Modify: `routes/settings.py:11` (import) and add helper after `_get_settings_dict` (~line 89)
- Test: `tests/test_settings.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_settings.py`:

```python
class TestGithubAuthHeaders:
    def test_returns_empty_when_no_token(self, app):
        from routes.settings import _github_auth_headers
        with app.app_context():
            from models import Setting
            Setting.set("github_token", "")
            assert _github_auth_headers() == {}

    def test_returns_bearer_when_token_set(self, app):
        from routes.settings import _github_auth_headers
        from auth.credential_store import encrypt
        from models import Setting
        with app.app_context():
            Setting.set("github_token", encrypt("ghp_test123"))
            assert _github_auth_headers() == {"Authorization": "Bearer ghp_test123"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev python -m pytest tests/test_settings.py::TestGithubAuthHeaders -v`
Expected: FAIL with `ImportError: cannot import name '_github_auth_headers'`

- [ ] **Step 3: Implement**

In `routes/settings.py`, change the import on line 11 from:

```python
from auth.credential_store import encrypt
```

to:

```python
from auth.credential_store import decrypt, encrypt
```

Then add this helper immediately after the `_get_settings_dict` function (after line 89):

```python
def _github_auth_headers():
    """Return an Authorization header dict for GitHub API calls, or {} if no
    token is configured. Used so the self-update check can read a private repo."""
    enc = Setting.get("github_token", "")
    if not enc:
        return {}
    token = decrypt(enc)
    return {"Authorization": f"Bearer {token}"} if token else {}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev python -m pytest tests/test_settings.py::TestGithubAuthHeaders -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add routes/settings.py tests/test_settings.py
git commit -m "feat(settings): add _github_auth_headers helper for private-repo update check"
```

---

## Task 2: Attach the auth header (and auth hints) in `check_update`

**Files:**
- Modify: `routes/settings.py` — `check_update` branch path (606-629) and release path (631-644); add `_update_check_hint` helper and `import urllib.error`
- Test: `tests/test_settings.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_settings.py`:

```python
class TestCheckUpdateAuthHeader:
    def _recorder(self):
        """Return (capture_dict, fake_urlopen) that records the Request passed in."""
        capture = {}

        def fake_urlopen(req, timeout=None):
            capture["auth"] = req.get_header("Authorization")
            resp = MagicMock()
            resp.read.return_value = json.dumps({"tag_name": "v0.0.1"}).encode()
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=False)
            return resp

        return capture, fake_urlopen

    def test_release_check_sends_bearer_when_token_set(self, app, auth_client):
        from auth.credential_store import encrypt
        from models import Setting
        with app.app_context():
            Setting.set("github_token", encrypt("ghp_abc"))
        capture, fake = self._recorder()
        with patch("urllib.request.urlopen", side_effect=fake):
            auth_client.post("/settings/check-update", data={"app_update_branch": ""},
                             follow_redirects=True)
        assert capture["auth"] == "Bearer ghp_abc"

    def test_release_check_no_header_when_no_token(self, app, auth_client):
        from models import Setting
        with app.app_context():
            Setting.set("github_token", "")
        capture, fake = self._recorder()
        with patch("urllib.request.urlopen", side_effect=fake):
            auth_client.post("/settings/check-update", data={"app_update_branch": ""},
                             follow_redirects=True)
        assert capture["auth"] is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev python -m pytest tests/test_settings.py::TestCheckUpdateAuthHeader -v`
Expected: FAIL — `test_release_check_sends_bearer_when_token_set` fails (`capture["auth"]` is `None`, header not attached yet).

- [ ] **Step 3: Implement**

In `routes/settings.py`, add this helper directly above the `@bp.route("/check-update", ...)` decorator (line 591):

```python
def _update_check_hint(exc):
    """Return a short, actionable hint to append to an update-check error flash."""
    import urllib.error
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code in (401, 403):
            return " — check the GitHub access token in Settings"
        if exc.code == 404:
            return " — for a private repo, set a GitHub access token in Settings"
    return ""
```

In `check_update`, the **branch path** Request (currently line 609) — change:

```python
            req = urllib.request.Request(url, headers={"User-Agent": "MCAT"})
```

to:

```python
            req = urllib.request.Request(url, headers={"User-Agent": "MCAT", **_github_auth_headers()})
```

and change the branch `except` (currently lines 627-629):

```python
        except Exception as e:
            flash(f"Could not check branch '{update_branch}': {e}", "error")
            return redirect(url_for("settings.index"))
```

to:

```python
        except Exception as e:
            flash(f"Could not check branch '{update_branch}': {e}{_update_check_hint(e)}", "error")
            return redirect(url_for("settings.index"))
```

In the **release path**, change the Request (currently line 633):

```python
        req = urllib.request.Request(url, headers={"User-Agent": "MCAT"})
```

to:

```python
        req = urllib.request.Request(url, headers={"User-Agent": "MCAT", **_github_auth_headers()})
```

and change the release `except` (currently lines 641-642):

```python
    except Exception as e:
        flash(f"Could not check for updates: {e}", "error")
```

to:

```python
    except Exception as e:
        flash(f"Could not check for updates: {e}{_update_check_hint(e)}", "error")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev python -m pytest tests/test_settings.py::TestCheckUpdateAuthHeader tests/test_settings.py::TestCheckUpdate -v`
Expected: PASS (both new tests + all existing `TestCheckUpdate` tests still pass — the hint only appends, so `b"Could not check branch"` / `b"Could not check for updates"` assertions stay valid).

- [ ] **Step 5: Commit**

```bash
git add routes/settings.py tests/test_settings.py
git commit -m "feat(settings): authenticate update check to private repo + auth hints"
```

---

## Task 3: Persist `github_token` (encrypted, only-if-provided) and surface it in settings dict

**Files:**
- Modify: `routes/settings.py` — add `_save_github_token_from_form()`; call in `save_update_mode` (~line 580) and `check_update` (~line 599); add `github_token` to `_get_settings_dict()` (~line 88)
- Test: `tests/test_settings.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_settings.py`:

```python
class TestGithubTokenSave:
    def test_app_update_mode_saves_encrypted_token(self, app, auth_client):
        from auth.credential_store import decrypt
        from models import Setting
        auth_client.post("/settings/app-update-mode",
                         data={"app_update_branch": "main", "github_token": "ghp_secret"},
                         follow_redirects=True)
        with app.app_context():
            stored = Setting.get("github_token", "")
            assert stored != ""
            assert stored != "ghp_secret"          # encrypted at rest
            assert decrypt(stored) == "ghp_secret"  # round-trips

    def test_blank_token_keeps_existing(self, app, auth_client):
        from auth.credential_store import decrypt, encrypt
        from models import Setting
        with app.app_context():
            Setting.set("github_token", encrypt("ghp_existing"))
        auth_client.post("/settings/app-update-mode",
                         data={"app_update_branch": "main", "github_token": ""},
                         follow_redirects=True)
        with app.app_context():
            assert decrypt(Setting.get("github_token", "")) == "ghp_existing"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev python -m pytest tests/test_settings.py::TestGithubTokenSave -v`
Expected: FAIL — `test_app_update_mode_saves_encrypted_token` fails (token not stored).

- [ ] **Step 3: Implement**

In `routes/settings.py`, add this helper directly above the `@bp.route("/check-update", ...)` decorator (next to `_update_check_hint`):

```python
def _save_github_token_from_form():
    """Persist the GitHub token from the submitted form, encrypted. Only updates
    when a non-blank value is supplied so a blank submit preserves the existing token."""
    token = request.form.get("github_token", "").strip()
    if token:
        Setting.set("github_token", encrypt(token))
```

In `save_update_mode` (the `/app-update-mode` route, after it sets `app_update_branch`, currently around line 583), add a call before `db.session.commit()`:

```python
    _save_github_token_from_form()
```

In `check_update`, after it sets `app_update_branch` (currently around line 600), add the same call:

```python
    _save_github_token_from_form()
```

In `_get_settings_dict()`, add to the returned dict (after the `app_update_branch` entry, line 87):

```python
        "github_token": Setting.get("github_token", ""),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev python -m pytest tests/test_settings.py::TestGithubTokenSave -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add routes/settings.py tests/test_settings.py
git commit -m "feat(settings): persist encrypted github_token from update form"
```

---

## Task 4: Masked `github_token` field in the settings template

**Files:**
- Modify: `templates/settings.html` — Application-updates form, after the branch field (after line 718)
- Test: `tests/test_settings.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_settings.py`:

```python
class TestGithubTokenField:
    def test_field_present_and_secret_not_leaked(self, app, auth_client):
        from auth.credential_store import encrypt
        from models import Setting
        with app.app_context():
            Setting.set("github_token", encrypt("ghp_TOPSECRET"))
        resp = auth_client.get("/settings/")
        assert resp.status_code == 200
        assert b'name="github_token"' in resp.data
        assert b"ghp_TOPSECRET" not in resp.data  # plaintext never rendered
```

- [ ] **Step 2: Run test to verify it fails**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev python -m pytest tests/test_settings.py::TestGithubTokenField -v`
Expected: FAIL — `b'name="github_token"'` not found.

- [ ] **Step 3: Implement**

In `templates/settings.html`, inside the Application-updates form, insert a new block immediately after the Update-Branch `</div>` (after line 719, before the `<div class="d-flex gap-2">` button row at line 720):

```html
                    <div class="mb-3">
                        <label class="form-label">GitHub Access Token</label>
                        <input type="password" class="form-control form-control-sm" name="github_token"
                               autocomplete="new-password"
                               placeholder="{{ '********' if settings.github_token else '' }}">
                        <div class="form-text">
                            Required when the repository is private. Use a fine-grained personal access
                            token with read-only <strong>Contents</strong> permission on this repo.
                            Leave blank to keep the current token.
                        </div>
                    </div>
```

- [ ] **Step 4: Run test to verify it passes**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev python -m pytest tests/test_settings.py::TestGithubTokenField -v`
Expected: PASS (1 passed)

- [ ] **Step 5: Commit**

```bash
git add templates/settings.html tests/test_settings.py
git commit -m "feat(settings): add masked GitHub token field to update settings"
```

---

## Task 5: Inject `GITHUB_TOKEN` into the `update.sh` subprocess

**Files:**
- Modify: `routes/settings.py` — `apply_update` (`subprocess.Popen` at line 664)
- Test: `tests/test_settings.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_settings.py`:

```python
class TestApplyUpdateTokenEnv:
    def test_popen_env_includes_token(self, app, auth_client):
        from auth.credential_store import encrypt
        from models import Setting
        from unittest.mock import mock_open
        with app.app_context():
            Setting.set("github_token", encrypt("ghp_run"))

        fake_proc = MagicMock()
        fake_proc.pid = 4242
        with patch("routes.settings.subprocess.Popen", return_value=fake_proc) as mpopen, \
             patch("builtins.open", mock_open()):
            auth_client.post("/settings/apply-update", follow_redirects=False)

        assert mpopen.called
        env = mpopen.call_args.kwargs.get("env")
        assert env is not None
        assert env.get("GITHUB_TOKEN") == "ghp_run"

    def test_popen_env_omits_token_when_unset(self, app, auth_client):
        from models import Setting
        from unittest.mock import mock_open
        with app.app_context():
            Setting.set("github_token", "")

        fake_proc = MagicMock()
        fake_proc.pid = 4243
        with patch("routes.settings.subprocess.Popen", return_value=fake_proc) as mpopen, \
             patch("builtins.open", mock_open()):
            auth_client.post("/settings/apply-update", follow_redirects=False)

        assert mpopen.called
        env = mpopen.call_args.kwargs.get("env")
        assert env is not None
        assert "GITHUB_TOKEN" not in env
```

- [ ] **Step 2: Run test to verify it fails**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev python -m pytest tests/test_settings.py::TestApplyUpdateTokenEnv -v`
Expected: FAIL — `Popen` is currently called without an `env` kwarg, so `env is None`.

- [ ] **Step 3: Implement**

In `routes/settings.py` `apply_update`, replace the Popen launch (currently line 664):

```python
        proc = subprocess.Popen(cmd, cwd=BASE_DIR)
```

with:

```python
        env = os.environ.copy()
        enc_token = Setting.get("github_token", "")
        if enc_token:
            token = decrypt(enc_token)
            if token:
                env["GITHUB_TOKEN"] = token
        proc = subprocess.Popen(cmd, cwd=BASE_DIR, env=env)
```

(`os`, `subprocess`, `Setting`, and now `decrypt` are already imported at module top.)

- [ ] **Step 4: Run test to verify it passes**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev python -m pytest tests/test_settings.py::TestApplyUpdateTokenEnv -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add routes/settings.py tests/test_settings.py
git commit -m "feat(settings): pass GITHUB_TOKEN env into update.sh subprocess"
```

---

## Task 6: Token-aware `git fetch` in `update.sh`

**Files:**
- Modify: `scripts/update.sh` — the `git fetch origin` line (line 102)
- Test: `tests/test_update_script.py` (create)

- [ ] **Step 1: Write the failing test**

Create `tests/test_update_script.py`:

```python
"""Static checks for scripts/update.sh."""
import os
import subprocess

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts", "update.sh")


def _read():
    with open(SCRIPT, encoding="utf-8") as f:
        return f.read()


def test_script_syntax_is_valid():
    result = subprocess.run(["bash", "-n", SCRIPT], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_fetch_uses_token_extraheader_when_present():
    content = _read()
    assert 'GITHUB_TOKEN' in content
    assert 'http.extraheader=' in content
    # token is passed via -c extraheader, never embedded in a remote URL
    assert '@github.com' not in content
```

- [ ] **Step 2: Run test to verify it fails**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev python -m pytest tests/test_update_script.py -v`
Expected: FAIL — `test_fetch_uses_token_extraheader_when_present` fails (`GITHUB_TOKEN` not in the script yet). The syntax test passes.

- [ ] **Step 3: Implement**

In `scripts/update.sh`, replace the fetch line (currently line 102):

```bash
    git fetch origin 2>&1 | sed 's/^/    /'
```

with:

```bash
    if [ -n "$GITHUB_TOKEN" ]; then
        # Private repo: authenticate this fetch only via an ephemeral header.
        # -c http.extraheader keeps the token out of .git/config; git does not
        # echo header values, and this script does not run `set -x`, so the
        # token never reaches the update log.
        git -c http.extraheader="AUTHORIZATION: bearer $GITHUB_TOKEN" fetch origin 2>&1 | sed 's/^/    /'
    else
        git fetch origin 2>&1 | sed 's/^/    /'
    fi
```

- [ ] **Step 4: Run test to verify it passes**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev python -m pytest tests/test_update_script.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add scripts/update.sh tests/test_update_script.py
git commit -m "feat(update): authenticate git fetch to private repo via GITHUB_TOKEN"
```

---

## Task 7: Full verification

**Files:** none (verification only)

- [ ] **Step 1: Run the settings + update-script tests**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev python -m pytest tests/test_settings.py tests/test_update_script.py -v`
Expected: PASS — all existing settings tests plus the new classes (`TestGithubAuthHeaders`, `TestCheckUpdateAuthHeader`, `TestGithubTokenSave`, `TestGithubTokenField`, `TestApplyUpdateTokenEnv`) and the two script tests.

- [ ] **Step 2: Lint**

Run: `python -m ruff check .`
Expected: `All checks passed!` (watch the import line `from auth.credential_store import decrypt, encrypt` — alphabetical; and the `import urllib.error` inside `_update_check_hint`).

- [ ] **Step 3: Security scan (changed Python file)**

Run: `python -m bandit -c pyproject.toml routes/settings.py`
Expected: No new issues. The token is never interpolated into a shell string (it rides in `subprocess.Popen(env=...)`), so no new injection finding.

- [ ] **Step 4: Full test suite**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev python -m pytest`
Expected: all pass. Per CLAUDE.md, own any failure on the branch — investigate and fix, do not dismiss.

- [ ] **Step 5: Final commit (only if lint/format changed files)**

```bash
git add -A
git commit -m "chore(settings): lint/format for private-repo update auth"
```

---

## Self-Review Notes (author)

- **Spec coverage:** encrypted DB Setting + masked field (Tasks 3, 4) ✓; `_github_auth_headers` Bearer (Task 1) ✓; both API requests send the header (Task 2) ✓; 401/403 + 404 hints (Task 2 — 404 added because it is the exact symptom the operator hit; consistent with the spec's "surface the auth problem" intent) ✓; only-update-when-provided / blank keeps existing (Task 3) ✓; `apply_update` env injection (Task 5) ✓; `update.sh` `http.extraheader`, no token in URL/log (Task 6) ✓; tests incl. secret-not-leaked and env injection (Tasks 1-6) ✓; full verification (Task 7) ✓.
- **Name consistency:** `_github_auth_headers()`, `_update_check_hint(exc)`, `_save_github_token_from_form()`, Setting key `github_token`, env var `GITHUB_TOKEN`, form field `name="github_token"` — used identically across tasks.
- **No placeholders:** every code step shows complete code and exact edit targets.
- **Deviation noted:** the 404 hint is a small addition beyond the spec's literal 401/403 wording, justified above.
