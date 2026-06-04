# Mastodon Runtime Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Mastodon upgrade tool auto-upgrade Ruby, Node.js, and Bundler to meet the target branch's requirements, instead of aborting on a compliance `[FAIL]`.

**Architecture:** Add pure parsing helpers plus three idempotent remediation functions (`_remediate_ruby`, `_remediate_bundler`, `_remediate_node`) and a coordinator (`_remediate_environment`), all in `apps/mastodon.py`. Remediation runs in Step 3 of the upgrade (after the snapshot and `git pull`, before `bundle install`) so rollback stays safe, and is also applied to the optional second app guest. The read-only pre-flight check is relabelled so fixable runtime gaps are informational, not blocking.

**Tech Stack:** Python 3.13, Flask, pytest, `unittest.mock`. Remote work runs over the existing `SSHClient` via `ssh.execute_sudo(cmd, timeout=...)` which returns `(stdout, stderr, code)`. Node.js installs via the NodeSource apt pattern already used in `apps/elk.py`.

---

## File Structure

- **Modify:** `apps/mastodon.py` — add helpers + remediation functions; rewire `run_mastodon_upgrade` and `_run_second_guest_sync`; relabel `_check_env_compliance`.
- **Create:** `tests/test_mastodon_remediation.py` — all tests for this feature, including a small `FakeSSH` harness.

All new functions live in `apps/mastodon.py` alongside the existing `_check_env_compliance` / `_check_version_range`. No other files change. No new settings or routes (remediation is always-on per the spec).

Existing symbols this plan reuses (already defined in `apps/mastodon.py`):
- `_RBENV_PATH` — `export PATH=$HOME/.rbenv/bin:$HOME/.rbenv/shims:$PATH`
- `_check_version_range(installed, requirement)` — returns `True`/`False`/`None`
- `_log_cmd_output(log, stdout, stderr, code, max_chars=...)` — imported from `apps.utils`
- `json`, `re` — already imported at module top

---

## Task 1: Pure helper — derive Node major from an `engines.node` range

**Files:**
- Modify: `apps/mastodon.py` (add `_node_major_from_range` after `_check_version_range`, ~line 55)
- Test: `tests/test_mastodon_remediation.py` (create)

- [ ] **Step 1: Write the failing test**

Create `tests/test_mastodon_remediation.py`:

```python
"""Tests for Mastodon runtime version remediation (Ruby / Node.js / Bundler)."""
from apps.mastodon import _node_major_from_range


class TestNodeMajorFromRange:
    def test_gte(self):
        assert _node_major_from_range(">=22") == 22

    def test_caret_with_patch(self):
        assert _node_major_from_range("^22.1.0") == 22

    def test_dot_x(self):
        assert _node_major_from_range("22.x") == 22

    def test_bounded_range_takes_floor(self):
        assert _node_major_from_range(">=20 <23") == 20

    def test_empty(self):
        assert _node_major_from_range("") is None

    def test_none(self):
        assert _node_major_from_range(None) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_mastodon_remediation.py::TestNodeMajorFromRange -v`
Expected: FAIL with `ImportError: cannot import name '_node_major_from_range'`

- [ ] **Step 3: Write minimal implementation**

In `apps/mastodon.py`, add directly after the `_check_version_range` function (ends ~line 54):

```python
def _node_major_from_range(node_range):
    """Return the floor major version from an engines.node range, or None.

    '>=22' -> 22, '^22.1.0' -> 22, '22.x' -> 22, '>=20 <23' -> 20.
    """
    if not node_range:
        return None
    m = re.search(r'(\d+)', node_range)
    return int(m.group(1)) if m else None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_mastodon_remediation.py::TestNodeMajorFromRange -v`
Expected: PASS (6 passed)

- [ ] **Step 5: Commit**

```bash
git add apps/mastodon.py tests/test_mastodon_remediation.py
git commit -m "feat(mastodon): derive Node major from engines.node range"
```

---

## Task 2: Pure helper — parse `BUNDLED WITH` from `Gemfile.lock`

**Files:**
- Modify: `apps/mastodon.py` (add `_bundler_from_lock` after `_node_major_from_range`)
- Test: `tests/test_mastodon_remediation.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_mastodon_remediation.py`:

```python
from apps.mastodon import _bundler_from_lock


class TestBundlerFromLock:
    def test_extracts_version(self):
        lock = "GEM\n  remote: https://rubygems.org/\n\nBUNDLED WITH\n   2.5.11\n"
        assert _bundler_from_lock(lock) == "2.5.11"

    def test_missing_section(self):
        assert _bundler_from_lock("GEM\n  specs:\n") is None

    def test_empty(self):
        assert _bundler_from_lock("") is None

    def test_none(self):
        assert _bundler_from_lock(None) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_mastodon_remediation.py::TestBundlerFromLock -v`
Expected: FAIL with `ImportError: cannot import name '_bundler_from_lock'`

- [ ] **Step 3: Write minimal implementation**

In `apps/mastodon.py`, add after `_node_major_from_range`:

```python
_BUNDLED_WITH_RE = re.compile(r'BUNDLED WITH\s+([\d.]+)')


def _bundler_from_lock(gemfile_lock):
    """Return the version under 'BUNDLED WITH' in a Gemfile.lock, or None."""
    if not gemfile_lock:
        return None
    m = _BUNDLED_WITH_RE.search(gemfile_lock)
    return m.group(1).strip() if m else None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_mastodon_remediation.py::TestBundlerFromLock -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add apps/mastodon.py tests/test_mastodon_remediation.py
git commit -m "feat(mastodon): parse Bundler version from Gemfile.lock"
```

---

## Task 3: `_remediate_node` — install required Node major via NodeSource

**Files:**
- Modify: `apps/mastodon.py` (add `_remediate_node` after `_bundler_from_lock`)
- Test: `tests/test_mastodon_remediation.py` (also add the shared `FakeSSH` harness)

- [ ] **Step 1: Write the failing test**

Append to `tests/test_mastodon_remediation.py`:

```python
from apps.mastodon import _remediate_node


class FakeSSH:
    """Mock SSHClient: matches command substrings to canned (stdout, stderr, code).

    `responses` is a list of (substring, (stdout, stderr, code)). The first
    substring contained in the command wins. Unmatched commands return ("","",0).
    """

    def __init__(self, responses=None):
        self.responses = responses or []
        self.calls = []

    def execute_sudo(self, cmd, timeout=None):
        self.calls.append(cmd)
        for substr, resp in self.responses:
            if substr in cmd:
                return resp
        return ("", "", 0)

    def ran(self, substr):
        return any(substr in c for c in self.calls)


def _collect_log():
    lines = []
    return lines, lines.append


class TestRemediateNode:
    def test_noop_when_major_matches(self):
        logs, log = _collect_log()
        ssh = FakeSSH()
        assert _remediate_node(ssh, 22, "22.4.1", log) is True
        assert not ssh.ran("nodesource")  # no install attempted

    def test_installs_when_major_differs(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("nodesource", ("done", "", 0)),
            ("node --version", ("v22.4.1\n", "", 0)),
        ])
        assert _remediate_node(ssh, 22, "20.20.2", log) is True
        assert ssh.ran("node_22.x")

    def test_fails_when_install_nonzero(self):
        logs, log = _collect_log()
        ssh = FakeSSH([("nodesource", ("", "apt error", 1))])
        assert _remediate_node(ssh, 22, "20.20.2", log) is False

    def test_fails_when_verify_wrong_major(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("nodesource", ("done", "", 0)),
            ("node --version", ("v20.20.2\n", "", 0)),
        ])
        assert _remediate_node(ssh, 22, "20.20.2", log) is False

    def test_warns_and_passes_when_no_requirement(self):
        logs, log = _collect_log()
        assert _remediate_node(FakeSSH(), None, "20.20.2", log) is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_mastodon_remediation.py::TestRemediateNode -v`
Expected: FAIL with `ImportError: cannot import name '_remediate_node'`

- [ ] **Step 3: Write minimal implementation**

In `apps/mastodon.py`, add after `_bundler_from_lock`:

```python
def _remediate_node(ssh, required_major, installed_node, log):
    """Ensure Node.js is on `required_major` via the NodeSource apt repo.

    No-op when the installed major already matches. Returns True on success
    (or no-op), False on install/verification failure.
    """
    if required_major is None:
        log("  [WARN] No Node.js requirement detected — skipping Node remediation")
        return True

    installed_major = None
    if installed_node:
        m = re.match(r'(\d+)', installed_node)
        if m:
            installed_major = int(m.group(1))

    if installed_major == required_major:
        log(f"  [OK] Node.js {installed_node} already on major {required_major}")
        return True

    log(f"--- Upgrading Node.js {installed_node or '(none)'} → {required_major}.x (NodeSource) ---")
    node_setup_cmds = (
        "export DEBIAN_FRONTEND=noninteractive"
        " && apt-get update -qq && apt-get install -y -qq ca-certificates curl gnupg"
        " && mkdir -p /etc/apt/keyrings"
        " && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key"
        " | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg --yes"
        " && echo 'deb [signed-by=/etc/apt/keyrings/nodesource.gpg]"
        f" https://deb.nodesource.com/node_{required_major}.x nodistro main'"
        " > /etc/apt/sources.list.d/nodesource.list"
        " && apt-get update -qq && apt-get install -y -qq nodejs"
    )
    stdout, stderr, code = ssh.execute_sudo(node_setup_cmds, timeout=300)
    _log_cmd_output(log, stdout, stderr, code, max_chars=2000)
    if code != 0:
        log(f"ERROR: Node.js install failed (exit {code})")
        return False

    stdout, stderr, code = ssh.execute_sudo("node --version 2>/dev/null", timeout=10)
    m = re.search(r'v?(\d+)', stdout or "")
    if code == 0 and m and int(m.group(1)) == required_major:
        log(f"  [OK] Node.js {(stdout or '').strip()} installed")
        return True
    log(f"ERROR: Node.js verification failed (got {(stdout or '').strip() or 'nothing'})")
    return False
```

- [ ] **Step 4: Run test to verify it passes**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_mastodon_remediation.py::TestRemediateNode -v`
Expected: PASS (5 passed)

- [ ] **Step 5: Commit**

```bash
git add apps/mastodon.py tests/test_mastodon_remediation.py
git commit -m "feat(mastodon): add Node.js NodeSource remediation"
```

---

## Task 4: `_remediate_ruby` — install + activate required Ruby via rbenv

**Files:**
- Modify: `apps/mastodon.py` (add `_remediate_ruby` after `_remediate_node`)
- Test: `tests/test_mastodon_remediation.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_mastodon_remediation.py`:

```python
from apps.mastodon import _remediate_ruby


class TestRemediateRuby:
    def test_noop_when_version_matches(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("cat /srv/live/.ruby-version", ("4.0.5\n", "", 0)),
            ("ruby --version", ("ruby 4.0.5 (2026-01-01)\n", "", 0)),
        ])
        assert _remediate_ruby(ssh, "mastodon", "/srv/live", log) is True
        assert not ssh.ran("rbenv install")

    def test_installs_when_version_differs(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("cat /srv/live/.ruby-version", ("4.0.5\n", "", 0)),
            ("ruby --version", ("ruby 3.4.1 (2025-01-01)\n", "", 0)),
            ("rbenv install", ("installed", "", 0)),
        ])
        # After install, the verify read of `ruby --version` must report 4.0.5.
        # FakeSSH returns the first matching substring, so override the verify
        # by ordering a more specific match isn't possible here; use a counter.
        calls = {"ruby": 0}

        def exec_sudo(cmd, timeout=None):
            ssh.calls.append(cmd)
            if "cat /srv/live/.ruby-version" in cmd:
                return ("4.0.5\n", "", 0)
            if "rbenv install" in cmd:
                return ("installed", "", 0)
            if "ruby --version" in cmd:
                calls["ruby"] += 1
                return ("ruby 3.4.1 (2025)\n", "", 0) if calls["ruby"] == 1 else ("ruby 4.0.5 (2026)\n", "", 0)
            return ("", "", 0)

        ssh.execute_sudo = exec_sudo
        assert _remediate_ruby(ssh, "mastodon", "/srv/live", log) is True
        assert ssh.ran("rbenv global 4.0.5")

    def test_fails_when_ruby_version_unreadable(self):
        logs, log = _collect_log()
        ssh = FakeSSH([("cat /srv/live/.ruby-version", ("", "", 1))])
        assert _remediate_ruby(ssh, "mastodon", "/srv/live", log) is False

    def test_fails_when_install_nonzero(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("cat /srv/live/.ruby-version", ("4.0.5\n", "", 0)),
            ("ruby --version", ("ruby 3.4.1 (2025)\n", "", 0)),
            ("rbenv install", ("", "rbenv: command not found", 127)),
        ])
        assert _remediate_ruby(ssh, "mastodon", "/srv/live", log) is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_mastodon_remediation.py::TestRemediateRuby -v`
Expected: FAIL with `ImportError: cannot import name '_remediate_ruby'`

- [ ] **Step 3: Write minimal implementation**

In `apps/mastodon.py`, add after `_remediate_node`:

```python
def _remediate_ruby(ssh, user, app_dir, log):
    """Ensure the Ruby version in .ruby-version is installed and global via rbenv.

    Updates the ruby-build plugin first so it knows about newer versions, then
    `rbenv install -s <ver>` and `rbenv global <ver>`. No-op when already
    matched. Returns True on success/no-op, False on failure.
    """
    out, _, code = ssh.execute_sudo(
        f"su - {user} -c 'cat {app_dir}/.ruby-version 2>/dev/null'", timeout=10
    )
    required = (out or "").strip()
    if not required:
        log(f"ERROR: Could not read {app_dir}/.ruby-version — cannot verify Ruby version")
        return False

    installed = None
    for cmd in (
        f"su - {user} -c 'ruby --version 2>/dev/null'",
        f"su - {user} -c '{_RBENV_PATH}; ruby --version 2>/dev/null'",
    ):
        rout, _, rcode = ssh.execute_sudo(cmd, timeout=10)
        if rcode == 0 and rout.strip():
            m = re.search(r'ruby\s+(\d+\.\d+\.\d+)', rout)
            if m:
                installed = m.group(1)
                break

    if installed == required:
        log(f"  [OK] Ruby {installed} already installed")
        return True

    log(f"--- Upgrading Ruby {installed or '(none)'} → {required} (rbenv) ---")
    install_cmd = (
        f"su - {user} -c '{_RBENV_PATH}; "
        f"(cd ~/.rbenv/plugins/ruby-build && git pull --quiet 2>/dev/null || true); "
        f"rbenv install -s {required} && rbenv global {required}'"
    )
    stdout, stderr, code = ssh.execute_sudo(install_cmd, timeout=1800)
    _log_cmd_output(log, stdout, stderr, code, max_chars=2000)
    if code != 0:
        log(f"ERROR: Ruby {required} install failed (exit {code})")
        return False

    vout, _, vcode = ssh.execute_sudo(
        f"su - {user} -c '{_RBENV_PATH}; ruby --version 2>/dev/null'", timeout=10
    )
    m = re.search(r'ruby\s+(\d+\.\d+\.\d+)', vout or "")
    if vcode == 0 and m and m.group(1) == required:
        log(f"  [OK] Ruby {required} installed")
        return True
    log(f"ERROR: Ruby verification failed (got {(vout or '').strip() or 'nothing'})")
    return False
```

- [ ] **Step 4: Run test to verify it passes**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_mastodon_remediation.py::TestRemediateRuby -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add apps/mastodon.py tests/test_mastodon_remediation.py
git commit -m "feat(mastodon): add rbenv Ruby remediation across major.minor"
```

---

## Task 5: `_remediate_bundler` — install Bundler pinned in `Gemfile.lock`

**Files:**
- Modify: `apps/mastodon.py` (add `_remediate_bundler` after `_remediate_ruby`)
- Test: `tests/test_mastodon_remediation.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_mastodon_remediation.py`:

```python
from apps.mastodon import _remediate_bundler


class TestRemediateBundler:
    def test_noop_when_version_matches(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("cat /srv/live/Gemfile.lock", ("BUNDLED WITH\n   2.5.11\n", "", 0)),
            ("bundle --version", ("Bundler version 2.5.11\n", "", 0)),
        ])
        assert _remediate_bundler(ssh, "mastodon", "/srv/live", log) is True
        assert not ssh.ran("gem install bundler")

    def test_installs_pinned_version(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("cat /srv/live/Gemfile.lock", ("BUNDLED WITH\n   2.5.11\n", "", 0)),
            ("bundle --version", ("Bundler version 2.4.1\n", "", 0)),
            ("gem install bundler", ("done", "", 0)),
        ])
        assert _remediate_bundler(ssh, "mastodon", "/srv/live", log) is True
        assert ssh.ran("gem install bundler -v 2.5.11")

    def test_installs_latest_when_no_pin(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("cat /srv/live/Gemfile.lock", ("GEM\n  specs:\n", "", 0)),
            ("gem install bundler --no-document", ("done", "", 0)),
        ])
        assert _remediate_bundler(ssh, "mastodon", "/srv/live", log) is True
        assert ssh.ran("gem install bundler --no-document")

    def test_fails_when_install_nonzero(self):
        logs, log = _collect_log()
        ssh = FakeSSH([
            ("cat /srv/live/Gemfile.lock", ("BUNDLED WITH\n   2.5.11\n", "", 0)),
            ("bundle --version", ("Bundler version 2.4.1\n", "", 0)),
            ("gem install bundler", ("", "boom", 1)),
        ])
        assert _remediate_bundler(ssh, "mastodon", "/srv/live", log) is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_mastodon_remediation.py::TestRemediateBundler -v`
Expected: FAIL with `ImportError: cannot import name '_remediate_bundler'`

- [ ] **Step 3: Write minimal implementation**

In `apps/mastodon.py`, add after `_remediate_ruby`:

```python
def _remediate_bundler(ssh, user, app_dir, log):
    """Ensure the Bundler version pinned in Gemfile.lock is installed.

    Falls back to latest Bundler when the lockfile has no 'BUNDLED WITH'.
    No-op when already matched. Returns True on success/no-op, False on failure.
    """
    out, _, _ = ssh.execute_sudo(
        f"su - {user} -c 'cat {app_dir}/Gemfile.lock 2>/dev/null'", timeout=15
    )
    required = _bundler_from_lock(out or "")

    if not required:
        log("  [WARN] No 'BUNDLED WITH' in Gemfile.lock — installing latest Bundler")
        cmd = f"su - {user} -c '{_RBENV_PATH}; gem install bundler --no-document'"
    else:
        installed = None
        for c_cmd in (
            f"su - {user} -c 'bundle --version 2>/dev/null'",
            f"su - {user} -c '{_RBENV_PATH}; bundle --version 2>/dev/null'",
        ):
            bout, _, bcode = ssh.execute_sudo(c_cmd, timeout=10)
            if bcode == 0 and bout.strip():
                m = re.search(r'(\d+\.\d+[\.\d]*)', bout)
                if m:
                    installed = m.group(1)
                    break
        if installed == required:
            log(f"  [OK] Bundler {installed} already installed")
            return True
        log(f"--- Installing Bundler {required} (from Gemfile.lock) ---")
        cmd = f"su - {user} -c '{_RBENV_PATH}; gem install bundler -v {required} --no-document'"

    stdout, stderr, code = ssh.execute_sudo(cmd, timeout=300)
    _log_cmd_output(log, stdout, stderr, code, max_chars=1000)
    if code != 0:
        log(f"ERROR: Bundler install failed (exit {code})")
        return False
    log("  [OK] Bundler installed")
    return True
```

- [ ] **Step 4: Run test to verify it passes**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_mastodon_remediation.py::TestRemediateBundler -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add apps/mastodon.py tests/test_mastodon_remediation.py
git commit -m "feat(mastodon): pin Bundler install to Gemfile.lock version"
```

---

## Task 6: `_remediate_environment` — coordinator (Ruby → Bundler → Node)

**Files:**
- Modify: `apps/mastodon.py` (add `_remediate_environment` after `_remediate_bundler`)
- Test: `tests/test_mastodon_remediation.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_mastodon_remediation.py`:

```python
from apps.mastodon import _remediate_environment


class TestRemediateEnvironment:
    def _ssh_all_current(self):
        """Everything already compliant: Ruby 4.0.5, Bundler 2.5.11, Node 22."""
        return FakeSSH([
            ("cat /srv/live/.ruby-version", ("4.0.5\n", "", 0)),
            ("ruby --version", ("ruby 4.0.5 (2026)\n", "", 0)),
            ("cat /srv/live/Gemfile.lock", ("BUNDLED WITH\n   2.5.11\n", "", 0)),
            ("bundle --version", ("Bundler version 2.5.11\n", "", 0)),
            ("cat /srv/live/package.json", ('{"engines":{"node":">=22"}}', "", 0)),
            ("node --version", ("v22.4.1\n", "", 0)),
        ])

    def test_all_compliant_no_actions(self):
        logs, log = _collect_log()
        ssh = self._ssh_all_current()
        assert _remediate_environment(ssh, "mastodon", "/srv/live", log) is True
        assert not ssh.ran("rbenv install")
        assert not ssh.ran("gem install bundler")
        assert not ssh.ran("nodesource")

    def test_aborts_when_ruby_fails(self):
        logs, log = _collect_log()
        ssh = FakeSSH([("cat /srv/live/.ruby-version", ("", "", 1))])
        assert _remediate_environment(ssh, "mastodon", "/srv/live", log) is False
        # Bundler/Node must not be attempted after Ruby aborts
        assert not ssh.ran("gem install bundler")
        assert not ssh.ran("nodesource")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_mastodon_remediation.py::TestRemediateEnvironment -v`
Expected: FAIL with `ImportError: cannot import name '_remediate_environment'`

- [ ] **Step 3: Write minimal implementation**

In `apps/mastodon.py`, add after `_remediate_bundler`:

```python
def _remediate_environment(ssh, user, app_dir, log):
    """Upgrade Ruby, Bundler, and Node.js to meet the target's requirements.

    Reads required versions from the working tree (run after `git pull`). Order
    is Ruby → Bundler → Node, since Bundler is a gem under the active Ruby.
    Returns True only if every required remediation succeeded.
    """
    if not _remediate_ruby(ssh, user, app_dir, log):
        return False
    if not _remediate_bundler(ssh, user, app_dir, log):
        return False

    required_major = None
    out, _, code = ssh.execute_sudo(
        f"su - {user} -c 'cat {app_dir}/package.json 2>/dev/null'", timeout=15
    )
    if code == 0 and out.strip():
        try:
            node_range = json.loads(out).get("engines", {}).get("node", "")
            required_major = _node_major_from_range(node_range)
        except Exception:
            pass

    installed_node = None
    nout, _, ncode = ssh.execute_sudo(
        f"su - {user} -c 'node --version 2>/dev/null'", timeout=10
    )
    if ncode == 0 and nout.strip():
        m = re.search(r'v?(\d+\.\d+\.\d+)', nout.strip())
        if m:
            installed_node = m.group(1)

    return _remediate_node(ssh, required_major, installed_node, log)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_mastodon_remediation.py::TestRemediateEnvironment -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add apps/mastodon.py tests/test_mastodon_remediation.py
git commit -m "feat(mastodon): add runtime remediation coordinator"
```

---

## Task 7: Relabel `_check_env_compliance` so fixable runtime gaps are non-blocking

**Files:**
- Modify: `apps/mastodon.py` (`_check_env_compliance`, the Ruby block ~lines 369-389 and the Node block ~lines 392-407)
- Test: `tests/test_mastodon_remediation.py`

The read-only pre-flight must no longer report `[FAIL]` / "upgrade blocked" for a Node or Ruby major.minor mismatch, because the upgrade now fixes them automatically.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_mastodon_remediation.py`:

```python
from apps.mastodon import _check_env_compliance


class TestComplianceNonBlocking:
    def _ssh(self, ruby_installed, node_installed):
        # Provides: git fetch (ok), remote .ruby-version, remote package.json,
        # installed ruby, installed node, installed bundler.
        return FakeSSH([
            ("git fetch", ("", "", 0)),
            (".ruby-version", ("4.0.5\n", "", 0)),
            ("package.json", ('{"engines":{"node":">=22"}}', "", 0)),
            ("ruby --version", (f"ruby {ruby_installed} (2026)\n", "", 0)),
            ("node --version", (f"v{node_installed}\n", "", 0)),
            ("bundle --version", ("Bundler version 2.5.11\n", "", 0)),
        ])

    def test_node_mismatch_is_not_blocking(self):
        logs, log = _collect_log()
        ssh = self._ssh(ruby_installed="4.0.5", node_installed="20.20.2")
        result = _check_env_compliance(ssh, "mastodon", "/srv/live", "main", log)
        assert result is True  # no longer blocks
        joined = "\n".join(logs)
        assert "will be upgraded" in joined
        assert "[FAIL] Node" not in joined

    def test_ruby_major_minor_mismatch_is_not_blocking(self):
        logs, log = _collect_log()
        ssh = self._ssh(ruby_installed="3.4.1", node_installed="22.4.1")
        result = _check_env_compliance(ssh, "mastodon", "/srv/live", "main", log)
        assert result is True
        joined = "\n".join(logs)
        assert "[FAIL] Ruby" not in joined
        assert "will be upgraded" in joined
```

- [ ] **Step 2: Run test to verify it fails**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_mastodon_remediation.py::TestComplianceNonBlocking -v`
Expected: FAIL — both currently produce `[FAIL]` lines and return `False`.

- [ ] **Step 3: Edit `_check_env_compliance`**

In the **Ruby comparison block**, replace the major.minor-mismatch and missing-installed `[FAIL]` branches. Find:

```python
        else:
            log(f"  [FAIL] Ruby {installed_ruby} installed, required {required_ruby} — major.minor mismatch, manual Ruby upgrade required")
            all_pass = False
    elif required_ruby and not installed_ruby:
        log(f"  [FAIL] Ruby required {required_ruby} but could not detect installed version")
        all_pass = False
```

Replace with:

```python
        else:
            log(f"  [INFO] Ruby {installed_ruby} installed, required {required_ruby} — will be upgraded during upgrade")
    elif required_ruby and not installed_ruby:
        log(f"  [INFO] Ruby required {required_ruby} — will be installed during upgrade")
```

In the **Node.js comparison block**, replace the two `[FAIL]` branches. Find:

```python
        elif result is False:
            log(f"  [FAIL] Node.js {installed_node} installed, required {required_node} — upgrade Node.js before proceeding")
            all_pass = False
        else:
            log(f"  [WARN] Node.js {installed_node} installed, required {required_node} (could not parse requirement range)")
    elif required_node and not installed_node:
        log(f"  [FAIL] Node.js required {required_node} but could not detect installed version")
        all_pass = False
```

Replace with:

```python
        elif result is False:
            log(f"  [INFO] Node.js {installed_node} installed, required {required_node} — will be upgraded during upgrade")
        else:
            log(f"  [WARN] Node.js {installed_node} installed, required {required_node} (could not parse requirement range)")
    elif required_node and not installed_node:
        log(f"  [INFO] Node.js required {required_node} — will be installed during upgrade")
```

Leave the `[PASS]` / `[WARN]` branches and the `bundler` block unchanged.

- [ ] **Step 4: Run test to verify it passes**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_mastodon_remediation.py::TestComplianceNonBlocking -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add apps/mastodon.py tests/test_mastodon_remediation.py
git commit -m "feat(mastodon): treat fixable runtime gaps as non-blocking in preflight"
```

---

## Task 8: Wire remediation into `run_mastodon_upgrade`

**Files:**
- Modify: `apps/mastodon.py` — the early compliance block (~lines 778-795) and step 2e (~lines 966-997)
- Test: `tests/test_mastodon_remediation.py`

Two edits: (a) make the pre-snapshot env check advisory (never abort), and (b) replace the inline rbenv/bundler block in Step 3 with a single `_remediate_environment` call that aborts cleanly on failure.

- [ ] **Step 1: Edit (a) — advisory pre-snapshot check**

Find this block in `run_mastodon_upgrade`:

```python
    log("=== Checking environment compliance ===")
    if mastodon_guest.ip_address:
        try:
            with SSHClient.from_credential(mastodon_guest.ip_address, credential) as ssh:
                env_ok = _check_env_compliance(ssh, user, app_dir, branch, log)
            if not env_ok:
                log("ERROR: Environment does not meet requirements. Upgrade aborted.")
                log("Fix the version issues above before running the upgrade.")
                return False, "\n".join(log_lines)
            log("Environment compliance: OK")
        except Exception as e:
            log(f"WARNING: Could not run environment compliance check: {e}")
            log("Proceeding with upgrade — verify environment manually if needed.")
    else:
        log("WARNING: No IP address for Mastodon guest — skipping environment compliance check")
    log("")
```

Replace with:

```python
    log("=== Checking environment compliance ===")
    if mastodon_guest.ip_address:
        try:
            with SSHClient.from_credential(mastodon_guest.ip_address, credential) as ssh:
                _check_env_compliance(ssh, user, app_dir, branch, log)
            log("Runtime versions (Ruby / Node.js / Bundler) will be upgraded automatically if needed.")
        except Exception as e:
            log(f"WARNING: Could not run environment compliance check: {e}")
            log("Proceeding with upgrade — runtimes will still be checked in Step 3.")
    else:
        log("WARNING: No IP address for Mastodon guest — skipping environment compliance check")
    log("")
```

- [ ] **Step 2: Edit (b) — replace step 2e with the coordinator**

Find the entire step 2e block (starts at the `# 2e. Ensure correct Ruby version...` comment, the `log("--- rbenv install (ensuring correct Ruby version) ---")` line through the closing `else:` / `log(f"NOTE: rbenv/gem step exited {code}...")` lines, ending just before `# 2f. bundle install`):

```python
            # 2e. Ensure correct Ruby version and Bundler are installed via rbenv.
            # Reads the target version from .ruby-version in the app dir (updated by git pull).
            # --skip-existing is a no-op if already installed; silently non-fatal if rbenv not present.
            log("--- rbenv install (ensuring correct Ruby version) ---")
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c '{_RBENV_PATH}; "
                f"cd {app_dir} && rbenv install --skip-existing && gem install bundler --no-document'",
                timeout=600,
            )
            out = ((stdout or "") + (stderr or "")).strip()
            if out:
                log(out[-500:] if len(out) > 500 else out)
            if code != 0:
                # Verify whether the required Ruby version is actually installed.
                # If not, this is a hard failure — bundle install will fail immediately.
                rv_out, _, _ = ssh.execute_sudo(
                    f"su - {user} -c 'cat {app_dir}/.ruby-version 2>/dev/null'", timeout=5
                )
                required_rv = rv_out.strip()
                ver_out, _, _ = ssh.execute_sudo(
                    f"su - {user} -c '{_RBENV_PATH}; rbenv versions --bare 2>/dev/null'", timeout=10
                )
                if required_rv and required_rv not in (ver_out or ""):
                    log(f"ERROR: rbenv install failed (exit {code}) and Ruby {required_rv} is not installed.")
                    log("ruby-build may not know about this version yet. To fix on the server:")
                    log("  cd ~/.rbenv/plugins/ruby-build && git pull")
                    log(f"  rbenv install {required_rv}")
                    _swap_env_db(ssh, app_dir, config["pgbouncer_host"], config["pgbouncer_port"])
                    env_swapped = False
                    return False, "\n".join(log_lines)
                else:
                    log(f"NOTE: rbenv/gem step exited {code} — rbenv not in use or bundler already present, continuing")
```

Replace the whole block above with:

```python
            # 2e. Ensure Ruby / Bundler / Node.js meet the target's requirements.
            # Runs after git pull so .ruby-version, Gemfile.lock and package.json
            # reflect the new code, and after the snapshot so a failed runtime
            # upgrade can be rolled back.
            log("--- Ensuring runtime versions (Ruby / Bundler / Node.js) ---")
            if not _remediate_environment(ssh, user, app_dir, log):
                log("ERROR: Runtime version remediation failed. Aborting upgrade.")
                _swap_env_db(ssh, app_dir, config["pgbouncer_host"], config["pgbouncer_port"])
                env_swapped = False
                return False, "\n".join(log_lines)
```

- [ ] **Step 3: Write the integration test**

Append to `tests/test_mastodon_remediation.py`:

```python
import sys
from unittest.mock import MagicMock, patch


class TestUpgradeWiring:
    """run_mastodon_upgrade calls _remediate_environment and aborts on failure."""

    def test_remediation_failure_aborts_upgrade(self):
        import apps.mastodon as m

        guest = MagicMock()
        guest.ip_address = "10.0.0.5"
        guest.credential = MagicMock()

        cfg = {
            "guest_id": "1", "db_guest_id": "2", "db_name": "mastodon_production",
            "user": "mastodon", "app_dir": "/srv/live", "branch": "main",
            "pgbouncer_host": "10.0.0.9", "pgbouncer_port": "6432",
            "direct_db_host": "10.0.0.2", "direct_db_port": "5432",
            "protection_type": "snapshot", "backup_storage": "", "backup_mode": "snapshot",
            "guest_id_2": "", "current_version": "4.0.0", "latest_version": "4.1.0",
            "auto_upgrade": False,
        }

        fake_ssh = FakeSSH()
        ssh_ctx = MagicMock()
        ssh_ctx.__enter__ = MagicMock(return_value=fake_ssh)
        ssh_ctx.__exit__ = MagicMock(return_value=False)

        with patch.object(m, "_get_mastodon_config", return_value=cfg), \
             patch.object(m.Guest, "query") as gq, \
             patch.object(m, "snapshot_guest", return_value=(True, "ok")), \
             patch.object(m.SSHClient, "from_credential", return_value=ssh_ctx), \
             patch.object(m, "_swap_env_db", return_value=(True, "swapped")), \
             patch.object(m, "_remediate_environment", return_value=False) as rem, \
             patch("apps.mastodon.Credential") as cred:
            gq.get.return_value = guest
            cred.query.filter_by.return_value.first.return_value = MagicMock()

            ok, log_out = m.run_mastodon_upgrade()

        assert ok is False
        assert rem.called
        assert "Runtime version remediation failed" in log_out
```

- [ ] **Step 4: Run the test**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_mastodon_remediation.py::TestUpgradeWiring -v`
Expected: PASS (1 passed)

> If `Guest.query` / `Credential` patching does not line up with the in-test module objects, adjust the patch targets to the names actually imported inside `run_mastodon_upgrade` (it does `from models import Credential, db` locally). The assertion that matters: remediation is invoked and a `False` return aborts with the "Runtime version remediation failed" message.

- [ ] **Step 5: Commit**

```bash
git add apps/mastodon.py tests/test_mastodon_remediation.py
git commit -m "feat(mastodon): run runtime remediation during upgrade"
```

---

## Task 9: Apply remediation to the second app guest (VM2)

**Files:**
- Modify: `apps/mastodon.py` — `_run_second_guest_sync`, after the `git stash pop` block (~line 189) and before `bundle install` (~line 191)
- Test: `tests/test_mastodon_remediation.py`

- [ ] **Step 1: Edit `_run_second_guest_sync`**

Find the end of the stash-pop block and the start of bundle install:

```python
            log("--- [VM2] git stash pop ---")
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c 'cd {app_dir} && git stash pop'", timeout=30
            )
            log(stdout or stderr or "(no output)")
            if code != 0:
                log("WARNING: [VM2] git stash pop returned non-zero (may be no stash to pop)")

            log("--- [VM2] bundle install ---")
```

Insert the remediation call between the stash-pop `if code != 0:` block and `log("--- [VM2] bundle install ---")`:

```python
            log("--- [VM2] git stash pop ---")
            stdout, stderr, code = ssh.execute_sudo(
                f"su - {user} -c 'cd {app_dir} && git stash pop'", timeout=30
            )
            log(stdout or stderr or "(no output)")
            if code != 0:
                log("WARNING: [VM2] git stash pop returned non-zero (may be no stash to pop)")

            log("--- [VM2] Ensuring runtime versions (Ruby / Bundler / Node.js) ---")
            if not _remediate_environment(ssh, user, app_dir, log):
                log("ERROR: [VM2] Runtime version remediation failed")
                return False

            log("--- [VM2] bundle install ---")
```

- [ ] **Step 2: Write the test**

Append to `tests/test_mastodon_remediation.py`:

```python
class TestSecondGuestWiring:
    def test_vm2_remediation_failure_returns_false(self):
        import apps.mastodon as m

        guest2 = MagicMock()
        guest2.ip_address = "10.0.0.6"
        guest2.credential = MagicMock()

        fake_ssh = FakeSSH()
        ssh_ctx = MagicMock()
        ssh_ctx.__enter__ = MagicMock(return_value=fake_ssh)
        ssh_ctx.__exit__ = MagicMock(return_value=False)

        logs, log = _collect_log()
        with patch.object(m.SSHClient, "from_credential", return_value=ssh_ctx), \
             patch.object(m, "_remediate_environment", return_value=False) as rem, \
             patch("apps.mastodon.Credential"):
            ok = m._run_second_guest_sync(guest2, "mastodon", "/srv/live", log, branch="main")

        assert ok is False
        assert rem.called
        assert any("[VM2] Runtime version remediation failed" in line for line in logs)
```

- [ ] **Step 3: Run the test**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_mastodon_remediation.py::TestSecondGuestWiring -v`
Expected: PASS (1 passed)

> If the `Credential` default-lookup path interferes, the guest2 mock already sets `.credential`, so the default branch is skipped. Adjust patch targets only if an `AttributeError`/`ImportError` surfaces.

- [ ] **Step 4: Commit**

```bash
git add apps/mastodon.py tests/test_mastodon_remediation.py
git commit -m "feat(mastodon): remediate runtimes on second app guest"
```

---

## Task 10: Full verification — lint, security, whole suite

**Files:** none (verification only)

- [ ] **Step 1: Run the new test module in full**

Run: `FLASK_SECRET_KEY=dev-secret DATABASE_URL="sqlite:////tmp/mstdnca-dev-test.db" MSTDNCA_DATA_DIR=/tmp/mstdnca-dev pytest tests/test_mastodon_remediation.py -v`
Expected: PASS (all tests from Tasks 1-9, ~28 tests)

- [ ] **Step 2: Run lint**

Run: `make lint`
Expected: `ruff check .` passes with no errors. Watch for line-length (120) on the long `node_setup_cmds` / log f-strings; wrap if flagged.

- [ ] **Step 3: Run security scan**

Run: `make security`
Expected: bandit + pip-audit clean. The remediation commands interpolate `required` (Ruby) / `required` (Bundler) / `required_major` (Node), all parsed by digit/dot regexes, so no new injection surface; if bandit flags `S602`/shell concerns on the new `execute_sudo` strings, confirm they mirror the existing `apps/elk.py` pattern (no untrusted interpolation) before any `# nosec`.

- [ ] **Step 4: Run the full test suite**

Run: `make test`
Expected: all tests pass (existing suite + the new module). Per CLAUDE.md working standards, own any failure on the branch — investigate and fix, do not dismiss as pre-existing.

- [ ] **Step 5: Final commit (if lint/format produced changes)**

```bash
git add -A
git commit -m "chore(mastodon): lint/format for runtime remediation"
```

---

## Self-Review Notes (author)

- **Spec coverage:** Ruby remediation (Task 4) ✓; Node NodeSource (Task 3) ✓; Bundler pinned to Gemfile.lock (Tasks 2, 5) ✓; always-on, no toggle (no settings task) ✓; remediation after snapshot in Step 3 (Task 8) ✓; pre-flight stays read-only & non-blocking (Task 7) ✓; VM2 (Task 9) ✓; testing (each task + Task 10) ✓; edge cases — missing files abort (Tasks 4, 6), absent rbenv/NodeSource abort (Tasks 3, 4) ✓.
- **Type/name consistency:** `_remediate_environment(ssh, user, app_dir, log)`, `_remediate_ruby/_bundler(ssh, user, app_dir, log)`, `_remediate_node(ssh, required_major, installed_node, log)`, `_node_major_from_range(node_range)`, `_bundler_from_lock(gemfile_lock)` — used identically across tasks.
- **No placeholders:** every code step shows complete code; every test step shows the assertions.
