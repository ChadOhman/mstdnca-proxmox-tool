# Mastodon Runtime Remediation — Design

**Date:** 2026-06-04
**Status:** Approved (design)
**Component:** `apps/mastodon.py`

## Problem

The Mastodon upgrade tool checks installed Ruby / Node.js / Bundler against the
target branch's requirements (`_check_env_compliance`). When the runtime is too
old it logs `[FAIL]` and aborts:

```
=== Checking environment compliance ===
  [PASS] Ruby 4.0.5 installed, required 4.0.5
  [FAIL] Node.js 20.20.2 installed, required ≥22 — upgrade Node.js before proceeding
  [PASS] Bundler 4.0.12 available
ERROR: Environment does not meet requirements. Upgrade aborted.
```

Today the operator must SSH in and upgrade the runtime by hand, then re-run.
Ruby patch bumps and Bundler are *partially* auto-handled during the upgrade
(`rbenv install --skip-existing`, `gem install bundler`), but a Ruby
**major.minor** change and **any** Node.js mismatch dead-end.

## Goal

Let the upgrade tool upgrade Ruby, Node.js, and Bundler itself, so the upgrade
proceeds without manual intervention.

## Decisions (from brainstorming)

| Decision | Choice |
|---|---|
| Trigger model | **Always auto-remediate** inline during the upgrade (no opt-in toggle). |
| Node.js mechanism | **NodeSource apt repo** — reuse the proven pattern in `apps/elk.py`. |
| Pre-flight scope | **Upgrade only.** Pre-flight stays read-only; it reports intent, not action. |
| Second guest (VM2) | **Remediate VM2 too**, before its code sync. |
| Bundler target | **Match `Gemfile.lock` `BUNDLED WITH`** version exactly. |

## Architecture

### Timing & rollback safety

Remediation modifies the server, so it must run **after** the Proxmox
snapshot/backup — otherwise a botched runtime install can't be rolled back.

```
Step 1: snapshot / backup        (unchanged — captures pristine pre-upgrade state)
Step 2: pg_dump                  (unchanged)
Step 3: SSH upgrade sequence
   git stash → swap .env to direct DB → git pull → git stash pop
   ► REMEDIATE RUNTIMES ◄        (NEW — after pull, so target version files are present)
   bundle install → yarn install → migrations → assets → restarts
```

The existing **pre-snapshot** compliance block (`run_mastodon_upgrade`, current
lines ~778-795) becomes **advisory**: it detects and logs
`… — will be upgraded in Step 3` instead of returning `False`. The real
remediation + hard verification happens in Step 3, inside the existing
`try/except` that already restores `.env.production` to PGBouncer on failure.

### Components (all in `apps/mastodon.py`)

#### `_detect_env_versions(ssh, user, app_dir, source) -> dict`
Single source of truth for required/installed versions. Reads target files from
either a git remote ref (`git show origin/<branch>:<file>`, used by the
read-only reporter pre-pull) or the working tree (post-pull, used by the
coordinator). Returns:

```python
{
  "required_ruby": "4.0.5" | None,      # .ruby-version
  "installed_ruby": "4.0.5" | None,     # ruby --version (with rbenv PATH fallback)
  "required_node_range": ">=22" | None, # package.json engines.node
  "required_node_major": 22 | None,     # floor major of the range
  "installed_node": "20.20.2" | None,   # node --version
  "required_bundler": "2.5.11" | None,  # Gemfile.lock "BUNDLED WITH"
  "installed_bundler": "4.0.12" | None, # bundle --version (rbenv PATH fallback)
}
```

Node major derivation: take the floor (first integer) of the `engines.node`
range. `>=22` → 22, `^22` → 22, `22.x` → 22. Post-install verification uses the
existing `_check_version_range` against the full range to confirm compliance.

#### `_remediate_ruby(ssh, user, app_dir, log) -> bool`
Reads `.ruby-version` from the working tree. If the installed version differs:
1. `cd ~/.rbenv/plugins/ruby-build && git pull` (so ruby-build knows newer
   versions — this is the exact remedy the current code only *prints* at lines
   ~989-992).
2. `rbenv install -s <ver>`
3. `rbenv global <ver>`
Verifies `ruby --version` matches afterward. Subsumes the current step 2e rbenv
logic and adds the major.minor-crossing capability. No-op when already matched.

#### `_remediate_bundler(ssh, user, app_dir, log) -> bool`
Parses `BUNDLED WITH` from the target `Gemfile.lock`; runs
`gem install bundler -v <ver> --no-document`. Verifies. Replaces the current
unversioned `gem install bundler`. No-op when already matched.

#### `_remediate_node(ssh, required_major, installed_node, log) -> bool`
If the installed major differs from `required_major` (or Node is absent), runs
the NodeSource keyring + apt install adapted from `apps/elk.py` lines ~589-602,
parameterized on `node_<major>.x`. Verifies `node --version` satisfies the full
range via `_check_version_range`. No-op when the major already matches.

#### `_remediate_environment(ssh, user, app_dir, log) -> bool`
Coordinator. Calls `_detect_env_versions(..., source=working_tree)`, then runs
**Ruby → Bundler → Node**, only where needed (Ruby before Bundler because
Bundler is a gem under that Ruby). Returns `True` if all required remediations
succeeded (and post-verify confirms compliance), else `False`.

### Integration points

- **`run_mastodon_upgrade`** — pre-snapshot env block becomes advisory
  (detect + log intent, never abort). In Step 3, after `git stash pop` and
  before `bundle install`, the existing rbenv/bundler block (2e) is replaced by
  a call to `_remediate_environment`. On `False`: log `ERROR`, restore `.env` to
  PGBouncer, `return False` (existing failure pattern).
- **`_run_second_guest_sync`** — insert `_remediate_environment` after
  `git stash pop` and before `bundle install` so VM2 runtimes match before its
  bundle/yarn run.
- **`_check_env_compliance`** (read-only, used by pre-flight) — reuse
  `_detect_env_versions`. Fixable runtime mismatches (Node any mismatch, Ruby
  major.minor) become non-blocking `[INFO] … — will be upgraded during upgrade`
  rather than `[FAIL]`. Unparseable / undetectable cases remain `[WARN]`. Other
  pre-flight checks are unchanged; the documented non-destructive guarantee
  holds.

### No settings / UI changes

"Always auto-remediate" means no new toggle. Remediation surfaces through the
existing streamed upgrade log. The screenshot's
`[FAIL] … Upgrade aborted` becomes:

```
--- Upgrading Node.js 20.20.2 → 22.x (NodeSource) ---
... apt output ...
  [OK] Node.js 22.x.y installed, satisfies ≥22
```

followed by the normal upgrade sequence.

## Error handling & edge cases

- **rbenv absent** (Ruby remediation needed) → log a clear error and abort;
  do not silently continue into a doomed `bundle install`.
- **NodeSource install fails** → abort with the apt error tail.
- **`.ruby-version` / `engines.node` / `Gemfile.lock` unreadable** → abort with
  a specific message naming the missing file.
- All remediators are **idempotent**: they compare installed vs required first
  and no-op when already compliant, avoiding needless apt/network churn.
- Failure inside Step 3 restores `.env.production` to PGBouncer via the existing
  `env_swapped` handling.

## Testing

Unit tests with a mocked `SSHClient` (the repo's established pattern):

- `engines.node` range → required-major extraction: `>=22`, `^22`, `22.x`,
  bounded ranges.
- `BUNDLED WITH` parsing from `Gemfile.lock`.
- `_remediate_ruby`: skips when matched; updates ruby-build + installs +
  sets global when mismatched; fails when post-verify fails; aborts when rbenv
  absent.
- `_remediate_bundler`: skips when matched; installs pinned version when not.
- `_remediate_node`: skips when major matches; runs NodeSource install when not;
  fails when post-verify doesn't satisfy the range.
- `_check_env_compliance` relabels Node/Ruby mismatch as non-blocking (pre-flight
  no longer reports "upgrade blocked" for a fixable runtime gap).
- `run_mastodon_upgrade`: full path remediates then proceeds (mocked SSH);
  remediation failure aborts and restores `.env`.
- `_run_second_guest_sync`: remediates VM2 before bundle/yarn.

## Out of scope

- Other apps (Ghost, Elk, PeerTube) — this change is Mastodon-only.
- A configurable opt-in toggle (explicitly decided against).
- Downgrading runtimes (only upgrades to meet requirements).
