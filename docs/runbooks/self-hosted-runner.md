# Runbook: the self-hosted GitHub Actions runner

All three workflows (`ci.yml`, `security.yml`, `release.yml`) run on one
self-hosted runner instead of GitHub-hosted `ubuntu-latest`. It lives on the
lambnet tool CT (`lambnet-mcat`, 10.0.0.193): Debian 12, 2 cores, 1 GB RAM.
Jobs target the labels `[self-hosted, linux, x64, lambnet]`.

## What changed versus GitHub-hosted

- **Python is the system 3.11**, the same interpreter production runs under,
  in a `.venv` created per job. `actions/setup-python` is gone: its prebuilt
  interpreters are published for Ubuntu only, and 3.11 is what we actually
  ship on. pip's cache persists in the runner user's home, so installs are
  fast after the first run.
- **One job at a time.** CI's five jobs and Security's two queue behind each
  other. Expect a full CI run to take longer than the parallel hosted runs
  did, mostly the pytest job.
- **Temp paths** come from `${{ runner.temp }}` rather than `/tmp`, so two
  runs never share a database file.
- `ruff-action`, `action-shellcheck` and `setup-node` download their own
  binaries and work unchanged on Debian.

## Install or upgrade

The script is idempotent; re-running it upgrades the runner binary and
re-registers. It needs a registration token, which expires after an hour:

```bash
gh api -X POST repos/ChadOhman/mstdnca-proxmox-tool/actions/runners/registration-token -q .token
```

Then, on the host as root:

```bash
RUNNER_TOKEN=<token> bash /opt/mstdnca/scripts/setup-runner.sh
```

What it does: installs the packages the workflows need, creates the
unprivileged `gh-runner` account (no sudo, no login shell), downloads
`actions/runner` and verifies its SHA-256, unpacks it to
`/opt/actions-runner`, registers it, and installs the systemd unit
`actions.runner.ChadOhman-mstdnca-proxmox-tool.lambnet-mcat`.

To move to a newer runner release, take the version and the linux-x64
checksum from https://github.com/actions/runner/releases and pass
`--version X.Y.Z --sha256 <hex>` (or update the defaults in the script).
Automatic self-update is disabled so the binary stays pinned.

## Security: the repository is public

A self-hosted runner executes whatever a pull request's workflow says. With
the default fork policy only first-time contributors need approval, so any
previous contributor's fork could run code on the tool host. Set the policy
to require approval for every outside collaborator before the first run:

```bash
gh api -X PUT repos/ChadOhman/mstdnca-proxmox-tool/actions/permissions/fork-pr-contributor-approval -f approval_policy=all_external_contributors
```

Check it:

```bash
gh api repos/ChadOhman/mstdnca-proxmox-tool/actions/permissions/fork-pr-contributor-approval
```

The runner user owns only `/opt/actions-runner`; the script removes
other-user read access from `/opt/mstdnca`, `/etc/mstdnca` and
`/var/lib/mstdnca`. CI jobs still share the host's CPU and memory with the
production tool, so a runaway test slows the tool down. If that becomes a
problem, run `setup-runner.sh` on a dedicated CT instead and nothing in the
workflows needs to change.

## Operate

```bash
systemctl status 'actions.runner.*'
```

```bash
journalctl -u 'actions.runner.*' -f
```

Work directories: `/opt/actions-runner/_work/<repo>/<repo>` (checkout) and
`/opt/actions-runner/_work/_temp` (`runner.temp`). `actions/checkout`
cleans the checkout before each job.

If GitHub shows the runner offline, restart the unit; if jobs sit in
"Queued" forever, the runner is not registered or its labels do not match.

## Remove

```bash
RUNNER_TOKEN=<token> bash /opt/mstdnca/scripts/setup-runner.sh --remove
```

That unregisters it from the repository, uninstalls the unit and deletes
`/opt/actions-runner`. To go back to GitHub-hosted runners, change
`runs-on` back to `ubuntu-latest` and restore `actions/setup-python` in the
workflows (git history has the previous versions).
