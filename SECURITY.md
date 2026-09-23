# Security Policy

## Supported versions

Only the latest tagged release and the current `main` commit receive security
fixes. `scripts/update.sh` tracks `main`, so an installation that runs the
updater is always on a supported commit; tagged releases exist for operators
who pin a version with `--version`.

| Version | Supported |
| --- | --- |
| `main` | yes |
| latest release (`v0.2.1`) | yes |
| older releases | no — upgrade |

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository
(**Security → Report a vulnerability**). Do not open a public issue for a
security problem.

Include what you can of: the affected route, setting or script; the role or
permission needed to reach it; a reproduction; and the impact you observed.
Reports are acknowledged within a few days.

## How fixes are published

Confirmed issues get a GitHub Security Advisory (GHSA) on this repository with
a CVSS 3.1 vector, CWE ids and the patched version. Fixes land on `main` first
and are included in the next tagged release; the advisory names both the fix
pull request and the release. CVEs are not requested for this single-operator
tool.

After a security fix is merged, `main` is diffed against the fix branch to
confirm the squash merge kept every file — v0.2.0 was tagged after a squash
merge silently reverted two critical fixes (see GHSA-3cjx-7w8r-jwxv and
GHSA-p3xx-rpm2-g5f8), and that check exists so it cannot happen quietly again.

## Known limitations

These are documented rather than fixed and are called out in the relevant
advisories:

- The web-terminal sudo gate injects the stored sudo password only after a
  server-seen `password:` prompt. The shell's operator can print such a prompt
  themselves; followers cannot. The operator already holds a root shell on
  that guest, so this is accepted.
- PeerTube releases are downloaded over HTTPS without signature verification
  (PeerTube publishes detached GPG signatures, which would need the upstream
  key pinned in this tool).
- `pct create` in `scripts/create-ct.sh` accepts the container root password
  only as a command-line argument, so it is briefly visible in the process
  list of the Proxmox host during provisioning.
- Inline scripts in the templates are allowed by the Content Security Policy
  (`'unsafe-inline'`); moving them to nonces is tracked as follow-up work.
- The service runs as root because the SSH/sudo model requires it today.
