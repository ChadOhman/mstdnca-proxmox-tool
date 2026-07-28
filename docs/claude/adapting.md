# Adapting This Tool for Different Infrastructure

This tool was built for one specific deployment: the mstdn.ca Mastodon instance
and its operator's Proxmox homelab. If you're helping a different admin fork or
retool it, this doc maps what's bespoke versus what's already generic, so you
don't reverse-engineer it from scratch.

## Already generic — no code changes needed

Everything stored as a `Setting` row is runtime-configurable through the web UI:
Proxmox/PBS hosts, SSH credentials, UniFi controller, Discord webhook, Cloudflare
Access, trusted subnets, scan intervals, maintenance windows, per-app guest
mappings, and the Mastodon upstream repo (`DEFAULT_MASTODON_REPO` in
`apps/mastodon.py` is only a default — the actual repo is a Setting). A new
admin pointing at their own hosts needs zero code changes for the core
scan/update/terminal/RBAC features.

## Hardcoded — retool when forking

1. **Self-update source** — `config.py:GITHUB_REPO = "ChadOhman/mstdnca-proxmox-tool"`.
   The Settings > Application update checker and `scripts/update.sh` pull from
   this repo. Point it at the fork, or the fork will "update" itself back into
   this codebase.

2. **Install identity** — the name `mstdnca` is baked into paths and units:
   `/opt/mstdnca`, `/var/lib/mstdnca`, `/etc/mstdnca` (config.py, all three
   scripts in `scripts/`), the systemd unit `mstdnca-proxmox-tool`, env vars
   `MSTDNCA_DATA_DIR` / `MSTDNCA_SECRET_KEY`, and the SQLite filename
   `mstdnca.db`. Tests set these env vars explicitly (see Makefile and
   `tests/conftest.py`), so a rename must cover tests too.

3. **Branding** — "Mastodon Canada Administration Tool" and "MCAT" appear in
   ~34 templates, `core/notifier.py` Discord embeds (including the
   `User-Agent: MCAT/1.0` header), scripts, and README. Precedent: this repo
   was itself renamed once (from "LambNet Update Manager") with a sed loop over
   `templates/*.html` — the same approach works.

4. **Prometheus metric prefix** — exported metrics are named `mstdnca_*`
   (`clients/prometheus_exporter.py`, `clients/prometheus_query.py`,
   `apps/prometheus_app.py`). Renaming breaks existing dashboards;
   keeping it in a fork is cosmetic debt. Decide once, early.

5. **Trusted-subnet default** — `10.0.0.0/8` in `routes/security.py` and the
   private ranges in `clients/unifi_geoip.py`. The default auto-authenticates
   the whole RFC1918 /8 as admin; a different admin should set this to their
   actual management subnet on day one (it's a Setting, but the default is
   generous).

## Deployment-shape assumptions (verify before promising features work)

- **App upgrade modules assume specific deployment styles.** `apps/mastodon.py`
  automates a glitch-soc-style source checkout: git stash/pop for local
  patches, PGBouncer→direct-DB swap in `.env.production`, systemd puma/sidekiq.
  A Docker or vanilla-package Mastodon deployment does not fit — advise
  disabling the module rather than adapting it. Similarly `apps/ghost.py`
  expects systemd units named `ghost_<dirname>` (Ghost-CLI convention),
  and the other `apps/*` modules encode the original operator's install
  conventions. Treat each as a template, not a universal integration.
- **Debian/Ubuntu + systemd only.** Scanning is APT-based (`core/scanner.py`);
  there is no dnf/yum/apk support. Service monitoring shells out to systemctl.
- **Single gunicorn worker.** Collaboration/presence state is in-process
  (see architecture.md) — don't "fix" a fork by scaling workers.

## Suggested retooling order

Fork → change `GITHUB_REPO` → global rename (paths, unit, env vars, branding,
metric prefix — grep for `mstdnca`, `MSTDNCA`, `MCAT`, `Mastodon Canada`) →
update `scripts/*.sh` and Makefile to match → run `make all` (tests reference
the renamed env vars) → review which `apps/*` modules apply to the target
infra and hide the rest from the Applications page.
