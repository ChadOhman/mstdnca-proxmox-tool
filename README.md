# Mastodon Canada Administration Tool

A datacenter-wide administration tool for Proxmox environments. Runs as an LXC container and provides a web interface for managing APT updates, UniFi network devices, and Mastodon upgrades across all your Proxmox hosts, VMs, and CTs.

## Features

- **Datacenter-wide update scanning** — Scan all hosts, VMs, and CTs for available APT updates with severity detection
- **Web SSH terminal** — Browser-based SSH sessions to any managed guest
- **UniFi network visibility** — View all UniFi devices and clients with subnet filtering and device restart support
- **Mastodon (glitch-soc) upgrade automation** — One-click upgrades with PGBouncer swap, git stash/pop, Proxmox snapshots, and auto-upgrade support
- **Discord notifications** — Webhook alerts for available updates, upgrade results, and service failures, with severity breakdown
- **Scheduled scans & auto-updates** — Configurable scan intervals and maintenance windows
- **4-tier role-based access control** — Super Admin, Admin, Operator, and Viewer roles with tag-based guest filtering
- **Encrypted credential storage** — SSH passwords and API tokens encrypted at rest with Fernet
- **Cloudflare Zero Trust** — Optional SSO authentication via Cloudflare Access
- **Local network bypass** — Trusted subnets skip authentication entirely
- **Self-updating** — Check for updates and apply them from the web UI

## Quick Start

### Option 1: Automated CT Creation

Run this on any Proxmox host to create a ready-to-use CT:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/ChadOhman/mstdnca-proxmox-tool/main/create-ct.sh)" -- \
  --hostname mstdnca \
  --storage local-lvm \
  --memory 1024 \
  --disk 8 \
  --cores 2 \
  --bridge vmbr0 \
  --ip dhcp
```

With a static IP:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/ChadOhman/mstdnca-proxmox-tool/main/create-ct.sh)" -- \
  --hostname mstdnca \
  --ip 10.0.0.100/24 \
  --gateway 10.0.0.1
```

With Cloudflare Tunnel support:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/ChadOhman/mstdnca-proxmox-tool/main/create-ct.sh)" -- \
  --hostname mstdnca \
  --ip dhcp \
  --cloudflared
```

#### CT Creation Options

| Flag | Default | Description |
|------|---------|-------------|
| `--ctid <ID>` | next available | Proxmox CT ID |
| `--hostname <NAME>` | `mstdnca` | CT hostname |
| `--storage <STORE>` | `local-lvm` | Storage for CT rootfs |
| `--template <PATH>` | auto-download Debian 12 | CT template path |
| `--memory <MB>` | `1024` | Memory allocation |
| `--disk <GB>` | `8` | Disk size |
| `--cores <N>` | `2` | CPU cores |
| `--bridge <BRIDGE>` | `vmbr0` | Network bridge |
| `--ip <IP/CIDR>` | `dhcp` | Static IP or `dhcp` |
| `--gateway <GW>` | — | Gateway (required for static IP) |
| `--cloudflared` | — | Also install cloudflared |

### Option 2: Manual Setup

Create a Debian 12 or Ubuntu 22.04+ CT in Proxmox, then inside the CT:

```bash
apt-get update && apt-get install -y git
git clone https://github.com/ChadOhman/mstdnca-proxmox-tool.git /tmp/mstdnca
cd /tmp/mstdnca && bash setup.sh
```

### First Login

Once deployed, open `http://<CT-IP>:5000` in your browser.

- **Username:** `admin`
- **Password:** `admin`

**Change the default password immediately** via the user dropdown menu.

## Configuration

### Adding Proxmox Hosts

1. Navigate to **Hosts** and click **Add Host**
2. Enter the Proxmox hostname/IP, port (default 8006), and authentication credentials (API token recommended)
3. Click **Test Connection** to verify, then save
4. Click **Discover Guests** to automatically import all VMs and CTs

### Adding Standalone Guests

Guests not managed by Proxmox (e.g. bare-metal servers) can be added manually under **Guests > Add Guest** with an IP address and SSH credential.

### Credentials

Under **Credentials** (super admin only), add SSH credentials (password or private key) that will be used to connect to your guests. You can assign a specific credential to each guest, or set one as the default.

### Discord Notifications

1. In Discord, create a webhook for the channel you want alerts in: **Channel Settings > Integrations > Webhooks > New Webhook**, then copy the webhook URL
2. In MCAT, go to **Settings > Discord Notifications** and paste the **Webhook URL**
3. Check **Enable Discord notifications** and pick which events to notify on — guest & host package updates (optionally security updates only), app version updates and upgrade started/result for Mastodon, Ghost, PeerTube, Elk, and Jitsi Meet, Prometheus exporter changes, and MCAT application updates
4. Click **Send Test Notification** to verify, then **Save Discord Settings**

Notifications arrive as rich embeds with per-guest update counts and severity colouring. Repeat scans that find the same set of pending updates are deduplicated, so you're only notified when something changes.

### Scan Settings

Under **Settings > Scan Settings**, configure how often to automatically scan for updates (1–168 hours). The scanner checks all enabled guests for available APT packages and flags security updates as critical.

### Maintenance Windows & Auto-Updates

Under **Schedules**, create maintenance windows specifying day, time range, and update type (`upgrade` or `dist-upgrade`). Assign windows to guests, then enable auto-update on each guest to have updates applied automatically during their window.

## UniFi Network Visibility

The **Network** page shows all devices and clients from your Ubiquiti UniFi controller.

### Setup

1. Go to **Settings > UniFi Controller** (super admin only)
2. Enter your controller URL (e.g. `https://10.0.4.1`), username, and password
3. Set the site name (default: `default`) and optionally filter by subnet (e.g. `10.0.4.0/24`)
4. Check **UDM / UniFi OS** if running on a UDM, UDM Pro, or UniFi OS Console; uncheck for standalone controller software
5. Click **Test Connection** to verify, then enable and save

### Capabilities

- **View devices** — All adopted UniFi network devices with name, model, IP, MAC, status, uptime, and firmware version
- **View clients** — All active clients with hostname, IP, MAC, network, connection type (wired/wireless), signal, and uptime
- **Restart devices** — Admins can restart individual devices (with confirmation)
- **Subnet filtering** — Optionally filter devices and clients to a specific subnet

All logged-in users can view the Network page. Only admins and super admins can restart devices.

## Mastodon Upgrades

The **Mastodon** page automates glitch-soc upgrades:

1. Navigate to **Mastodon** and configure:
   - **Mastodon App Guest** — the VM/CT running puma/sidekiq
   - **PostgreSQL Guest** — the VM/CT running your database
   - **PGBouncer host/port** — your normal DB connection (via PGBouncer)
   - **Direct DB host/port** — direct PostgreSQL connection (used during migrations)
   - **Current version** — your installed Mastodon version
2. Click **Check for Updates** to query the [mastodon/mastodon](https://github.com/mastodon/mastodon/releases) GitHub repo
3. Click **Upgrade Now** to run the full upgrade sequence:

The upgrade process:
1. Snapshots both the app and database guests via Proxmox API
2. `git stash` to save local customizations
3. Swaps `.env.production` DB_HOST/DB_PORT from PGBouncer to direct PostgreSQL
4. `git pull` to fetch the latest glitch-soc code
5. `git stash pop` to restore local customizations
6. `bundle install` and `yarn install`
7. Pre-deployment database migrations
8. Asset precompilation
9. Service reload/restart
10. Cache clear and post-deployment migrations
11. Restores `.env.production` back to PGBouncer
12. Final service restart

Enable **automatic upgrades** to have this run whenever a new release is detected.

## User Management & Access Control

### Roles

MCAT uses a 4-tier role system:

| Role | Level | Capabilities |
|------|-------|-------------|
| **Super Admin** | 4 | Full access. Configure API keys (UniFi, Proxmox), manage settings, credentials, users, app updates |
| **Admin** | 3 | Manage guests, hosts, schedules, apply updates, scan all, restart UniFi devices, manage non-super users |
| **Operator** | 2 | SSH into assigned guests, scan/apply updates on assigned guests, view network, view dashboard |
| **Viewer** | 1 | Read-only dashboard, view assigned guests and network devices |

### Tags

Tags map to Proxmox guest tags and control which guests non-admin users can access:

- Create tags under **Users** and assign them to users
- Users can only see and manage guests that share their assigned tags
- Admins and super admins see all guests regardless of tags
- Untagged guests are accessible to admins only

### User Management

Admins and super admins can manage users under **Users**:

- Create users with a role and optional tag assignments
- Users can only edit/delete users with a lower role level
- Super admins can assign any role; admins can assign operator and viewer roles

## Cloudflare Zero Trust

For secure external access without a VPN. MCAT validates Cloudflare Access JWTs — it doesn't matter where `cloudflared` runs.

### Using an Existing Tunnel

If you already have `cloudflared` running on another CT, VM, or your Proxmox host:

1. Open the **Cloudflare Zero Trust dashboard** > Networks > Tunnels
2. Select your existing tunnel and click **Configure**
3. Add a **Public Hostname** entry pointing to `http://<MCAT-CT-IP>:5000`
4. Go to **Access > Applications**, create an application for the hostname
5. Copy the **Application Audience (AUD)** tag
6. In MCAT, go to **Settings > Cloudflare Zero Trust**, enter your team domain and AUD tag, and enable

### Creating a New Tunnel

If you don't have a tunnel yet:

1. Run `bash setup.sh --cloudflared` inside the MCAT CT to install cloudflared
2. `cloudflared tunnel login` and `cloudflared tunnel create mstdnca`
3. Configure the tunnel to route to `http://localhost:5000`
4. Create an Access Application in the Zero Trust dashboard
5. Enter the team domain and AUD tag in MCAT settings

### Options

- **Auto-provision users** — automatically creates accounts for new CF Access users (viewer role, no tags until admin assigns them)
- **CF Access as sole authentication** — disables local login entirely (ensure CF Access is working first)

## Local Network Bypass

Under **Settings > Local Network Access**, trusted subnets (default `10.0.0.0/8`) are automatically authenticated as admin without login. This allows seamless LAN access while requiring authentication for external connections.

## Updating

### From the Web UI

Go to **Settings > Application** and click **Check for Updates**. If a new version is available, click **Update Now**.

### From the Command Line

```bash
bash /opt/mstdnca/update.sh
```

This backs up the database, pulls the latest code, updates dependencies, and restarts the service.

## Architecture

```
Flask Web UI (:5000)
├── Dashboard ─── update overview across datacenter
├── Hosts ─────── Proxmox node management + guest discovery
├── Guests ────── VM/CT list with update status
├── Terminal ──── browser-based SSH (xterm.js + WebSocket)
├── Network ───── UniFi device/client visibility
├── Mastodon ──── glitch-soc upgrade automation
├── Credentials ─ encrypted SSH key/password storage
├── Schedules ─── maintenance windows for auto-updates
├── Users ─────── 4-tier RBAC with tag-based filtering
└── Settings ──── Discord, scan, UniFi, CF Access, local bypass

Background Services (APScheduler)
├── Update scanner ─── periodic APT check across all guests
├── Mastodon checker ─ polls GitHub for new releases
├── Auto-updater ───── applies updates during maintenance windows
└── Discord notifier ─ webhook alerts for updates & upgrades
```

## Requirements

### System Dependencies

Installed automatically by `setup.sh`:

- **Python 3.11+** with `pip` and `venv`
- **git** (for cloning and self-update)
- **curl** (for template downloads)
- **Debian 12** or **Ubuntu 22.04+** (LXC container or VM)

### Python Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| Flask | 3.1.0 | Web framework |
| Flask-SQLAlchemy | 3.1.1 | Database ORM integration |
| Flask-Login | 0.6.3 | Session-based authentication |
| flask-sock | 0.7.0 | WebSocket support for SSH terminal |
| SQLAlchemy | 2.0.36 | Database ORM |
| proxmoxer | 2.1.0 | Proxmox API client |
| requests | 2.32.3 | HTTP client (used by proxmoxer and UniFi API) |
| paramiko | 3.5.0 | SSH client for remote command execution |
| cryptography | 44.0.0 | Fernet encryption for stored credentials |
| APScheduler | 3.10.4 | Background job scheduling |
| Werkzeug | 3.1.3 | WSGI utilities |
| PyJWT[crypto] | 2.10.1 | JWT validation for Cloudflare Access |
| gunicorn | 23.0.0 | Production WSGI server |
| gevent | latest | Async worker for WebSocket support |
| gevent-websocket | latest | WebSocket protocol for gunicorn |

### Frontend (CDN, no install needed)

- **Bootstrap 5.3.3** — UI framework (dark theme)
- **Bootstrap Icons 1.11.3** — Icon set
- **htmx 2.0.4** — Dynamic HTML updates
- **xterm.js** — Terminal emulator for web SSH

### Optional

- **cloudflared** — Cloudflare Tunnel agent for Zero Trust access (install with `setup.sh --cloudflared`)

## Tech Stack

- **Backend:** Python 3.11+, Flask, SQLAlchemy, APScheduler
- **Frontend:** Bootstrap 5 (dark theme), htmx, xterm.js
- **Database:** SQLite
- **Connections:** proxmoxer (Proxmox API), paramiko (SSH), UniFi Controller API
- **Security:** Fernet encryption, PyJWT (Cloudflare Access), 4-tier RBAC
- **Production server:** gunicorn with gevent-websocket worker

## File Layout

```
/opt/mstdnca/          # Application code + Python venv
/var/lib/mstdnca/      # SQLite database + backups
/etc/mstdnca/          # Encryption keys (secret.key, flask_secret)
```

## License

This project is licensed under the GNU General Public License v3.0 — see the [LICENSE](LICENSE) file for details.
