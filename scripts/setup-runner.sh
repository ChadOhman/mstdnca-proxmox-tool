#!/bin/bash
set -euo pipefail

# ============================================================
# Self-hosted GitHub Actions runner for the lambnet tool CI
# Run this as root on the Debian 12 host that will execute CI
# (the lambnet-mcat CT, 10.0.0.193). Idempotent: re-running
# upgrades the runner binary and re-registers it.
#
# Usage:
#   RUNNER_TOKEN=<registration token> bash setup-runner.sh [OPTIONS]
#     --repo <owner/name>   GitHub repository (default: ChadOhman/mstdnca-proxmox-tool)
#     --name <NAME>         Runner name shown in GitHub (default: hostname)
#     --labels <a,b,c>      Extra labels (default: lambnet)
#     --version <X.Y.Z>     actions/runner version (default: 2.338.2)
#     --sha256 <hex>        SHA-256 of the linux-x64 tarball for --version
#     --remove              Unregister and remove the runner, then exit
#
# The registration token comes from GitHub and expires after an hour:
#   gh api -X POST repos/ChadOhman/mstdnca-proxmox-tool/actions/runners/registration-token -q .token
#
# What this does:
#   * installs the packages the workflows need (git, python3-venv, zip, libicu)
#   * creates the unprivileged service account 'gh-runner' (no sudo, no shell login)
#   * downloads actions/runner, verifies its checksum, unpacks it to /opt/actions-runner
#   * registers it with the repository and installs the systemd unit
#
# Security notes (the repository is public):
#   * Set the repository's fork-PR policy to "Require approval for all
#     outside collaborators" before the first run, or any previous
#     contributor's fork can execute code on this host:
#       gh api -X PUT repos/<owner/name>/actions/permissions/fork-pr-contributor-approval \
#          -f approval_policy=all_external_contributors
#   * The runner user owns only /opt/actions-runner. It cannot read
#     /opt/mstdnca, /etc/mstdnca or /var/lib/mstdnca.
# ============================================================

REPO="ChadOhman/mstdnca-proxmox-tool"
RUNNER_NAME="$(hostname)"
EXTRA_LABELS="lambnet"
RUNNER_VERSION="2.338.2"
# From the actions/runner release notes (<!-- BEGIN SHA linux-x64 -->).
RUNNER_SHA256="baebf204307bac6193480852732f0aba2ae97b6c5597c244f4d5558390147c40"
RUNNER_USER="gh-runner"
RUNNER_DIR="/opt/actions-runner"
REMOVE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --repo) REPO="$2"; shift 2 ;;
        --name) RUNNER_NAME="$2"; shift 2 ;;
        --labels) EXTRA_LABELS="$2"; shift 2 ;;
        --version) RUNNER_VERSION="$2"; shift 2 ;;
        --sha256) RUNNER_SHA256="$2"; shift 2 ;;
        --remove) REMOVE=1; shift ;;
        -h|--help) sed -n '4,36p' "$0"; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: run as root" >&2
    exit 1
fi
if [[ -z "${RUNNER_TOKEN:-}" ]]; then
    echo "ERROR: RUNNER_TOKEN is not set (see the header for how to mint one)" >&2
    exit 1
fi
if ! [[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
    echo "ERROR: --repo must be owner/name" >&2
    exit 1
fi

run_as_runner() {
    # The runner refuses to run as root; everything under RUNNER_DIR is
    # done as the service account. -H sets HOME so the tool cache lands in
    # the runner's own home and not root's.
    sudo -H -u "$RUNNER_USER" "$@"
}

if [[ $REMOVE -eq 1 ]]; then
    if [[ -x "$RUNNER_DIR/svc.sh" ]]; then
        (cd "$RUNNER_DIR" && ./svc.sh stop || true)
        (cd "$RUNNER_DIR" && ./svc.sh uninstall || true)
    fi
    if [[ -x "$RUNNER_DIR/config.sh" ]]; then
        (cd "$RUNNER_DIR" && run_as_runner ./config.sh remove --token "$RUNNER_TOKEN")
    fi
    rm -rf "$RUNNER_DIR"
    echo "Runner removed from $REPO and $RUNNER_DIR deleted."
    exit 0
fi

echo "[1/5] Installing packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
# libicu: the runner's .NET host needs it. zip/tar: release.yml archives.
# python3-venv/dev + build-essential: the workflows build a venv on the
# system Python (3.11, the same version production runs).
apt-get install -y -qq git curl tar zip unzip ca-certificates libicu72 \
    python3 python3-venv python3-dev python3-pip build-essential sudo

echo "[2/5] Creating service account '$RUNNER_USER'..."
if ! id "$RUNNER_USER" >/dev/null 2>&1; then
    useradd --system --create-home --home-dir "/home/$RUNNER_USER" \
        --shell /usr/sbin/nologin "$RUNNER_USER"
fi
mkdir -p "$RUNNER_DIR"
chown "$RUNNER_USER:$RUNNER_USER" "$RUNNER_DIR"
chmod 750 "$RUNNER_DIR"
# Belt and braces: the tool's own data must stay out of reach of CI jobs.
for p in /opt/mstdnca /etc/mstdnca /var/lib/mstdnca; do
    [[ -e "$p" ]] && chmod o-rwx "$p"
done

echo "[3/5] Downloading actions/runner v$RUNNER_VERSION..."
TARBALL="actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz"
URL="https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${TARBALL}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
curl -fsSL -o "$TMP/$TARBALL" "$URL"
echo "$RUNNER_SHA256  $TMP/$TARBALL" | sha256sum -c -
if [[ -x "$RUNNER_DIR/svc.sh" ]]; then
    echo "    existing install found — stopping its service for the upgrade"
    (cd "$RUNNER_DIR" && ./svc.sh stop || true)
    (cd "$RUNNER_DIR" && ./svc.sh uninstall || true)
fi
tar -xzf "$TMP/$TARBALL" -C "$RUNNER_DIR"
chown -R "$RUNNER_USER:$RUNNER_USER" "$RUNNER_DIR"

echo "[4/5] Registering with $REPO as '$RUNNER_NAME'..."
cd "$RUNNER_DIR"
if [[ -f .runner ]]; then
    run_as_runner ./config.sh remove --token "$RUNNER_TOKEN" || true
fi
# --replace: a stale registration under the same name is overwritten.
# --disableupdate: upgrades happen by re-running this script, so the
# version and checksum stay under our control.
run_as_runner ./config.sh --unattended --replace --disableupdate \
    --url "https://github.com/$REPO" \
    --token "$RUNNER_TOKEN" \
    --name "$RUNNER_NAME" \
    --labels "$EXTRA_LABELS" \
    --work _work

echo "[5/5] Installing the systemd service..."
./svc.sh install "$RUNNER_USER"
./svc.sh start
sleep 3
./svc.sh status | tail -5

echo
echo "Done. The runner appears under Settings > Actions > Runners in $REPO"
echo "with labels self-hosted, linux, x64, $EXTRA_LABELS."
echo "Logs: journalctl -u 'actions.runner.*' -f"
