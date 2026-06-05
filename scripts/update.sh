#!/bin/bash
set -e

# ============================================================
# Mastodon Canada Administration Tool - Self-Update Script
# Pulls latest from GitHub, updates deps, restarts service
# Usage: bash update.sh
# ============================================================

APP_NAME="mstdnca-proxmox-tool"
APP_DIR="/opt/mstdnca"
DATA_DIR="/var/lib/mstdnca"
BACKUP_DIR="/var/lib/mstdnca/backups"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
UPDATE_BRANCH=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --branch) UPDATE_BRANCH="$2"; shift 2 ;;
        *) shift ;;
    esac
done

# Log all output to file for web UI progress tracking
LOG_FILE="$DATA_DIR/update.log"
mkdir -p "$DATA_DIR"
echo "" > "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

ts() { date '+%H:%M:%S'; }

echo "============================================"
echo " Mastodon Canada Administration Tool"
echo " Self-Update  $(ts)"
echo "============================================"
echo ""

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root."
    exit 1
fi

# Navigate into the correct directory
if [ -f "$APP_DIR/app.py" ]; then
    cd "$APP_DIR"
elif [ -f "$APP_DIR/mstdnca-proxmox-tool/app.py" ]; then
    APP_DIR="$APP_DIR/mstdnca-proxmox-tool"
    cd "$APP_DIR"
else
    echo "ERROR: Cannot find application directory."
    exit 1
fi

# Read current version
CURRENT_VERSION="unknown"
if [ -f "VERSION" ]; then
    CURRENT_VERSION=$(cat VERSION | tr -d '[:space:]')
fi
echo "Current version : v$CURRENT_VERSION"
echo "App directory   : $APP_DIR"
echo ""

# ── Step 1: Backup ──────────────────────────────────────────
echo "[1/4] Backing up database...  ($(ts))"
mkdir -p "$BACKUP_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
if [ -f "$DATA_DIR/mstdnca.db" ]; then
    DB_SIZE=$(du -sh "$DATA_DIR/mstdnca.db" | cut -f1)
    cp "$DATA_DIR/mstdnca.db" "$BACKUP_DIR/mstdnca_${TIMESTAMP}.db"
    echo "  Saved $BACKUP_DIR/mstdnca_${TIMESTAMP}.db  ($DB_SIZE)"

    # Keep only last 10 backups
    REMOVED=$(ls -t "$BACKUP_DIR"/mstdnca_*.db 2>/dev/null | tail -n +11)
    if [ -n "$REMOVED" ]; then
        echo "$REMOVED" | xargs -r rm
        echo "  Removed old backups: $(echo "$REMOVED" | wc -l | tr -d ' ')"
    fi
else
    echo "  No database found — skipping backup."
fi

# ── Step 2: Pull code ────────────────────────────────────────
echo ""
echo "[2/4] Pulling latest code...  ($(ts))"

GIT_DIR="$APP_DIR"
if [ ! -d "$APP_DIR/.git" ]; then
    PARENT_DIR=$(dirname "$APP_DIR")
    if [ -d "$PARENT_DIR/.git" ]; then
        GIT_DIR="$PARENT_DIR"
    fi
fi

if [ -d "$GIT_DIR/.git" ]; then
    cd "$GIT_DIR"
    BRANCH="${UPDATE_BRANCH:-main}"
    echo "  Branch: $BRANCH"

    echo "  Fetching from origin..."
    if [ -n "$GITHUB_TOKEN" ]; then
        # Private repo: authenticate this fetch only via an ephemeral header.
        # -c http.extraheader keeps the token out of .git/config; git does not
        # echo header values, and this script does not run `set -x`, so the
        # token never reaches the update log.
        git -c http.extraheader="AUTHORIZATION: bearer $GITHUB_TOKEN" fetch origin 2>&1 | sed 's/^/    /'
    else
        git fetch origin 2>&1 | sed 's/^/    /'
    fi

    # Show incoming commits before applying them
    AHEAD=$(git log --oneline HEAD..origin/"$BRANCH" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$AHEAD" -gt 0 ]; then
        echo "  $AHEAD new commit(s) incoming:"
        git log --oneline HEAD..origin/"$BRANCH" 2>/dev/null | sed 's/^/    + /'
    else
        echo "  Already up to date."
    fi

    git checkout "$BRANCH" 2>&1 | sed 's/^/    /'
    git reset --hard "origin/$BRANCH" 2>&1 | sed 's/^/    /'
    cd "$APP_DIR"
    echo "  Code updated."
else
    echo "  WARNING: Not a git repository. Manual update may be needed."
fi

# Read new version
NEW_VERSION="unknown"
if [ -f "VERSION" ]; then
    NEW_VERSION=$(cat VERSION | tr -d '[:space:]')
fi
echo "  New version: v$NEW_VERSION"

# ── Step 3: Python dependencies ──────────────────────────────
echo ""
echo "[3/4] Updating Python dependencies...  ($(ts))"
source venv/bin/activate

echo "  Upgrading pip..."
pip install --upgrade pip 2>&1 | grep -E 'Successfully|already|Requirement|ERROR' | sed 's/^/    /'

echo "  Installing requirements..."
pip install -r requirements.txt 2>&1 | grep -E 'Successfully|already|Requirement|Collecting|ERROR' | sed 's/^/    /'

echo "  Installing gevent..."
pip install gevent 2>&1 | grep -E 'Successfully|already|Requirement|Collecting|ERROR' | sed 's/^/    /'

echo "  Dependencies up to date."

# ── Step 4: Restart ──────────────────────────────────────────
echo ""
echo "[4/4] Restarting service...  ($(ts))"

# Patch missing environment variables into the service file.
# SESSION_COOKIE_SECURE=0 is required for HTTP-only installs so that
# browsers send back the session cookie and session state (e.g. safety mode)
# is not lost on every request.
if [ -f "$SERVICE_FILE" ]; then
    if ! grep -q "SESSION_COOKIE_SECURE" "$SERVICE_FILE"; then
        sed -i '/^Environment=FLASK_SECRET_KEY_FILE/a Environment=SESSION_COOKIE_SECURE=0' "$SERVICE_FILE"
        systemctl daemon-reload
        echo "  Patched SESSION_COOKIE_SECURE=0 into service file."
    fi
fi

systemctl restart "$APP_NAME"
sleep 2

if systemctl is-active --quiet "$APP_NAME"; then
    echo "  Service is active."
    systemctl status "$APP_NAME" --no-pager -n 3 2>&1 | sed 's/^/    /'
else
    echo "  WARNING: Service may not have started."
    echo "  Check: journalctl -u $APP_NAME -n 20"
fi

echo ""
echo "============================================"
echo " Update Complete!  ($(ts))"
echo " v$CURRENT_VERSION -> v$NEW_VERSION"
echo "============================================"
echo ""
