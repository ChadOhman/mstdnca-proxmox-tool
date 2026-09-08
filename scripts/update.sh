#!/bin/bash
set -e
set -o pipefail

# ============================================================
# Mastodon Canada Administration Tool - Self-Update Script
# Pulls latest from GitHub, updates deps, restarts service
# Usage: bash update.sh
# ============================================================

APP_NAME="mstdnca-proxmox-tool"
APP_DIR="/opt/mstdnca"
DATA_DIR="/var/lib/mstdnca"
BACKUP_DIR="/var/lib/mstdnca/backups"
HEALTH_URL="http://127.0.0.1:5000/health"
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

# GIT_DIR / PREV_COMMIT are populated in step 2 and read by rollback_to_previous.
GIT_DIR="$APP_DIR"
PREV_COMMIT=""

# Revert to the commit recorded before this update started, reinstall its
# requirements, and restart the service. Used when a step fails partway
# through, or when the post-restart health check does not come up.
rollback_to_previous() {
    local reason="$1"
    echo ""
    echo "============================================"
    echo " ROLLING BACK ($reason)"
    echo "============================================"
    if [ -z "$PREV_COMMIT" ]; then
        echo "  No previous commit recorded (fresh checkout or non-git deploy) — cannot roll back code."
    else
        echo "  Reverting code to $PREV_COMMIT..."
        set +e
        (cd "$GIT_DIR" && git checkout --quiet "$PREV_COMMIT") 2>&1 | sed 's/^/    /'
        checkout_status=${PIPESTATUS[0]}
        set -e
        if [ "$checkout_status" -ne 0 ]; then
            echo "  ERROR: rollback checkout failed (exit $checkout_status). Manual intervention required."
        else
            echo "  Reinstalling previous requirements..."
            cd "$APP_DIR"
            source venv/bin/activate
            pip install -r requirements.txt 2>&1 | grep -E 'Successfully|already|Requirement|Collecting|ERROR' | sed 's/^/    /'
        fi
    fi
    echo "  Restarting service..."
    systemctl restart "$APP_NAME" || true
    sleep 2
    if systemctl is-active --quiet "$APP_NAME"; then
        echo "  Service is active after rollback."
    else
        echo "  WARNING: Service did not come back up after rollback. Check: journalctl -u $APP_NAME -n 50"
    fi
}

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
echo "[1/5] Backing up database...  ($(ts))"
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
echo "[2/5] Pulling latest code...  ($(ts))"

if [ ! -d "$APP_DIR/.git" ]; then
    PARENT_DIR=$(dirname "$APP_DIR")
    if [ -d "$PARENT_DIR/.git" ]; then
        GIT_DIR="$PARENT_DIR"
    fi
fi

if [ -d "$GIT_DIR/.git" ]; then
    cd "$GIT_DIR"
    PREV_COMMIT=$(git rev-parse HEAD)
    BRANCH="${UPDATE_BRANCH:-main}"
    echo "  Branch: $BRANCH"
    echo "  Previous commit: $PREV_COMMIT"

    echo "  Fetching from origin..."
    set +e
    if [ -n "$GITHUB_TOKEN" ]; then
        # Private repo: authenticate this fetch only via an ephemeral header.
        # GitHub git-over-HTTPS requires Basic auth with the token as the password
        # (it rejects "Authorization: Bearer" for git transport — that is only for
        # the REST API).  The header is handed to git through GIT_CONFIG_* in the
        # environment rather than `git -c ...`: a command-line argument is visible
        # in /proc/<pid>/cmdline and to `ps` for anyone on the box while the fetch
        # runs.  It still never lands in .git/config, is not echoed, is not printed
        # by git, and this script does not run `set -x`, so it stays out of the log.
        _gh_basic=$(printf 'x-access-token:%s' "$GITHUB_TOKEN" | base64 | tr -d '\n')
        GIT_CONFIG_COUNT=1 \
        GIT_CONFIG_KEY_0=http.extraheader \
        GIT_CONFIG_VALUE_0="Authorization: Basic $_gh_basic" \
            git fetch origin 2>&1 | sed 's/^/    /'
        fetch_status=${PIPESTATUS[0]}
        unset _gh_basic
    else
        git fetch origin 2>&1 | sed 's/^/    /'
        fetch_status=${PIPESTATUS[0]}
    fi
    set -e
    if [ "$fetch_status" -ne 0 ]; then
        echo "ERROR: git fetch failed (exit $fetch_status). Aborting update; repository left at $PREV_COMMIT, service not restarted."
        exit 1
    fi

    # Show incoming commits before applying them
    AHEAD=$(git log --oneline HEAD..origin/"$BRANCH" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$AHEAD" -gt 0 ]; then
        echo "  $AHEAD new commit(s) incoming:"
        git log --oneline HEAD..origin/"$BRANCH" 2>/dev/null | sed 's/^/    + /'
    else
        echo "  Already up to date."
    fi

    set +e
    git checkout "$BRANCH" 2>&1 | sed 's/^/    /'
    checkout_status=${PIPESTATUS[0]}
    set -e
    if [ "$checkout_status" -ne 0 ]; then
        echo "ERROR: git checkout $BRANCH failed (exit $checkout_status). Aborting update; repository left at $PREV_COMMIT, service not restarted."
        exit 1
    fi

    set +e
    git reset --hard "origin/$BRANCH" 2>&1 | sed 's/^/    /'
    reset_status=${PIPESTATUS[0]}
    set -e
    if [ "$reset_status" -ne 0 ]; then
        echo "ERROR: git reset --hard failed (exit $reset_status). Aborting update; repository left at $PREV_COMMIT, service not restarted."
        exit 1
    fi

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
echo "[3/5] Updating Python dependencies...  ($(ts))"
source venv/bin/activate

echo "  Upgrading pip..."
# A failed pip self-upgrade is not fatal on its own (the existing pip is
# reused below), so this one is logged but not treated as an abort condition.
pip install --upgrade pip 2>&1 | grep -E 'Successfully|already|Requirement|ERROR' | sed 's/^/    /' || true

echo "  Installing requirements..."
set +e
pip install -r requirements.txt 2>&1 | grep -E 'Successfully|already|Requirement|Collecting|ERROR' | sed 's/^/    /'
pip_status=${PIPESTATUS[0]}
set -e
if [ "$pip_status" -ne 0 ]; then
    echo "ERROR: pip install -r requirements.txt failed (exit $pip_status)."
    rollback_to_previous "dependency install failure"
    exit 1
fi

echo "  Dependencies up to date."

# ── Step 4: Restart ──────────────────────────────────────────
echo ""
echo "[4/5] Restarting service...  ($(ts))"

systemctl restart "$APP_NAME"
sleep 2

if systemctl is-active --quiet "$APP_NAME"; then
    echo "  Service is active."
    systemctl status "$APP_NAME" --no-pager -n 3 2>&1 | sed 's/^/    /'
else
    echo "  WARNING: Service is not active yet; continuing to health check."
fi

# ── Step 5: Verify health, roll back automatically on failure ──
echo ""
echo "[5/5] Verifying health...  ($(ts))"

HEALTH_OK=false
for _i in $(seq 1 30); do
    if curl -fsS -o /dev/null -m 3 "$HEALTH_URL" 2>/dev/null; then
        HEALTH_OK=true
        break
    fi
    sleep 2
done

if [ "$HEALTH_OK" != true ]; then
    echo "  ERROR: $HEALTH_URL did not respond within ~60s after restart."
    rollback_to_previous "failed post-update health check"
    echo ""
    echo "============================================"
    echo " Update FAILED — rolled back to v$CURRENT_VERSION ($PREV_COMMIT)"
    echo "============================================"
    exit 1
fi

echo "  Health check passed."

echo ""
echo "============================================"
echo " Update Complete!  ($(ts))"
echo " v$CURRENT_VERSION -> v$NEW_VERSION"
echo "============================================"
echo ""
