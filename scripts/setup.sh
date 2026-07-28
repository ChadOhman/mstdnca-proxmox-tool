#!/bin/bash
set -e

# ============================================================
# Mastodon Canada Administration Tool - CT Setup Script
# Run this inside a fresh Debian/Ubuntu LXC container
# Usage: bash setup.sh [--version <TAG>] [--cloudflared]
#   --version <TAG>  Checkout a specific version tag (default: main branch)
#   --cloudflared    Also install cloudflared for CF Zero Trust tunnel
# ============================================================

APP_NAME="mstdnca-proxmox-tool"
APP_DIR="/opt/mstdnca"
DATA_DIR="/var/lib/mstdnca"
SECRET_DIR="/etc/mstdnca"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
REPO_URL="https://github.com/ChadOhman/mstdnca-proxmox-tool.git"
INSTALL_CLOUDFLARED=false
TARGET_VERSION=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --cloudflared)
            INSTALL_CLOUDFLARED=true
            shift
            ;;
        --version)
            TARGET_VERSION="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

echo "============================================"
echo " Mastodon Canada Administration Tool - Setup"
echo "============================================"
echo ""

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root."
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    echo "Detected OS: $PRETTY_NAME"
else
    echo "ERROR: Cannot detect OS. This script requires Debian or Ubuntu."
    exit 1
fi

if [[ "$OS" != "debian" && "$OS" != "ubuntu" ]]; then
    echo "ERROR: This script only supports Debian and Ubuntu."
    exit 1
fi

TOTAL_STEPS=7
if [ "$INSTALL_CLOUDFLARED" = true ]; then
    TOTAL_STEPS=8
fi

echo ""
echo "[1/$TOTAL_STEPS] Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv git curl > /dev/null 2>&1
echo "  Done."

echo ""
echo "[2/$TOTAL_STEPS] Setting up application directory..."
if [ -d "$APP_DIR" ] && [ -d "$APP_DIR/.git" ]; then
    echo "  Directory $APP_DIR already exists with git. Updating..."
    cd "$APP_DIR"
    git fetch --quiet --tags
    git pull --quiet
elif [ -d "$APP_DIR" ] && [ ! -d "$APP_DIR/.git" ]; then
    echo "  Directory $APP_DIR exists but has no git repo. Re-cloning..."
    rm -rf "$APP_DIR"
    git clone --quiet "$REPO_URL" "$APP_DIR"
else
    echo "  Cloning from GitHub..."
    git clone --quiet "$REPO_URL" "$APP_DIR"
fi
cd "$APP_DIR"

# Checkout specific version if requested, otherwise stay on main
if [ -n "$TARGET_VERSION" ]; then
    echo "  Checking out version $TARGET_VERSION..."
    git checkout --quiet "$TARGET_VERSION"
else
    git checkout --quiet main
fi
echo "  Done."

echo ""
echo "[3/$TOTAL_STEPS] Creating Python virtual environment..."
cd "$APP_DIR"
python3 -m venv venv
source venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
echo "  Done."

echo ""
echo "[4/$TOTAL_STEPS] Creating data directories..."
mkdir -p "$DATA_DIR"
mkdir -p "$SECRET_DIR"
chmod 700 "$SECRET_DIR"
echo "  Done."

echo ""
echo "[5/$TOTAL_STEPS] Generating encryption key and Flask secret..."
if [ ! -f "$SECRET_DIR/secret.key" ]; then
    cd "$APP_DIR"
    source venv/bin/activate
    python3 -c "
from cryptography.fernet import Fernet
key = Fernet.generate_key()
with open('$SECRET_DIR/secret.key', 'wb') as f:
    f.write(key)
"
    chmod 600 "$SECRET_DIR/secret.key"
    echo "  New encryption key generated."
else
    echo "  Encryption key already exists, keeping existing."
fi

# Generate a random Flask secret key if not already set
if [ ! -f "$SECRET_DIR/flask_secret" ]; then
    python3 -c "import secrets; print(secrets.token_hex(32))" > "$SECRET_DIR/flask_secret"
    chmod 600 "$SECRET_DIR/flask_secret"
    echo "  Flask secret key generated."
fi

echo ""
echo "[6/$TOTAL_STEPS] Initializing database..."
cd "$APP_DIR"
source venv/bin/activate
python3 -c "
from app import create_app
app = create_app()
print('  Database initialized.')
"

echo ""
echo "[7/$TOTAL_STEPS] Creating systemd service..."
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Mastodon Canada Administration Tool
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
Environment=MSTDNCA_DATA_DIR=$DATA_DIR
Environment=MSTDNCA_SECRET_KEY=$SECRET_DIR/secret.key
Environment=FLASK_SECRET_KEY_FILE=$SECRET_DIR/flask_secret
Environment=SESSION_COOKIE_SECURE=0
ExecStart=$APP_DIR/venv/bin/gunicorn --worker-class gevent --bind 0.0.0.0:5000 --workers 1 --timeout 120 "app:create_app()"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Install gevent for websocket support in production
source venv/bin/activate
pip install --quiet gevent

systemctl daemon-reload
systemctl enable "$APP_NAME"
systemctl restart "$APP_NAME"
echo "  Done."

# Optional: Install cloudflared
if [ "$INSTALL_CLOUDFLARED" = true ]; then
    echo ""
    echo "[8/$TOTAL_STEPS] Installing cloudflared..."

    # Detect architecture (cloudflared package repo handles arch automatically,
    # but we still check for supported platforms)
    ARCH=$(dpkg --print-architecture)
    if [ "$ARCH" != "amd64" ] && [ "$ARCH" != "arm64" ]; then
        echo "  WARNING: Unsupported architecture $ARCH for cloudflared. Skipping."
        INSTALL_CLOUDFLARED=false
    fi

    if [ "$INSTALL_CLOUDFLARED" = true ]; then
        # Install cloudflared via official package repo
        curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg 2>/dev/null
        echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main" > /etc/apt/sources.list.d/cloudflared.list
        apt-get update -qq
        apt-get install -y -qq cloudflared > /dev/null 2>&1
        echo "  cloudflared installed: $(cloudflared --version 2>&1 | head -1)"
    fi
fi

echo ""
echo "============================================"
echo " Setup Complete!"
echo "============================================"
echo ""
echo " Web UI:    http://$(hostname -I | awk '{print $1}'):5000"
echo " Username:  admin"
echo " Password:  generated on first start (view with: journalctl -u $APP_NAME | grep -A3 'DEFAULT ADMIN')"
echo ""
echo " IMPORTANT: Change the generated password after first login!"
echo ""
echo " Service commands:"
echo "   systemctl status $APP_NAME"
echo "   systemctl restart $APP_NAME"
echo "   journalctl -u $APP_NAME -f"
echo ""
echo " Data directory: $DATA_DIR"
echo " App directory:  $APP_DIR"
echo ""

if [ "$INSTALL_CLOUDFLARED" = true ]; then
    echo " Cloudflare Tunnel Setup:"
    echo "   1. cloudflared tunnel login"
    echo "   2. cloudflared tunnel create mstdnca"
    echo "   3. Create config at /etc/cloudflared/config.yml:"
    echo ""
    echo "      tunnel: <TUNNEL-ID>"
    echo "      credentials-file: /root/.cloudflared/<TUNNEL-ID>.json"
    echo "      ingress:"
    echo "        - hostname: mstdnca.yourdomain.com"
    echo "          service: http://localhost:5000"
    echo "        - service: http_status:404"
    echo ""
    echo "   4. cloudflared tunnel route dns mstdnca mstdnca.yourdomain.com"
    echo "   5. cloudflared service install"
    echo "   6. systemctl start cloudflared"
    echo ""
    echo "   Then configure CF Access in Zero Trust dashboard"
    echo "   and enter the AUD tag in Settings > Cloudflare Zero Trust."
    echo ""
fi
