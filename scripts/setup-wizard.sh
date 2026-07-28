#!/bin/bash
# AEGIS-SIGMA setup wizard
CONFIG="/etc/aegis-sigma/.env"
LOCAL_ENV=".env"

echo ""
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║     AEGIS-SIGMA Setup Wizard                  ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo ""

# Use local .env if not root, /etc/aegis-sigma/.env if root
if [ "$(id -u)" -eq 0 ]; then
    ENVFILE="$CONFIG"
else
    ENVFILE="$LOCAL_ENV"
fi

# ── Consent ────────────────────────────────────────────────────
echo "  AEGIS-SIGMA collects anonymized threat data (attack patterns,"
echo "  IP fingerprints, classification results) to improve model"
echo "  accuracy across the network. No personal data, no browsing"
echo "  history, no content — only security telemetry."
echo ""
echo "  Telemetry is required for the free edition."
echo ""

# ── Your Site ──────────────────────────────────────────────────
read -p "  Your site URL [https://your-site.com]: " PRIMARY_SITE
PRIMARY_SITE=${PRIMARY_SITE:-"https://your-site.com"}

# ── Backend ────────────────────────────────────────────────────
read -p "  Origin server URL [http://127.0.0.1:8081]: " BACKEND_URL
BACKEND_URL=${BACKEND_URL:-"http://127.0.0.1:8081"}

# ── Strike Server ──────────────────────────────────────────────
echo ""
echo "  Strike server (where hostile traffic is redirected):"
echo "    1) Local only (default)"
echo "    2) Aegis-SIGMA hosted (pro license)"
echo "    3) Custom URL"
read -p "  Choose [1]: " strike_choice
case "$strike_choice" in
    2) STRIKE_URL="http://strike.aegis-sigma.com:8443" ;;
    3) read -p "  Strike URL: " STRIKE_URL; STRIKE_URL=${STRIKE_URL:-"local"} ;;
    *) STRIKE_URL="local" ;;
esac

# ── Data Paths ─────────────────────────────────────────────────
echo ""
echo "  Data storage paths (press Enter for defaults):"
read -p "  Data directory [./data]: " DATA_DIR; DATA_DIR=${DATA_DIR:-"./data"}
read -p "  Log directory [./logs]: " LOG_DIR; LOG_DIR=${LOG_DIR:-"./logs"}
read -p "  Models directory [./models]: " MODELS_DIR; MODELS_DIR=${MODELS_DIR:-"./models"}

# ── LLM (optional) ────────────────────────────────────────────
echo ""
echo "  LLM API for teacher (optional, leave empty to skip):"
read -p "  LLM API key: " LLM_KEY
read -p "  LLM API URL: " LLM_URL
read -p "  LLM model: " LLM_MODEL

# ── Network ────────────────────────────────────────────────────
echo ""
echo "  Network mode:"
echo "    1) Standalone (no VPN, direct connection)"
echo "    2) WireGuard mesh (server-to-server VPN) [RECOMMENDED]"
echo ""
echo "  WireGuard encrypts all internal traffic, hides admin ports"
echo "  from the public internet, and enables multi-node clusters."
echo ""
read -p "  Choose [2]: " network_choice
case "$network_choice" in
    1) WIREGUARD_IP="" ;;
    *) read -p "  WireGuard IP [10.88.0.1]: " WIREGUARD_IP; WIREGUARD_IP=${WIREGUARD_IP:-"10.88.0.1"} ;;
esac

# ── Install WireGuard if chosen and missing ────────────────────
if [ -n "$WIREGUARD_IP" ] && [ "$(id -u)" -eq 0 ] && ! command -v wg &>/dev/null; then
    echo ""
    echo "  WireGuard not found. Install now?"
    read -p "  Install WireGuard? [Y/n]: " wg_install
    if [ "$wg_install" != "n" ] && [ "$wg_install" != "N" ]; then
        apt-get install -y wireguard 2>/dev/null && echo "  ✓ WireGuard installed" || echo "  ⚠ Manual install: sudo apt-get install wireguard"
    fi
fi

# ── Write .env ─────────────────────────────────────────────────
mkdir -p "$DATA_DIR" "$LOG_DIR" "$MODELS_DIR"

cat > "$ENVFILE" <<EOF
TELEMETRY=true
PRIMARY_SITE=$PRIMARY_SITE
BACKEND_URL=$BACKEND_URL
STRIKE_URL=$STRIKE_URL
DATA_DIR=$DATA_DIR
LOG_DIR=$LOG_DIR
MODELS_DIR=$MODELS_DIR
VAULT_DIR=./vault
WIREGUARD_IP=$WIREGUARD_IP
LLM_KEY=$LLM_KEY
LLM_MODEL=$LLM_MODEL
LLM_URL=$LLM_URL
EOF

chmod 600 "$ENVFILE"

# ── Add APT repo for updates ──────────────────────────────────
if [ "$(id -u)" -eq 0 ] && command -v apt-get &>/dev/null; then
    echo "deb [trusted=yes] http://apt.aegis-sigma.com/aegis ./" > /etc/apt/sources.list.d/aegis.list
    apt-get update -qq 2>/dev/null
    echo "  ✓ APT repo added for automatic updates"
fi

echo ""
echo "  ✓ Saved to $ENVFILE"
echo "  ✓ Created directories: $DATA_DIR $LOG_DIR $MODELS_DIR"
echo ""
echo "  Start services: sudo systemctl enable --now aegis-c aegis-shield aegis-soul aegis-geoip aegis-trap"
echo "  Update: apt update && apt upgrade aegis-sigma-v5-free"
echo ""

# ── Check for updates ──────────────────────────────────────────
echo "  Checking for updates..."
REMOTE=$(curl -s https://api.github.com/repos/jaredrlawson/aegis-sigma/releases/latest 2>/dev/null | grep '"tag_name"' | cut -d'"' -f4)
LOCAL=$(dpkg -s aegis-sigma 2>/dev/null | grep Version | awk '{print $2}')
if [ -n "$REMOTE" ] && [ -n "$LOCAL" ] && [ "$REMOTE" != "$LOCAL" ]; then
    echo "  ⚠ Update available: $REMOTE (you have $LOCAL)"
    echo "  Download: https://github.com/jaredrlawson/aegis-sigma/releases/latest"
elif [ -n "$REMOTE" ]; then
    echo "  ✓ You're up to date ($LOCAL)"
fi
echo ""

# ── Upgrade prompt ─────────────────────────────────────────────
echo "  ─────────────────────────────────────────────────────"
echo "  Want more? Pro tier ($59/mo) adds:"
echo "    • Pre-trained threat models (plug & play)"
echo "    • Web management dashboard"
echo "    • Teacher LLM (120B deep-path forensics)"
echo "    • 583 security agent prompts"
echo "    • Monthly email threat reports"
echo ""
echo "  Upgrade: https://aegis-sigma.com/pricing"
echo "  ─────────────────────────────────────────────────────"
echo ""
