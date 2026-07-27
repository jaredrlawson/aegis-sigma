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
echo "    1) Enable telemetry (recommended)"
echo "    2) Disable telemetry"
echo ""
read -p "  Choose [1]: " telemetry_choice
TELEMETRY=$( [ "$telemetry_choice" = "2" ] && echo "false" || echo "true" )

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

# ── Write .env ─────────────────────────────────────────────────
mkdir -p "$DATA_DIR" "$LOG_DIR" "$MODELS_DIR"

cat > "$ENVFILE" <<EOF
TELEMETRY=$TELEMETRY
PRIMARY_SITE=$PRIMARY_SITE
BACKEND_URL=$BACKEND_URL
STRIKE_URL=$STRIKE_URL
DATA_DIR=$DATA_DIR
LOG_DIR=$LOG_DIR
MODELS_DIR=$MODELS_DIR
VAULT_DIR=./vault
LLM_KEY=$LLM_KEY
LLM_MODEL=$LLM_MODEL
LLM_URL=https://api.openai.com/v1/chat/completions
EOF

chmod 600 "$ENVFILE"
echo ""
echo "  ✓ Saved to $ENVFILE"
echo "  ✓ Created directories: $DATA_DIR $LOG_DIR $MODELS_DIR"
echo ""
echo "  Done. Start with: aegis-shield"
echo ""
