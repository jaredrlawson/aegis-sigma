#!/bin/bash
# AEGIS-SIGMA setup wizard — configures site, strike, and telemetry.
# Run interactively after first install.

CONFIG="/etc/aegis-sigma/.env"

echo ""
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║     AEGIS-SIGMA Setup Wizard                  ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo ""

# ── Data Collection Consent ──────────────────────────────────────
echo "  AEGIS-SIGMA collects anonymized threat data (attack patterns,"
echo "  IP fingerprints, classification results) to improve model"
echo "  accuracy across the network. No personal data, no browsing"
echo "  history, no content — only security telemetry."
echo ""
echo "    1) Enable telemetry (recommended) — helps improve protection"
echo "    2) Disable telemetry — local only, no data shared"
echo ""
read -p "  Choose [1]: " telemetry_choice
telemetry_choice=${telemetry_choice:-1}

case "$telemetry_choice" in
    1) TELEMETRY="true"; echo "  → Telemetry enabled" ;;
    *) TELEMETRY="false"; echo "  → Telemetry disabled" ;;
esac

echo ""

# ── Your Domain ────────────────────────────────────────────────
read -p "  Your domain (e.g. https://example.com): " PRIMARY_SITE
PRIMARY_SITE=${PRIMARY_SITE:-"http://localhost:8080"}
echo "  → Primary site: $PRIMARY_SITE"

echo ""

# ── Backend ────────────────────────────────────────────────────
echo "  Origin server URL (the app Shield protects and proxies to)"
echo "    Example: http://127.0.0.1:8080"
echo "    Leave empty for Host header routing (multi-site)"
read -p "  Backend URL [leave empty]: " BACKEND_URL
BACKEND_URL=${BACKEND_URL:-"http://127.0.0.1:8081"}

echo ""

# ── Strike Server ──────────────────────────────────────────────
echo "  Strike server — where hostile traffic is redirected"
echo ""
echo "    1) Local only (default — no external connection)"
echo "    2) Aegis-SIGMA hosted (pro license required)"
echo "    3) My own server"
echo ""
read -p "  Choose [1]: " strike_choice
strike_choice=${strike_choice:-1}

case "$strike_choice" in
    1) STRIKE_URL="local" ;;
    2) STRIKE_URL="http://strike.aegis-sigma.com:8443" ;;
    3) read -p "  Strike URL: " STRIKE_URL; STRIKE_URL=${STIKE_URL:-"local"} ;;
    *) STRIKE_URL="local" ;;
esac

echo ""

# ── Write .env ─────────────────────────────────────────────────
cat > "$CONFIG" <<EOF
TELEMETRY=$TELEMETRY
PRIMARY_SITE=$PRIMARY_SITE
BACKEND_URL=$BACKEND_URL
STRIKE_URL=$STRIKE_URL
WIREGUARD_IP=127.0.0.1
EOF

chmod 644 "$CONFIG"
echo "  ✓ Saved to $CONFIG"
echo ""

# ── Restart ────────────────────────────────────────────────────
echo "  Restarting services..."
for svc in aegis-shield-go aegis-bridge-go; do
    systemctl restart "$svc" 2>/dev/null && echo "  ✓ $svc" || true
done

echo ""
echo "  Done. Services running."
echo ""
