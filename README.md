# AEGIS-SIGMA v5 Free

Open-source web security platform with SIMD-optimized C inference, LightGBM classifier, Isolation Forest anomaly detection, and Go gateway.

**Best for:** Developers, homelab users, open-source contributors.
**Benefit:** "Free security firewall you can train on your own traffic."

## Quick Start

```bash
# Clone
git clone https://github.com/jaredrlawson/aegis-sigma.git
cd aegis-sigma

# Install
sudo dpkg -i editions/free/aegis-sigma-v5-free_1.0.0-0_arm64.deb

# Configure
./scripts/setup.sh

# Verify
curl http://localhost:8086/
```

## Architecture

```
Internet → Go Shield (:3000)
  → Extracts 30 features from HTTP request
  → C Engine (:20129) classifies with 4-model pipeline
    1. Shield (Random Forest) — hostile/benign probability
    2. Soul (Isolation Forest) — anomaly score
    3. Lead Hunter (Linear) — online learning
    4. Phi Auditor (Consensus Gate) — final verdict
  → Go Shield: pass/block/challenge
```

## Components

| Component | Port | Purpose |
|-----------|------|---------|
| aegis-shield | 3000 | HTTP classifier + challenge pages |
| aegis-soul | 3007 | Event clustering + LLM integration |
| aegis-trap | 3001 | Honeypots + tarpit |
| aegis-geoip | 4040 | IP enrichment (MaxMind) |
| aegis-bridge | 8899 | Lead management API |
| aegis-c-engine | 20129 | ML inference engine |

## SSH Log Tailing

No dashboard or CLI in the free version. Use SSH to monitor:

```bash
# Shield (classifier + blocks)
ssh user@your-server "tail -f /var/log/aegis/shield_soul.log"

# C Engine (ML inference)
ssh user@your-server "journalctl -u aegis-c -f"

# Bridge (lead management)
ssh user@your-server "tail -f /var/log/aegis/bridge-go.log"

# Trap (honeypots)
ssh user@your-server "journalctl -u aegis-trap -f"

# All services
ssh user@your-server "journalctl -u aegis-shield-go -u aegis-soul -u aegis-c -u aegis-trap -f"
```

## Configuration

All settings via `.env` file:

```bash
cp .env.example .env
./scripts/setup.sh
```

## Docker

```bash
docker build -f packaging/docker/Dockerfile -t aegis-sigma .
docker run -p 3000:3000 -p 8086:8086 aegis-sigma
```

## Training

```bash
python3 training/retrain_models.py
sudo systemctl restart aegis-c
```

## Updates

Setup wizard adds APT repo automatically:
```bash
apt update && apt upgrade aegis-sigma-v5-free
```

## What's Included (Free)

- C Engine (30-feature ML inference, not pre-trained)
- Go Shield (HTTP classifier + challenge pages)
- Go Soul (Isolation Forest anomaly detection)
- Go GeoIP (MaxMind IP enrichment)
- Go Trap (honeypots + tarpit)
- Go Bridge (lead management API, disabled by default)
- Traffic generator
- Training scripts

## What's NOT Included (Pro only)

- Go Auditor (integrity verification + monitoring)
- Go Dashboard (admin UI)
- Teacher LLM (real-time classification)
- Active Learning pipeline
- Multi-Node Dashboard
- Agent Library (583 prompts)
- Pre-trained models
- Automated incident response
- Monthly email reports

## License

MIT License — see [LICENSE](LICENSE) for details.
