# AEGIS-SIGMA v5 Free

Open-source web security platform with SIMD-optimized C inference, LightGBM classifier, Isolation Forest anomaly detection, and Go gateway.

**Best for:** Developers, homelab users, open-source contributors.
**Benefit:** "Security platform you can train on your own traffic."
**Pricing:** [aegis-sigma.com/pricing](https://aegis-sigma.com/pricing)

## Quick Start

```bash
# Download latest .deb from releases
# ARM64 (Raspberry Pi 4/5, Oracle Free Tier, AWS Graviton):
sudo dpkg -i aegis-sigma-v5-free_1.1.0-1_arm64.deb
# AMD64 (x86_64 servers):
sudo dpkg -i aegis-sigma-v5-free_1.1.0-1_amd64.deb

# The setup wizard runs automatically on install.
# Edit config any time: sudo nano /etc/aegis-sigma/.env

# Start services
sudo systemctl enable --now aegis-c aegis-shield aegis-soul aegis-geoip aegis-trap

# Verify (C engine health endpoint)
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
| aegis-c-engine | 20129 | ML inference engine |

## SSH Log Tailing

No dashboard or CLI in the free version. Use SSH to monitor:

```bash
# Shield (classifier + blocks)
ssh user@your-server "tail -f /var/log/aegis/shield_soul.log"

# C Engine (ML inference)
ssh user@your-server "journalctl -u aegis-c -f"

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

- C Engine (30-feature ML inference — sub-millisecond, 2-3 MB RAM)
- Go Shield (HTTP classifier + challenge pages, port 3000)
- Go Soul (Isolation Forest anomaly detection, port 3007)
- Go GeoIP (MaxMind IP enrichment, port 4040)
- Go Trap (honeypots + tarpit, port 3001)
- Traffic generator (load testing tool)
- Baseline static model (works on first boot — no training required)
- Training scripts (Python — retrain on your own traffic)
- Telemetry (anonymized, opt-out in `.env`)
- systemd unit files (one-command service enable)

## Pro Feature Locks (upgrade for)

- 🔒 **Pro Feature: Pre-trained Threat Models** (Plug & Play — skip the training step)
- 🔒 **Pro Feature: Web Management Dashboard** (graphs, live ops console, multi-node)
- 🔒 **Pro Feature: Teacher LLM** (120B MoE deep-path forensics, real-time)
- 🔒 **Pro Feature: Active Learning Pipeline** (continuous retraining from live traffic)
- 🔒 **Pro Feature: Agent Library** (583 security prompt templates)
- 🔒 **Pro Feature: Go Auditor** (integrity verification, 24/7 compliance probing)
- 🔒 **Pro Feature: Automated Incident Response** (STIX-2.1 forensic packets)
- 🔒 **Pro Feature: Monthly Email Threat Reports**

## Managed Feature Locks (Managed tier and above)

- 🔒 **Managed Feature: Active Deception & Advanced Tarpitting** (counter-attack server)
- 🔒 **Managed Feature: Court-Ready Forensic Exporting** (law enforcement evidence pipeline)
- 🔒 **Managed Feature: Our Servers, Our IP, Our AI API** (just point DNS at us)

## License

MIT License — see [LICENSE](LICENSE) for details.
