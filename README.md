# AEGIS-SIGMA

Open-source web security firewall engine with SIMD-optimized C inference, LightGBM classifier, Isolation Forest anomaly detection, and Go gateway.

## Quick Start

```bash
# Clone
git clone https://github.com/jaredrlawson/aegis-sigma.git
cd aegis-sigma

# Install
sudo dpkg -i aegis-sigma_1.0.0_arm64.deb

# Configure
cp .env.example .env
sudo ./scripts/setup.sh

# Verify
curl http://localhost:8086/  # C engine status
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

## Configuration

All settings via environment variables (`.env` file):

```bash
# Your sites
PRIMARY_SITE=https://your-site.com

# Backend origin
BACKEND_URL=http://127.0.0.1:8081

# Strike server
STRIKE_URL=local  # or http://strike.aegis-sigma.com:8443

# Email
EMAIL_FROM=shield@your-site.com

# LLM (for Teacher)
LLM_BASE_URL=https://ai.aegis-sigma.com/v1
```

## Docker

```bash
docker build -f packaging/docker/Dockerfile -t aegis-sigma .
docker run -p 3000:3000 -p 8086:8086 aegis-sigma
```

## Training

```bash
# Retrain models from brain.sqlite
python3 training/retrain_models.py

# Restart C engine to load new weights
sudo systemctl restart aegis-c
```

## Community vs Pro

| Feature | Community | Pro |
|---------|-----------|-----|
| C Engine | ✅ | ✅ |
| Go Shield | ✅ | ✅ |
| Go Soul | ✅ | ✅ |
| Go GeoIP | ✅ | ✅ |
| Go Trap | ✅ | ✅ |
| Go Bridge | ✅ (disabled) | ✅ |
| Teacher LLM | ❌ | ✅ |
| Active Learning | ❌ | ✅ |
| Multi-Node Dashboard | ❌ | ✅ |
| Agent Library (500+) | ❌ | ✅ |

## License

MIT License — see [LICENSE](LICENSE) for details.
