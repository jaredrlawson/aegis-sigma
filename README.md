# AEGIS-SIGMA v5 Free

Real-time web security platform — SIMD-optimized C inference (30-feature, sub-millisecond) wrapped in Go gateway services.

**Best for:** Developers, homelab users, VPS operators.
**Pricing:** [aegis-sigma.com/pricing](https://aegis-sigma.com/pricing)

## Install

Download the latest `.deb` from [Releases](https://github.com/jaredrlawson/aegis-sigma/releases).

```bash
# ARM64 (Raspberry Pi 4/5, Oracle Free Tier, AWS Graviton, Oracle ARM)
sudo dpkg -i aegis-sigma-v5-free_1.1.2-0_arm64.deb

# AMD64 (x86_64 servers)
sudo dpkg -i aegis-sigma-v5-free_1.1.2-0_amd64.deb

# Start services
sudo systemctl enable --now aegis-c aegis-shield aegis-soul

# Verify (C engine health endpoint)
curl http://localhost:8086/
```

The setup wizard runs automatically on install. Edit config any time: `sudo nano /etc/aegis-sigma/.env`

## What's Included (Free)

- **C Engine** (port 20129) — Random Forest / Isolation Forest inference, sub-millisecond, 2-3 MB RAM
- **Go Shield** (port 3000) — HTTP classifier + rate limiting + challenge pages
- **Go Soul** (port 3007) — clustering + anomaly detection
- **Baseline static model** — works on first boot, no training required
- **Telemetry** (anonymized, optional) — helps improve models across the network

## Architecture

```
Internet → Go Shield (:3000)
  → Extracts 30 features from HTTP request
  → C Engine (:20129) classifies with multi-model pipeline
  → Go Shield: pass / block / challenge
```

## Pro Feature Locks (upgrade for)

- Pre-trained threat models (Plug and Play)
- Web management dashboard (multi-node)
- Active deception and advanced tarpitting (honeypots, decoys, tarpits)
- Court-ready forensic export
- Teacher LLM (120B deep-path)
- Go Auditor for compliance monitoring
- Multi-node orchestration

See [aegis-sigma.com/pricing](https://aegis-sigma.com/pricing) for tiers and licensing.

## License

MIT License — see [LICENSE](LICENSE) for details.
