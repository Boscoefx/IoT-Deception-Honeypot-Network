# 🏥 Healthcare IoT Deception Honeypot Network

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Required-2496ED.svg)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Honeypot-red.svg)]()

> A proactive IoT deception system that simulates vulnerable medical devices to trap attackers, capture malicious payloads, and generate real-time threat intelligence — all within a fully isolated Docker sandbox.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [Dashboard](#dashboard)
- [Alerting](#alerting)
- [HIPAA Compliance Notes](#hipaa-compliance-notes)
- [Week-by-Week Roadmap](#week-by-week-roadmap)

---

## Overview

This project deploys a network of low-to-medium interaction honeypots that impersonate real healthcare IoT devices (infusion pumps, HVAC controllers, patient monitors). When attackers probe or compromise these fake devices, every keystroke, command, and payload drop is logged, parsed, and visualized on a live threat dashboard.

**Key Capabilities:**
- Simulates SSH/Telnet services with default medical IoT credentials
- Captures brute-force attempts, dropped malware, and shell commands
- Sends real-time alerts when internal IPs interact with honeypots (lateral movement detection)
- Generates GeoIP-enriched threat intelligence reports
- Fully sandboxed — attackers cannot pivot to the real network

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Docker Isolated Network                │
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  Cowrie SSH  │  │  Cowrie      │  │  Honeyd      │  │
│  │  Honeypot    │  │  Telnet      │  │  HTTP Panel  │  │
│  │  Port 2222   │  │  Port 2323   │  │  Port 8080   │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
│         └─────────────────┴──────────────────┘          │
│                           │                             │
│                    ┌──────▼───────┐                     │
│                    │  Log Shipper │                     │
│                    │  (Filebeat)  │                     │
│                    └──────┬───────┘                     │
└───────────────────────────┼─────────────────────────────┘
                            │
              ┌─────────────▼──────────────┐
              │   Python Analysis Engine   │
              │  • GeoIP enrichment        │
              │  • Payload extraction      │
              │  • Alert generation        │
              └─────────────┬──────────────┘
                            │
              ┌─────────────▼──────────────┐
              │   Threat Dashboard (Flask)  │
              │  • Live attack map         │
              │  • Command frequency       │
              │  • Attacker timeline       │
              └────────────────────────────┘
```

---

## Prerequisites

- Docker & Docker Compose v2+
- Python 3.10+
- 2GB+ RAM recommended
- (Optional) MaxMind GeoLite2 free account for GeoIP

```bash
# Check Docker
docker --version
docker compose version

# Check Python
python3 --version
```

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/healthcare-iot-honeypot.git
cd healthcare-iot-honeypot

# 2. Copy and configure environment
cp .env.example .env
# Edit .env with your settings (see Configuration section)

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Start all honeypot containers
docker compose up -d

# 5. Verify containers are running
docker compose ps

# 6. Launch the threat dashboard
python dashboard/app.py

# 7. Open dashboard at http://localhost:5000
```

---

## Project Structure

```
healthcare-iot-honeypot/
├── docker/
│   ├── docker-compose.yml          # Orchestrates all honeypot containers
│   ├── cowrie.dockerfile           # Custom Cowrie image for medical IoT simulation
│   └── honeyd.dockerfile           # Honeyd HTTP panel simulation
├── cowrie-config/
│   ├── cowrie.cfg                  # Main Cowrie configuration
│   ├── userdb.txt                  # Default credential pairs (admin/admin, etc.)
│   └── fs.pickle                   # Simulated medical device filesystem
├── dashboard/
│   ├── app.py                      # Flask threat dashboard server
│   ├── templates/
│   │   └── index.html              # Dashboard UI
│   └── static/
│       └── dashboard.js            # Live-updating chart logic
├── scripts/
│   ├── log_parser.py               # Parses raw Cowrie JSON logs
│   ├── geoip_enricher.py           # Adds GeoIP data to attacker IPs
│   ├── payload_extractor.py        # Extracts and hashes dropped malware
│   └── report_generator.py         # Weekly threat intelligence PDF report
├── alerts/
│   ├── alerter.py                  # Alert engine (email + Slack)
│   └── internal_ip_monitor.py      # Lateral movement detector
├── tests/
│   ├── test_parser.py              # Unit tests for log parser
│   └── test_alerter.py             # Unit tests for alert engine
├── logs/                           # Mounted log volume (gitignored)
├── docs/
│   └── ARCHITECTURE.md             # Detailed architecture notes
├── .env.example                    # Environment variable template
├── requirements.txt                # Python dependencies
└── README.md                       # This file
```

---

## Configuration

Copy `.env.example` to `.env` and fill in your values:

```env
# Honeypot Settings
HONEYPOT_HOSTNAME=MedDevice-Infusion-Pump-01
HONEYPOT_SSH_PORT=2222
HONEYPOT_TELNET_PORT=2323
HONEYPOT_HTTP_PORT=8080

# Internal network CIDR — alerts fire if these IPs hit the honeypot
INTERNAL_NETWORK_CIDR=192.168.1.0/24

# Alert Settings
ALERT_EMAIL=security@yourhospital.com
SMTP_HOST=smtp.yourhospital.com
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...

# GeoIP (get free key at maxmind.com)
MAXMIND_LICENSE_KEY=your_key_here

# Dashboard
DASHBOARD_PORT=5000
DASHBOARD_SECRET_KEY=change_me_in_production
```

---

## Dashboard

The Flask dashboard auto-refreshes every 30 seconds and displays:

| Panel | Description |
|-------|-------------|
| 🗺️ Attack Map | GeoIP-mapped source of all connection attempts |
| 📊 Top Attacker IPs | Ranked table of most active attackers |
| 💻 Command Frequency | Bar chart of most-attempted shell commands |
| 📁 Payload Gallery | Dropped malware files with SHA256 hashes |
| ⏱️ Attack Timeline | Hourly attack volume over the last 7 days |
| 🚨 Lateral Movement | Internal IP alerts in real time |

---

## Alerting

The alert engine fires immediately when:

1. **Any internal IP** connects to a honeypot node (lateral movement indicator)
2. A **new payload** is uploaded to the honeypot
3. An attacker achieves **persistent shell access**

Alerts are sent via:
- Email (SMTP)
- Slack webhook
- Local log file (`logs/alerts.log`)

---

## HIPAA Compliance Notes

This system supports HIPAA Security Rule compliance by providing:

- **§164.308(a)(1)** — Risk analysis evidence via captured threat data
- **§164.308(a)(6)** — Security incident documentation with full attacker logs
- **§164.312(b)** — Audit controls through immutable honeypot logs

> ⚠️ **Legal Notice:** Only deploy this honeypot on networks you own or have explicit written authorization to monitor. Honeypot data may be used as evidence; consult legal counsel before internet exposure.

---

## Week-by-Week Roadmap

| Week | Focus | Key Deliverable |
|------|-------|-----------------|
| 1 | Environment Setup | Docker + Cowrie deployed, medical IoT persona configured |
| 2 | Exposure & Capture | Live logging of brute force, commands, payloads |
| 3 | Analysis Engine | GeoIP enrichment, payload hashing, alert system |
| 4 | Dashboard & Reporting | Live threat dashboard, HIPAA compliance report |

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built as part of a Healthcare Cybersecurity Internship Program. For educational and authorized security research purposes only.*
