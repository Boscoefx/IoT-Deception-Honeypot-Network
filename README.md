.

# Healthcare IoT Deception Honeypot Network

## Project Overview

The Healthcare IoT Deception Honeypot Network is a cybersecurity research and threat intelligence platform designed to simulate vulnerable healthcare IoT devices inside an isolated Docker-based environment. The project proactively deceives attackers, captures malicious activity, records attacker behavior, and visualizes security telemetry using the Elastic Stack.

This project focuses on healthcare cyber-physical systems such as:

* Smart patient monitoring systems
* IoT-enabled medical devices
* Smart HVAC infrastructure
* Network-connected healthcare equipment

The environment uses low-to-medium interaction honeypots to safely monitor:

* SSH brute-force attacks
* Telnet attacks
* Malicious payload downloads
* Unauthorized login attempts
* Command execution attempts
* Threat actor telemetry

---

# Project Objectives

## Primary Goal

Shift from reactive cybersecurity defense to proactive threat intelligence gathering using deception technologies.

## Key Security Objectives

* Simulate vulnerable healthcare IoT devices
* Capture attacker interactions safely
* Prevent attacker escape using Docker isolation
* Centralize attack logs using Elasticsearch
* Visualize attack telemetry using Kibana
* Extract indicators of compromise (IoCs)
* Demonstrate healthcare-focused cyber deception architecture

---

# Features

## Implemented Features

### Honeypot Infrastructure

* Docker-isolated honeypot environment
* Simulated healthcare IoT devices
* Cowrie-based SSH/Telnet deception
* Medical device banner simulation
* Vulnerable service emulation

### Threat Collection

* SSH brute-force logging
* Telnet attack logging
* Login telemetry capture
* Command execution capture
* Payload metadata logging
* Threat severity tagging

### Elastic Stack Integration

* Elasticsearch indexing
* Kibana dashboards
* Threat visualization
* Real-time log monitoring
* Attack telemetry analysis

### Python Automation

* Log parsing automation
* SQLite threat database
* Elasticsearch shipping pipeline
* Payload extraction workflow
* Threat enrichment utilities

### Security Operations Workflow

* Threat monitoring
* IOC extraction
* Simulated malware tracking
* Dashboard-based analysis
* Incident visibility

---

# Technology Stack

| Component          | Technology            |
| ------------------ | --------------------- |
| Honeypot           | Cowrie                |
| Containerization   | Docker                |
| Search Engine      | Elasticsearch         |
| Visualization      | Kibana                |
| Backend Automation | Python                |
| Database           | SQLite                |
| Log Shipping       | Python + Elastic APIs |
| Operating System   | Kali Linux            |

---

# Final Project Architecture

```text
                    ┌─────────────────────────┐
                    │      Attacker / Bot     │
                    │ SSH / Telnet Attempts   │
                    └────────────┬────────────┘
                                 │
                                 ▼
                ┌────────────────────────────────┐
                │  Docker Isolated Honeypot Lab │
                └────────────────────────────────┘
                                 │
         ┌───────────────────────┴────────────────────────┐
         │                                                │
         ▼                                                ▼
┌────────────────────┐                        ┌────────────────────┐
│  Cowrie Honeypot   │                        │ HTTP IoT Honeypot  │
│ SSH/Telnet Capture │                        │ Medical Web Device │
└──────────┬─────────┘                        └──────────┬─────────┘
           │                                             │
           └─────────────────────┬───────────────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │      SQLite Database    │
                    │  events / payload logs  │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ Python Log Parser       │
                    │ elastic_shipper.py      │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │     Elasticsearch       │
                    │  Threat Intelligence    │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │         Kibana          │
                    │ Dashboards & Analytics  │
                    └─────────────────────────┘
```

---

# Project Structure

```text
IoT-Deception-Honeypot-Network/
│
├── app.py
├── alerter.py
├── elastic_shipper.py
├── log_parser.py
├── payload_extractor.py
├── http_honeypot_server.py
├── cowrie.cfg
├── userdb.txt
├── start.sh
├── requirements.txt
├── README.md
├── ARCHITECTURE.md
├── docker-compose.yml
├── docker-compose-elastic.yml
├── cowrie.dockerfile
├── honeypot.db
├── scripts/
│   ├── __init__.py
│   └── log_parser.py
│
└── Kibana + Elasticsearch Stack
```

---

# Installation Guide

## 1. Clone Repository

```bash
git clone https://github.com//Boscoefx/IoT-Deception-Honeypot-Network.git
cd IoT-Deception-Honeypot-Network
```

---

# 2. Install Docker

```bash
sudo apt update
sudo apt install docker.io docker-compose -y
```

Enable Docker:

```bash
sudo systemctl enable docker
sudo systemctl start docker
```

---

# 3. Fix Docker Permission Issue

Allow normal user access to Docker:

```bash
sudo usermod -aG docker $USER
newgrp docker
```

Verify:

```bash
docker ps
```

---

# 4. Install Python Requirements

```bash
pip install -r requirements.txt
```

---

# 5. Initialize SQLite Database

```bash
sqlite3 honeypot.db
```

Create tables:

```sql
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    event_type TEXT,
    src_ip TEXT,
    src_port INTEGER,
    username TEXT,
    password TEXT,
    command TEXT,
    session_id TEXT,
    sensor TEXT
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    src_ip TEXT,
    username TEXT,
    password TEXT,
    success INTEGER
);

CREATE TABLE IF NOT EXISTS payloads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    src_ip TEXT,
    filename TEXT,
    sha256 TEXT,
    url TEXT
);
```

Exit:

```sql
.exit
```

---

# 6. Start Elastic Stack

```bash
chmod +x start.sh
./start.sh
```

Services:

| Service       | URL                                            |
| ------------- | ---------------------------------------------- |
| Elasticsearch | [http://localhost:9200](http://localhost:9200) |
| Kibana        | [http://localhost:5601](http://localhost:5601) |

---

# Testing Attack Logs

## Test SSH Brute Force Event

```bash
curl -X POST "localhost:9200/honeypot-events/_doc" \
-H "Content-Type: application/json" \
-d '{
  "@timestamp":"2026-05-11T22:12:00Z",
  "src_ip":"192.168.1.55",
  "attack_type":"SSH Brute Force",
  "username":"root",
  "password":"toor",
  "severity":"critical",
  "command":"wget malware.sh",
  "sensor":"cowrie"
}'
```

---

## Test Login Attempt

```bash
curl -X POST "localhost:9200/honeypot-logins/_doc" \
-H "Content-Type: application/json" \
-d '{
  "@timestamp":"2026-05-11T22:13:00Z",
  "src_ip":"10.0.0.5",
  "username":"admin",
  "password":"123456",
  "success":false
}'
```

---

## Test Payload Upload

```bash
curl -X POST "localhost:9200/honeypot-payloads/_doc" \
-H "Content-Type: application/json" \
-d '{
  "@timestamp":"2026-05-11T22:14:00Z",
  "src_ip":"45.33.22.11",
  "filename":"malware.sh",
  "sha256":"e3b0c44298fc1c149afbf4c8996fb924",
  "url":"http://malicious.site/malware.sh"
}'
```

---

# Kibana Dashboard Usage

Open:

```text
http://localhost:5601
```

Navigate to:

* Discover
* Lens
* Dashboard

Available indexes:

* honeypot-events
* honeypot-logins
* honeypot-payloads

Recommended Visualizations:

* Attack frequency chart
* Top attacker IPs
* Login brute-force trends
* Payload download tracking
* Severity distribution
* SSH/Telnet attack counts

---

# Security Features

## Isolation Controls

* Docker container sandboxing
* No direct host exposure
* Controlled network segmentation
* Isolated honeypot infrastructure

## Threat Intelligence

* IOC extraction
* Attack telemetry
* Login analytics
* Command capture
* Payload tracking

## Healthcare Relevance

* Simulated medical device infrastructure
* Healthcare IoT attack surface representation
* HIPAA-oriented monitoring concepts
* Proactive cyber deception strategy

---

# Known Limitations

* Geolocation enrichment partially implemented
* Full malware reverse engineering not included
* Cowrie runtime may require environment-specific tuning
* Simulated attack data used for demonstrations

---

# Future Improvements

* Real-time alerting system
* GeoIP threat mapping
* ML-based anomaly detection
* SIEM integration
* Advanced malware sandboxing
* Threat scoring engine
* Automated IOC correlation

---

# Demonstration Workflow

## Step 1

Start Docker and Elastic stack.

## Step 2

Launch honeypot services.

## Step 3

Inject simulated SSH/Telnet attacks.

## Step 4

Verify logs inside Elasticsearch.

## Step 5

Visualize attacks in Kibana.

## Step 6

Demonstrate IOC extraction and dashboard analytics.

---

# Final Outcome

The project successfully demonstrates a healthcare-focused deception-based cybersecurity architecture capable of:

* Simulating vulnerable IoT infrastructure
* Capturing attacker behavior
* Logging malicious activity
* Aggregating centralized threat intelligence
* Visualizing attack telemetry using Elastic Stack
* Providing proactive cybersecurity monitoring workflows

---

# Author

Cybersecurity Internship Project

Healthcare IoT Deception Honeypot Network

Developed using

* Docker
* Cowrie
* Elasticsearch
* Kibana
* Python
* SQLite
