# Architecture Deep Dive

## Data Flow

```
Internet / Test Network
        │
        ▼
┌──────────────────────────────────────────────────────┐
│              Docker Isolated Network                 │
│                 (172.20.0.0/24)                      │
│                                                      │
│  Port 2222 ──► Cowrie SSH Honeypot (172.20.0.10)    │
│  Port 2323 ──► Cowrie Telnet Honeypot               │
│  Port 8080 ──► HTTP Panel Honeypot (172.20.0.11)    │
│                                                      │
│  All outbound traffic BLOCKED (no pivot possible)   │
└──────────────┬───────────────────────────────────────┘
               │ Shared Docker volume (logs only)
               ▼
┌──────────────────────────────────────────────────────┐
│            Analysis Pipeline (Host)                  │
│                                                      │
│  log_parser.py       → Parses JSON logs → SQLite    │
│  geoip_enricher.py   → Adds lat/lon/ASN to IPs      │
│  payload_extractor.py → Hashes & classifies malware │
│  alerter.py          → Fires Slack/email alerts     │
│                                                      │
└──────────────┬───────────────────────────────────────┘
               │ SQLite database reads
               ▼
┌──────────────────────────────────────────────────────┐
│          Threat Dashboard (Flask :5000)              │
│                                                      │
│  /api/stats/overview     → KPI cards                │
│  /api/stats/attack_map   → GeoIP world map          │
│  /api/stats/top_commands → Bar chart                │
│  /api/stats/timeline     → Hourly line chart        │
│  /api/payloads           → Malware gallery          │
│  /api/alerts             → Alert feed               │
└──────────────────────────────────────────────────────┘
```

## Security Isolation

The honeypot containers run in a dedicated Docker bridge network with no default route to the host or internet. Docker `iptables` rules prevent:

- Container-to-host traffic (attackers cannot reach the host OS)
- Container-to-container traffic outside the honeypot network
- Outbound internet access from inside the container (prevents C2 callbacks from attacker tools)

Logs are written to a Docker volume and read by the analysis pipeline via a **read-only** volume mount.

## Medical Device Persona

The Cowrie honeypot is configured to impersonate a **BD Alaris 8015 infusion pump** running embedded Linux. This is achieved by:

1. **Banner**: SSH version string matches OpenSSH builds found on ARM embedded systems
2. **Hostname**: Set to `infusion-pump-01` in `cowrie.cfg`
3. **Fake filesystem**: `fs.pickle` contains a minimal embedded Linux filesystem with device-specific paths
4. **Process list**: `ps aux` shows `alaris_pump_daemon` and `watchdog` processes
5. **Credentials**: `userdb.txt` includes real default credentials from ICS-CERT advisories

## HIPAA Alignment

| HIPAA Rule | Honeypot Capability |
|---|---|
| 164.308(a)(1) Risk Analysis | Captures attacker TTPs targeting medical devices |
| 164.308(a)(6) Incident Response | Full attacker session log as incident evidence |
| 164.312(b) Audit Controls | Immutable JSON logs with timestamps |
| 164.308(a)(5) Security Awareness | Real attack data for staff training |
