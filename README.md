

# Dashboard
DASHBOARD_PORT=5000
DASHBOARD_SECRET_KEY=change_me_in_production
```

---

## Dashboard

The Flask dashboard auto-refreshes every 30 seconds and displays:

| Panel | Description |
|-------|-------------|
|  Attack Map | GeoIP-mapped source of all connection attempts |
| Top Attacker IPs | Ranked table of most active attackers |
| Command Frequency | Bar chart of most-attempted shell commands |
|  Payload Gallery | Dropped malware files with SHA256 hashes |
|  Attack Timeline | Hourly attack volume over the last 7 days |
|  Lateral Movement | Internal IP alerts in real time |

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

>  **Legal Notice:** Only deploy this honeypot on networks you own or have explicit written authorization to monitor. Honeypot data may be used as evidence; consult legal counsel before internet exposure.

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
