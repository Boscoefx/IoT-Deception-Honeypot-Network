"""
Alert Engine — Healthcare IoT Honeypot Network
===============================================
Monitors the honeypot database and fires alerts via
email and Slack when high-priority events occur:

  CRITICAL: Internal IP connects to honeypot (lateral movement)
  HIGH:     Attacker uploads a payload
  HIGH:     Attacker achieves persistent shell access
  MEDIUM:   New attacker IP detected
  LOW:      Brute-force threshold exceeded

Usage:
    python alerts/alerter.py --db honeypot.db --watch
"""

import sqlite3
import smtplib
import json
import os
import time
import argparse
import urllib.request
import urllib.error
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()

# ── Config from environment ────────────────────────────────────

ALERT_EMAIL = os.getenv("ALERT_EMAIL", "")
SMTP_HOST = os.getenv("SMTP_HOST", "localhost")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL", "")
INTERNAL_CIDR = os.getenv("INTERNAL_NETWORK_CIDR", "192.168.1.0/24")
ALERT_LOG = "logs/alerts.log"

SEVERITY_EMOJI = {
    "CRITICAL": "🚨",
    "HIGH": "🔴",
    "MEDIUM": "🟡",
    "LOW": "🟢",
}


# ── Alert Delivery ─────────────────────────────────────────────

def log_alert(severity: str, title: str, body: str):
    """Write alert to local log file."""
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "severity": severity,
        "title": title,
        "body": body,
    }
    os.makedirs("logs", exist_ok=True)
    with open(ALERT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")
    emoji = SEVERITY_EMOJI.get(severity, "⚪")
    print(f"[ALERT] {emoji} {severity}: {title}")


def send_slack(severity: str, title: str, body: str):
    """Post alert to Slack webhook."""
    if not SLACK_WEBHOOK:
        return

    emoji = SEVERITY_EMOJI.get(severity, "⚪")
    payload = json.dumps({
        "text": f"{emoji} *{severity} — Healthcare Honeypot*",
        "attachments": [{
            "color": {"CRITICAL": "danger", "HIGH": "danger",
                      "MEDIUM": "warning", "LOW": "good"}.get(severity, "good"),
            "title": title,
            "text": body,
            "footer": "Healthcare IoT Honeypot Network",
            "ts": int(time.time()),
        }]
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            SLACK_WEBHOOK,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"[!] Slack alert failed: {e}")


def send_email(severity: str, title: str, body: str):
    """Send alert via SMTP."""
    if not ALERT_EMAIL or not SMTP_HOST:
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[{severity}] Healthcare Honeypot: {title}"
    msg["From"] = SMTP_USER or "honeypot@hospital.local"
    msg["To"] = ALERT_EMAIL

    html = f"""
    <html><body style="font-family:Arial;background:#f5f5f5;padding:20px">
    <div style="background:white;padding:20px;border-radius:8px;border-left:5px solid
        {'#dc3545' if severity in ('CRITICAL','HIGH') else '#ffc107' if severity == 'MEDIUM' else '#28a745'}">
    <h2>🏥 Healthcare IoT Honeypot Alert</h2>
    <table>
        <tr><td><b>Severity:</b></td><td>{severity}</td></tr>
        <tr><td><b>Alert:</b></td><td>{title}</td></tr>
        <tr><td><b>Time:</b></td><td>{datetime.utcnow().isoformat()}Z</td></tr>
    </table>
    <hr>
    <pre style="background:#f8f8f8;padding:10px">{body}</pre>
    </div></body></html>
    """
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(msg["From"], [ALERT_EMAIL], msg.as_string())
    except Exception as e:
        print(f"[!] Email alert failed: {e}")


def fire_alert(severity: str, title: str, body: str):
    """Fire alert across all configured channels."""
    log_alert(severity, title, body)
    send_slack(severity, title, body)
    send_email(severity, title, body)


# ── Alert Rules ────────────────────────────────────────────────

def check_lateral_movement(conn: sqlite3.Connection, seen_events: set) -> list:
    """CRITICAL: Detect internal IPs interacting with honeypot."""
    import ipaddress
    try:
        internal_net = ipaddress.ip_network(INTERNAL_CIDR, strict=False)
    except ValueError:
        return []

    alerts = []
    cursor = conn.execute("""
        SELECT src_ip, timestamp, event_type, sensor
        FROM events
        WHERE datetime(timestamp) >= datetime('now', '-2 minutes')
        ORDER BY timestamp DESC
        LIMIT 100
    """)

    for row in cursor:
        ip = row[0]
        event_key = f"lateral_{ip}_{row[1]}"
        if event_key in seen_events:
            continue
        try:
            if ipaddress.ip_address(ip) in internal_net:
                seen_events.add(event_key)
                body = (
                    f"Internal IP {ip} connected to honeypot!\n"
                    f"Event: {row[2]}\nSensor: {row[3]}\nTime: {row[1]}\n\n"
                    f"⚠️  This likely indicates a COMPROMISED INTERNAL MACHINE.\n"
                    f"Action: Isolate {ip} immediately and investigate."
                )
                alerts.append(("CRITICAL", f"Lateral Movement Detected — {ip}", body))
        except ValueError:
            pass

    return alerts


def check_payload_uploads(conn: sqlite3.Connection, seen_events: set) -> list:
    """HIGH: New malware payload uploaded to honeypot."""
    alerts = []
    cursor = conn.execute("""
        SELECT src_ip, timestamp, filename, sha256
        FROM payloads
        WHERE datetime(timestamp) >= datetime('now', '-2 minutes')
        ORDER BY timestamp DESC
        LIMIT 20
    """)

    for row in cursor:
        event_key = f"payload_{row[3]}"
        if event_key in seen_events:
            continue
        seen_events.add(event_key)
        body = (
            f"Attacker {row[0]} dropped a file onto the honeypot.\n"
            f"Filename: {row[2]}\n"
            f"SHA256: {row[3]}\n"
            f"Time: {row[1]}\n\n"
            f"Run: python scripts/payload_extractor.py --file logs/downloads/{row[2]}"
        )
        alerts.append(("HIGH", f"Payload Dropped by {row[0]}", body))

    return alerts


def check_brute_force_spikes(conn: sqlite3.Connection, seen_events: set) -> list:
    """MEDIUM: IP exceeds brute-force threshold in short window."""
    alerts = []
    cursor = conn.execute("""
        SELECT src_ip, COUNT(*) as attempts
        FROM login_attempts
        WHERE datetime(timestamp) >= datetime('now', '-5 minutes')
        GROUP BY src_ip
        HAVING attempts >= 50
        ORDER BY attempts DESC
    """)

    for row in cursor:
        event_key = f"brute_{row[0]}_{datetime.utcnow().strftime('%Y%m%d%H%M')}"
        if event_key in seen_events:
            continue
        seen_events.add(event_key)
        body = (
            f"IP {row[0]} made {row[1]} login attempts in the last 5 minutes.\n"
            f"This is a brute-force credential stuffing attack.\n"
            f"All attempts logged. Attacker is trapped in honeypot."
        )
        alerts.append(("MEDIUM", f"Brute Force Spike — {row[0]} ({row[1]} attempts)", body))

    return alerts


# ── Main Watch Loop ────────────────────────────────────────────

def watch(db_path: str, interval: int = 60):
    """Continuously poll database for new alert conditions."""
    print(f"[*] Alert engine started — polling every {interval}s")
    print(f"[*] Internal CIDR: {INTERNAL_CIDR}")
    print(f"[*] Slack: {'configured' if SLACK_WEBHOOK else 'not configured'}")
    print(f"[*] Email: {'configured' if ALERT_EMAIL else 'not configured'}")

    seen_events: set = set()

    while True:
        try:
            conn = sqlite3.connect(db_path)

            for check in [check_lateral_movement, check_payload_uploads, check_brute_force_spikes]:
                alerts = check(conn, seen_events)
                for severity, title, body in alerts:
                    fire_alert(severity, title, body)

            conn.close()
        except Exception as e:
            print(f"[!] Alert engine error: {e}")

        time.sleep(interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Honeypot Alert Engine")
    parser.add_argument("--db", default="honeypot.db", help="SQLite database path")
    parser.add_argument("--watch", action="store_true", help="Continuously monitor")
    parser.add_argument("--interval", type=int, default=60, help="Poll interval in seconds")
    parser.add_argument("--test", action="store_true", help="Send a test alert")
    args = parser.parse_args()

    if args.test:
        fire_alert("HIGH", "Test Alert", "Alert engine is working correctly.")
    elif args.watch:
        watch(args.db, args.interval)
    else:
        parser.print_help()
