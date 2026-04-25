"""
Threat Dashboard — Healthcare IoT Honeypot Network
===================================================
Flask web application that serves a live threat intelligence
dashboard. Reads from the SQLite database populated by
log_parser.py and presents:

  - Attack map data (GeoIP coordinates)
  - Top attacker IPs
  - Command frequency analysis
  - Payload gallery
  - Attack timeline
  - Lateral movement alerts

Usage:
    python dashboard/app.py
    python dashboard/app.py --db honeypot.db --port 5000
"""

import sqlite3
import os
import json
import argparse
from datetime import datetime
from flask import Flask, render_template_string, jsonify, request

app = Flask(__name__)
DB_PATH = os.getenv("HONEYPOT_DB", "honeypot.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ── API Endpoints ──────────────────────────────────────────────

@app.route("/api/stats/overview")
def api_overview():
    conn = get_db()
    stats = {}

    stats["total_connections"] = conn.execute(
        "SELECT COUNT(*) FROM events WHERE event_type = 'connect'"
    ).fetchone()[0]

    stats["unique_attackers"] = conn.execute(
        "SELECT COUNT(DISTINCT src_ip) FROM events"
    ).fetchone()[0]

    stats["login_attempts"] = conn.execute(
        "SELECT COUNT(*) FROM login_attempts"
    ).fetchone()[0]

    stats["successful_logins"] = conn.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE success = 1"
    ).fetchone()[0]

    stats["payloads_captured"] = conn.execute(
        "SELECT COUNT(*) FROM payloads"
    ).fetchone()[0]

    stats["commands_recorded"] = conn.execute(
        "SELECT COUNT(*) FROM events WHERE event_type = 'command'"
    ).fetchone()[0]

    stats["last_attack"] = conn.execute(
        "SELECT MAX(timestamp) FROM events"
    ).fetchone()[0] or "None"

    lateral = conn.execute("""
        SELECT COUNT(*) FROM events e
        WHERE e.src_ip LIKE '192.168.%'
           OR e.src_ip LIKE '10.%'
           OR e.src_ip LIKE '172.16.%'
    """).fetchone()[0]
    stats["lateral_movement_alerts"] = lateral

    conn.close()
    return jsonify(stats)


@app.route("/api/stats/top_ips")
def api_top_ips():
    limit = request.args.get("limit", 10, type=int)
    conn = get_db()
    rows = conn.execute("""
        SELECT e.src_ip,
               COUNT(*) as event_count,
               SUM(CASE WHEN e.event_type = 'login_success' THEN 1 ELSE 0 END) as successes,
               NULL as country,
               NULL as city,
               NULL as org,
               MAX(e.timestamp) as last_seen
        FROM events e
        GROUP BY e.src_ip
        ORDER BY event_count DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/stats/attack_map")
def api_attack_map():
    """GeoIP coordinates for world map visualization."""
    conn = get_db()
    try:
        rows = conn.execute("""
            SELECT g.ip, g.country, g.country_code, g.city,
                   g.latitude, g.longitude, g.org,
                   COUNT(e.id) as attacks
            FROM enriched_ips g
            JOIN events e ON g.ip = e.src_ip
            WHERE g.latitude IS NOT NULL
              AND g.is_internal = 0
            GROUP BY g.ip
            ORDER BY attacks DESC
            LIMIT 500
        """).fetchall()
    except Exception:
        rows = []
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/stats/top_commands")
def api_top_commands():
    conn = get_db()
    rows = conn.execute("""
        SELECT command, COUNT(*) as frequency
        FROM events
        WHERE event_type = 'command'
          AND command != ''
          AND LENGTH(command) < 200
        GROUP BY command
        ORDER BY frequency DESC
        LIMIT 20
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/stats/timeline")
def api_timeline():
    """Hourly attack volume for the past 7 days."""
    conn = get_db()
    rows = conn.execute("""
        SELECT strftime('%Y-%m-%d %H:00', timestamp) as hour,
               COUNT(*) as count,
               COUNT(DISTINCT src_ip) as unique_ips
        FROM events
        WHERE datetime(timestamp) >= datetime('now', '-7 days')
        GROUP BY hour
        ORDER BY hour
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/stats/top_credentials")
def api_top_credentials():
    conn = get_db()
    rows = conn.execute("""
        SELECT username, password, COUNT(*) as attempts
        FROM login_attempts
        GROUP BY username, password
        ORDER BY attempts DESC
        LIMIT 15
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/payloads")
def api_payloads():
    conn = get_db()
    rows = conn.execute("""
        SELECT p.*, e.src_ip as attacker_ip
        FROM payloads p
        LEFT JOIN events e ON p.session_id = e.session_id AND e.event_type = 'payload_download'
        ORDER BY p.timestamp DESC
        LIMIT 50
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/alerts")
def api_alerts():
    """Recent alerts from the alert log."""
    alerts = []
    alert_log = "logs/alerts.log"
    if os.path.exists(alert_log):
        with open(alert_log, "r") as f:
            lines = f.readlines()
        for line in reversed(lines[-50:]):
            try:
                alerts.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                pass
    return jsonify(alerts)


# ── Dashboard HTML ─────────────────────────────────────────────

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Healthcare IoT Honeypot — Threat Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  :root { --bg: #0d1117; --card: #161b22; --border: #30363d; --accent: #e94560; --green: #4ecca3; --text: #c9d1d9; --muted: #8b949e; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', Arial, sans-serif; }

  .navbar { background: var(--card); border-bottom: 1px solid var(--border); padding: 14px 24px; display: flex; align-items: center; gap: 12px; }
  .navbar h1 { font-size: 1.1em; color: var(--accent); }
  .navbar .badge { background: #1f6feb; color: white; padding: 3px 10px; border-radius: 20px; font-size: 0.75em; }
  .live-dot { width: 8px; height: 8px; background: var(--green); border-radius: 50%; animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }

  .main { padding: 20px 24px; }

  .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 20px; }
  .stat-card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
  .stat-card .label { font-size: 0.75em; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
  .stat-card .value { font-size: 2em; font-weight: 700; color: var(--text); margin: 4px 0; }
  .stat-card.alert .value { color: var(--accent); }
  .stat-card.good .value { color: var(--green); }

  .charts-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px; }
  .chart-card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
  .chart-card h3 { font-size: 0.85em; color: var(--muted); margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.05em; }
  canvas { max-height: 220px; }

  .wide { grid-column: 1 / -1; }

  table { width: 100%; border-collapse: collapse; font-size: 0.85em; }
  th { color: var(--muted); text-align: left; padding: 8px; border-bottom: 1px solid var(--border); font-weight: 500; }
  td { padding: 8px; border-bottom: 1px solid #21262d; }
  tr:hover td { background: #1c2128; }
  .ip { font-family: monospace; color: var(--green); }
  .hash { font-family: monospace; color: var(--muted); font-size: 0.8em; }
  .badge-crit { background: #dc3545; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.75em; }
  .badge-high { background: #fd7e14; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.75em; }
  .badge-med { background: #ffc107; color: #000; padding: 2px 8px; border-radius: 4px; font-size: 0.75em; }

  .last-update { text-align: right; font-size: 0.75em; color: var(--muted); margin-bottom: 8px; }
  .empty { color: var(--muted); text-align: center; padding: 20px; font-style: italic; }
</style>
</head>
<body>

<div class="navbar">
  <div class="live-dot"></div>
  <h1>🏥 Healthcare IoT Honeypot — Threat Dashboard</h1>
  <span class="badge">LIVE</span>
  <span style="margin-left:auto;color:var(--muted);font-size:0.8em" id="last-update"></span>
</div>

<div class="main">

  <!-- Overview Stats -->
  <div class="stat-grid" id="stat-grid">
    <div class="stat-card"><div class="label">Total Connections</div><div class="value" id="s-connections">—</div></div>
    <div class="stat-card"><div class="label">Unique Attackers</div><div class="value" id="s-attackers">—</div></div>
    <div class="stat-card"><div class="label">Login Attempts</div><div class="value" id="s-logins">—</div></div>
    <div class="stat-card good"><div class="label">Payloads Captured</div><div class="value" id="s-payloads">—</div></div>
    <div class="stat-card"><div class="label">Commands Logged</div><div class="value" id="s-commands">—</div></div>
    <div class="stat-card alert"><div class="label">🚨 Lateral Movement</div><div class="value" id="s-lateral">—</div></div>
  </div>

  <div class="last-update" id="update-time"></div>

  <!-- Charts Row 1 -->
  <div class="charts-grid">
    <div class="chart-card wide">
      <h3>📈 Attack Timeline — Hourly (7 Days)</h3>
      <canvas id="timeline-chart"></canvas>
    </div>
    <div class="chart-card">
      <h3>💻 Top Shell Commands</h3>
      <canvas id="commands-chart"></canvas>
    </div>
    <div class="chart-card">
      <h3>🔑 Most-Tried Credentials</h3>
      <canvas id="creds-chart"></canvas>
    </div>
  </div>

  <!-- Top Attackers Table -->
  <div class="chart-card" style="margin-bottom:16px">
    <h3>🌐 Top Attacker IPs</h3>
    <table>
      <thead><tr><th>IP</th><th>Events</th><th>Country</th><th>Organization</th><th>Last Seen</th></tr></thead>
      <tbody id="top-ips-tbody"><tr><td class="empty" colspan="5">Loading...</td></tr></tbody>
    </table>
  </div>

  <!-- Payloads Table -->
  <div class="chart-card" style="margin-bottom:16px">
    <h3>📁 Captured Payloads</h3>
    <table>
      <thead><tr><th>Time</th><th>Source IP</th><th>Filename</th><th>SHA256</th></tr></thead>
      <tbody id="payloads-tbody"><tr><td class="empty" colspan="4">No payloads captured yet</td></tr></tbody>
    </table>
  </div>

  <!-- Alerts Table -->
  <div class="chart-card">
    <h3>🚨 Recent Alerts</h3>
    <table>
      <thead><tr><th>Time</th><th>Severity</th><th>Alert</th></tr></thead>
      <tbody id="alerts-tbody"><tr><td class="empty" colspan="3">No alerts yet</td></tr></tbody>
    </table>
  </div>

</div>

<script>
const REFRESH_MS = 30000;
let timelineChart, commandsChart, credsChart;

function fmtTime(ts) {
  if (!ts || ts === 'None') return 'Never';
  return new Date(ts).toLocaleString();
}

async function fetchJSON(url) {
  const r = await fetch(url);
  return r.json();
}

async function loadOverview() {
  const d = await fetchJSON('/api/stats/overview');
  document.getElementById('s-connections').textContent = (d.total_connections || 0).toLocaleString();
  document.getElementById('s-attackers').textContent = (d.unique_attackers || 0).toLocaleString();
  document.getElementById('s-logins').textContent = (d.login_attempts || 0).toLocaleString();
  document.getElementById('s-payloads').textContent = (d.payloads_captured || 0).toLocaleString();
  document.getElementById('s-commands').textContent = (d.commands_recorded || 0).toLocaleString();
  document.getElementById('s-lateral').textContent = (d.lateral_movement_alerts || 0).toLocaleString();
}

async function loadTimeline() {
  const d = await fetchJSON('/api/stats/timeline');
  const labels = d.map(r => r.hour);
  const counts = d.map(r => r.count);
  const ctx = document.getElementById('timeline-chart').getContext('2d');
  if (timelineChart) timelineChart.destroy();
  timelineChart = new Chart(ctx, {
    type: 'line',
    data: { labels, datasets: [{
      label: 'Events', data: counts, borderColor: '#e94560', backgroundColor: 'rgba(233,69,96,0.1)',
      fill: true, tension: 0.3, pointRadius: 2
    }]},
    options: { responsive: true, plugins: { legend: { display: false } },
      scales: { x: { ticks: { color: '#8b949e', maxRotation: 45 }, grid: { color: '#21262d' } },
                y: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' } } } }
  });
}

async function loadCommands() {
  const d = await fetchJSON('/api/stats/top_commands');
  const labels = d.slice(0,10).map(r => r.command.substring(0,30));
  const counts = d.slice(0,10).map(r => r.frequency);
  const ctx = document.getElementById('commands-chart').getContext('2d');
  if (commandsChart) commandsChart.destroy();
  commandsChart = new Chart(ctx, {
    type: 'bar',
    data: { labels, datasets: [{ label: 'Count', data: counts,
      backgroundColor: '#4ecca3', borderRadius: 4 }]},
    options: { indexAxis: 'y', responsive: true, plugins: { legend: { display: false } },
      scales: { x: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' } },
                y: { ticks: { color: '#8b949e', font: { family: 'monospace', size: 11 } }, grid: { color: '#21262d' } } } }
  });
}

async function loadCreds() {
  const d = await fetchJSON('/api/stats/top_credentials');
  const labels = d.slice(0,8).map(r => r.username + ':' + r.password);
  const counts = d.slice(0,8).map(r => r.attempts);
  const ctx = document.getElementById('creds-chart').getContext('2d');
  if (credsChart) credsChart.destroy();
  credsChart = new Chart(ctx, {
    type: 'bar',
    data: { labels, datasets: [{ label: 'Attempts', data: counts,
      backgroundColor: '#f59e0b', borderRadius: 4 }]},
    options: { indexAxis: 'y', responsive: true, plugins: { legend: { display: false } },
      scales: { x: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' } },
                y: { ticks: { color: '#8b949e', font: { family: 'monospace', size: 11 } }, grid: { color: '#21262d' } } } }
  });
}

async function loadTopIPs() {
  const d = await fetchJSON('/api/stats/top_ips');
  const tbody = document.getElementById('top-ips-tbody');
  if (!d.length) { tbody.innerHTML = '<tr><td class="empty" colspan="5">No data yet</td></tr>'; return; }
  tbody.innerHTML = d.map(r => `<tr>
    <td class="ip">${r.src_ip}</td>
    <td>${r.event_count.toLocaleString()}</td>
    <td>${r.country || '—'}</td>
    <td>${r.org || '—'}</td>
    <td>${fmtTime(r.last_seen)}</td>
  </tr>`).join('');
}

async function loadPayloads() {
  const d = await fetchJSON('/api/payloads');
  const tbody = document.getElementById('payloads-tbody');
  if (!d.length) { tbody.innerHTML = '<tr><td class="empty" colspan="4">No payloads captured yet</td></tr>'; return; }
  tbody.innerHTML = d.map(r => `<tr>
    <td>${fmtTime(r.timestamp)}</td>
    <td class="ip">${r.src_ip || r.attacker_ip || '—'}</td>
    <td>${r.filename || '—'}</td>
    <td class="hash">${(r.sha256 || '').substring(0, 16)}...</td>
  </tr>`).join('');
}

async function loadAlerts() {
  const d = await fetchJSON('/api/alerts');
  const tbody = document.getElementById('alerts-tbody');
  if (!d.length) { tbody.innerHTML = '<tr><td class="empty" colspan="3">No alerts yet</td></tr>'; return; }
  tbody.innerHTML = d.slice(0, 20).map(r => {
    const cls = r.severity === 'CRITICAL' ? 'badge-crit' : r.severity === 'HIGH' ? 'badge-high' : 'badge-med';
    return `<tr>
      <td>${fmtTime(r.timestamp)}</td>
      <td><span class="${cls}">${r.severity}</span></td>
      <td>${r.title}</td>
    </tr>`;
  }).join('');
}

async function refresh() {
  await Promise.all([
    loadOverview(), loadTimeline(), loadCommands(),
    loadCreds(), loadTopIPs(), loadPayloads(), loadAlerts()
  ]);
  document.getElementById('update-time').textContent = 'Updated: ' + new Date().toLocaleTimeString();
}

refresh();
setInterval(refresh, REFRESH_MS);
</script>
</body>
</html>
"""


@app.route("/")
def dashboard():
    return DASHBOARD_HTML


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Honeypot Threat Dashboard")
    parser.add_argument("--db", default="honeypot.db")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    DB_PATH = args.db
    print(f"[+] Dashboard starting on http://{args.host}:{args.port}")
    print(f"[+] Reading from database: {DB_PATH}")
    app.run(host=args.host, port=args.port, debug=False)
