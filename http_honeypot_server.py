"""
HTTP Honeypot Server
Simulates the unauthenticated web management panel of a BD Alaris 8015
infusion pump running firmware 12.1.2.

Every request is logged to /logs/http_honeypot.json for analysis.
"""

import json
import os
import datetime
from flask import Flask, request, render_template_string, jsonify

app = Flask(__name__)
LOG_PATH = "/logs/http_honeypot.json"
DEVICE_MODEL = os.getenv("DEVICE_MODEL", "BD_Alaris_8015")
FIRMWARE = os.getenv("FIRMWARE_VERSION", "12.1.2")


def log_event(event_type: str, extra: dict = None):
    """Append a JSON event to the log file."""
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "event_type": event_type,
        "src_ip": request.remote_addr,
        "method": request.method,
        "path": request.path,
        "user_agent": request.headers.get("User-Agent", ""),
        "headers": dict(request.headers),
        "body": request.get_data(as_text=True)[:4096],  # Cap at 4KB
    }
    if extra:
        entry.update(extra)

    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")

    print(f"[HTTP HONEYPOT] {entry['timestamp']} | {entry['src_ip']} | {event_type} | {request.path}")


# ── Fake device homepage ──────────────────────────────────────

DEVICE_PANEL_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>{{ model }} - Administration</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; background: #1a1a2e; color: #eee; margin: 0; }
        .header { background: #16213e; padding: 15px 30px; border-bottom: 2px solid #0f3460; }
        .header h1 { color: #e94560; margin: 0; font-size: 1.4em; }
        .content { padding: 30px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { background: #0f3460; padding: 10px; text-align: left; }
        td { padding: 8px 10px; border-bottom: 1px solid #333; }
        .status-ok { color: #4ecca3; }
        .btn { background: #e94560; color: white; padding: 8px 16px; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <div class="header">
        <h1>⚕ {{ model }} — Device Administration Panel</h1>
        <small>Firmware: {{ firmware }} | Network Mode: Active</small>
    </div>
    <div class="content">
        <h3>Device Status</h3>
        <table>
            <tr><th>Parameter</th><th>Value</th></tr>
            <tr><td>Device ID</td><td>ALR-2024-00147</td></tr>
            <tr><td>IP Address</td><td>172.20.0.11</td></tr>
            <tr><td>Status</td><td class="status-ok">● ACTIVE</td></tr>
            <tr><td>Current Rate</td><td>125 mL/hr</td></tr>
            <tr><td>Volume Infused</td><td>432 mL</td></tr>
            <tr><td>Drug Library</td><td>LOADED (v8.4)</td></tr>
            <tr><td>Last Maintenance</td><td>2024-11-03</td></tr>
        </table>

        <h3>Administration</h3>
        <form method="POST" action="/admin/login">
            <p>Username: <input type="text" name="username" value="admin"></p>
            <p>Password: <input type="password" name="password"></p>
            <button class="btn" type="submit">Login</button>
        </form>

        <h3>System</h3>
        <ul>
            <li><a href="/admin/config" style="color:#4ecca3">Device Configuration</a></li>
            <li><a href="/admin/logs" style="color:#4ecca3">System Logs</a></li>
            <li><a href="/admin/update" style="color:#4ecca3">Firmware Update</a></li>
            <li><a href="/api/v1/status" style="color:#4ecca3">REST API Status</a></li>
        </ul>
    </div>
</body>
</html>
"""


@app.route("/", methods=["GET"])
def index():
    log_event("page_view")
    return render_template_string(DEVICE_PANEL_HTML, model=DEVICE_MODEL, firmware=FIRMWARE)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    credentials = {
        "username": request.form.get("username", request.args.get("username", "")),
        "password": request.form.get("password", request.args.get("password", "")),
    }
    log_event("login_attempt", {"credentials_attempted": credentials})
    # Always fail — but look like it almost worked
    return render_template_string("""
        <html><body style="background:#1a1a2e;color:#eee;font-family:Arial;padding:30px">
        <h2 style="color:#e94560">Authentication Failed</h2>
        <p>Invalid credentials. This access attempt has been logged.</p>
        <p>Session ID: {{ session_id }}</p>
        <a href="/" style="color:#4ecca3">← Back to panel</a>
        </body></html>
    """, session_id=os.urandom(8).hex())


@app.route("/admin/config", methods=["GET", "POST"])
def config():
    log_event("config_access")
    return jsonify({
        "device": DEVICE_MODEL,
        "firmware": FIRMWARE,
        "network": {"ip": "172.20.0.11", "gateway": "172.20.0.1", "dns": "8.8.8.8"},
        "auth": {"mode": "basic", "timeout": 300},
        "error": "Authentication required"
    })


@app.route("/admin/update", methods=["GET", "POST"])
def firmware_update():
    uploaded_file = request.files.get("firmware")
    if uploaded_file:
        # Save payload for analysis — never execute
        safe_path = f"/logs/payloads/{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{uploaded_file.filename}"
        os.makedirs("/logs/payloads", exist_ok=True)
        uploaded_file.save(safe_path)
        log_event("payload_upload", {"filename": uploaded_file.filename, "saved_to": safe_path})
    else:
        log_event("firmware_update_page_view")
    return jsonify({"status": "error", "message": "Firmware update requires physical access mode"})


@app.route("/api/v1/status", methods=["GET"])
def api_status():
    log_event("api_probe")
    return jsonify({
        "device": DEVICE_MODEL,
        "firmware": FIRMWARE,
        "uptime_seconds": 1209600,
        "active_infusion": True,
        "rate_ml_per_hr": 125,
        "api_version": "1.0",
        "authentication": "none"  # Intentionally exposed — part of deception
    })


@app.route("/api/v1/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE"])
def api_catch_all(subpath):
    log_event("api_exploration", {"api_path": subpath})
    return jsonify({"error": "endpoint not found", "path": subpath}), 404


@app.errorhandler(404)
def not_found(e):
    log_event("404_probe")
    return jsonify({"error": "not found"}), 404


if __name__ == "__main__":
    os.makedirs("/logs/payloads", exist_ok=True)
    app.run(host="0.0.0.0", port=80, debug=False)
