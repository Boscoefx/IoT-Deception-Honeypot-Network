"""
Log Parser — Healthcare IoT Honeypot Network
=============================================
Reads raw Cowrie JSON logs and HTTP honeypot logs,
normalizes them into a unified schema, and writes
enriched events to the analysis database (SQLite).

Usage:
    python scripts/log_parser.py --log-dir logs/ --db honeypot.db
    python scripts/log_parser.py --watch  # Tail mode for live monitoring
"""

import json
import sqlite3
import argparse
import time
import os
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Iterator


# ── Database Schema ────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT NOT NULL,
    event_type   TEXT NOT NULL,
    src_ip       TEXT NOT NULL,
    src_port     INTEGER,
    username     TEXT,
    password     TEXT,
    command      TEXT,
    session_id   TEXT,
    sensor       TEXT DEFAULT 'cowrie',
    raw_event    TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id   TEXT PRIMARY KEY,
    src_ip       TEXT NOT NULL,
    start_time   TEXT NOT NULL,
    end_time     TEXT,
    login_success INTEGER DEFAULT 0,
    commands_run  INTEGER DEFAULT 0,
    payloads_dropped INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS payloads (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT NOT NULL,
    src_ip       TEXT NOT NULL,
    session_id   TEXT,
    filename     TEXT,
    sha256       TEXT NOT NULL,
    url          TEXT,
    file_path    TEXT
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT NOT NULL,
    src_ip       TEXT NOT NULL,
    username     TEXT NOT NULL,
    password     TEXT NOT NULL,
    success      INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_events_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_login_ip ON login_attempts(src_ip);
"""


def init_db(db_path: str) -> sqlite3.Connection:
    """Initialize SQLite database with honeypot schema."""
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.commit()
    print(f"[+] Database initialized: {db_path}")
    return conn


# ── Cowrie Log Parser ──────────────────────────────────────────

class CowrieLogParser:
    """
    Parses Cowrie JSON log lines into normalized event dicts.
    Cowrie event types we care about:
      - cowrie.session.connect
      - cowrie.login.failed
      - cowrie.login.success
      - cowrie.command.input
      - cowrie.session.file_download
      - cowrie.session.closed
    """

    def parse_line(self, line: str) -> dict | None:
        """Parse a single JSON log line. Returns None if not parseable."""
        try:
            raw = json.loads(line.strip())
        except json.JSONDecodeError:
            return None

        event_type = raw.get("eventid", "unknown")
        normalized = {
            "timestamp": raw.get("timestamp", datetime.utcnow().isoformat()),
            "event_type": self._map_event_type(event_type),
            "src_ip": raw.get("src_ip", ""),
            "src_port": raw.get("src_port"),
            "session_id": raw.get("session", ""),
            "username": raw.get("username", ""),
            "password": raw.get("password", ""),
            "command": raw.get("input", ""),
            "sensor": "cowrie_ssh",
            "raw_event": json.dumps(raw),
            # Extra fields depending on event type
            "url": raw.get("url", ""),
            "outfile": raw.get("outfile", ""),
            "shasum": raw.get("shasum", ""),
        }
        return normalized

    def _map_event_type(self, cowrie_event: str) -> str:
        mapping = {
            "cowrie.session.connect": "connect",
            "cowrie.login.failed": "login_fail",
            "cowrie.login.success": "login_success",
            "cowrie.command.input": "command",
            "cowrie.session.file_download": "payload_download",
            "cowrie.session.file_upload": "payload_upload",
            "cowrie.session.closed": "session_close",
            "cowrie.direct-tcpip.request": "port_forward_attempt",
        }
        return mapping.get(cowrie_event, cowrie_event)

    def parse_file(self, log_path: str) -> Iterator[dict]:
        """Yield parsed events from a Cowrie JSON log file."""
        with open(log_path, "r") as f:
            for line in f:
                event = self.parse_line(line)
                if event:
                    yield event


# ── HTTP Honeypot Log Parser ───────────────────────────────────

class HttpHoneypotParser:
    """Parses logs produced by the Flask HTTP honeypot server."""

    def parse_line(self, line: str) -> dict | None:
        try:
            raw = json.loads(line.strip())
        except json.JSONDecodeError:
            return None

        event_type = raw.get("event_type", "unknown")
        credentials = raw.get("credentials_attempted", {})

        return {
            "timestamp": raw.get("timestamp", ""),
            "event_type": f"http_{event_type}",
            "src_ip": raw.get("src_ip", ""),
            "src_port": None,
            "session_id": "",
            "username": credentials.get("username", ""),
            "password": credentials.get("password", ""),
            "command": raw.get("path", ""),
            "sensor": "http_panel",
            "raw_event": json.dumps(raw),
            "url": raw.get("path", ""),
            "outfile": "",
            "shasum": "",
        }

    def parse_file(self, log_path: str) -> Iterator[dict]:
        with open(log_path, "r") as f:
            for line in f:
                event = self.parse_line(line)
                if event:
                    yield event


# ── Database Insertion ─────────────────────────────────────────

def insert_event(conn: sqlite3.Connection, event: dict):
    """Insert a normalized event into the database."""
    conn.execute("""
        INSERT INTO events
            (timestamp, event_type, src_ip, src_port, username,
             password, command, session_id, sensor, raw_event)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event["timestamp"], event["event_type"], event["src_ip"],
        event.get("src_port"), event.get("username"), event.get("password"),
        event.get("command"), event.get("session_id"),
        event.get("sensor", "unknown"), event.get("raw_event")
    ))

    # Track login attempts separately
    if event["event_type"] in ("login_fail", "login_success", "http_login_attempt"):
        conn.execute("""
            INSERT INTO login_attempts (timestamp, src_ip, username, password, success)
            VALUES (?, ?, ?, ?, ?)
        """, (
            event["timestamp"], event["src_ip"],
            event.get("username", ""), event.get("password", ""),
            1 if event["event_type"] == "login_success" else 0
        ))

    # Track payload downloads
    if event["event_type"] in ("payload_download", "payload_upload"):
        conn.execute("""
            INSERT INTO payloads (timestamp, src_ip, session_id, filename, sha256, url, file_path)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            event["timestamp"], event["src_ip"], event.get("session_id"),
            os.path.basename(event.get("outfile", "") or event.get("url", "")),
            event.get("shasum", ""), event.get("url", ""), event.get("outfile", "")
        ))

    conn.commit()


# ── Session Tracking ───────────────────────────────────────────

def update_session(conn: sqlite3.Connection, event: dict):
    """Maintain session summary records."""
    sid = event.get("session_id")
    if not sid:
        return

    existing = conn.execute(
        "SELECT * FROM sessions WHERE session_id = ?", (sid,)
    ).fetchone()

    if not existing:
        conn.execute("""
            INSERT INTO sessions (session_id, src_ip, start_time, login_success, commands_run, payloads_dropped)
            VALUES (?, ?, ?, 0, 0, 0)
        """, (sid, event["src_ip"], event["timestamp"]))

    if event["event_type"] == "login_success":
        conn.execute(
            "UPDATE sessions SET login_success = 1 WHERE session_id = ?", (sid,)
        )
    elif event["event_type"] == "command":
        conn.execute(
            "UPDATE sessions SET commands_run = commands_run + 1 WHERE session_id = ?", (sid,)
        )
    elif event["event_type"] in ("payload_download", "payload_upload"):
        conn.execute(
            "UPDATE sessions SET payloads_dropped = payloads_dropped + 1 WHERE session_id = ?", (sid,)
        )
    elif event["event_type"] == "session_close":
        conn.execute(
            "UPDATE sessions SET end_time = ? WHERE session_id = ?",
            (event["timestamp"], sid)
        )

    conn.commit()


# ── Main Processing Loop ───────────────────────────────────────

def process_log_directory(log_dir: str, conn: sqlite3.Connection, watch: bool = False):
    """Process all log files in directory. If watch=True, tail indefinitely."""
    cowrie_parser = CowrieLogParser()
    http_parser = HttpHoneypotParser()
    processed = 0

    log_dir = Path(log_dir)

    # Initial pass — process existing logs
    for log_file in log_dir.rglob("cowrie.json*"):
        print(f"[+] Processing: {log_file}")
        for event in cowrie_parser.parse_file(str(log_file)):
            insert_event(conn, event)
            update_session(conn, event)
            processed += 1

    for log_file in log_dir.rglob("http_honeypot.json*"):
        print(f"[+] Processing: {log_file}")
        for event in http_parser.parse_file(str(log_file)):
            insert_event(conn, event)
            processed += 1

    print(f"[+] Processed {processed} events")

    if watch:
        print("[*] Watch mode active — tailing logs...")
        tail_logs(log_dir, conn, cowrie_parser, http_parser)


def tail_logs(log_dir: Path, conn, cowrie_parser, http_parser):
    """Simple tail implementation for live log monitoring."""
    file_positions = {}

    while True:
        for log_file in log_dir.rglob("*.json"):
            path_str = str(log_file)
            if path_str not in file_positions:
                file_positions[path_str] = os.path.getsize(path_str)
                continue

            current_size = os.path.getsize(path_str)
            if current_size > file_positions[path_str]:
                with open(path_str, "r") as f:
                    f.seek(file_positions[path_str])
                    for line in f:
                        parser = cowrie_parser if "cowrie" in path_str else http_parser
                        event = parser.parse_line(line)
                        if event:
                            insert_event(conn, event)
                            update_session(conn, event)
                            print(f"[LIVE] {event['timestamp']} | {event['src_ip']} | {event['event_type']}")
                file_positions[path_str] = current_size

        time.sleep(2)


# ── CLI Entry Point ────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Honeypot Log Parser")
    parser.add_argument("--log-dir", default="logs/", help="Directory containing honeypot logs")
    parser.add_argument("--db", default="honeypot.db", help="SQLite database path")
    parser.add_argument("--watch", action="store_true", help="Enable live tail mode")
    args = parser.parse_args()

    conn = init_db(args.db)
    process_log_directory(args.log_dir, conn, watch=args.watch)
