"""
Tests — Log Parser
==================
Unit tests for the Cowrie and HTTP honeypot log parsers.

Run with:
    pytest tests/test_parser.py -v
"""

import pytest
import json
import sqlite3
import tempfile
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts.log_parser import (
    CowrieLogParser,
    HttpHoneypotParser,
    init_db,
    insert_event,
    update_session,
)


# ── Fixtures ───────────────────────────────────────────────────

@pytest.fixture
def cowrie_parser():
    return CowrieLogParser()


@pytest.fixture
def http_parser():
    return HttpHoneypotParser()


@pytest.fixture
def temp_db():
    """Create a temporary SQLite database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    conn = init_db(db_path)
    yield conn
    conn.close()
    os.unlink(db_path)


# ── Sample Log Lines ───────────────────────────────────────────

COWRIE_CONNECT = json.dumps({
    "eventid": "cowrie.session.connect",
    "timestamp": "2024-01-15T10:23:45.000000Z",
    "src_ip": "1.2.3.4",
    "src_port": 54321,
    "session": "abc123",
    "protocol": "ssh"
})

COWRIE_LOGIN_FAIL = json.dumps({
    "eventid": "cowrie.login.failed",
    "timestamp": "2024-01-15T10:23:46.000000Z",
    "src_ip": "1.2.3.4",
    "src_port": 54321,
    "session": "abc123",
    "username": "admin",
    "password": "admin123"
})

COWRIE_LOGIN_SUCCESS = json.dumps({
    "eventid": "cowrie.login.success",
    "timestamp": "2024-01-15T10:23:47.000000Z",
    "src_ip": "1.2.3.4",
    "session": "abc123",
    "username": "root",
    "password": "root"
})

COWRIE_COMMAND = json.dumps({
    "eventid": "cowrie.command.input",
    "timestamp": "2024-01-15T10:23:50.000000Z",
    "src_ip": "1.2.3.4",
    "session": "abc123",
    "input": "cat /etc/passwd"
})

COWRIE_DOWNLOAD = json.dumps({
    "eventid": "cowrie.session.file_download",
    "timestamp": "2024-01-15T10:23:55.000000Z",
    "src_ip": "1.2.3.4",
    "session": "abc123",
    "url": "http://malicious.example.com/bot.sh",
    "outfile": "/var/lib/cowrie/downloads/bot.sh",
    "shasum": "abc123def456"
})

HTTP_LOGIN_ATTEMPT = json.dumps({
    "timestamp": "2024-01-15T10:24:00.000000Z",
    "event_type": "login_attempt",
    "src_ip": "5.6.7.8",
    "method": "POST",
    "path": "/admin/login",
    "credentials_attempted": {"username": "admin", "password": "password"}
})


# ── Cowrie Parser Tests ────────────────────────────────────────

class TestCowrieParser:

    def test_parse_connect_event(self, cowrie_parser):
        event = cowrie_parser.parse_line(COWRIE_CONNECT)
        assert event is not None
        assert event["event_type"] == "connect"
        assert event["src_ip"] == "1.2.3.4"
        assert event["session_id"] == "abc123"
        assert event["sensor"] == "cowrie_ssh"

    def test_parse_login_fail(self, cowrie_parser):
        event = cowrie_parser.parse_line(COWRIE_LOGIN_FAIL)
        assert event is not None
        assert event["event_type"] == "login_fail"
        assert event["username"] == "admin"
        assert event["password"] == "admin123"

    def test_parse_login_success(self, cowrie_parser):
        event = cowrie_parser.parse_line(COWRIE_LOGIN_SUCCESS)
        assert event is not None
        assert event["event_type"] == "login_success"
        assert event["username"] == "root"

    def test_parse_command(self, cowrie_parser):
        event = cowrie_parser.parse_line(COWRIE_COMMAND)
        assert event is not None
        assert event["event_type"] == "command"
        assert event["command"] == "cat /etc/passwd"

    def test_parse_download(self, cowrie_parser):
        event = cowrie_parser.parse_line(COWRIE_DOWNLOAD)
        assert event is not None
        assert event["event_type"] == "payload_download"
        assert "malicious.example.com" in event["url"]
        assert event["shasum"] == "abc123def456"

    def test_invalid_json_returns_none(self, cowrie_parser):
        result = cowrie_parser.parse_line("not json at all {{{")
        assert result is None

    def test_empty_line_returns_none(self, cowrie_parser):
        result = cowrie_parser.parse_line("")
        assert result is None

    def test_unknown_event_type_preserved(self, cowrie_parser):
        line = json.dumps({"eventid": "cowrie.unknown.event", "src_ip": "1.1.1.1", "timestamp": "2024-01-01T00:00:00Z"})
        event = cowrie_parser.parse_line(line)
        assert event is not None
        assert "unknown" in event["event_type"].lower() or event["event_type"] == "cowrie.unknown.event"


# ── HTTP Parser Tests ──────────────────────────────────────────

class TestHttpParser:

    def test_parse_login_attempt(self, http_parser):
        event = http_parser.parse_line(HTTP_LOGIN_ATTEMPT)
        assert event is not None
        assert "login" in event["event_type"]
        assert event["src_ip"] == "5.6.7.8"
        assert event["username"] == "admin"
        assert event["password"] == "password"
        assert event["sensor"] == "http_panel"

    def test_invalid_json_returns_none(self, http_parser):
        result = http_parser.parse_line("bad input")
        assert result is None


# ── Database Tests ─────────────────────────────────────────────

class TestDatabase:

    def test_insert_connect_event(self, cowrie_parser, temp_db):
        event = cowrie_parser.parse_line(COWRIE_CONNECT)
        insert_event(temp_db, event)
        row = temp_db.execute("SELECT * FROM events WHERE event_type = 'connect'").fetchone()
        assert row is not None
        assert row["src_ip"] == "1.2.3.4"

    def test_login_attempt_tracked(self, cowrie_parser, temp_db):
        event = cowrie_parser.parse_line(COWRIE_LOGIN_FAIL)
        insert_event(temp_db, event)
        row = temp_db.execute("SELECT * FROM login_attempts").fetchone()
        assert row is not None
        assert row["username"] == "admin"
        assert row["success"] == 0

    def test_login_success_tracked(self, cowrie_parser, temp_db):
        event = cowrie_parser.parse_line(COWRIE_LOGIN_SUCCESS)
        insert_event(temp_db, event)
        row = temp_db.execute("SELECT * FROM login_attempts WHERE success = 1").fetchone()
        assert row is not None

    def test_payload_tracked(self, cowrie_parser, temp_db):
        event = cowrie_parser.parse_line(COWRIE_DOWNLOAD)
        insert_event(temp_db, event)
        row = temp_db.execute("SELECT * FROM payloads").fetchone()
        assert row is not None
        assert row["sha256"] == "abc123def456"

    def test_session_tracking(self, cowrie_parser, temp_db):
        for line in [COWRIE_CONNECT, COWRIE_LOGIN_SUCCESS, COWRIE_COMMAND]:
            event = cowrie_parser.parse_line(line)
            insert_event(temp_db, event)
            update_session(temp_db, event)

        session = temp_db.execute(
            "SELECT * FROM sessions WHERE session_id = 'abc123'"
        ).fetchone()
        assert session is not None
        assert session["login_success"] == 1
        assert session["commands_run"] == 1

    def test_multiple_events_same_session(self, cowrie_parser, temp_db):
        events = [COWRIE_CONNECT, COWRIE_LOGIN_FAIL, COWRIE_LOGIN_FAIL, COWRIE_LOGIN_SUCCESS, COWRIE_COMMAND]
        for line in events:
            event = cowrie_parser.parse_line(line)
            insert_event(temp_db, event)
            update_session(temp_db, event)

        count = temp_db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        assert count == len(events)

        login_fails = temp_db.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE success = 0"
        ).fetchone()[0]
        assert login_fails == 2
