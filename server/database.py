"""
database.py
Evidence store for the Insider Threat Digital Forensic Investigation Tool.

Every event (USB activity or file access activity) is written to a SQLite
table as a hash-chained ledger: each row stores SHA-256(previous_hash +
canonical_row_json). This gives a tamper-evident chain of custody --
if any historical row is edited, every hash after it breaks, which is
exactly what /api/verify checks. This directly addresses the "Deploying
Hash Algorithm" integrity challenge described in the project.
"""

import sqlite3
import hashlib
import json
import os
import threading

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "evidence.db")
_lock = threading.Lock()


def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_conn()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,          -- 'usb' or 'file'
            hostname TEXT,
            username TEXT,
            agent_id TEXT,
            action TEXT,                       -- connect/disconnect, read/write/delete/rename
            detail TEXT,                       -- JSON blob of raw event fields
            file_hash TEXT,                    -- SHA-256 of the file, if applicable
            received_at TEXT NOT NULL,         -- server ingestion timestamp (UTC ISO)
            event_time TEXT NOT NULL,           -- timestamp reported by agent
            prev_hash TEXT NOT NULL,
            row_hash TEXT NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER,
            rule TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(event_id) REFERENCES events(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS usb_whitelist (
            serial TEXT PRIMARY KEY,
            description TEXT,
            added_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def _last_hash(conn):
    row = conn.execute("SELECT row_hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
    return row["row_hash"] if row else "0" * 64  # genesis hash


def insert_event(event_type, hostname, username, agent_id, action, detail,
                  file_hash, received_at, event_time):
    """Insert a new evidence record into the hash-chained ledger."""
    with _lock:
        conn = get_conn()
        prev_hash = _last_hash(conn)
        payload = {
            "event_type": event_type,
            "hostname": hostname,
            "username": username,
            "agent_id": agent_id,
            "action": action,
            "detail": detail,
            "file_hash": file_hash,
            "received_at": received_at,
            "event_time": event_time,
            "prev_hash": prev_hash,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        row_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        cur = conn.execute("""
            INSERT INTO events (event_type, hostname, username, agent_id, action, detail,
                                 file_hash, received_at, event_time, prev_hash, row_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (event_type, hostname, username, agent_id, action, detail,
              file_hash, received_at, event_time, prev_hash, row_hash))
        conn.commit()
        event_id = cur.lastrowid
        conn.close()
        return event_id, row_hash


def insert_alert(event_id, rule, severity, message, created_at):
    conn = get_conn()
    conn.execute("""
        INSERT INTO alerts (event_id, rule, severity, message, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (event_id, rule, severity, message, created_at))
    conn.commit()
    conn.close()


def verify_chain():
    """Recompute the hash chain from scratch and report the first break, if any."""
    conn = get_conn()
    rows = conn.execute("SELECT * FROM events ORDER BY id ASC").fetchall()
    conn.close()
    prev_hash = "0" * 64
    for r in rows:
        payload = {
            "event_type": r["event_type"],
            "hostname": r["hostname"],
            "username": r["username"],
            "agent_id": r["agent_id"],
            "action": r["action"],
            "detail": r["detail"],
            "file_hash": r["file_hash"],
            "received_at": r["received_at"],
            "event_time": r["event_time"],
            "prev_hash": prev_hash,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if expected != r["row_hash"] or r["prev_hash"] != prev_hash:
            return {"valid": False, "broken_at_event_id": r["id"], "checked": len(rows)}
        prev_hash = r["row_hash"]
    return {"valid": True, "broken_at_event_id": None, "checked": len(rows)}
