"""
app.py
Central Station Flask API for the Automated Insider Threat Digital Forensic
Investigation Tool (USB activity + file access activity).

Role in the architecture (per project methodology):
  - Receives agent data (USB + file access events) from the PowerShell agent
  - Stores evidence in a tamper-evident, hash-chained SQLite ledger
  - Applies detection rules to raise alerts
  - Serves the HTML dashboard, which polls this API for live data

Run:
    pip install -r requirements.txt
    python app.py
Server listens on 0.0.0.0:5000 by default.
"""

from flask import Flask, request, jsonify, send_from_directory
from datetime import datetime, timedelta
import os
import json
import secrets
import database as db
import rules

app = Flask(__name__, static_folder=None)

# --- Simple shared-secret auth for agents -----------------------------------
# In production, replace with per-agent API keys issued at enrollment time
# and stored hashed. This is intentionally minimal for a prototype.
AGENT_API_KEY = os.environ.get("AGENT_API_KEY", "change-me-agent-key")

DASHBOARD_DIR = os.path.join(os.path.dirname(__file__), "..", "dashboard")


def now_iso():
    return datetime.utcnow().isoformat() + "Z"


def require_agent_auth():
    key = request.headers.get("X-Agent-Key")
    return key == AGENT_API_KEY


def get_whitelist_serials():
    conn = db.get_conn()
    rows = conn.execute("SELECT serial FROM usb_whitelist").fetchall()
    conn.close()
    return {r["serial"] for r in rows}


def get_recent_file_events_for_user(username, window_minutes):
    conn = db.get_conn()
    cutoff = (datetime.utcnow() - timedelta(minutes=window_minutes)).isoformat() + "Z"
    rows = conn.execute("""
        SELECT event_time, action FROM events
        WHERE event_type='file' AND username=? AND received_at >= ?
    """, (username, cutoff)).fetchall()
    conn.close()
    return [(r["event_time"], r["action"]) for r in rows]


# ---------------------------------------------------------------------------
# Agent ingestion endpoints
# ---------------------------------------------------------------------------

@app.route("/api/agent/usb", methods=["POST"])
def ingest_usb_event():
    if not require_agent_auth():
        return jsonify({"error": "unauthorized"}), 401
    payload = request.get_json(force=True, silent=True) or {}

    required = ["agent_id", "hostname", "username", "action", "event_time"]
    missing = [f for f in required if f not in payload]
    if missing:
        return jsonify({"error": f"missing fields: {missing}"}), 400

    detail = {
        "serial": payload.get("serial"),
        "vendor_id": payload.get("vendor_id"),
        "product_id": payload.get("product_id"),
        "device_name": payload.get("device_name"),
    }

    event_id, row_hash = db.insert_event(
        event_type="usb",
        hostname=payload["hostname"],
        username=payload["username"],
        agent_id=payload["agent_id"],
        action=payload["action"],
        detail=json.dumps(detail),
        file_hash=None,
        received_at=now_iso(),
        event_time=payload["event_time"],
    )

    whitelist = get_whitelist_serials()
    fired = rules.evaluate_usb_event(event_id, payload["hostname"], payload["username"],
                                      payload["action"], detail, whitelist)
    for a in fired:
        db.insert_alert(event_id, a["rule"], a["severity"], a["message"], now_iso())

    return jsonify({"status": "stored", "event_id": event_id, "row_hash": row_hash,
                     "alerts_raised": len(fired)}), 201


@app.route("/api/agent/file", methods=["POST"])
def ingest_file_event():
    if not require_agent_auth():
        return jsonify({"error": "unauthorized"}), 401
    payload = request.get_json(force=True, silent=True) or {}

    required = ["agent_id", "hostname", "username", "action", "path", "event_time"]
    missing = [f for f in required if f not in payload]
    if missing:
        return jsonify({"error": f"missing fields: {missing}"}), 400

    detail = {
        "path": payload.get("path"),
        "process": payload.get("process"),
        "event_time_local": payload.get("event_time_local"),
    }

    event_id, row_hash = db.insert_event(
        event_type="file",
        hostname=payload["hostname"],
        username=payload["username"],
        agent_id=payload["agent_id"],
        action=payload["action"],
        detail=json.dumps(detail),
        file_hash=payload.get("file_hash"),
        received_at=now_iso(),
        event_time=payload["event_time"],
    )

    recent = get_recent_file_events_for_user(payload["username"], rules.BULK_ACCESS_WINDOW_MIN)
    fired = rules.evaluate_file_event(event_id, payload["hostname"], payload["username"],
                                       payload["action"], detail, recent)
    for a in fired:
        db.insert_alert(event_id, a["rule"], a["severity"], a["message"], now_iso())

    return jsonify({"status": "stored", "event_id": event_id, "row_hash": row_hash,
                     "alerts_raised": len(fired)}), 201


# ---------------------------------------------------------------------------
# Dashboard / investigator read endpoints
# ---------------------------------------------------------------------------

@app.route("/api/events", methods=["GET"])
def list_events():
    event_type = request.args.get("type")
    username = request.args.get("username")
    limit = min(int(request.args.get("limit", 100)), 1000)

    query = "SELECT * FROM events WHERE 1=1"
    params = []
    if event_type in ("usb", "file"):
        query += " AND event_type = ?"
        params.append(event_type)
    if username:
        query += " AND username = ?"
        params.append(username)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    conn = db.get_conn()
    rows = conn.execute(query, params).fetchall()
    conn.close()

    out = []
    for r in rows:
        out.append({
            "id": r["id"],
            "event_type": r["event_type"],
            "hostname": r["hostname"],
            "username": r["username"],
            "agent_id": r["agent_id"],
            "action": r["action"],
            "detail": json.loads(r["detail"]) if r["detail"] else {},
            "file_hash": r["file_hash"],
            "received_at": r["received_at"],
            "event_time": r["event_time"],
            "row_hash": r["row_hash"],
        })
    return jsonify(out)


@app.route("/api/alerts", methods=["GET"])
def list_alerts():
    limit = min(int(request.args.get("limit", 100)), 1000)
    conn = db.get_conn()
    rows = conn.execute("""
        SELECT alerts.*, events.hostname, events.username, events.event_type
        FROM alerts JOIN events ON alerts.event_id = events.id
        ORDER BY alerts.id DESC LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/stats", methods=["GET"])
def stats():
    conn = db.get_conn()
    usb_count = conn.execute("SELECT COUNT(*) c FROM events WHERE event_type='usb'").fetchone()["c"]
    file_count = conn.execute("SELECT COUNT(*) c FROM events WHERE event_type='file'").fetchone()["c"]
    alert_count = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
    high_count = conn.execute("SELECT COUNT(*) c FROM alerts WHERE severity='HIGH'").fetchone()["c"]
    hosts = conn.execute("SELECT COUNT(DISTINCT hostname) c FROM events").fetchone()["c"]
    conn.close()
    return jsonify({
        "usb_events": usb_count,
        "file_events": file_count,
        "total_alerts": alert_count,
        "high_severity_alerts": high_count,
        "monitored_hosts": hosts,
    })


@app.route("/api/verify", methods=["GET"])
def verify():
    """Chain-of-custody integrity check for the whole evidence ledger."""
    return jsonify(db.verify_chain())


# ---------------------------------------------------------------------------
# USB whitelist administration
# ---------------------------------------------------------------------------

@app.route("/api/whitelist", methods=["GET"])
def get_whitelist():
    conn = db.get_conn()
    rows = conn.execute("SELECT * FROM usb_whitelist ORDER BY added_at DESC").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/whitelist", methods=["POST"])
def add_whitelist():
    payload = request.get_json(force=True, silent=True) or {}
    serial = payload.get("serial")
    if not serial:
        return jsonify({"error": "serial required"}), 400
    conn = db.get_conn()
    conn.execute("INSERT OR REPLACE INTO usb_whitelist (serial, description, added_at) VALUES (?, ?, ?)",
                 (serial, payload.get("description", ""), now_iso()))
    conn.commit()
    conn.close()
    return jsonify({"status": "added"}), 201


# ---------------------------------------------------------------------------
# Dashboard static files
# ---------------------------------------------------------------------------

@app.route("/")
def dashboard_index():
    return send_from_directory(DASHBOARD_DIR, "index.html")


@app.route("/<path:filename>")
def dashboard_static(filename):
    return send_from_directory(DASHBOARD_DIR, filename)


if __name__ == "__main__":
    db.init_db()
    print(f"Agent API key (set AGENT_API_KEY env var to change): {AGENT_API_KEY}")
    app.run(host="0.0.0.0", port=5000, debug=False)
