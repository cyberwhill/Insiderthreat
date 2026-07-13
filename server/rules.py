"""
rules.py
Detection logic run against every new event to flag potential insider-threat
behaviour, per the research questions in the project: "What forensic
artifacts and evidence can be generated to support investigations of
insider threats involving unauthorized data transfers?"

Rules are intentionally simple / explainable, which matters for evidentiary
use -- an investigator needs to be able to say exactly why an alert fired.
"""

from datetime import datetime, timedelta

# Tunable thresholds
BULK_ACCESS_COUNT = 15          # file events by one user
BULK_ACCESS_WINDOW_MIN = 10     # within this many minutes -> "bulk data access"
OFF_HOURS_START = 22            # 22:00
OFF_HOURS_END = 6               # 06:00
SENSITIVE_KEYWORDS = ["evidence", "intel", "criminal", "case", "confidential", "personnel"]
HIGH_RISK_EXTENSIONS = [".csv", ".xlsx", ".db", ".sqlite", ".pst", ".zip", ".pdf", ".docx"]


def evaluate_usb_event(event_id, hostname, username, action, detail, whitelist_serials):
    """detail: dict with keys like serial, vendor_id, product_id"""
    alerts = []
    serial = (detail or {}).get("serial")
    if action == "connect" and serial and serial not in whitelist_serials:
        alerts.append({
            "rule": "UNAUTHORIZED_USB_DEVICE",
            "severity": "HIGH",
            "message": f"Unregistered USB device (serial={serial}) connected on {hostname} by {username}.",
        })
    return alerts


def evaluate_file_event(event_id, hostname, username, action, detail, recent_events_for_user):
    """
    recent_events_for_user: list of (event_time_iso, action) tuples for this
    user within the lookback window, provided by the caller (app.py) via a DB query.
    """
    alerts = []
    path = (detail or {}).get("path", "") or ""
    lower_path = path.lower()

    # Rule: sensitive folder / file touched
    if any(kw in lower_path for kw in SENSITIVE_KEYWORDS):
        alerts.append({
            "rule": "SENSITIVE_DATA_ACCESS",
            "severity": "MEDIUM",
            "message": f"{username} performed '{action}' on sensitive path: {path}",
        })

    # Rule: high-risk file type combined with a USB-adjacent write/copy action
    if action in ("write", "rename", "delete") and any(lower_path.endswith(ext) for ext in HIGH_RISK_EXTENSIONS):
        alerts.append({
            "rule": "HIGH_RISK_FILE_TYPE_MODIFIED",
            "severity": "MEDIUM",
            "message": f"{username} modified a high-risk file type: {path}",
        })

    # Rule: off-hours activity
    try:
        ts = datetime.fromisoformat((detail or {}).get("event_time_local", "")) if detail.get("event_time_local") else None
    except Exception:
        ts = None
    if ts:
        hour = ts.hour
        if hour >= OFF_HOURS_START or hour < OFF_HOURS_END:
            alerts.append({
                "rule": "OFF_HOURS_ACTIVITY",
                "severity": "LOW",
                "message": f"{username} accessed files at {ts.strftime('%H:%M')} (outside normal hours).",
            })

    # Rule: bulk / rapid access pattern
    if len(recent_events_for_user) + 1 >= BULK_ACCESS_COUNT:
        alerts.append({
            "rule": "BULK_DATA_ACCESS",
            "severity": "HIGH",
            "message": (f"{username} triggered {len(recent_events_for_user) + 1} file events "
                        f"within {BULK_ACCESS_WINDOW_MIN} minutes on {hostname}."),
        })

    return alerts
