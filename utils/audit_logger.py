# ============================================================
# utils/audit_logger.py — Audit Log Writer
# ============================================================
from datetime import datetime, timezone

def log_action(db, user_id, action, ip_address="unknown", status="success", details=None):
    """Write an audit log entry to the audit_logs collection."""
    entry = {
        "user_id": str(user_id),
        "action": action,
        "timestamp": datetime.now(timezone.utc),
        "ip_address": ip_address,
        "status": status,
        "details": details or {}
    }
    db.audit_logs.insert_one(entry)
