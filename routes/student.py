# ============================================================
# routes/student.py — Student Data Routes
# ============================================================
from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from bson import ObjectId
from database import get_db
from utils.audit_logger import log_action

student_bp = Blueprint("student", __name__)

def serialize(doc):
    """Convert MongoDB doc to JSON-safe dict."""
    if doc:
        doc["_id"] = str(doc["_id"])
    return doc

# ── GET /api/student/profile ─────────────────────────────────
@student_bp.route("/profile", methods=["GET"])
@jwt_required()
def get_profile():
    db = get_db()
    user_id = get_jwt_identity()
    claims = get_jwt()

    user = db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        return jsonify({"error": "Not found"}), 404

    risk = db.risk_scores.find_one({"user_id": user_id})

    return jsonify({
        "user_id": user_id,
        "name": user.get("name"),
        "email": user.get("email"),
        "register_number": user.get("register_number"),
        "department": user.get("department"),
        "year": user.get("year"),
        "phone": user.get("phone"),
        "role": user.get("role"),
        "risk_score": risk["risk_score"] if risk else 0,
        "risk_level": risk["risk_level"] if risk else "Low",
    }), 200

# ── GET /api/student/attendance ──────────────────────────────
@student_bp.route("/attendance", methods=["GET"])
@jwt_required()
def get_attendance():
    db = get_db()
    user_id = get_jwt_identity()
    records = list(db.attendance.find({"user_id": user_id}))
    for r in records:
        r["_id"] = str(r["_id"])
        if hasattr(r.get("date"), "isoformat"):
            r["date"] = r["date"].isoformat()
    return jsonify(records), 200

# ── GET /api/student/marks ───────────────────────────────────
@student_bp.route("/marks", methods=["GET"])
@jwt_required()
def get_marks():
    db = get_db()
    user_id = get_jwt_identity()
    records = list(db.marks.find({"user_id": user_id}))
    for r in records:
        r["_id"] = str(r["_id"])
    return jsonify(records), 200

# ── GET /api/student/fees ────────────────────────────────────
@student_bp.route("/fees", methods=["GET"])
@jwt_required()
def get_fees():
    db = get_db()
    user_id = get_jwt_identity()
    record = db.fees.find_one({"user_id": user_id})
    if record:
        record["_id"] = str(record["_id"])
        if hasattr(record.get("due_date"), "isoformat"):
            record["due_date"] = record["due_date"].isoformat()
    return jsonify(record or {}), 200

# ── GET /api/student/alerts ──────────────────────────────────
@student_bp.route("/alerts", methods=["GET"])
@jwt_required()
def get_alerts():
    db = get_db()
    user_id = get_jwt_identity()
    alerts = list(db.alerts.find({"user_id": user_id}).sort("created_at", -1).limit(50))
    for a in alerts:
        a["_id"] = str(a["_id"])
        if hasattr(a.get("created_at"), "isoformat"):
            a["created_at"] = a["created_at"].isoformat()
    return jsonify(alerts), 200

# ── PATCH /api/student/alerts/<id>/read ──────────────────────
@student_bp.route("/alerts/<alert_id>/read", methods=["PATCH"])
@jwt_required()
def mark_alert_read(alert_id):
    db = get_db()
    user_id = get_jwt_identity()
    db.alerts.update_one(
        {"_id": ObjectId(alert_id), "user_id": user_id},
        {"$set": {"read": True}}
    )
    return jsonify({"message": "Marked as read"}), 200

# ── GET /api/student/login-history ───────────────────────────
@student_bp.route("/login-history", methods=["GET"])
@jwt_required()
def get_login_history():
    db = get_db()
    user_id = get_jwt_identity()
    logs = list(db.login_logs.find({"user_id": user_id}).sort("timestamp", -1).limit(30))
    for l in logs:
        l["_id"] = str(l["_id"])
        if hasattr(l.get("timestamp"), "isoformat"):
            l["timestamp"] = l["timestamp"].isoformat()
    return jsonify(logs), 200

# ── GET /api/student/risk-score ──────────────────────────────
@student_bp.route("/risk-score", methods=["GET"])
@jwt_required()
def get_risk_score():
    db = get_db()
    user_id = get_jwt_identity()
    record = db.risk_scores.find_one({"user_id": user_id})
    if record:
        record["_id"] = str(record["_id"])
        if hasattr(record.get("updated_at"), "isoformat"):
            record["updated_at"] = record["updated_at"].isoformat()
    return jsonify(record or {"risk_score": 0, "risk_level": "Low"}), 200
