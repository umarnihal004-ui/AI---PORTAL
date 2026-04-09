# ============================================================
# routes/alerts.py — Alert Routes
# ============================================================
from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from bson import ObjectId
from database import get_db

alerts_bp = Blueprint("alerts", __name__)

def serialize_list(docs):
    result = []
    for d in docs:
        d["_id"] = str(d["_id"])
        for k, v in d.items():
            if hasattr(v, "isoformat"):
                d[k] = v.isoformat()
        result.append(d)
    return result

# ── GET /api/alerts/ ─────────────────────────────────────────
@alerts_bp.route("/", methods=["GET"])
@jwt_required()
def get_alerts():
    db = get_db()
    user_id = get_jwt_identity()
    claims = get_jwt()

    if claims.get("role") == "admin":
        alerts = list(db.alerts.find().sort("created_at", -1).limit(100))
    else:
        alerts = list(db.alerts.find({"user_id": user_id}).sort("created_at", -1).limit(50))

    return jsonify(serialize_list(alerts)), 200

# ── GET /api/alerts/unread-count ─────────────────────────────
@alerts_bp.route("/unread-count", methods=["GET"])
@jwt_required()
def unread_count():
    db = get_db()
    user_id = get_jwt_identity()
    claims = get_jwt()

    if claims.get("role") == "admin":
        count = db.alerts.count_documents({"read": False})
    else:
        count = db.alerts.count_documents({"user_id": user_id, "read": False})

    return jsonify({"count": count}), 200

# ── PATCH /api/alerts/<id>/read ──────────────────────────────
@alerts_bp.route("/<alert_id>/read", methods=["PATCH"])
@jwt_required()
def mark_read(alert_id):
    db = get_db()
    user_id = get_jwt_identity()
    claims = get_jwt()

    query = {"_id": ObjectId(alert_id)}
    if claims.get("role") != "admin":
        query["user_id"] = user_id  # students can only mark their own

    db.alerts.update_one(query, {"$set": {"read": True}})
    return jsonify({"message": "Marked as read"}), 200

# ── PATCH /api/alerts/read-all ───────────────────────────────
@alerts_bp.route("/read-all", methods=["PATCH"])
@jwt_required()
def mark_all_read():
    db = get_db()
    user_id = get_jwt_identity()
    claims = get_jwt()

    if claims.get("role") == "admin":
        db.alerts.update_many({"read": False}, {"$set": {"read": True}})
    else:
        db.alerts.update_many({"user_id": user_id, "read": False}, {"$set": {"read": True}})

    return jsonify({"message": "All alerts marked as read"}), 200
