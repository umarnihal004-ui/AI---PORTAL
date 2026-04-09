# ============================================================
# routes/admin.py — Admin Routes (protected, admin-only)
# ============================================================
from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from flask_bcrypt import Bcrypt
from bson import ObjectId
from datetime import datetime, timezone
from database import get_db
from utils.audit_logger import log_action

admin_bp = Blueprint("admin", __name__)
bcrypt = Bcrypt()

def require_admin():
    claims = get_jwt()
    return claims.get("role") == "admin"

def serialize_list(docs):
    result = []
    for d in docs:
        d["_id"] = str(d["_id"])
        for k, v in d.items():
            if hasattr(v, "isoformat"):
                d[k] = v.isoformat()
        result.append(d)
    return result

# ── GET /api/admin/dashboard ─────────────────────────────────
@admin_bp.route("/dashboard", methods=["GET"])
@jwt_required()
def dashboard():
    db = get_db()
    if not require_admin():
        return jsonify({"error": "Forbidden"}), 403

    total_students = db.users.count_documents({"role": "student"})
    total_admins = db.users.count_documents({"role": "admin"})
    total_alerts = db.alerts.count_documents({})
    unread_alerts = db.alerts.count_documents({"read": False})
    total_attacks = db.attack_logs.count_documents({})
    suspicious_logins = db.login_logs.count_documents({"prediction": "suspicious"})

    # Risk score distribution
    high_risk = db.risk_scores.count_documents({"risk_level": "High"})
    medium_risk = db.risk_scores.count_documents({"risk_level": "Medium"})
    low_risk = db.risk_scores.count_documents({"risk_level": "Low"})

    # Attack type breakdown
    pipeline = [{"$group": {"_id": "$attack_type", "count": {"$sum": 1}}}]
    attack_breakdown = {r["_id"]: r["count"] for r in db.attack_logs.aggregate(pipeline)}

    # Recent logins (last 10)
    recent_logins = list(db.login_logs.find().sort("timestamp", -1).limit(10))
    for l in recent_logins:
        l["_id"] = str(l["_id"])
        if hasattr(l.get("timestamp"), "isoformat"):
            l["timestamp"] = l["timestamp"].isoformat()

    return jsonify({
        "total_students": total_students,
        "total_admins": total_admins,
        "total_alerts": total_alerts,
        "unread_alerts": unread_alerts,
        "total_attacks": total_attacks,
        "suspicious_logins": suspicious_logins,
        "risk_distribution": {"High": high_risk, "Medium": medium_risk, "Low": low_risk},
        "attack_breakdown": attack_breakdown,
        "recent_logins": recent_logins
    }), 200

# ── GET /api/admin/students ───────────────────────────────────
@admin_bp.route("/students", methods=["GET"])
@jwt_required()
def get_students():
    db = get_db()
    if not require_admin():
        return jsonify({"error": "Forbidden"}), 403
    students = list(db.users.find({"role": "student"}, {"password_hash": 0}))
    return jsonify(serialize_list(students)), 200

# ── POST /api/admin/students ──────────────────────────────────
@admin_bp.route("/students", methods=["POST"])
@jwt_required()
def add_student():
    db = get_db()
    if not require_admin(): return jsonify({"error": "Forbidden"}), 403
    data = request.get_json()
    admin_id = get_jwt_identity()

    if db.users.find_one({"email": data.get("email", "").lower()}):
        return jsonify({"error": "Email already exists"}), 409

    hashed = bcrypt.generate_password_hash(data.get("password", "student123")).decode("utf-8")
    student = {
        "name": data.get("name"),
        "email": data.get("email", "").lower(),
        "password_hash": hashed,
        "role": "student",
        "register_number": data.get("register_number"),
        "department": data.get("department"),
        "year": data.get("year", 1),
        "phone": data.get("phone", ""),
        "failed_attempts": 0,
        "locked_until": None,
        "created_at": datetime.now(timezone.utc)
    }
    result = db.users.insert_one(student)
    uid = str(result.inserted_id)

    # Seed default fee record
    db.fees.insert_one({
        "user_id": uid,
        "total_amount": 75000,
        "paid_amount": 0,
        "balance": 75000,
        "status": "Pending",
        "due_date": datetime(2026, 6, 30, tzinfo=timezone.utc)
    })

    log_action(db, admin_id, "student_added", "server", "success", {"new_student_id": uid})
    return jsonify({"message": "Student added", "user_id": uid}), 201

# ── POST /api/admin/students/bulk ─────────────────────────────
@admin_bp.route("/students/bulk", methods=["POST"])
@jwt_required()
def add_students_bulk():
    db = get_db()
    if not require_admin(): return jsonify({"error": "Forbidden"}), 403
    
    data_list = request.get_json()
    if not isinstance(data_list, list) or len(data_list) == 0:
        return jsonify({"error": "Invalid format. Expected array of students."}), 400

    admin_id = get_jwt_identity()
    inserted_users = []
    fees_records = []
    
    existing_emails = set(u["email"] for u in db.users.find({"role": "student"}, {"email": 1}))
    
    for row in data_list:
        email = str(row.get("email", "")).strip().lower()
        if not email or email in existing_emails:
            continue
            
        hashed = bcrypt.generate_password_hash(str(row.get("password", "Student@123"))).decode("utf-8")
        
        student = {
            "name": row.get("name", "Unknown"),
            "email": email,
            "password_hash": hashed,
            "role": "student",
            "register_number": row.get("register_number", f"GEN-{(datetime.now().timestamp() * 1000)}"),
            "department": row.get("department", "General"),
            "year": int(row.get("year", 1)),
            "phone": str(row.get("phone", "")),
            "failed_attempts": 0,
            "locked_until": None,
            "created_at": datetime.now(timezone.utc)
        }
        
        # Manually assign objectId to cross-ref fees
        from bson import ObjectId
        student["_id"] = ObjectId()
        inserted_users.append(student)
        
        fees_records.append({
            "user_id": str(student["_id"]),
            "total_amount": 75000,
            "paid_amount": 0,
            "balance": 75000,
            "status": "Pending",
            "due_date": datetime(2026, 6, 30, tzinfo=timezone.utc)
        })
        existing_emails.add(email)

    if inserted_users:
        db.users.insert_many(inserted_users)
        db.fees.insert_many(fees_records)
        log_action(db, admin_id, "student_bulk_added", "server", "success", {"count": len(inserted_users)})
        return jsonify({"message": f"Successfully imported {len(inserted_users)} students!", "count": len(inserted_users)}), 201
    else:
        return jsonify({"message": "No new valid students to add (might be duplicates).", "count": 0}), 200

# ── PUT /api/admin/students/<id> ───────────────────────────────
@admin_bp.route("/students/<student_id>", methods=["PUT"])
@jwt_required()
def update_student(student_id):
    db = get_db()
    if not require_admin(): return jsonify({"error": "Forbidden"}), 403
    admin_id = get_jwt_identity()
    data = request.get_json()
    allowed = ["name", "department", "year", "phone"]
    update = {k: data[k] for k in allowed if k in data}
    db.users.update_one({"_id": ObjectId(student_id)}, {"$set": update})
    log_action(db, admin_id, "student_updated", "server", "success", {"student_id": student_id})
    return jsonify({"message": "Updated"}), 200

# ── DELETE /api/admin/students/<id> ───────────────────────────
@admin_bp.route("/students/<student_id>", methods=["DELETE"])
@jwt_required()
def delete_student(student_id):
    db = get_db()
    if not require_admin(): return jsonify({"error": "Forbidden"}), 403
    admin_id = get_jwt_identity()
    db.users.delete_one({"_id": ObjectId(student_id), "role": "student"})
    log_action(db, admin_id, "student_deleted", "server", "success", {"student_id": student_id})
    return jsonify({"message": "Deleted"}), 200

# ── POST /api/admin/students/<id>/unlock ──────────────────────
@admin_bp.route("/students/<student_id>/unlock", methods=["POST"])
@jwt_required()
def unlock_student(student_id):
    db = get_db()
    if not require_admin(): return jsonify({"error": "Forbidden"}), 403
    admin_id = get_jwt_identity()
    db.users.update_one(
        {"_id": ObjectId(student_id)},
        {"$set": {"locked_until": None, "failed_attempts": 0}}
    )
    log_action(db, admin_id, "student_unlocked", "server", "success", {"student_id": student_id})
    return jsonify({"message": "Account unlocked successfully"}), 200

# ── POST /api/admin/students/<id>/reset-risk ─────────────────
@admin_bp.route("/students/<student_id>/reset-risk", methods=["POST"])
@jwt_required()
def reset_risk(student_id):
    db = get_db()
    if not require_admin(): return jsonify({"error": "Forbidden"}), 403
    admin_id = get_jwt_identity()
    db.risk_scores.update_one(
        {"user_id": student_id},
        {"$set": {"risk_score": 0, "risk_level": "Low", "prediction": "normal", "anomaly_score": 0}},
        upsert=True
    )
    log_action(db, admin_id, "risk_score_reset", "server", "success", {"student_id": student_id})
    return jsonify({"message": "Risk score reset to zero"}), 200

# ── GET /api/admin/attack-logs ────────────────────────────────
@admin_bp.route("/attack-logs", methods=["GET"])
@jwt_required()
def get_attack_logs():
    db = get_db()
    if not require_admin(): return jsonify({"error": "Forbidden"}), 403
    logs = list(db.attack_logs.find().sort("timestamp", -1).limit(100))
    return jsonify(serialize_list(logs)), 200

# ── POST /api/admin/ml/retrain ──────────────────────────────
@admin_bp.route("/ml/retrain", methods=["POST"])
@jwt_required()
def retrain_model():
    db = get_db()
    if not require_admin(): return jsonify({"error": "Forbidden"}), 403
    from ml.isolation_forest import retrain_with_history
    try:
        retrain_with_history(db)
        log_action(db, get_jwt_identity(), "ml_model_retrained", "server", "success")
        return jsonify({"message": "AI Model successfully retrained with historical data!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── GET /api/admin/audit-logs ─────────────────────────────────
@admin_bp.route("/audit-logs", methods=["GET"])
@jwt_required()
def get_audit_logs():
    db = get_db()
    if not require_admin(): return jsonify({"error": "Forbidden"}), 403
    logs = list(db.audit_logs.find().sort("timestamp", -1).limit(100))
    return jsonify(serialize_list(logs)), 200

# ── GET /api/admin/alerts ─────────────────────────────────────
@admin_bp.route("/alerts", methods=["GET"])
@jwt_required()
def get_all_alerts():
    db = get_db()
    if not require_admin(): return jsonify({"error": "Forbidden"}), 403
    alerts = list(db.alerts.find().sort("created_at", -1).limit(100))
    return jsonify(serialize_list(alerts)), 200

# ── GET /api/admin/login-logs ─────────────────────────────────
@admin_bp.route("/login-logs", methods=["GET"])
@jwt_required()
def get_login_logs():
    db = get_db()
    if not require_admin(): return jsonify({"error": "Forbidden"}), 403
    logs = list(db.login_logs.find().sort("timestamp", -1).limit(100))
    return jsonify(serialize_list(logs)), 200

# ── GET /api/admin/risk-scores ────────────────────────────────
@admin_bp.route("/risk-scores", methods=["GET"])
@jwt_required()
def get_risk_scores():
    db = get_db()
    if not require_admin(): return jsonify({"error": "Forbidden"}), 403
    scores = list(db.risk_scores.find().sort("risk_score", -1))
    return jsonify(serialize_list(scores)), 200

# ── GET /api/admin/login-trends ───────────────────────────────
@admin_bp.route("/login-trends", methods=["GET"])
@jwt_required()
def login_trends():
    db = get_db()
    if not require_admin(): return jsonify({"error": "Forbidden"}), 403
    pipeline = [
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}},
            "total": {"$sum": 1},
            "suspicious": {"$sum": {"$cond": [{"$eq": ["$prediction", "suspicious"]}, 1, 0]}}
        }},
        {"$sort": {"_id": 1}},
        {"$limit": 14}
    ]
    trends = list(db.login_logs.aggregate(pipeline))
    return jsonify(trends), 200
