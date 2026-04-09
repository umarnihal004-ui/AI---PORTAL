# ============================================================
# routes/auth.py — Authentication Routes
# ============================================================
from flask import Blueprint, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timezone, timedelta
from database import get_db
from utils.otp_service import generate_otp, save_otp, verify_otp, send_otp_email
from utils.audit_logger import log_action
from ml.risk_scorer import calculate_risk_score
from config import Config

auth_bp = Blueprint("auth", __name__)
bcrypt = Bcrypt()

def get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)

from extensions import limiter

# ── POST /api/auth/login ─────────────────────────────────────
@auth_bp.route("/login", methods=["POST"])
@limiter.limit("5 per minute", override_defaults=False)
def login():
    db = get_db()
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    ip = get_client_ip()

    user = db.users.find_one({"email": email})

    # User not found
    if not user:
        log_action(db, "unknown", "login_failed", ip, "failed", {"email": email, "reason": "user not found"})
        return jsonify({"error": "Invalid credentials"}), 401

    # Account locked?
    locked_until = user.get("locked_until")
    if locked_until:
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) < locked_until:
            remaining = int((locked_until - datetime.now(timezone.utc)).total_seconds() // 60)
            return jsonify({"error": f"Account locked. Try again in {remaining} minute(s)."}), 403

    # Wrong password
    if not bcrypt.check_password_hash(user["password_hash"], password):
        attempts = user.get("failed_attempts", 0) + 1
        update = {"failed_attempts": attempts}
        if attempts >= Config.MAX_LOGIN_ATTEMPTS:
            update["locked_until"] = datetime.now(timezone.utc) + timedelta(minutes=Config.LOCK_DURATION_MINUTES)
        db.users.update_one({"email": email}, {"$set": update})
        log_action(db, str(user["_id"]), "login_failed", ip, "failed", {"attempts": attempts})
        
        # === Trigger Brute Force Attack Detection visibly on UI ===
        if attempts >= 3:
            db.attack_logs.insert_one({
                "user_id": str(user["_id"]),
                "ip_address": ip,
                "attack_type": "brute_force",
                "attack_name": "Brute Force Attack",
                "description": f"Multiple failed login attempts ({attempts}).",
                "ml_prediction": "suspicious",
                "risk_score": 85 + attempts,
                "severity": "High",
                "timestamp": datetime.now(timezone.utc)
            })
            # 1. Update ML Prediction visually
            db.risk_scores.update_one(
                {"user_id": str(user["_id"])},
                {"$set": {"risk_score": 85 + attempts, "risk_level": "High", "prediction": "suspicious"}},
                upsert=True
            )
            # 2. Trigger Alert Notification
            db.alerts.insert_one({
                "user_id": str(user["_id"]), "type": "brute_force",
                "message": f"🚨 Brute Force connection dropped from {ip}.",
                "severity": "High", "ip_address": ip, "read": False, "created_at": datetime.now(timezone.utc)
            })
            
            from app import socketio
            payload = {"attack_type": "brute_force", "attack_name": "Brute Force", "ip_address": ip, "risk_score": 85 + attempts}
            socketio.emit("attack_detected", payload)
            socketio.emit(f"user_alert_{str(user['_id'])}", payload)
            
            # Emit system event for live terminal
            socketio.emit("system_event", {
                "type": "danger",
                "message": f"Brute Force Attack Prevented: {email}",
                "ip_address": ip,
                "timestamp": datetime.now(timezone.utc).isoformat()
            })

        return jsonify({"error": "Invalid credentials", "attempts": attempts}), 401

    # Reset failed attempts
    db.users.update_one({"email": email}, {"$set": {"failed_attempts": 0, "locked_until": None}})

    # Generate and send OTP
    otp = generate_otp()
    save_otp(db, email, otp)
    send_otp_email(email, otp, purpose="login")

    log_action(db, str(user["_id"]), "otp_sent", ip, "success", {"email": email})
    return jsonify({"message": "OTP sent to your email.", "email": email, "require_otp": True}), 200

# ── POST /api/auth/verify-otp ────────────────────────────────
@auth_bp.route("/verify-otp", methods=["POST"])
@limiter.limit("5 per minute", override_defaults=False)
def verify_otp_route():
    db = get_db()
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    otp_input = data.get("otp", "").strip()
    ip = get_client_ip()

    ok, reason = verify_otp(db, email, otp_input)
    if not ok:
        user = db.users.find_one({"email": email})
        if user:
            otp_fails = user.get("otp_fails", 0) + 1
            db.users.update_one({"email": email}, {"$set": {"otp_fails": otp_fails}})
            if otp_fails >= 3:
                # 3. Active Prevention -> Lock Account
                db.users.update_one({"email": email}, {"$set": {"locked_until": datetime.now(timezone.utc) + timedelta(minutes=15)}})
                
                db.attack_logs.insert_one({
                    "user_id": str(user["_id"]), "ip_address": ip,
                    "attack_type": "bot_attack", "attack_name": "Bot Attack",
                    "description": f"Repeated invalid OTP submissions ({otp_fails}). Account Locked.",
                    "ml_prediction": "suspicious", "risk_score": 92, "severity": "High",
                    "timestamp": datetime.now(timezone.utc)
                })
                # 1. Update ML Prediction Visually
                db.risk_scores.update_one(
                    {"user_id": str(user["_id"])},
                    {"$set": {"risk_score": 92, "risk_level": "High", "prediction": "suspicious"}},
                    upsert=True
                )
                # 2. Trigger Alert Notification
                db.alerts.insert_one({
                    "user_id": str(user["_id"]), "type": "bot_attack",
                    "message": f"🚨 Bot Attack mitigated. Account temporarily locked.",
                    "severity": "High", "ip_address": ip, "read": False, "created_at": datetime.now(timezone.utc)
                })
                
                from app import socketio
                payload = {"attack_type": "bot_attack", "attack_name": "Bot Attack", "ip_address": ip, "risk_score": 92}
                socketio.emit("attack_detected", payload)
                socketio.emit(f"user_alert_{str(user['_id'])}", payload)
                socketio.emit("system_event", {"type": "danger", "message": f"Bot Attack Prevented: {email}", "ip_address": ip, "timestamp": datetime.now(timezone.utc).isoformat()})
        return jsonify({"error": reason}), 400

    user = db.users.find_one({"email": email})
    if not user:
        return jsonify({"error": "User not found"}), 404
        
    db.users.update_one({"email": email}, {"$set": {"otp_fails": 0}})

    user_id = str(user["_id"])

    # ML risk scoring on login
    features = {
        "login_hour": datetime.now(timezone.utc).hour,
        "failed_attempts": user.get("failed_attempts", 0),
        "session_duration": 30,
        "request_rate": 2,
        "ip_risk_score": 0,
        "location_change": 0,
        "device_change": 0,
    }
    risk = calculate_risk_score(db, user_id, features)

    # Save login log
    db.login_logs.insert_one({
        "user_id": user_id,
        "email": email,
        "ip_address": ip,
        "role": user.get("role"),
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "prediction": risk["prediction"],
        "timestamp": datetime.now(timezone.utc),
        "status": "success"
    })

    log_action(db, user_id, "login_success", ip, "success")
    
    # Emit normal login system event
    from app import socketio
    socketio.emit("system_event", {
        "type": "info",
        "message": f"Successful login: {email}",
        "ip_address": ip,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

    # If suspicious, create alert, log the attack, and emit real-time signals
    if risk["prediction"] == "suspicious":
        alert_data = {
            "user_id": user_id,
            "type": "suspicious_login",
            "message": f"⚠️ Suspicious login detected from {ip}. Risk score: {risk['risk_score']}",
            "severity": "High",
            "ip_address": ip,
            "risk_score": risk["risk_score"],
            "read": False,
            "created_at": datetime.now(timezone.utc)
        }
        db.alerts.insert_one(alert_data)
        
        attack_log = {
            "user_id": user_id,
            "ip_address": ip,
            "attack_type": "suspicious_login",
            "attack_name": "Suspicious Login detected by ML",
            "description": "Isolation Forest model flagged login behavior as an anomaly.",
            "ml_prediction": "suspicious",
            "risk_score": risk["risk_score"],
            "severity": "High",
            "timestamp": datetime.now(timezone.utc)
        }
        db.attack_logs.insert_one(attack_log)

        # Emit real-time Socket.IO events for live UI updates
        from app import socketio
        socket_payload = {
            "attack_type": "suspicious_login",
            "attack_name": "Suspicious Login",
            "ip_address": ip,
            "risk_score": risk["risk_score"]
        }
        socketio.emit("attack_detected", socket_payload)
        socketio.emit(f"user_alert_{user_id}", socket_payload)
        
        # Emit system event for live terminal
        socketio.emit("system_event", {
            "type": "danger",
            "message": f"ML Anomaly Flagged: {email}",
            "ip_address": ip,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    # Create JWT
    token = create_access_token(
        identity=user_id,
        additional_claims={"role": user.get("role"), "email": email}
    )

    return jsonify({
        "token": token,
        "role": user.get("role"),
        "user_id": user_id,
        "name": user.get("name"),
        "email": email,
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"]
    }), 200

# ── POST /api/auth/forgot-password ───────────────────────────
@auth_bp.route("/forgot-password", methods=["POST"])
def forgot_password():
    db = get_db()
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    ip = get_client_ip()

    user = db.users.find_one({"email": email})
    if not user:
        # Don't reveal if email exists
        return jsonify({"message": "If that email is registered, an OTP has been sent."}), 200

    otp = generate_otp()
    save_otp(db, email, otp)
    send_otp_email(email, otp, purpose="reset")
    log_action(db, str(user["_id"]), "password_reset_requested", ip, "success")

    return jsonify({"message": "OTP sent to your email.", "email": email}), 200

# ── POST /api/auth/reset-password ────────────────────────────
@auth_bp.route("/reset-password", methods=["POST"])
def reset_password():
    db = get_db()
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    otp_input = data.get("otp", "").strip()
    new_password = data.get("new_password", "")
    ip = get_client_ip()

    if len(new_password) < 6:
        return jsonify({"error": "Password must be at least 6 characters."}), 400

    ok, reason = verify_otp(db, email, otp_input)
    if not ok:
        return jsonify({"error": reason}), 400

    hashed = bcrypt.generate_password_hash(new_password).decode("utf-8")
    db.users.update_one({"email": email}, {"$set": {"password_hash": hashed}})

    user = db.users.find_one({"email": email})
    log_action(db, str(user["_id"]), "password_reset_success", ip, "success")

    return jsonify({"message": "Password reset successfully."}), 200

# ── GET /api/auth/me ─────────────────────────────────────────
@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def get_me():
    db = get_db()
    from bson import ObjectId
    user_id = get_jwt_identity()
    user = db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        return jsonify({"error": "User not found"}), 404

    risk = db.risk_scores.find_one({"user_id": user_id})

    return jsonify({
        "user_id": user_id,
        "name": user.get("name"),
        "email": user.get("email"),
        "role": user.get("role"),
        "department": user.get("department"),
        "register_number": user.get("register_number"),
        "risk_score": risk["risk_score"] if risk else 0,
        "risk_level": risk["risk_level"] if risk else "Low"
    }), 200
