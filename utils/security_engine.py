# ============================================================
# utils/security_engine.py — AI Active Defense Engine
# ============================================================
import time
from datetime import datetime, timezone, timedelta
from flask import request, abort
from ml.risk_scorer import calculate_risk_score
from ml.isolation_forest import predict as ml_predict

# In-memory tracking (for local demo)
# In production, use Redis for multi-worker support
USER_STATS = {} # { user_id: { "last_request": float, "request_rate": int, "session_start": float } }
IP_TRACKER = {} # { ip: { "emails": set(), "last_reset": float } }

def track_ip_emails(ip, email):
    """
    Tracks how many unique emails are attempted from a single IP.
    Used to prevent Account Takeover (ATO) / Credential Stuffing.
    Returns: True if should block, False otherwise.
    """
    now = time.time()
    if ip not in IP_TRACKER:
        IP_TRACKER[ip] = {"emails": {email}, "last_reset": now}
        return False
    
    tracker = IP_TRACKER[ip]
    
    # Reset tracker every 5 minutes
    if now - tracker["last_reset"] > 300:
        tracker["emails"] = {email}
        tracker["last_reset"] = now
        return False
    
    tracker["emails"].add(email)
    
    # Block if an IP tries more than 5 different emails in 5 mins
    if len(tracker["emails"]) > 5:
        return True
        
    return False

def monitor_security(db, socketio, user_id, email, role):
    """
    Evaluates the security risk of the current request in real-time.
    Returns: (bool should_block, dict features)
    """
    now = time.time()
    
    # 1. Initialize stats for new user session
    if user_id not in USER_STATS:
        USER_STATS[user_id] = {
            "last_request": now,
            "request_rate": 0,
            "session_start": now,
            "tracking_window": now
        }

    stats = USER_STATS[user_id]
    
    # 2. Calculate Real-Time Features
    # Reset window every 10 seconds to calculate rate
    if now - stats["tracking_window"] > 10:
        stats["request_rate"] = 0
        stats["tracking_window"] = now
    
    stats["request_rate"] += 1
    stats["last_request"] = now
    
    duration_mins = (now - stats["session_start"]) / 60
    
    # Features for AI Model
    features = {
        "login_hour": datetime.now().hour,
        "failed_attempts": 0, # Brute force handled in auth routes
        "session_duration": int(duration_mins),
        "request_rate": stats["request_rate"] * 6, # Extrapolate 10s window to 60s
        "ip_risk_score": 0, # Standard local IP
        "location_change": 0,
        "device_change": 0
    }

    # 3. AI Prediction
    # We only call the AI for evaluation if the behavior looks slightly suspicious
    # to save CPU, OR we do it every request for high-security demo.
    risk_result = calculate_risk_score(db, user_id, features)
    
    # 4. Decision Logic (Blocking Threshold)
    is_suspicious = risk_result["prediction"] == "suspicious"
    risk_score = risk_result["risk_score"]
    
    # Block if risk is Critical (e.g., > 92) OR AI is certain it's an anomaly
    should_block = (risk_score >= 92) or (is_suspicious and stats["request_rate"] > 15)

    if should_block:
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        
        # Log the auto-detected attack
        attack_type = "bot_attack" if features["request_rate"] > 500 else "suspicious_activity"
        
        attack_doc = {
            "user_id": user_id,
            "email": email,
            "ip_address": ip,
            "attack_type": attack_type,
            "attack_name": "Active Defense Block",
            "description": f"AI blocked request due to anomalous {attack_type} pattern.",
            "ml_prediction": "anomaly",
            "risk_score": risk_score,
            "severity": "High",
            "timestamp": datetime.now(timezone.utc)
        }
        db.attack_logs.insert_one(attack_doc)

        # Broadcast real-time alert
        payload = {
            "attack_type": "security_block",
            "message": f"Security system blocked suspicious action from {email}",
            "ip_address": ip,
            "risk_score": risk_score,
            "timestamp": attack_doc["timestamp"].isoformat()
        }
        socketio.emit("attack_detected", payload)
        socketio.emit("system_event", {
            "type": "danger",
            "message": f"ACTIVE BLOCK: {email} (Account Locked)",
            "ip_address": ip,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        
        # Persistently lock the account in DB for prevention
        from bson import ObjectId
        db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"locked_until": datetime.now(timezone.utc) + timedelta(minutes=15)}})

    return should_block, risk_result
