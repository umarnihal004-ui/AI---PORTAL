# ============================================================
# utils/attack_simulator.py — Threat Scenario Generator
# ============================================================
import random
from datetime import datetime, timezone
from ml.isolation_forest import predict as ml_predict
from ml.risk_scorer import calculate_risk_score

SCENARIOS = {
    "brute_force": {
        "name": "Brute Force Attack",
        "severity": "High",
        "description": "Micro-anomaly detected: Failed login count reached threshold of 5.",
        "features": {
            "login_hour": 1,
            "failed_attempts": 5,
            "session_duration": 1,
            "request_rate": 10,
            "ip_risk_score": 1,
            "location_change": 0,
            "device_change": 1
        }
    },
    "bot_attack": {
        "name": "Bot Attack",
        "severity": "High",
        "description": "Minor request rate elevation (Capped at 45 req/min).",
        "features": {
            "login_hour": 14,
            "failed_attempts": 0,
            "session_duration": 0,
            "request_rate": 5,
            "ip_risk_score": 1,
            "location_change": 1,
            "device_change": 1
        }
    },
    "data_exfiltration": {
        "name": "Data Exfiltration",
        "severity": "Critical",
        "description": "Session duration anomaly: Exceeded 60-minute baseline.",
        "features": {
            "login_hour": 11,
            "failed_attempts": 0,
            "session_duration": 65,
            "request_rate": 5,
            "ip_risk_score": 0,
            "location_change": 0,
            "device_change": 0
        }
    },
    "suspicious_login": {
        "name": "Suspicious Login",
        "severity": "Medium",
        "description": "Single geo-location mismatch detected during standard hours.",
        "features": {
            "login_hour": 18,
            "failed_attempts": 0,
            "session_duration": 5,
            "request_rate": 2,
            "ip_risk_score": 0,
            "location_change": 1,
            "device_change": 0
        }
    },
    "account_takeover": {
        "name": "Account Takeover",
        "severity": "Critical",
        "description": "Targeted device shift at anomalous 4 AM window.",
        "features": {
            "login_hour": 4,
            "failed_attempts": 0,
            "session_duration": 5,
            "request_rate": 3,
            "ip_risk_score": 1,
            "location_change": 0,
            "device_change": 1
        }
    },
    "unauthorized_access": {
        "name": "Unauthorized Access",
        "severity": "High",
        "description": "Minimal pathway scan: 2 failed access attempts detected.",
        "features": {
            "login_hour": 14,
            "failed_attempts": 2,
            "session_duration": 1,
            "request_rate": 15,
            "ip_risk_score": 1,
            "location_change": 0,
            "device_change": 0
        }
    }
}

def simulate_attack(db, socketio, attack_type, user_id):
    """
    Simulates a cyber attack by:
    1. Generating anomalous features.
    2. Predicting risk using ML.
    3. Logging to database.
    4. Emitting real-time Socket.IO alerts.
    """
    if attack_type not in SCENARIOS:
        raise ValueError(f"Invalid attack type: {attack_type}")

    scenario = SCENARIOS[attack_type]
    features = scenario["features"]
    
    # 1. Get ML Prediction & Risk Score
    risk_result = calculate_risk_score(db, user_id, features)
    
    # 2. Get User Info for the event
    from bson import ObjectId
    user = db.users.find_one({"_id": ObjectId(user_id)})
    user_email = user["email"] if user else "target@student.com"
    ip_addr = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"

    # 3. Insert Attack Log
    attack_doc = {
        "user_id": user_id,
        "email": user_email,
        "ip_address": ip_addr,
        "attack_type": attack_type,
        "attack_name": scenario["name"],
        "description": scenario["description"],
        "ml_prediction": risk_result["prediction"],
        "risk_score": risk_result["risk_score"],
        "severity": scenario["severity"],
        "timestamp": datetime.now(timezone.utc)
    }
    db.attack_logs.insert_one(attack_doc)

    # 4. Create Alert
    alert_doc = {
        "user_id": user_id,
        "type": attack_type,
        "message": f"[ALERT] {scenario['name']} detected! Source: {ip_addr}",
        "severity": scenario["severity"],
        "ip_address": ip_addr,
        "risk_score": risk_result["risk_score"],
        "read": False,
        "created_at": datetime.now(timezone.utc)
    }
    db.alerts.insert_one(alert_doc)

    # 5. Emit Socket.IO Events
    payload = {
        "attack_type": attack_type,
        "attack_name": scenario["name"],
        "severity": scenario["severity"],
        "ip_address": ip_addr,
        "risk_score": risk_result["risk_score"],
        "message": alert_doc["message"],
        "timestamp": alert_doc["created_at"].isoformat()
    }
    
    # Global broadcast for security command center
    socketio.emit("attack_detected", payload)
    
    # Target specific user broadcast
    socketio.emit(f"user_alert_{user_id}", payload)
    
    # Audit trail telemetry feed
    socketio.emit("system_event", {
        "type": "danger" if scenario["severity"] in ["High", "Critical"] else "warning",
        "message": f"{scenario['name'].upper()}: {user_email}",
        "ip_address": ip_addr,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

    return {
        "status": "success",
        "attack": scenario["name"],
        "risk_score": risk_result["risk_score"]
    }
