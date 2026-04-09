# ============================================================
# ml/isolation_forest.py — Isolation Forest ML Model
# ============================================================
"""
Isolation Forest detects anomalous login behavior.

Features used:
  0. login_hour        — hour of login (0–23)
  1. failed_attempts   — recent failed login attempts
  2. session_duration  — session length in minutes
  3. request_rate      — requests per minute
  4. ip_risk_score     — 0=known IP, 1=new IP, 2=Tor/VPN
  5. location_change   — 0=same location, 1=different country
  6. device_change     — 0=known device, 1=new device

Output:
  1  → Normal
  -1 → Anomaly (suspicious)
"""

import numpy as np
from sklearn.ensemble import IsolationForest
import pickle
import os

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")

# Training data: mostly normal behavior with injected anomalies
NORMAL_DATA = [
    [9, 0, 45, 2, 0, 0, 0],   # 9am, no fails, normal session
    [10, 0, 30, 3, 0, 0, 0],
    [11, 1, 60, 2, 0, 0, 0],
    [14, 0, 90, 2, 0, 0, 0],
    [15, 0, 25, 1, 0, 0, 0],
    [16, 1, 40, 2, 0, 0, 0],
    [17, 0, 55, 3, 0, 0, 0],
    [8, 0, 20, 2, 0, 0, 0],
    [13, 0, 35, 2, 0, 0, 0],
    [12, 1, 45, 3, 0, 0, 0],
    [9, 0, 30, 2, 1, 0, 0],   # new IP but otherwise normal
    [10, 0, 40, 2, 0, 0, 1],  # new device but otherwise normal
]

ANOMALY_DATA = [
    [3, 15, 200, 120, 2, 1, 1],  # 3am, brute force + Tor + new loc
    [2, 20, 0, 200, 2, 1, 1],    # brute force bot
    [1, 10, 5, 150, 1, 1, 1],    # midnight suspicious login
    [4, 25, 1, 300, 2, 1, 1],    # extreme bot attack
]

def train_model(extra_data=None):
    """Train Isolation Forest and save to disk."""
    data_list = NORMAL_DATA + ANOMALY_DATA
    if extra_data:
        data_list.extend(extra_data)
        
    data = np.array(data_list)
    model = IsolationForest(
        n_estimators=200,
        contamination=0.15,  # ~15% anomalies expected
        random_state=42,
        max_samples="auto"
    )
    model.fit(data)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    print(f"[ML] ✅ Isolation Forest model trained with {len(data_list)} samples.")
    
    global _model
    _model = model
    return model

def retrain_with_history(db):
    """Fetch all successful logins and use them to retrain the model."""
    logs = list(db.login_logs.find({"status": "success"}))
    extra = []
    for l in logs:
        # Extract features (defaulting safe if missing)
        hour = l.get("timestamp").hour if hasattr(l.get("timestamp"), "hour") else 12
        extra.append([
            hour,
            0, # failed_attempts
            30, # session_duration
            2, # request_rate
            0, # ip_risk
            0, # loc change
            0  # device change
        ])
    return train_model(extra_data=extra)

def load_model():
    """Load model from disk, training it first if not found."""
    if not os.path.exists(MODEL_PATH):
        return train_model()
    with open(MODEL_PATH, "rb") as f:
        return pickle.load(f)

# Singleton model instance
_model = None

def get_model():
    global _model
    if _model is None:
        _model = load_model()
    return _model

def predict(features: dict) -> dict:
    """
    Predict whether login behavior is normal or suspicious.

    Args:
        features: dict with keys matching the feature list above.
    Returns:
        dict: { "prediction": "normal"|"suspicious", "anomaly_score": float }
    """
    model = get_model()

    vector = np.array([[
        features.get("login_hour", 12),
        features.get("failed_attempts", 0),
        features.get("session_duration", 30),
        features.get("request_rate", 2),
        features.get("ip_risk_score", 0),
        features.get("location_change", 0),
        features.get("device_change", 0),
    ]])

    result = model.predict(vector)[0]        # 1 = normal, -1 = anomaly
    score = model.score_samples(vector)[0]   # negative; closer to 0 = anomaly

    # Normalize anomaly score to 0–100 risk scale
    # score_samples returns values roughly in [-0.5, 0.5]
    # More negative = more anomalous
    risk = int(min(100, max(0, (-score) * 200)))

    return {
        "prediction": "suspicious" if result == -1 else "normal",
        "anomaly_score": round(float(-score), 4),
        "risk_contribution": risk
    }
