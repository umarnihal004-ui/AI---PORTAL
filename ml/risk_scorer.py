# ============================================================
# ml/risk_scorer.py — Risk Score Calculator
# ============================================================
"""
Calculates a 0–100 risk score for each user based on:
  - ML anomaly score from Isolation Forest
  - Failed login attempts
  - Number of flagged alerts
  - Recent suspicious activity
"""

from datetime import datetime, timezone, timedelta
from ml.isolation_forest import predict as ml_predict

def calculate_risk_score(db, user_id: str, features: dict) -> dict:
    """
    Compute risk score and update risk_scores collection.

    Returns:
        dict: { "risk_score": int, "risk_level": str, "prediction": str }
    """
    # ML model contribution
    ml_result = ml_predict(features)
    ml_risk = ml_result["risk_contribution"]

    # Failed attempts bonus
    failed = min(features.get("failed_attempts", 0), 20)
    failed_risk = int(failed * 2.5)  # max 50

    # Recent alerts count (last 24h)
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    alert_count = db.alerts.count_documents({
        "user_id": str(user_id),
        "created_at": {"$gte": since}
    })
    alert_risk = min(alert_count * 10, 30)  # max 30

    # Weighted total (capped 0–100)
    total = int(ml_risk * 0.5 + failed_risk * 0.3 + alert_risk * 0.2)
    total = min(100, max(0, total))

    # Risk level label
    if total <= 30:
        level = "Low"
    elif total <= 70:
        level = "Medium"
    else:
        level = "High"

    # Persist to DB (upsert)
    db.risk_scores.update_one(
        {"user_id": str(user_id)},
        {"$set": {
            "user_id": str(user_id),
            "risk_score": total,
            "risk_level": level,
            "ml_contribution": ml_risk,
            "failed_contribution": failed_risk,
            "alert_contribution": alert_risk,
            "prediction": ml_result["prediction"],
            "anomaly_score": ml_result["anomaly_score"],
            "updated_at": datetime.now(timezone.utc)
        }},
        upsert=True
    )

    return {
        "risk_score": total,
        "risk_level": level,
        "prediction": ml_result["prediction"],
        "anomaly_score": ml_result["anomaly_score"]
    }
