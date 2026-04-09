# ============================================================
# database.py — MongoDB Connection Manager
# ============================================================
from pymongo import MongoClient
from config import Config

client = None
db = None

def get_db():
    """Return the active database instance, creating it if needed."""
    global client, db
    if db is None:
        client = MongoClient(Config.MONGO_URI)
        db = client[Config.DB_NAME]
        _create_indexes()
    return db

def _create_indexes():
    """Create indexes on frequently queried fields."""
    db.users.create_index("email", unique=True)
    db.users.create_index("register_number")
    db.login_logs.create_index("user_id")
    db.login_logs.create_index("timestamp")
    db.alerts.create_index("user_id")
    db.attack_logs.create_index("timestamp")
    db.audit_logs.create_index("user_id")
    db.otp_logs.create_index("email")
    db.risk_scores.create_index("user_id", unique=True)
    print("[DB] ✅ MongoDB connected and indexes created.")
