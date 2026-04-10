# ============================================================
# app.py — Main Flask Application Entry Point
# ============================================================
"""
AI Model for Predicting Technology Misuse
Flask + Socket.IO backend server

Run: python app.py
"""

import eventlet
eventlet.monkey_patch()

from flask import Flask
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_socketio import SocketIO, emit, join_room
from config import Config
from database import get_db
from ml.isolation_forest import get_model  # pre-load model on startup

# ── App Setup ────────────────────────────────────────────────
app = Flask(__name__)
app.config.from_object(Config)
app.config["JWT_SECRET_KEY"] = Config.JWT_SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = Config.JWT_ACCESS_TOKEN_EXPIRES

# Extensions
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app, origins=["http://localhost:5173", "http://127.0.0.1:5173"], supports_credentials=True)

from extensions import limiter
limiter.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# ── Blueprints ───────────────────────────────────────────────
from routes.auth import auth_bp
from routes.student import student_bp
from routes.admin import admin_bp
from routes.alerts import alerts_bp
from routes.reports import reports_bp

app.register_blueprint(auth_bp, url_prefix="/api/auth")
app.register_blueprint(student_bp, url_prefix="/api/student")
app.register_blueprint(admin_bp, url_prefix="/api/admin")
app.register_blueprint(alerts_bp, url_prefix="/api/alerts")
app.register_blueprint(reports_bp, url_prefix="/api/reports")

# ── AI Active Defense Interceptor ────────────────────────────
from flask import request, abort, jsonify
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
from utils.security_engine import monitor_security

@app.before_request
def active_defense_layer():
    # Only monitor protected API routes
    if request.path.startswith("/api/student") or request.path.startswith("/api/admin"):
        try:
            # Check if user is authenticated
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            
            # Skip security check if no user identity
            if not user_id: return
            
            db = get_db()
            user = db.users.find_one({"_id": ObjectId(user_id)})
            if not user: return

            # Evaluate behavior in real-time
            should_block, risk = monitor_security(
                db, 
                socketio, 
                user_id, 
                user.get("email"), 
                user.get("role")
            )

            if should_block:
                # Prediction: Block the specific anomalous action
                return jsonify({
                    "error": "Security Blocked",
                    "message": "AI detected suspicious activity. This action has been blocked for system safety.",
                    "risk_score": risk["risk_score"]
                }), 403

        except Exception:
            # If JWT missing or invalid, ignore (standard 401 will handle it)
            pass

# ── Health Check ─────────────────────────────────────────────
@app.route("/api/health")
def health():
    return {"status": "ok", "message": "AI Portal Backend Running"}

# ── Socket.IO Events ─────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    print(f"[Socket.IO] Client connected: {socketio.server.manager.rooms.keys()}")
    emit("connected", {"message": "Connected to AI Portal real-time system"})

@socketio.on("disconnect")
def on_disconnect():
    print("[Socket.IO] Client disconnected")

@socketio.on("join")
def on_join(data):
    """Client joins their personal room for targeted alerts."""
    room = data.get("room", "general")
    join_room(room)
    emit("joined", {"room": room})

@socketio.on("ping_test")
def on_ping(data):
    emit("pong", {"message": "Server is alive!", "data": data})

# ── Startup ───────────────────────────────────────────────────
if __name__ == "__main__":
    # Initialize DB and pre-load ML model
    db = get_db()
    model = get_model()
    
    # ── Background Task: Weekly ML Retraining ───────────────
    from apscheduler.schedulers.background import BackgroundScheduler
    from ml.isolation_forest import retrain_with_history
    
    scheduler = BackgroundScheduler(daemon=True)
    # Automatically retrain the Isolation Forest every 7 days with new data
    scheduler.add_job(func=lambda: retrain_with_history(get_db()), trigger="interval", days=7)
    scheduler.start()

    print("=" * 60)
    print("  AI Model for Predicting Technology Misuse")
    print("  Backend Server Starting...")
    print("  URL: http://localhost:5000")
    print("  API: http://localhost:5000/api")
    print("  Background Scheduler Running (Next Retrain: 7 Days)")
    print("=" * 60)
    
    try:
        socketio.run(app, host="0.0.0.0", port=5000, debug=Config.DEBUG)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
