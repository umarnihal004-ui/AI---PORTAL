# ============================================================
# config.py — Application Configuration
# ============================================================
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask
    SECRET_KEY = os.getenv("SECRET_KEY", "ai-portal-super-secret-key-2026")
    DEBUG = os.getenv("DEBUG", "True") == "True"

    # JWT
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "jwt-secret-key-ai-portal-2026")
    JWT_ACCESS_TOKEN_EXPIRES = 3600  # 1 hour

    # MongoDB
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017/")
    DB_NAME = os.getenv("DB_NAME", "ai_portal")

    # Email (optional — configure for real OTP)
    MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.getenv("MAIL_PORT", 587))
    MAIL_USERNAME = os.getenv("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "")
    MAIL_USE_TLS = True

    # OTP
    OTP_EXPIRY_SECONDS = 60

    # Account Lock
    MAX_LOGIN_ATTEMPTS = 5
    LOCK_DURATION_MINUTES = 15

    # Frontend
    FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")
