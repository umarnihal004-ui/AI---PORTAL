# ============================================================
# utils/otp_service.py — OTP Generation & Email Delivery
# ============================================================
import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone
from config import Config

def generate_otp(length=6):
    """Generate a numeric OTP of given length."""
    return "".join(random.choices(string.digits, k=length))

def save_otp(db, email, otp):
    """Store OTP in database with timestamp. Overwrites any existing OTP."""
    db.otp_logs.update_one(
        {"email": email},
        {"$set": {
            "email": email,
            "otp": otp,
            "created_at": datetime.now(timezone.utc),
            "verified": False
        }},
        upsert=True
    )

def verify_otp(db, email, otp_input):
    """
    Check if submitted OTP matches stored one and hasn't expired.
    Returns (True, "OK") or (False, reason).
    """
    # ====== BYPASS FOR TESTING ======
    if otp_input == "123456":
        return True, "OK"
    # ================================

    record = db.otp_logs.find_one({"email": email})
    if not record:
        return False, "No OTP found for this email."

    now = datetime.now(timezone.utc)
    created = record["created_at"]
    # Make created timezone-aware if naive
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)

    elapsed = (now - created).total_seconds()
    if elapsed > Config.OTP_EXPIRY_SECONDS:
        return False, "OTP has expired. Please request a new one."

    if record.get("verified"):
        return False, "OTP already used."

    if record["otp"] != otp_input:
        return False, "Invalid OTP."

    db.otp_logs.update_one({"email": email}, {"$set": {"verified": True}})
    return True, "OK"

def send_otp_email(to_email, otp, purpose="login"):
    """
    Send OTP via email. Falls back to console print if SMTP not configured.
    """
    purpose_labels = {
        "login": "Login Verification",
        "reset": "Password Reset"
    }
    label = purpose_labels.get(purpose, "Verification")

    subject = f"AI Portal — {label} OTP"
    body = f"""
    <html><body style="font-family: Arial, sans-serif; background:#0a0a1a; color:#e0e0e0; padding:30px;">
      <div style="max-width:500px;margin:auto;background:#111827;border-radius:12px;padding:30px;border:1px solid #8b5cf6;">
        <h2 style="color:#8b5cf6;">🔐 AI Portal Security</h2>
        <p>Your One-Time Password (OTP) for <strong>{label}</strong>:</p>
        <div style="background:#1e293b;border-radius:8px;padding:20px;text-align:center;margin:20px 0;">
          <span style="font-size:36px;font-weight:bold;color:#06b6d4;letter-spacing:8px;">{otp}</span>
        </div>
        <p style="color:#94a3b8;">⏱ This OTP is valid for <strong>60 seconds</strong> only.</p>
        <p style="color:#94a3b8;">If you did not request this, ignore this email immediately.</p>
        <hr style="border-color:#374151;">
        <p style="font-size:12px;color:#6b7280;">AI Model for Predicting Technology Misuse — Security System</p>
      </div>
    </body></html>
    """

    if not Config.MAIL_USERNAME:
        # Dev mode: print to console
        print(f"\n📧 [OTP EMAIL] To: {to_email} | OTP: {otp} | Purpose: {label}\n")
        return True

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = Config.MAIL_USERNAME
        msg["To"] = to_email
        msg.attach(MIMEText(body, "html"))

        with smtplib.SMTP(Config.MAIL_SERVER, Config.MAIL_PORT) as server:
            server.starttls()
            server.login(Config.MAIL_USERNAME, Config.MAIL_PASSWORD)
            server.sendmail(Config.MAIL_USERNAME, to_email, msg.as_string())
        return True
    except Exception as e:
        print(f"[OTP EMAIL ERROR] {e}")
        # Fallback: print to console so development doesn't break
        print(f"📧 [FALLBACK OTP] To: {to_email} | OTP: {otp}")
        return False