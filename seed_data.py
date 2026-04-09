# ============================================================
# seed_data.py — Populate MongoDB with Sample Data
# ============================================================
"""
Run: python seed_data.py

Creates:
  - 1 admin account
  - 5 student accounts
  - Attendance, marks, fee records
  - Sample attack logs & alerts
  - Risk scores
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from datetime import datetime, timezone, timedelta
from database import get_db
from flask_bcrypt import generate_password_hash
import random

db = get_db()

def hash_pw(pw):
    return generate_password_hash(pw).decode("utf-8")

def clear_collections():
    for col in ["users", "students", "attendance", "marks", "fees",
                "alerts", "attack_logs", "audit_logs", "login_logs",
                "risk_scores", "otp_logs"]:
        db[col].drop()
    print("[Seed] 🗑️  Cleared all collections.")

def seed_users():
    users = [
        {
            "name": "Harshavarthan K S",
            "email": "harshavarthanks583224104037@nprcollleges.org",
            "password_hash": hash_pw("harsha@2006"),
            "role": "admin",
            "department": "CSE",
            "register_number": "ADMIN001",
            "year": None,
            "phone": "9566798961",
            "failed_attempts": 0,
            "locked_until": None,
            "created_at": datetime.now(timezone.utc)
        },
        {
            "name": "Yogeshwaran P",
            "email": "yogeshwaranp583224104123@nprcolleges.org",
            "password_hash": hash_pw("yogesh@123"),
            "role": "student",
            "department": "Computer Science",
            "register_number": "CS583224104123",
            "year": 3,
            "phone": "8838892181",
            "failed_attempts": 0,
            "locked_until": None,
            "created_at": datetime.now(timezone.utc)
        },
        {
            "name": "Priya Sharma",
            "email": "priya@student.com",
            "password_hash": hash_pw("Student@123"),
            "role": "student",
            "department": "Electronics",
            "register_number": "EC2023002",
            "year": 2,
            "phone": "9222222222",
            "failed_attempts": 0,
            "locked_until": None,
            "created_at": datetime.now(timezone.utc)
        },
        {
            "name": "Rahul Nair",
            "email": "rahul@student.com",
            "password_hash": hash_pw("Student@123"),
            "role": "student",
            "department": "Mechanical",
            "register_number": "ME2023003",
            "year": 1,
            "phone": "9333333333",
            "failed_attempts": 3,
            "locked_until": None,
            "created_at": datetime.now(timezone.utc)
        },
        {
            "name": "Divya Menon",
            "email": "divya@student.com",
            "password_hash": hash_pw("Student@123"),
            "role": "student",
            "department": "Computer Science",
            "register_number": "CS2023004",
            "year": 4,
            "phone": "9444444444",
            "failed_attempts": 0,
            "locked_until": None,
            "created_at": datetime.now(timezone.utc)
        },
        {
            "name": "Vikram Singh",
            "email": "vikram@student.com",
            "password_hash": hash_pw("Student@123"),
            "role": "student",
            "department": "Information Technology",
            "register_number": "IT2023005",
            "year": 2,
            "phone": "9555555555",
            "failed_attempts": 0,
            "locked_until": None,
            "created_at": datetime.now(timezone.utc)
        }
    ]
    result = db.users.insert_many(users)
    print(f"[Seed] ✅ {len(result.inserted_ids)} users created.")
    return result.inserted_ids

def seed_academic(user_ids):
    subjects_cs = ["Data Structures", "DBMS", "OS", "Networks", "ML"]
    subjects_ec = ["Analog Circuits", "Digital Electronics", "Communication", "VLSI", "Signals"]
    subjects_me = ["Thermodynamics", "Fluid Mechanics", "Manufacturing", "CAD", "Dynamics"]
    subjects_it = ["Web Technology", "Cloud Computing", "Cybersecurity", "AI", "Software Engineering"]

    student_ids = user_ids[1:]  # skip admin
    departments_subjects = [subjects_cs, subjects_ec, subjects_me, subjects_cs, subjects_it]

    attendance_docs = []
    marks_docs = []
    fees_docs = []

    for uid, subjects in zip(student_ids, departments_subjects):
        uid_str = str(uid)
        for subj in subjects:
            total = random.randint(60, 80)
            present = random.randint(int(total * 0.65), total)
            attendance_docs.append({
                "user_id": uid_str,
                "subject": subj,
                "present": present,
                "total": total,
                "date": datetime.now(timezone.utc)
            })
            marks_docs.append({
                "user_id": uid_str,
                "subject": subj,
                "internal": random.randint(35, 50),
                "external": random.randint(40, 75),
                "total": random.randint(75, 125),
                "grade": random.choice(["A+", "A", "B+", "B", "C"])
            })

        paid = random.randint(0, 75000)
        total_amount = 75000
        fees_docs.append({
            "user_id": uid_str,
            "total_amount": total_amount,
            "paid_amount": paid,
            "balance": total_amount - paid,
            "status": "Paid" if paid >= total_amount else ("Partial" if paid > 0 else "Pending"),
            "due_date": datetime(2026, 6, 30, tzinfo=timezone.utc)
        })

    db.attendance.insert_many(attendance_docs)
    db.marks.insert_many(marks_docs)
    db.fees.insert_many(fees_docs)
    print(f"[Seed] ✅ Academic records seeded.")

def seed_attack_logs(user_ids):
    attack_types = [
        ("brute_force", "Brute Force Attack", "High"),
        ("bot_attack", "Bot Attack", "High"),
        ("data_exfiltration", "Data Exfiltration", "Critical"),
        ("suspicious_login", "Suspicious Login", "Medium"),
    ]

    logs = []
    alerts = []
    risk_scores = []
    login_logs = []

    for uid in user_ids:
        uid_str = str(uid)
        risk_val = random.randint(5, 95)
        risk_level = "Low" if risk_val <= 30 else ("Medium" if risk_val <= 70 else "High")

        risk_scores.append({
            "user_id": uid_str,
            "risk_score": risk_val,
            "risk_level": risk_level,
            "prediction": "suspicious" if risk_val > 60 else "normal",
            "anomaly_score": round(random.uniform(0.1, 0.9), 4),
            "ml_contribution": risk_val // 2,
            "failed_contribution": random.randint(0, 30),
            "alert_contribution": random.randint(0, 20),
            "updated_at": datetime.now(timezone.utc)
        })

        # Generate login logs for last 14 days
        for day in range(14):
            ts = datetime.now(timezone.utc) - timedelta(days=day, hours=random.randint(0, 12))
            pred = "suspicious" if random.random() < 0.2 else "normal"
            login_logs.append({
                "user_id": uid_str,
                "email": "",
                "ip_address": f"192.168.{random.randint(1,10)}.{random.randint(1,254)}",
                "role": "admin" if uid == user_ids[0] else "student",
                "risk_score": random.randint(5, 80),
                "risk_level": random.choice(["Low", "Medium", "High"]),
                "prediction": pred,
                "timestamp": ts,
                "status": "success"
            })

    # Random attack logs
    for _ in range(20):
        uid = random.choice(user_ids[1:])
        uid_str = str(uid)
        atype, aname, severity = random.choice(attack_types)
        ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
        logs.append({
            "user_id": uid_str,
            "attack_type": atype,
            "attack_name": aname,
            "description": f"Simulated {aname} detected",
            "severity": severity,
            "ip_address": ip,
            "risk_score": random.randint(50, 100),
            "risk_level": "High",
            "ml_prediction": "suspicious",
            "anomaly_score": round(random.uniform(0.4, 0.9), 4),
            "timestamp": datetime.now(timezone.utc) - timedelta(hours=random.randint(0, 72)),
            "status": "detected"
        })
        alerts.append({
            "user_id": uid_str,
            "type": "attack_detected",
            "attack_type": atype,
            "message": f"⚠️ {aname} detected from {ip}",
            "severity": severity,
            "ip_address": ip,
            "risk_score": random.randint(50, 100),
            "read": random.choice([True, False]),
            "created_at": datetime.now(timezone.utc) - timedelta(hours=random.randint(0, 48))
        })

    db.attack_logs.insert_many(logs)
    db.alerts.insert_many(alerts)
    db.risk_scores.insert_many(risk_scores)
    db.login_logs.insert_many(login_logs)
    print(f"[Seed] ✅ Attack logs, alerts, risk scores, login logs seeded.")

if __name__ == "__main__":
    clear_collections()
    ids = seed_users()
    seed_academic(ids)
    seed_attack_logs(ids)
    print("\n" + "=" * 50)
    print("✅ Database seeded successfully!")
    print("\n🔑 Login Credentials:")
    print("  Admin  → admin@aiportal.com    / Admin@123")
    print("  Student→ arjun@student.com     / Student@123")
    print("  Student→ priya@student.com     / Student@123")
    print("  Student→ rahul@student.com     / Student@123")
    print("  Student→ divya@student.com     / Student@123")
    print("  Student→ vikram@student.com    / Student@123")
    print("=" * 50)
