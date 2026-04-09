# ============================================================
# routes/reports.py — PDF Report Generation
# ============================================================
from flask import Blueprint, jsonify, send_file, request
from flask_jwt_extended import jwt_required, get_jwt, get_jwt_identity
from datetime import datetime, timezone
from io import BytesIO
from database import get_db
from bson import ObjectId

reports_bp = Blueprint("reports", __name__)

def require_admin():
    return get_jwt().get("role") == "admin"

def _make_pdf(title, sections):
    """Build a PDF using reportlab and return a BytesIO buffer."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.units import cm

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("Title", parent=styles["Title"],
                                  fontSize=20, textColor=colors.HexColor("#7c3aed"),
                                  spaceAfter=12)
    heading_style = ParagraphStyle("H2", parent=styles["Heading2"],
                                    fontSize=13, textColor=colors.HexColor("#4f46e5"),
                                    spaceBefore=14, spaceAfter=6)
    normal = styles["Normal"]

    story = []
    story.append(Paragraph(title, title_style))
    story.append(Paragraph(
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        normal
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#7c3aed")))
    story.append(Spacer(1, 12))

    for section_title, rows, col_names in sections:
        story.append(Paragraph(section_title, heading_style))
        if rows:
            table_data = [col_names] + rows
            t = Table(table_data, repeatRows=1)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4f46e5")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f5f3ff"), colors.white]),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(t)
        else:
            story.append(Paragraph("No records found.", normal))
        story.append(Spacer(1, 10))

    doc.build(story)
    buf.seek(0)
    return buf

# ── GET /api/reports/security ────────────────────────────────
@reports_bp.route("/security", methods=["GET"])
@jwt_required()
def security_report():
    db = get_db()
    if not require_admin():
        return jsonify({"error": "Forbidden"}), 403

    # Attack logs section
    attacks = list(db.attack_logs.find().sort("timestamp", -1).limit(100))
    attack_rows = [
        [
            a.get("attack_name", ""),
            a.get("severity", ""),
            a.get("ip_address", ""),
            str(a.get("risk_score", 0)),
            a.get("timestamp", "").strftime("%Y-%m-%d %H:%M") if hasattr(a.get("timestamp"), "strftime") else ""
        ]
        for a in attacks
    ]

    # Risk scores section
    scores = list(db.risk_scores.find().sort("risk_score", -1).limit(50))
    score_rows = [
        [s.get("user_id", ""), str(s.get("risk_score", 0)), s.get("risk_level", ""), s.get("prediction", "")]
        for s in scores
    ]

    # Login logs section
    logins = list(db.login_logs.find().sort("timestamp", -1).limit(50))
    login_rows = [
        [
            l.get("email", ""),
            l.get("ip_address", ""),
            l.get("risk_level", ""),
            l.get("status", ""),
            l.get("timestamp", "").strftime("%Y-%m-%d %H:%M") if hasattr(l.get("timestamp"), "strftime") else ""
        ]
        for l in logins
    ]

    sections = [
        ("Attack Logs", attack_rows, ["Attack Name", "Severity", "IP Address", "Risk Score", "Timestamp"]),
        ("Risk Scores", score_rows, ["User ID", "Risk Score", "Risk Level", "ML Prediction"]),
        ("Login Logs", login_rows, ["Email", "IP Address", "Risk Level", "Status", "Timestamp"]),
    ]

    buf = _make_pdf("AI Portal — Security Report 2026", sections)
    year = datetime.now(timezone.utc).year
    return send_file(buf, mimetype="application/pdf",
                     as_attachment=True,
                     download_name=f"Security_Report_{year}.pdf")

# ── GET /api/reports/student/<id> ────────────────────────────
@reports_bp.route("/student/<student_id>", methods=["GET"])
@jwt_required()
def student_report(student_id):
    db = get_db()
    claims = get_jwt()
    caller_id = get_jwt_identity()

    # Students can only download their own report; admins can download any
    if claims.get("role") != "admin" and caller_id != student_id:
        return jsonify({"error": "Forbidden"}), 403

    user = db.users.find_one({"_id": ObjectId(student_id)})
    if not user:
        return jsonify({"error": "Student not found"}), 404

    name = user.get("name", "Unknown")

    # === Trigger Data Exfiltration Attack Detection ===
    downloads = user.get("report_downloads", 0) + 1
    db.users.update_one({"_id": ObjectId(student_id)}, {"$set": {"report_downloads": downloads}})
    if downloads >= 3:
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        # 3. Active Prevention -> Lock Account
        db.users.update_one({"_id": ObjectId(student_id)}, {"$set": {"locked_until": datetime.now(timezone.utc) + timedelta(minutes=15)}})
        
        db.attack_logs.insert_one({
            "user_id": student_id, "ip_address": ip,
            "attack_type": "data_exfiltration", "attack_name": "Data Exfiltration",
            "description": f"Massive data pull detected ({downloads} downloads). Account Locked.",
            "ml_prediction": "suspicious", "risk_score": 95, "severity": "Critical",
            "timestamp": datetime.now(timezone.utc)
        })
        # 1. Update ML Prediction Visually
        db.risk_scores.update_one(
            {"user_id": student_id},
            {"$set": {"risk_score": 95, "risk_level": "High", "prediction": "suspicious"}},
            upsert=True
        )
        # 2. Trigger Alert Notification
        db.alerts.insert_one({
            "user_id": student_id, "type": "data_exfiltration",
            "message": f"🚨 Data exfiltration prevented. Account locked.",
            "severity": "Critical", "ip_address": ip, "read": False, "created_at": datetime.now(timezone.utc)
        })
        
        from app import socketio
        payload = {"attack_type": "data_exfiltration", "attack_name": "Data Exfiltration", "ip_address": ip, "risk_score": 95}
        socketio.emit("attack_detected", payload)
        socketio.emit(f"user_alert_{student_id}", payload)
        socketio.emit("system_event", {"type": "danger", "message": f"Data Exfil Prevented: {user.get('email')}", "ip_address": ip, "timestamp": datetime.now(timezone.utc).isoformat()})

    # Attendance
    attendance = list(db.attendance.find({"user_id": student_id}))
    att_rows = [[a["subject"], str(a["present"]), str(a["total"]),
                 f"{round(a['present']/a['total']*100,1)}%"] for a in attendance if a.get("total")]

    # Marks
    marks = list(db.marks.find({"user_id": student_id}))
    mark_rows = [[m["subject"], str(m.get("internal", 0)), str(m.get("external", 0)),
                  str(m.get("total", 0))] for m in marks]

    # Fees
    fee = db.fees.find_one({"user_id": student_id})
    fee_rows = [[str(fee.get("total_amount", 0)), str(fee.get("paid_amount", 0)),
                 str(fee.get("balance", 0)), fee.get("status", "")]] if fee else []

    # Risk
    risk = db.risk_scores.find_one({"user_id": student_id})
    risk_rows = [[str(risk.get("risk_score", 0)), risk.get("risk_level", ""), risk.get("prediction", "")]] if risk else []

    sections = [
        ("Attendance", att_rows, ["Subject", "Present", "Total", "Percentage"]),
        ("Internal Marks", mark_rows, ["Subject", "Internal", "External", "Total"]),
        ("Fees", fee_rows, ["Total Amount", "Paid", "Balance", "Status"]),
        ("Risk Score", risk_rows, ["Score", "Level", "ML Prediction"]),
    ]

    buf = _make_pdf(f"Student Report — {name}", sections)
    year = datetime.now(timezone.utc).year
    return send_file(buf, mimetype="application/pdf",
                     as_attachment=True,
                     download_name=f"Student_Report_{name.replace(' ','_')}_{year}.pdf")
