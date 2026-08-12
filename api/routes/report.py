# ============================================================
# CyberGuard AI — api/routes/report.py
# GET /api/report/{alert_id} — generate PDF threat report
# ============================================================

import os
import sys
from datetime import datetime
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from bson import ObjectId

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config import REPORTS_DIR, BASE_DIR
from storage.db import get_db

router = APIRouter()

def generate_pdf_report(alert_data: dict) -> str:
    """Generate a PDF threat report and return the file path."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle, HRFlowable)
        from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    except ImportError:
        raise HTTPException(status_code=500, detail="reportlab not installed")

    os.makedirs(REPORTS_DIR, exist_ok=True)

    alert_id  = str(alert_data.get("_id", "unknown"))
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename  = f"cyberguard_report_{timestamp}.pdf"
    filepath  = os.path.join(REPORTS_DIR, filename)

    doc    = SimpleDocTemplate(filepath, pagesize=A4,
                               topMargin=15*mm, bottomMargin=15*mm,
                               leftMargin=20*mm, rightMargin=20*mm)
    styles = getSampleStyleSheet()
    story  = []

    # Colours
    DARK_BG   = colors.HexColor("#0d1117")
    TEAL      = colors.HexColor("#58a6ff")
    RED       = colors.HexColor("#f85149")
    ORANGE    = colors.HexColor("#d29922")
    GREEN     = colors.HexColor("#2ea043")
    GRAY      = colors.HexColor("#8b949e")

    # Custom styles
    title_style = ParagraphStyle("Title2", parent=styles["Title"],
                                 fontSize=22, textColor=TEAL,
                                 spaceAfter=4, alignment=TA_CENTER)
    sub_style   = ParagraphStyle("Sub", parent=styles["Normal"],
                                 fontSize=10, textColor=GRAY,
                                 alignment=TA_CENTER, spaceAfter=12)
    h2_style    = ParagraphStyle("H2", parent=styles["Heading2"],
                                 fontSize=13, textColor=TEAL, spaceAfter=4)
    body_style  = ParagraphStyle("Body", parent=styles["Normal"],
                                 fontSize=10, leading=14, spaceAfter=4)
    label_style = ParagraphStyle("Label", parent=styles["Normal"],
                                 fontSize=9, textColor=GRAY)

    # ── Header ────────────────────────────────────────────────
    story.append(Paragraph("CyberGuard AI", title_style))
    story.append(Paragraph("Threat Analysis Report — v2.0", sub_style))
    story.append(HRFlowable(width="100%", thickness=1, color=TEAL))
    story.append(Spacer(1, 8*mm))

    # ── Summary box ───────────────────────────────────────────
    verdict      = alert_data.get("verdict", "Unknown")
    risk_score   = alert_data.get("risk_score", 0)
    severity     = alert_data.get("severity", "Unknown")
    threat_cat   = alert_data.get("threat_category", "Unknown")
    ts           = alert_data.get("timestamp", datetime.utcnow().isoformat())
    if hasattr(ts, "isoformat"):
        ts = ts.isoformat()

    verdict_color = RED if verdict == "Phishing" else (ORANGE if verdict == "Suspicious" else GREEN)

    summary_data = [
        ["Field", "Value"],
        ["Verdict",          verdict],
        ["Risk Score",       f"{risk_score}/100"],
        ["Severity",         severity],
        ["Threat Category",  threat_cat],
        ["Language",         alert_data.get("language", "en").upper()],
        ["Analysis Time",    ts[:19].replace("T", " ")],
        ["Alert ID",         alert_id[:24]],
    ]
    summary_table = Table(summary_data, colWidths=[55*mm, 115*mm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0),  TEAL),
        ("TEXTCOLOR",   (0, 0), (-1, 0),  colors.white),
        ("FONTSIZE",    (0, 0), (-1, 0),  10),
        ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("BACKGROUND",  (0, 1), (-1, -1), colors.HexColor("#161b22")),
        ("TEXTCOLOR",   (0, 1), (0, -1),  GRAY),
        ("TEXTCOLOR",   (1, 1), (1, 1),   verdict_color),
        ("TEXTCOLOR",   (1, 2), (1, -1),  colors.HexColor("#e6edf3")),
        ("FONTNAME",    (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",    (0, 1), (-1, -1), 10),
        ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#30363d")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.HexColor("#161b22"), colors.HexColor("#21262d")]),
        ("TOPPADDING",  (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 8*mm))

    # ── Why flagged ───────────────────────────────────────────
    reasons = alert_data.get("reasons", [])
    if reasons:
        story.append(Paragraph("Why This Was Flagged", h2_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=GRAY))
        story.append(Spacer(1, 3*mm))
        for i, reason in enumerate(reasons, 1):
            story.append(Paragraph(f"{i}. {reason}", body_style))
        story.append(Spacer(1, 6*mm))

    # ── Score breakdown ───────────────────────────────────────
    breakdown = alert_data.get("score_breakdown", {})
    if breakdown:
        story.append(Paragraph("Risk Score Breakdown", h2_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=GRAY))
        story.append(Spacer(1, 3*mm))
        bd_data = [["Signal", "Score"]]
        labels  = {
            "ai_model":      "AI Model (MuRIL)",
            "ner_signals":   "NER Content Signals",
            "sender":        "Sender Domain",
            "subject":       "Subject Analysis",
            "urls":          "URL Analysis",
            "brand_spoof":   "Brand Spoof Detection",
            "threat_intel":  "Threat Intelligence APIs",
            "severity_bonus":"Threat Severity Bonus",
        }
        for key, label in labels.items():
            if key in breakdown:
                bd_data.append([label, str(breakdown[key])])
        bd_data.append(["TOTAL RAW SCORE", str(breakdown.get("total_raw", 0))])
        bd_data.append(["FINAL SCORE (normalised)", f"{risk_score}/100"])

        bd_table = Table(bd_data, colWidths=[120*mm, 50*mm])
        bd_table.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0),  TEAL),
            ("TEXTCOLOR",   (0, 0), (-1, 0),  colors.white),
            ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, 0),  10),
            ("BACKGROUND",  (0, -2), (-1, -1), colors.HexColor("#1f6feb")),
            ("TEXTCOLOR",   (0, -2), (-1, -1), colors.white),
            ("FONTNAME",    (0, -2), (-1, -1), "Helvetica-Bold"),
            ("BACKGROUND",  (0, 1), (-1, -3), colors.HexColor("#161b22")),
            ("TEXTCOLOR",   (0, 1), (-1, -3), colors.HexColor("#e6edf3")),
            ("FONTNAME",    (0, 1), (-1, -3), "Helvetica"),
            ("FONTSIZE",    (0, 1), (-1, -1), 10),
            ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#30363d")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -3),
             [colors.HexColor("#161b22"), colors.HexColor("#21262d")]),
            ("TOPPADDING",  (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("ALIGN",       (1, 0), (1, -1), "CENTER"),
        ]))
        story.append(bd_table)
        story.append(Spacer(1, 6*mm))

    # ── Detected signals ──────────────────────────────────────
    story.append(Paragraph("Detected Signals", h2_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=GRAY))
    story.append(Spacer(1, 3*mm))

    urgency_words = alert_data.get("urgency_words", [])
    if urgency_words:
        story.append(Paragraph(
            f"Urgency words: {', '.join(urgency_words[:10])}", body_style))

    suspicious_urls = alert_data.get("suspicious_urls", [])
    if suspicious_urls:
        story.append(Paragraph(
            f"Suspicious URLs: {', '.join(suspicious_urls[:5])}", body_style))

    orgs = alert_data.get("orgs", [])
    if orgs:
        story.append(Paragraph(
            f"Organisations mentioned: {', '.join(orgs[:10])}", body_style))

    brand_details = alert_data.get("brand_details", [])
    if brand_details:
        for detail in brand_details[:3]:
            story.append(Paragraph(f"Brand spoof: {detail}", body_style))

    story.append(Spacer(1, 6*mm))

    # ── Email content ─────────────────────────────────────────
    email_text = alert_data.get("email_text", "")
    if email_text:
        story.append(Paragraph("Email Content (first 500 chars)", h2_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=GRAY))
        story.append(Spacer(1, 3*mm))
        preview = email_text[:500].replace("<", "&lt;").replace(">", "&gt;")
        content_style = ParagraphStyle(
            "Content", parent=styles["Normal"],
            fontSize=9, leading=13,
            backColor=colors.HexColor("#161b22"),
            textColor=colors.HexColor("#8b949e"),
            borderPadding=8,
        )
        story.append(Paragraph(preview + ("..." if len(email_text) > 500 else ""), content_style))
        story.append(Spacer(1, 6*mm))

    # ── Recommendations ───────────────────────────────────────
    story.append(Paragraph("Recommended Actions", h2_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=GRAY))
    story.append(Spacer(1, 3*mm))

    if verdict == "Phishing":
        actions = [
            "Do NOT click any links or download attachments from this email.",
            "Do NOT provide any personal information, OTP, or bank details.",
            "Report this email to your IT security team immediately.",
            "Delete the email from your inbox and sent items.",
            "If you already clicked a link, change your passwords immediately.",
            "Contact your bank directly using official numbers if banking fraud.",
            "Report to CERT-In at incident@cert-in.org.in",
        ]
    elif verdict == "Suspicious":
        actions = [
            "Treat this email with caution — do not click links yet.",
            "Verify the sender by calling the official number of the organisation.",
            "Do not provide sensitive information until identity is confirmed.",
            "Forward to IT security team for further investigation.",
        ]
    else:
        actions = [
            "Email appears safe based on current analysis.",
            "Always stay cautious — verify sender if in doubt.",
            "Do not share OTPs or passwords with anyone.",
        ]

    for i, action in enumerate(actions, 1):
        story.append(Paragraph(f"{i}. {action}", body_style))

    story.append(Spacer(1, 8*mm))

    # ── Footer ────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=1, color=TEAL))
    story.append(Spacer(1, 3*mm))
    footer_style = ParagraphStyle("Footer", parent=styles["Normal"],
                                  fontSize=8, textColor=GRAY,
                                  alignment=TA_CENTER)
    story.append(Paragraph(
        f"Generated by CyberGuard AI v2.0 | {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC | "
        f"REVA University — M.Tech Cybersecurity Capstone Project",
        footer_style
    ))

    doc.build(story)
    return filepath


@router.get("/report/{alert_id}")
def download_report(alert_id: str):
    """Generate and download a PDF threat report for a phishing alert."""
    try:
        db    = get_db()
        alert = db["phishing_alerts"].find_one({"_id": ObjectId(alert_id)})
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        alert["_id"] = str(alert["_id"])
        filepath = generate_pdf_report(alert)
        return FileResponse(
            filepath,
            media_type="application/pdf",
            filename=f"cyberguard_report_{alert_id[:8]}.pdf",
            headers={"Content-Disposition": f"attachment; filename=cyberguard_report_{alert_id[:8]}.pdf"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))