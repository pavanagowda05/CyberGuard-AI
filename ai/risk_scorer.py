# ============================================================
# CyberGuard AI — ai/risk_scorer.py
# Combines phishing classifier output + NER signals
# into a final risk score 0-100 with severity label.
# ============================================================

import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    PHISHING_RISK_CRITICAL, PHISHING_RISK_HIGH, PHISHING_RISK_MEDIUM,
    INSIDER_RISK_CRITICAL, INSIDER_RISK_HIGH, INSIDER_RISK_MEDIUM,
)


def get_severity_label(score: int, thresholds: dict) -> str:
    if score >= thresholds["critical"]:
        return "Critical"
    elif score >= thresholds["high"]:
        return "High"
    elif score >= thresholds["medium"]:
        return "Medium"
    return "Low"


def score_phishing(classifier_result: dict, ner_result: dict) -> dict:
    """
    Combine classifier probability + NER signals into a final
    phishing risk score.

    Scoring breakdown:
      - Base score from model probability (0-80 points)
      - Suspicious URL found          (+10 points)
      - Each urgency word             (+2 points, max +10)
      - IP address in email           (+5 points)
    """
    base   = int(classifier_result["prob_phishing"] * 80)
    bonus  = 0

    if ner_result.get("has_suspicious_url"):
        bonus += 10
    bonus += min(ner_result.get("urgency_count", 0) * 2, 10)
    if len(ner_result.get("ips", [])) > 0:
        bonus += 5

    final_score = min(base + bonus, 100)

    thresholds = {
        "critical": PHISHING_RISK_CRITICAL,
        "high":     PHISHING_RISK_HIGH,
        "medium":   PHISHING_RISK_MEDIUM,
    }

    return {
        "risk_score":    final_score,
        "severity":      get_severity_label(final_score, thresholds),
        "base_score":    base,
        "bonus_score":   bonus,
        "verdict":       classifier_result["verdict"],
        "confidence":    classifier_result["confidence"],
        "prob_phishing": classifier_result["prob_phishing"],
        "prob_safe":     classifier_result["prob_safe"],
    }


def score_insider(anomaly_score: float, features: dict) -> dict:
    """
    Convert Isolation Forest anomaly score to a 0-100 risk score.

    Isolation Forest returns values roughly in [-0.5, 0.5].
    Negative = more anomalous. We convert to 0-100 where:
      100 = most anomalous (Critical threat)
        0 = completely normal

    Extra signals that boost the score:
      - Login between midnight and 5am   (+15)
      - Files accessed > 200             (+10)
      - USB connected                    (+10)
      - External emails > 20             (+5)
    """
    # Convert raw score: more negative = higher risk
    base = int(max(0, min(100, (0.3 - anomaly_score) * 150)))

    bonus = 0
    login_hour = features.get("login_hour_avg", 9)
    if login_hour < 5 or login_hour > 22:
        bonus += 15
    if features.get("files_accessed", 0) > 200:
        bonus += 10
    if features.get("usb_connects", 0) > 0:
        bonus += 10
    if features.get("emails_external", 0) > 20:
        bonus += 5

    final_score = min(base + bonus, 100)

    thresholds = {
        "critical": INSIDER_RISK_CRITICAL,
        "high":     INSIDER_RISK_HIGH,
        "medium":   INSIDER_RISK_MEDIUM,
    }

    # Build human-readable reason
    reasons = []
    if login_hour < 5 or login_hour > 22:
        reasons.append(f"Login at {login_hour:.0f}:00 — outside normal hours")
    if features.get("files_accessed", 0) > 200:
        reasons.append(f"{int(features['files_accessed'])} files accessed — unusually high")
    if features.get("usb_connects", 0) > 0:
        reasons.append(f"USB device connected {int(features['usb_connects'])} time(s)")
    if features.get("emails_external", 0) > 20:
        reasons.append(f"{int(features['emails_external'])} external emails — unusually high")
    if not reasons:
        reasons.append("Behaviour within normal range")

    return {
        "risk_score":  final_score,
        "severity":    get_severity_label(final_score, thresholds),
        "base_score":  base,
        "bonus_score": bonus,
        "reason":      " | ".join(reasons),
    }


# ── Quick test ────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("CyberGuard AI — Risk Scorer Test")
    print("=" * 60)

    # Phishing score test
    classifier_result = {
        "verdict": "Phishing", "confidence": 0.96,
        "prob_phishing": 0.96, "prob_safe": 0.04
    }
    ner_result = {
        "has_suspicious_url": True, "urgency_count": 3,
        "ips": [], "suspicious_urls": ["http://fake-sbi.com"]
    }
    ph = score_phishing(classifier_result, ner_result)
    print(f"\nPhishing risk score : {ph['risk_score']}/100 — {ph['severity']}")
    print(f"  Base: {ph['base_score']}  Bonus: {ph['bonus_score']}")

    # Insider score test
    suspicious_features = {
        "login_hour_avg": 2.0, "files_accessed": 847,
        "emails_sent": 25, "emails_external": 22, "usb_connects": 1
    }
    ins = score_insider(-0.15, suspicious_features)
    print(f"\nInsider risk score  : {ins['risk_score']}/100 — {ins['severity']}")
    print(f"  Reason: {ins['reason']}")