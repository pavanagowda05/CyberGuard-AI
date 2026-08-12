# ============================================================
# CyberGuard AI — ai/insider_detector.py
# Loads the trained Isolation Forest model, scaler, and
# employee baselines. Scores any employee-day activity.
# ============================================================

import os
import sys
import pickle
import numpy as np

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    INSIDER_MODEL_PATH, INSIDER_SCALER_PATH,
    INSIDER_BASELINES_PATH,
)

FEATURE_COLS = [
    "login_hour_avg", "login_hour_min", "num_logons",
    "files_accessed", "emails_sent", "emails_external",
    "avg_email_size", "usb_connects",
]

# ── Singleton — load once ─────────────────────────────────────
_model     = None
_scaler    = None
_baselines = None


def _load_artifacts():
    global _model, _scaler, _baselines
    if _model is not None:
        return

    print("[InsiderDetector] Loading Isolation Forest model ...")
    with open(INSIDER_MODEL_PATH,    "rb") as f: _model     = pickle.load(f)
    with open(INSIDER_SCALER_PATH,   "rb") as f: _scaler    = pickle.load(f)
    with open(INSIDER_BASELINES_PATH,"rb") as f: _baselines = pickle.load(f)
    print(f"[InsiderDetector] Loaded — baselines for {len(_baselines)} employees")


def score_employee_day(user: str, features: dict) -> dict:
    """
    Score one employee-day activity record.

    Args:
        user:     employee ID string e.g. 'NGF0157'
        features: dict with keys matching FEATURE_COLS

    Returns:
        {
          "user":           str,
          "anomaly_score":  float (raw Isolation Forest score),
          "is_anomaly":     bool,
          "risk_score":     int (0-100),
          "severity":       str,
          "reason":         str,
          "vs_baseline":    dict comparing today vs personal average
        }
    """
    _load_artifacts()

    # Build feature vector in correct column order
    X = np.array([[features.get(col, 0.0) for col in FEATURE_COLS]])
    X_scaled = _scaler.transform(X)

    raw_score  = float(_model.decision_function(X_scaled)[0])
    prediction = int(_model.predict(X_scaled)[0])  # -1=anomaly, 1=normal
    is_anomaly = prediction == -1

    # Convert raw score to 0-100 risk
    risk_score = int(max(0, min(100, (0.3 - raw_score) * 150)))

    # Compare to personal baseline if available
    vs_baseline = {}
    if user in _baselines:
        baseline_mean = _baselines[user]["mean"]
        for col in FEATURE_COLS:
            today_val    = features.get(col, 0.0)
            baseline_val = baseline_mean.get(col, 0.0)
            if baseline_val > 0:
                ratio = today_val / baseline_val
                vs_baseline[col] = {
                    "today":    round(today_val, 2),
                    "baseline": round(baseline_val, 2),
                    "ratio":    round(ratio, 2),
                    "flagged":  ratio > 3.0,  # 3x above baseline = suspicious
                }

    # Build reason string from most suspicious signals
    reasons = []
    login_hour = features.get("login_hour_avg", 9)
    if login_hour < 5 or login_hour > 22:
        reasons.append(f"Login at {login_hour:.0f}:00 (outside normal hours)")
    if features.get("files_accessed", 0) > 200:
        reasons.append(f"{int(features['files_accessed'])} files accessed")
    if features.get("usb_connects", 0) > 0:
        reasons.append(f"USB connected {int(features['usb_connects'])} time(s)")
    if features.get("emails_external", 0) > 20:
        reasons.append(f"{int(features['emails_external'])} external emails sent")

    # Check vs baseline for unusual ratios
    for col, info in vs_baseline.items():
        if info["flagged"] and col not in ["login_hour_avg", "login_hour_min"]:
            reasons.append(
                f"{col}={info['today']} is {info['ratio']}x above personal average"
            )

    if not reasons:
        reasons.append("All activity within normal range")

    # Severity label
    if risk_score >= 80:   severity = "Critical"
    elif risk_score >= 60: severity = "High"
    elif risk_score >= 40: severity = "Medium"
    else:                  severity = "Low"

    return {
        "user":          user,
        "anomaly_score": round(raw_score, 4),
        "is_anomaly":    is_anomaly,
        "risk_score":    risk_score,
        "severity":      severity,
        "reason":        " | ".join(reasons),
        "vs_baseline":   vs_baseline,
    }


def get_all_high_risk_employees(df_today) -> list:
    """
    Score all employees for a given day's activity dataframe.
    Returns only those with risk_score >= 40 (Medium or above).

    Args:
        df_today: pandas DataFrame with columns matching FEATURE_COLS + 'user'

    Returns:
        list of result dicts, sorted by risk_score descending
    """
    _load_artifacts()
    results = []
    for _, row in df_today.iterrows():
        features = {col: row.get(col, 0.0) for col in FEATURE_COLS}
        result   = score_employee_day(row["user"], features)
        if result["risk_score"] >= 40:
            results.append(result)
    results.sort(key=lambda x: x["risk_score"], reverse=True)
    return results


# ── Quick test ────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("CyberGuard AI — Insider Detector Test")
    print("=" * 60)

    # Suspicious employee — logged in at 2am, downloaded 847 files
    suspicious = {
        "login_hour_avg": 2.0, "login_hour_min": 2.0,
        "num_logons": 3, "files_accessed": 847,
        "emails_sent": 25, "emails_external": 22,
        "avg_email_size": 45000, "usb_connects": 1,
    }
    r1 = score_employee_day("NGF0157", suspicious)
    print(f"\nSuspicious employee:")
    print(f"  Risk score : {r1['risk_score']}/100 — {r1['severity']}")
    print(f"  Is anomaly : {r1['is_anomaly']}")
    print(f"  Reason     : {r1['reason']}")

    # Normal employee — regular 9am login, few files
    normal = {
        "login_hour_avg": 9.0, "login_hour_min": 9.0,
        "num_logons": 1, "files_accessed": 15,
        "emails_sent": 12, "emails_external": 2,
        "avg_email_size": 28000, "usb_connects": 0,
    }
    r2 = score_employee_day("LRR0148", normal)
    print(f"\nNormal employee:")
    print(f"  Risk score : {r2['risk_score']}/100 — {r2['severity']}")
    print(f"  Is anomaly : {r2['is_anomaly']}")
    print(f"  Reason     : {r2['reason']}")