# ============================================================
# CyberGuard AI — storage/db.py
# MongoDB connection and all database operations.
# ============================================================

import os
import sys
from datetime import datetime
from pymongo import MongoClient, DESCENDING
from pymongo.errors import ConnectionFailure

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    MONGO_URI, MONGO_DB,
    COL_PHISHING, COL_INSIDER, COL_SIMULATIONS
)

_client = None
_db     = None

def get_db():
    global _client, _db
    if _db is not None:
        return _db
    _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    _db     = _client[MONGO_DB]
    print(f"[DB] Connected to MongoDB — database: {MONGO_DB}")
    return _db

def check_connection() -> bool:
    try:
        get_db().command("ping")
        return True
    except ConnectionFailure:
        return False

# ── Phishing ─────────────────────────────────────────────────
def save_phishing_alert(data: dict) -> str:
    db  = get_db()
    doc = {
        "email_text":      data.get("email_text", "")[:500],
        "subject":         data.get("subject", ""),
        "sender_email":    data.get("sender_email", ""),
        "sender_domain":   data.get("sender_domain", ""),
        "source":          data.get("source", "text"),
        "verdict":         data.get("verdict"),
        "risk_score":      data.get("risk_score"),
        "severity":        data.get("severity"),
        "threat_category": data.get("threat_category"),
        "reasons":         data.get("reasons", []),
        "score_breakdown": data.get("score_breakdown", {}),
        "confidence":      data.get("confidence"),
        "prob_phishing":   data.get("prob_phishing"),
        "prob_safe":       data.get("prob_safe"),
        "urls":            data.get("urls", []),
        "suspicious_urls": data.get("suspicious_urls", []),
        "urgency_words":   data.get("urgency_words", []),
        "orgs":            data.get("orgs", []),
        "sender_flags":    data.get("sender_flags", []),
        "subject_flags":   data.get("subject_flags", []),
        "url_flags":       data.get("url_flags", []),
        "brand_spoofed":   data.get("brand_spoofed", False),
        "spoofed_brand":   data.get("spoofed_brand"),
        "brand_details":   data.get("brand_details", []),
        "multilingual_keywords": data.get("multilingual_keywords", []),
        "intel_flagged":   data.get("intel_flagged", False),
        "intel_sources":   data.get("intel_sources", []),
        "language":        data.get("language", "en"),
        "timestamp":       datetime.utcnow(),
    }
    result = db[COL_PHISHING].insert_one(doc)
    return str(result.inserted_id)

def get_phishing_alerts(limit: int = 50) -> list:
    db     = get_db()
    cursor = db[COL_PHISHING].find(
        {},
        {"_id": 1, "verdict": 1, "risk_score": 1, "severity": 1,
         "threat_category": 1, "spoofed_brand": 1,
         "confidence": 1, "urgency_words": 1, "suspicious_urls": 1,
         "language": 1, "timestamp": 1, "email_text": 1}
    ).sort("timestamp", DESCENDING).limit(limit)
    
    alerts = []
    for doc in cursor:
        doc["_id"]       = str(doc["_id"])
        doc["timestamp"] = doc["timestamp"].isoformat()
        alerts.append(doc)
    return alerts

def get_phishing_stats() -> dict:
    db    = get_db()
    total = db[COL_PHISHING].count_documents({})
    phish = db[COL_PHISHING].count_documents({"verdict": "Phishing"})
    safe  = db[COL_PHISHING].count_documents({"verdict": "Safe"})
    return {
        "total_analyzed": total,
        "phishing_count": phish,
        "safe_count":     safe,
        "detection_rate": round(phish / total * 100, 1) if total > 0 else 0,
    }

# ── Insider ───────────────────────────────────────────────────
def save_insider_alert(data: dict) -> str:
    db  = get_db()
    doc = {
        "user":          data.get("user"),
        "day":           str(data.get("day", "")),
        "risk_score":    data.get("risk_score"),
        "severity":      data.get("severity"),
        "is_anomaly":    data.get("is_anomaly", False),
        "reason":        data.get("reason", ""),
        "anomaly_score": data.get("anomaly_score"),
        "features":      data.get("features", {}),
        "source":        data.get("source", "cert"),
        "timestamp":     datetime.utcnow(),
    }
    result = db[COL_INSIDER].insert_one(doc)
    return str(result.inserted_id)

def get_insider_alerts(limit: int = 50, min_risk: int = 0) -> list:
    db     = get_db()
    cursor = db[COL_INSIDER].find(
        {"risk_score": {"$gte": min_risk}},
        {"_id": 1, "user": 1, "day": 1, "risk_score": 1,
         "severity": 1, "is_anomaly": 1, "reason": 1,
         "features": 1, "source": 1, "timestamp": 1}
    ).sort("risk_score", DESCENDING).limit(limit)
    alerts = []
    for doc in cursor:
        doc["_id"]       = str(doc["_id"])
        doc["timestamp"] = doc["timestamp"].isoformat()
        alerts.append(doc)
    return alerts

def get_insider_stats() -> dict:
    db       = get_db()
    total    = db[COL_INSIDER].count_documents({})
    critical = db[COL_INSIDER].count_documents({"severity": "Critical"})
    high     = db[COL_INSIDER].count_documents({"severity": "High"})
    return {
        "total_alerts":      total,
        "critical_count":    critical,
        "high_count":        high,
        "employees_flagged": len(db[COL_INSIDER].distinct("user")),
    }

# ── Simulation ────────────────────────────────────────────────
def save_simulation_event(data: dict) -> str:
    db     = get_db()
    doc    = {**data, "timestamp": datetime.utcnow(), "source": "simulation"}
    result = db[COL_SIMULATIONS].insert_one(doc)
    return str(result.inserted_id)

def get_recent_simulations(limit: int = 10) -> list:
    db     = get_db()
    cursor = db[COL_SIMULATIONS].find().sort("timestamp", DESCENDING).limit(limit)
    results = []
    for doc in cursor:
        doc["_id"]       = str(doc["_id"])
        doc["timestamp"] = doc["timestamp"].isoformat()
        results.append(doc)
    return results

# ── Dashboard summary ─────────────────────────────────────────
def get_dashboard_summary() -> dict:
    p = get_phishing_stats()
    i = get_insider_stats()
    return {
        "phishing": p,
        "insider":  i,
        "combined": {
            "total_threats": p["phishing_count"] + i["critical_count"] + i["high_count"]
        },
    }

# ── Quick test ────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("CyberGuard AI — Database Test")
    print("=" * 60)
    if not check_connection():
        print("ERROR: Cannot connect to MongoDB.")
        sys.exit(1)
    print("MongoDB connected!")

    pid = save_phishing_alert({
        "email_text": "Your account is suspended. Click here.",
        "verdict": "Phishing", "risk_score": 92, "severity": "Critical",
        "confidence": 0.99, "prob_phishing": 0.99, "prob_safe": 0.01,
        "urls": ["http://fake.com"], "suspicious_urls": ["http://fake.com"],
        "urgency_words": ["suspended"], "orgs": ["SBI"], "language": "en",
    })
    print(f"Saved phishing alert: {pid}")

    iid = save_insider_alert({
        "user": "TEST001", "day": "2026-07-01",
        "risk_score": 85, "severity": "Critical",
        "is_anomaly": True, "reason": "Login at 2am | 847 files",
        "anomaly_score": -0.15, "features": {"login_hour_avg": 2.0},
        "source": "cert",
    })
    print(f"Saved insider alert : {iid}")

    summary = get_dashboard_summary()
    print(f"\nDashboard summary: {summary}")
    print("\nDatabase layer working correctly!")
    print("Next: api/main.py")