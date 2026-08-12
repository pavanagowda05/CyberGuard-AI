from storage.db import save_phishing_alert, get_phishing_alerts

fake_alert = {
    "email_text": "Test email for field-persistence check",
    "verdict": "Phishing",
    "risk_score": 75,
    "severity": "High",
    "threat_category": "Banking Fraud",
    "reasons": ["AI model detected phishing patterns", "Brand impersonation detected"],
    "sender_flags": ["Sender uses free email provider"],
    "brand_spoofed": True,
    "spoofed_brand": "Bank of Baroda",
    "confidence": 0.99,
    "prob_phishing": 0.99,
    "prob_safe": 0.01,
    "language": "en",
}

alert_id = save_phishing_alert(fake_alert)
print("Saved with ID:", alert_id)

alerts = get_phishing_alerts(limit=1)
print(alerts[0])