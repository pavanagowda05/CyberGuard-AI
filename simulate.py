# ============================================================
# CyberGuard AI — simulate.py
# Run this in a second terminal during your demo to inject
# a fake suspicious employee event and trigger a live alert.
# ============================================================

import requests

url = "http://127.0.0.1:8000/api/simulate-event"

event = {
    "employee_id":        "EMP_DEMO_042",
    "employee_name":      "Ravi Kumar",
    "department":         "Finance",
    "login_time":         "02:14:33",
    "files_accessed":     847,
    "usb_connected":      True,
    "emails_to_external": 22,
    "emails_sent":        25,
}

print("=" * 50)
print("CyberGuard AI — Demo Simulation")
print("=" * 50)
print(f"Injecting suspicious event for: {event['employee_name']}")
print(f"Department : {event['department']}")
print(f"Login time : {event['login_time']} (2am — suspicious)")
print(f"Files      : {event['files_accessed']} (40x above normal)")
print(f"USB        : {event['usb_connected']}")
print(f"Ext emails : {event['emails_to_external']}")
print("\nSending to CyberGuard AI...")

response = requests.post(url, json=event)

if response.status_code == 200:
    result = response.json()
    print("\nALERT TRIGGERED!")
    print(f"Risk score : {result['risk_score']}/100")
    print(f"Severity   : {result['severity']}")
    print(f"Is anomaly : {result['is_anomaly']}")
    print(f"Reason     : {result['reason']}")
    print("\nCheck your dashboard — alert should appear in the")
    print("Insider Threat tab live simulation feed.")
else:
    print(f"Error: {response.status_code} — {response.text}")