import os, sys
import json
from fastapi import APIRouter, Request
from pydantic import BaseModel

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from ai.insider_detector import score_employee_day
from storage.db import save_insider_alert, save_simulation_event

router = APIRouter()

class SimulateEvent(BaseModel):
    employee_id: str
    employee_name: str
    department: str
    login_time: str
    files_accessed: int = 0
    usb_connected: bool = False
    emails_to_external: int = 0
    emails_sent: int = 0

@router.post("/simulate-event")
async def simulate_event(payload: SimulateEvent, request: Request):
    try:
        login_hour = float(payload.login_time.split(":")[0])
    except Exception:
        login_hour = 9.0
    features = {
        "login_hour_avg":  login_hour,
        "login_hour_min":  login_hour,
        "num_logons":      1,
        "files_accessed":  float(payload.files_accessed),
        "emails_sent":     float(payload.emails_sent),
        "emails_external": float(payload.emails_to_external),
        "avg_email_size":  30000.0,
        "usb_connects":    1.0 if payload.usb_connected else 0.0,
    }
    result = score_employee_day(payload.employee_id, features)
    alert_data = {
        "user": payload.employee_id, "day": "simulation",
        "risk_score": result["risk_score"], "severity": result["severity"],
        "is_anomaly": result["is_anomaly"], "reason": result["reason"],
        "anomaly_score": result["anomaly_score"], "features": features,
        "source": "simulation", "employee_name": payload.employee_name,
        "department": payload.department,
    }
    save_insider_alert(alert_data)
    save_simulation_event(alert_data)

    # Broadcast to dashboard via WebSocket — now runs BEFORE return,
    # and is properly awaited since the route is now async
    try:
        await request.app.state.manager.broadcast(json.dumps({
            **result,
            "employee_name": payload.employee_name,
            "department":    payload.department,
            "reason":        result["reason"],
        }))
    except Exception:
        pass

    return {**result, "employee_name": payload.employee_name,
            "department": payload.department, "features": features}