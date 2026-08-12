import os, sys
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from config import BASE_DIR
from storage.db import get_dashboard_summary, get_phishing_alerts, get_insider_alerts

router = APIRouter()
templates = Jinja2Templates(
    directory=os.path.join(BASE_DIR, "dashboard", "templates")
)

@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    summary = get_dashboard_summary()
    phishing_alerts = get_phishing_alerts(limit=10)
    insider_alerts = get_insider_alerts(limit=10, min_risk=40)
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "summary": summary,
            "phishing_alerts": phishing_alerts,
            "insider_alerts": insider_alerts,
        }
    )

@router.get("/api/summary")
def api_summary():
    return get_dashboard_summary()