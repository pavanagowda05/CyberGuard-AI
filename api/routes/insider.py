import os, sys
from fastapi import APIRouter

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from storage.db import get_insider_alerts, get_insider_stats

router = APIRouter()

@router.get("/insider/alerts")
def insider_alerts(limit: int = 50, min_risk: int = 0):
    return get_insider_alerts(limit=limit, min_risk=min_risk)

@router.get("/insider/stats")
def insider_stats():
    return get_insider_stats()