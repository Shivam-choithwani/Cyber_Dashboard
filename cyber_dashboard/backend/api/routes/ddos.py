# ddos.py
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import text
from db.db import get_db

router = APIRouter(prefix="/ddos", tags=["DDoS"])

@router.get("/alerts")
def get_ddos_alerts(limit: int = Query(default=100, le=500), db: Session = Depends(get_db)):
    """Fetches list of historical DDoS and scanning alerts."""
    try:
        query = text("""
            SELECT id, source_ip, request_count, requests_per_second, severity, detected_at, description
            FROM ddos_alerts
            ORDER BY detected_at DESC
            LIMIT :limit
        """)
        rows = db.execute(query, {"limit": limit}).fetchall()
        
        alerts = []
        for r in rows:
            alerts.append({
                "id": r[0],
                "source_ip": r[1],
                "request_count": r[2],
                "requests_per_second": r[3],
                "severity": r[4],
                "detected_at": r[5].isoformat() if r[5] else "",
                "description": r[6]
            })
        return alerts
    except Exception as e:
        return {"error": str(e)}
