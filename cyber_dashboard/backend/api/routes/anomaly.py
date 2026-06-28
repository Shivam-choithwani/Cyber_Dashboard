# anomaly.py
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import text
from db.db import get_db

router = APIRouter(prefix="/anomaly", tags=["Behavioral Anomaly"])

@router.get("/scores")
def get_anomaly_scores(limit: int = Query(default=100, le=500), db: Session = Depends(get_db)):
    """Fetches list of historical behavioral anomaly scores."""
    try:
        query = text("""
            SELECT id, key_type, key_value, score, is_anomaly, scored_at, details
            FROM anomaly_scores
            ORDER BY scored_at DESC
            LIMIT :limit
        """)
        rows = db.execute(query, {"limit": limit}).fetchall()
        
        scores = []
        for r in rows:
            scores.append({
                "id": r[0],
                "key_type": r[1],
                "key_value": r[2],
                "score": r[3],
                "is_anomaly": r[4],
                "scored_at": r[5].isoformat() if r[5] else "",
                "details": r[6]
            })
        return scores
    except Exception as e:
        return {"error": str(e)}
