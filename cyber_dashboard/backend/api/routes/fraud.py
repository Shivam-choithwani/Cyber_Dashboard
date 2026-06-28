# fraud.py
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import text
from db.db import get_db

router = APIRouter(prefix="/fraud", tags=["Checkout Fraud"])

@router.get("/scores")
def get_fraud_scores(limit: int = Query(default=100, le=500), db: Session = Depends(get_db)):
    """Fetches list of historical checkout fraud audits."""
    try:
        query = text("""
            SELECT id, customer_id, score, is_fraud, scored_at, details
            FROM fraud_scores
            ORDER BY scored_at DESC
            LIMIT :limit
        """)
        rows = db.execute(query, {"limit": limit}).fetchall()
        
        scores = []
        for r in rows:
            scores.append({
                "id": r[0],
                "customer_id": r[1],
                "score": r[2],
                "is_fraud": r[3],
                "scored_at": r[4].isoformat() if r[4] else "",
                "details": r[5]
            })
        return scores
    except Exception as e:
        return {"error": str(e)}
