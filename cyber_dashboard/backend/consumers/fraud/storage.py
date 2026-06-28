# storage.py
import json
from datetime import datetime
from sqlalchemy import text
from db.db import SessionLocal
from consumers.shared.logger import setup_logger

logger = setup_logger("cyber.fraud.storage")

class FraudStorage:
    def save_feature_vector(self, customer_id: str, feature_vector: list[float]):
        """Saves features to fraud_feature_windows for future training."""
        db = SessionLocal()
        try:
            query = text("""
                INSERT INTO fraud_feature_windows (
                    customer_id, feature_vector, window_end_ts
                ) VALUES (
                    :customer_id, :feature_vector, :window_end_ts
                )
            """)
            db.execute(query, {
                "customer_id": customer_id,
                "feature_vector": json.dumps(feature_vector),
                "window_end_ts": datetime.utcnow()
            })
            db.commit()
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to save fraud feature window: {e}")
        finally:
            db.close()

    def save_fraud_score(self, customer_id: str, score: float, is_fraud: bool, reason: str):
        """Saves score to the fraud_scores table."""
        db = SessionLocal()
        try:
            query = text("""
                INSERT INTO fraud_scores (
                    customer_id, score, is_fraud, scored_at, details
                ) VALUES (
                    :customer_id, :score, :is_fraud, :scored_at, :details
                )
            """)
            db.execute(query, {
                "customer_id": customer_id,
                "score": score,
                "is_fraud": is_fraud,
                "scored_at": datetime.utcnow(),
                "details": reason
            })
            db.commit()
            logger.info(f"Saved fraud score in DB for user: {customer_id}")
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to save fraud score: {e}")
        finally:
            db.close()
