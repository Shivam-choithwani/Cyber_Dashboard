# storage.py
import json
from datetime import datetime
from sqlalchemy import text
from db.db import SessionLocal
from consumers.shared.logger import setup_logger

logger = setup_logger("cyber.anomaly.storage")

class AnomalyStorage:
    def save_feature_vector(self, key_type: str, key_value: str, feature_vector: list[float]):
        """Saves feature vector into anomaly_feature_windows for future training."""
        db = SessionLocal()
        try:
            query = text("""
                INSERT INTO anomaly_feature_windows (
                    key_type, key_value, feature_vector, window_end_ts
                ) VALUES (
                    :key_type, :key_value, :feature_vector, :window_end_ts
                )
            """)
            db.execute(query, {
                "key_type": key_type,
                "key_value": key_value,
                "feature_vector": json.dumps(feature_vector),
                "window_end_ts": datetime.utcnow()
            })
            db.commit()
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to save anomaly feature window to Postgres: {e}")
        finally:
            db.close()

    def save_anomaly_score(self, key_type: str, key_value: str, score: float, is_anomaly: bool, reason: str):
        """Saves score to the anomaly_scores table."""
        db = SessionLocal()
        try:
            query = text("""
                INSERT INTO anomaly_scores (
                    key_type, key_value, score, is_anomaly, scored_at, details
                ) VALUES (
                    :key_type, :key_value, :score, :is_anomaly, :scored_at, :details
                )
            """)
            db.execute(query, {
                "key_type": key_type,
                "key_value": key_value,
                "score": score,
                "is_anomaly": is_anomaly,
                "scored_at": datetime.utcnow(),
                "details": reason
            })
            db.commit()
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to save anomaly score: {e}")
        finally:
            db.close()
