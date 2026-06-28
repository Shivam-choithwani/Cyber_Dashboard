# storage.py
import json
import logging
from datetime import datetime
from sqlalchemy import text
from db.db import SessionLocal
from consumers.shared.logger import setup_logger

logger = setup_logger("cyber.ddos.storage")

class DDoSAlertStorage:
    def save_alert(self, alert: dict):
        """Inserts a DDoS alert record into the PostgreSQL database."""
        db = SessionLocal()
        try:
            query = text("""
                INSERT INTO ddos_alerts (
                    source_ip, request_count, requests_per_second, 
                    severity, detected_at, description
                ) VALUES (
                    :source_ip, :request_count, :requests_per_second, 
                    :severity, :detected_at, :description
                )
            """)
            
            db.execute(query, {
                "source_ip": alert["source_ip"],
                "request_count": alert["request_count"],
                "requests_per_second": alert["requests_per_second"],
                "severity": alert["severity"],
                "detected_at": datetime.utcnow(),
                "description": alert["description"]
            })
            db.commit()
            logger.info(f"DDoS alert stored in DB for IP: {alert['source_ip']}")
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to save DDoS alert to Postgres: {e}")
        finally:
            db.close()
