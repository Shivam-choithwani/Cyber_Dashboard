# consumer.py
import sys
import os
import time
from sqlalchemy import text

# Ensure parent directory is on the path so we can import from shared/db/etc.
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from consumers.shared.kafka import SecurityTelemetryConsumer
from consumers.shared.logger import setup_logger
from consumers.shared.config import HTTP_LOGS_TOPIC
from consumers.fraud.preprocessing.features import FraudFeatureExtractor
from consumers.fraud.inference.predictor import FraudPredictor
from consumers.fraud.storage import FraudStorage
from db.db import SessionLocal

logger = setup_logger("cyber.fraud.consumer")

class FraudDetectorApp:
    def __init__(self):
        self.extractor = FraudFeatureExtractor()
        self.predictor = FraudPredictor()
        self.storage = FraudStorage()

    def fetch_user_orders(self, user_id: str) -> list[dict]:
        """Fetches historical orders for the user from the PostgreSQL database."""
        db = SessionLocal()
        orders = []
        try:
            # Query the orders table in the e_commerce DB
            query = text("""
                SELECT created_at, total_price, payment_method 
                FROM orders 
                WHERE user_id = :user_id 
                ORDER BY created_at DESC 
                LIMIT 50
            """)
            rows = db.execute(query, {"user_id": user_id}).fetchall()
            for r in rows:
                orders.append({
                    "created_at": r[0],
                    "total_price": r[1],
                    "payment_method": r[2]
                })
        except Exception as e:
            logger.error(f"Failed to fetch order history for user {user_id}: {e}")
        finally:
            db.close()
        return orders

    def on_event_received(self, topic: str, data: dict):
        if topic != HTTP_LOGS_TOPIC:
            return
            
        path = data.get("path", "")
        method = data.get("method", "")
        status_code = int(data.get("status_code", 200) or 200)
        user_id = data.get("user_id")

        # Checkout event: POST /orders/ resulting in status 201 (Created)
        # We also inspect if path contains "orders" to be robust to trailing slashes
        is_checkout = ("orders" in path.lower() and method == "POST" and status_code == 201)
        
        if not is_checkout or not user_id:
            return

        logger.info(f"Interception: user '{user_id}' checkout transaction processed. Auditing for fraud...")
        
        try:
            # 1. Fetch historical orders from database (hot state lookup)
            orders = self.fetch_user_orders(user_id)
            
            if not orders:
                logger.warning(f"No database order records found for user {user_id}. Proceeding with default values.")
                current_order = {"total_price": data.get("response_time_ms", 0.0), "payment_method": "unknown"}
            else:
                # The first order in the DESC ordered list is the current order just placed
                current_order = orders[0]
                
            # 2. Preprocess: Extract order features
            features = self.extractor.extract_features(orders, current_order)
            
            # 3. Inference: Perform fraud analysis
            score, is_fraud, reason = self.predictor.predict(features)
            
            # 4. Storage: Save training feature logs and final risk alarms
            self.storage.save_feature_vector(user_id, features)
            self.storage.save_fraud_score(user_id, score, is_fraud, reason)
            
            if is_fraud:
                logger.warning(
                    f"🚨 [FRAUD ALERT] User: {user_id} - Risk Score: {round(score, 3)} - Reason: {reason}"
                )
                
        except Exception as e:
            logger.error(f"Error in fraud pipeline event handling: {e}")

    def run(self):
        logger.info("Initializing Checkout Fraud pipeline consumer...")
        consumer = SecurityTelemetryConsumer(
            group_id="fraud-detector-v1",
            topics=[HTTP_LOGS_TOPIC]
        )
        
        consumer.start(self.on_event_received)
        
        logger.info("Checkout Fraud Consumer is running. Press Ctrl+C to terminate.")
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            logger.info("Stopping Checkout Fraud Consumer...")
            consumer.stop()
            logger.info("Checkout Fraud Consumer stopped.")

if __name__ == "__main__":
    app = FraudDetectorApp()
    app.run()
