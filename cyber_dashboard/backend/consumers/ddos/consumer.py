# consumer.py
import sys
import os
import time

# Ensure parent directory is on the path so we can import from shared/db/etc.
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from consumers.shared.kafka import SecurityTelemetryConsumer
from consumers.shared.logger import setup_logger
from consumers.shared.config import HTTP_LOGS_TOPIC
from consumers.ddos.preprocessing.features import DDoSFeatureExtractor
from consumers.ddos.inference.predictor import DDoSAlertPredictor
from consumers.ddos.storage import DDoSAlertStorage

logger = setup_logger("cyber.ddos.consumer")

class DDoSDetectorApp:
    def __init__(self):
        self.extractor = DDoSFeatureExtractor()
        self.predictor = DDoSAlertPredictor()
        self.storage = DDoSAlertStorage()
        
    def on_event_received(self, topic: str, data: dict):
        # We only process http-logs
        if topic != HTTP_LOGS_TOPIC:
            return
            
        try:
            # 1. Preprocess: Extract volumetric rolling window parameters
            features = self.extractor.extract_features(data)
            
            # 2. Inference: Evaluate limits and triggers
            alert = self.predictor.evaluate(features)
            
            # 3. Storage: If triggered, write alert to PostgreSQL
            if alert:
                logger.warning(
                    f"🚨 [DDoS ALERT] IP: {alert['source_ip']} - {alert['description']} (Severity: {alert['severity']})"
                )
                self.storage.save_alert(alert)
        except Exception as e:
            logger.error(f"Error processing telemetry event: {e}")

    def run(self):
        logger.info("Initializing DDoS Detection pipeline consumer...")
        consumer = SecurityTelemetryConsumer(
            group_id="ddos-detector-v1",
            topics=[HTTP_LOGS_TOPIC]
        )
        
        # Start consumer loop in separate daemon thread
        consumer.start(self.on_event_received)
        
        logger.info("DDoS Detector Consumer is running. Press Ctrl+C to terminate.")
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            logger.info("Stopping DDoS Detector Consumer...")
            consumer.stop()
            logger.info("DDoS Detector Consumer stopped.")

if __name__ == "__main__":
    app = DDoSDetectorApp()
    app.run()
