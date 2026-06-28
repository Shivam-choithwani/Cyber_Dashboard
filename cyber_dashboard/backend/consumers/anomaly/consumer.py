# consumer.py
import sys
import os
import time

# Ensure parent directory is on the path so we can import from shared/db/etc.
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from consumers.shared.kafka import SecurityTelemetryConsumer
from consumers.shared.logger import setup_logger
from consumers.shared.config import HTTP_LOGS_TOPIC
from consumers.anomaly.windows import SlidingWindowManager
from consumers.anomaly.preprocessing.features import AnomalyFeatureExtractor
from consumers.anomaly.inference.predictor import AnomalyPredictor
from consumers.anomaly.storage import AnomalyStorage

logger = setup_logger("cyber.anomaly.consumer")

class AnomalyDetectorApp:
    def __init__(self):
        self.window_mgr = SlidingWindowManager(max_size=10)
        self.extractor = AnomalyFeatureExtractor()
        self.predictor = AnomalyPredictor()
        self.storage = AnomalyStorage()

    def on_event_received(self, topic: str, data: dict):
        if topic != HTTP_LOGS_TOPIC:
            return
            
        try:
            ip = data.get("ip_address", "unknown")
            if ip == "unknown":
                return
                
            # 1. State: Add event to rolling window for this IP
            window = self.window_mgr.add_event(ip, data)
            
            # We want at least 3 events in the window to make sensible statistics (avg/std)
            if len(window) < 3:
                return
                
            # 2. Preprocess: Extract latency & frequency features
            features = self.extractor.extract_features(window)
            
            # 3. Inference: Perform anomaly scoring
            score, is_anomaly, reason = self.predictor.predict(features)
            
            # 4. Storage: Log training vector and save operational score
            self.storage.save_feature_vector("ip", ip, features)
            self.storage.save_anomaly_score("ip", ip, score, is_anomaly, reason)
            
            if is_anomaly:
                logger.warning(
                    f"🚨 [BEHAVIORAL ANOMALY] IP: {ip} - Score: {round(score, 3)} - Reason: {reason}"
                )
                
        except Exception as e:
            logger.error(f"Error in anomaly pipeline event handling: {e}")

    def run(self):
        logger.info("Initializing Behavioral Anomaly Detection pipeline consumer...")
        consumer = SecurityTelemetryConsumer(
            group_id="anomaly-detector-v1",
            topics=[HTTP_LOGS_TOPIC]
        )
        
        consumer.start(self.on_event_received)
        
        logger.info("Behavioral Anomaly Consumer is running. Press Ctrl+C to terminate.")
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            logger.info("Stopping Behavioral Anomaly Consumer...")
            consumer.stop()
            logger.info("Behavioral Anomaly Consumer stopped.")

if __name__ == "__main__":
    app = AnomalyDetectorApp()
    app.run()
