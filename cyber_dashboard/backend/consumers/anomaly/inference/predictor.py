# predictor.py
import numpy as np
from consumers.anomaly.inference.model_loader import AnomalyModelLoader
from consumers.shared.config import DEFAULT_Z_SCORE_THRESHOLD
from consumers.shared.logger import setup_logger

logger = setup_logger("cyber.anomaly.predictor")

class AnomalyPredictor:
    def __init__(self):
        self.loader = AnomalyModelLoader()
        
    def predict(self, feature_vector: list[float]) -> tuple[float, bool, str]:
        """
        Runs anomaly inference.
        Returns:
            score (float between 0 and 1)
            is_anomaly (bool)
            reason (str)
        """
        model = self.loader.load_model()
        
        # Features map: [latency_avg, latency_std, error_rate, path_variety]
        latency_avg, latency_std, error_rate, path_variety = feature_vector
        
        if model is not None:
            try:
                # Features shape: (1, 4)
                X = np.array([feature_vector])
                
                # Isolation Forest prediction: 1 = normal, -1 = anomaly
                pred = model.predict(X)[0]
                
                # Decision function returns a score (lower means more abnormal)
                decision_score = model.decision_function(X)[0]
                
                # Map decision function score to a 0-1 scale where 1 is highly anomalous.
                # Standard threshold for decision_score is < 0 for anomalies.
                anomaly_score = float(1.0 / (1.0 + np.exp(decision_score * 5.0)))
                is_anomaly = (pred == -1)
                
                reason = "ML Isolation Forest flagged behavior as statistical outlier."
                return anomaly_score, is_anomaly, reason
                
            except Exception as e:
                logger.error(f"ML inference failed: {e}. Defaulting to rule fallback.")
                
        # --- Fallback Heuristic Rules Mode ---
        is_anomaly = False
        reasons = []
        scores = []
        
        # 1. Latency Anomaly: check if window average latency is excessive (> 800ms)
        if latency_avg > 800:
            is_anomaly = True
            reasons.append(f"High latency spike: average is {latency_avg}ms")
            scores.append(min(0.95, 0.5 + (latency_avg - 800) / 2000))
            
        # 2. Error Rate Anomaly: check if window error rate is high (> 40% failures)
        if error_rate > 0.4:
            is_anomaly = True
            reasons.append(f"High HTTP error rate: {int(error_rate * 100)}% failures in window")
            scores.append(0.8)
            
        # 3. Path variety / scanner trace: check if path variety is extremely high
        # (meaning 10 requests hit 10 different endpoints in 10 requests - scan fingerprint)
        if path_variety >= 0.9 and error_rate > 0.2:
            is_anomaly = True
            reasons.append("High path fuzzing variety detected with errors")
            scores.append(0.85)

        if is_anomaly:
            final_score = max(scores)
            final_reason = "; ".join(reasons)
        else:
            final_score = 0.15
            final_reason = "Normal behavioral baseline."
            
        return final_score, is_anomaly, final_reason
