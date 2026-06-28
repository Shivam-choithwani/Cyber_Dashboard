# predictor.py
import numpy as np
from consumers.fraud.inference.model_loader import FraudModelLoader
from consumers.shared.logger import setup_logger

logger = setup_logger("cyber.fraud.predictor")

class FraudPredictor:
    def __init__(self):
        self.loader = FraudModelLoader()

    def predict(self, feature_vector: list[float]) -> tuple[float, bool, str]:
        """
        Runs fraud inference on checkouts.
        Returns:
            score (float 0 to 1)
            is_fraud (bool)
            reason (str)
        """
        model = self.loader.load_model()
        
        # Features map: [order_count_last_hour, current_order_price, avg_order_price, payment_method_val]
        order_count_last_hour, current_order, avg_order, payment_method_val = feature_vector
        
        if model is not None:
            try:
                X = np.array([feature_vector])
                # Scikit-learn models like LogisticRegression or IsolationForest
                pred = model.predict(X)[0]
                
                if hasattr(model, "predict_proba"):
                    # Class 1 probability represents fraud score
                    fraud_score = float(model.predict_proba(X)[0][1])
                    is_fraud = (fraud_score > 0.5)
                else:
                    is_fraud = (pred == 1 or pred == -1)
                    fraud_score = 0.85 if is_fraud else 0.15
                    
                reason = "ML classification flagged checkout transaction as high-risk fraud."
                return fraud_score, is_fraud, reason
            except Exception as e:
                logger.error(f"Fraud ML inference failed: {e}. Falling back to heuristics.")
                
        # --- Fallback Heuristic Rules Mode ---
        is_fraud = False
        reasons = []
        scores = []
        
        # 1. High frequency velocity attack: user checkout spams
        if order_count_last_hour >= 4:
            is_fraud = True
            reasons.append(f"High order velocity: {order_count_last_hour} orders in the last hour")
            scores.append(0.9)
            
        # 2. Large order amount outlier
        if current_order > 5000.0:
            is_fraud = True
            reasons.append(f"Excessive order total price: ${current_order} exceeds limit")
            scores.append(0.85)
            
        # 3. Size spike comparison (order is 4x larger than user average)
        if avg_order > 0 and current_order > 4.0 * avg_order and current_order > 500.0:
            is_fraud = True
            reasons.append(f"Checkout total price (${current_order}) is 4x larger than user average (${round(avg_order, 2)})")
            scores.append(0.8)

        if is_fraud:
            final_score = max(scores)
            final_reason = "; ".join(reasons)
        else:
            final_score = 0.05
            final_reason = "Transaction within normal parameters."
            
        return final_score, is_fraud, final_reason
