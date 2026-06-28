# features.py
from datetime import datetime, timedelta

class FraudFeatureExtractor:
    def extract_features(self, orders: list[dict], current_order: dict) -> list[float]:
        """
        Extracts features for fraud check.
        orders: list of order records for the user from PostgreSQL
        current_order: dict containing details of the order being evaluated
        
        Vector: [order_count_last_hour, current_order_price, avg_order_price, payment_method_val]
        """
        now = datetime.utcnow()
        one_hour_ago = now - timedelta(hours=1)
        
        # 1. Order count in the last hour
        order_count_last_hour = sum(
            1 for o in orders 
            if o.get("created_at") and o["created_at"] >= one_hour_ago
        )
        
        # 2. Current order total price
        current_order_price = float(current_order.get("total_price", 0.0) or 0.0)
        
        # 3. Average order price
        all_prices = [float(o.get("total_price", 0.0) or 0.0) for o in orders]
        if all_prices:
            avg_order_price = sum(all_prices) / len(all_prices)
        else:
            avg_order_price = current_order_price
            
        # 4. Payment method numeric value
        pay_method = str(current_order.get("payment_method", "")).lower()
        if "card" in pay_method or "stripe" in pay_method:
            payment_method_val = 1.0 # Credit/Debit card
        elif "cod" in pay_method or "cash" in pay_method:
            payment_method_val = 2.0 # Cash on delivery
        else:
            payment_method_val = 0.0 # Other/Unknown
            
        return [
            float(order_count_last_hour),
            current_order_price,
            avg_order_price,
            payment_method_val
        ]
