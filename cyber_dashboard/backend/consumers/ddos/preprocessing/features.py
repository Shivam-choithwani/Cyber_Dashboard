# features.py
from datetime import datetime, timedelta

class DDoSFeatureExtractor:
    def __init__(self, window_seconds: float = 5.0):
        self.window_seconds = window_seconds
        # In-memory sliding history: IP -> list of dicts {"timestamp": datetime, "path": str, "status_code": int}
        self.ip_histories = {}

    def extract_features(self, event: dict) -> dict:
        """
        Updates the sliding window history for the client IP and computes features.
        Returns a dict of engineered features.
        """
        ip = event.get("ip_address", "unknown")
        path = event.get("path", "")
        status_code = int(event.get("status_code", 200) or 200)
        
        now = datetime.utcnow()
        
        if ip not in self.ip_histories:
            self.ip_histories[ip] = []
            
        # Append current request
        self.ip_histories[ip].append({
            "timestamp": now,
            "path": path,
            "status_code": status_code
        })
        
        # Prune request histories older than sliding window threshold
        threshold_time = now - timedelta(seconds=self.window_seconds)
        self.ip_histories[ip] = [
            req for req in self.ip_histories[ip] if req["timestamp"] >= threshold_time
        ]
        
        # Calculate features over the pruned window
        window = self.ip_histories[ip]
        request_count = len(window)
        requests_per_second = round(request_count / self.window_seconds, 2)
        
        unique_paths = len(set(req["path"] for req in window))
        error_count_404 = sum(1 for req in window if req["status_code"] == 404)
        error_count_5xx = sum(1 for req in window if 500 <= req["status_code"] <= 599)
        
        return {
            "source_ip": ip,
            "request_count": request_count,
            "requests_per_second": requests_per_second,
            "unique_paths_count": unique_paths,
            "error_count_404": error_count_404,
            "error_count_5xx": error_count_5xx,
            "window_duration_seconds": self.window_seconds
        }
