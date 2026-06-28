# predictor.py
import json
import os
from consumers.shared.config import (
    DEFAULT_RATE_LIMIT_THRESHOLD,
    DEFAULT_SCANNING_LIMIT
)

class DDoSAlertPredictor:
    def __init__(self):
        # Allow dynamic overriding of thresholds
        self.rate_limit_threshold = int(os.environ.get("RATE_LIMIT_THRESHOLD", DEFAULT_RATE_LIMIT_THRESHOLD))
        self.scanning_limit = int(os.environ.get("SCANNING_LIMIT", DEFAULT_SCANNING_LIMIT))

    def evaluate(self, features: dict) -> dict | None:
        """
        Evaluates DDoS features against alert rules.
        Returns alert payload dict if rule triggered, else None.
        """
        ip = features["source_ip"]
        if ip == "unknown":
            return None
            
        request_count = features["request_count"]
        requests_per_second = features["requests_per_second"]
        error_count_404 = features["error_count_404"]
        
        # 1. Check for high-frequency DDoS / brute volumetric limit
        # The threshold is given for a 10s window in the frontend (default 40 requests).
        # Since our extractor uses a 5s window, we scale the threshold by 0.5.
        scaled_rate_threshold = self.rate_limit_threshold * 0.5
        
        if request_count > scaled_rate_threshold:
            return {
                "source_ip": ip,
                "request_count": request_count,
                "requests_per_second": requests_per_second,
                "severity": "CRITICAL" if requests_per_second > 15.0 else "HIGH",
                "description": f"DDoS Volumetric Alert: {request_count} requests in 5 seconds from IP {ip}",
                "details": {
                    "request_count": request_count,
                    "requests_per_second": requests_per_second,
                    "unique_paths": features["unique_paths_count"]
                }
            }
            
        # 2. Check for directory fuzzing / path scanning (too many 404s)
        # The threshold is default 10 404s in 15 seconds. For a 5s window, we scale it to ~4.
        scaled_scanning_threshold = max(3, int(self.scanning_limit * (5.0 / 15.0)))
        
        if error_count_404 > scaled_scanning_threshold:
            return {
                "source_ip": ip,
                "request_count": request_count,
                "requests_per_second": requests_per_second,
                "severity": "HIGH",
                "description": f"DDoS Path Scanning Alert: {error_count_404} 404 status errors in 5 seconds from IP {ip}",
                "details": {
                    "error_404_count": error_count_404,
                    "unique_paths": features["unique_paths_count"]
                }
            }
            
        return None
