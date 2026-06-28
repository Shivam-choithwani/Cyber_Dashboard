# features.py
import math

class AnomalyFeatureExtractor:
    def extract_features(self, window_events: list[dict]) -> list[float]:
        """
        Computes the feature vector from a list of window events.
        Vector: [latency_avg, latency_std, error_rate, path_variety]
        """
        if not window_events:
            return [0.0, 0.0, 0.0, 0.0]
            
        n = len(window_events)
        
        # Latency statistics
        latencies = [float(evt.get("response_time_ms", 0.0) or 0.0) for evt in window_events]
        latency_avg = sum(latencies) / n
        
        if n > 1:
            variance = sum((x - latency_avg) ** 2 for x in latencies) / (n - 1)
            latency_std = math.sqrt(variance)
        else:
            latency_std = 0.0
            
        # Error rate (HTTP Status >= 400)
        errors = sum(1 for evt in window_events if int(evt.get("status_code", 200) or 200) >= 400)
        error_rate = errors / n
        
        # Path variety (unique paths / total request count in window)
        paths = set(evt.get("path", "") for evt in window_events)
        path_variety = len(paths) / n
        
        return [
            round(latency_avg, 3),
            round(latency_std, 3),
            round(error_rate, 3),
            round(path_variety, 3)
        ]
