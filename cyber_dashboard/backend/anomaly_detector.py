import re
import math
import uuid
import urllib.parse
from datetime import datetime

class AnomalyDetector:
    def __init__(self):
        # Volumetric counters: IP -> list of timestamps (datetime objects)
        self.ip_requests = {}
        self.ip_404s = {}
        self.ip_login_failures = {}
        
        # Latency statistics per route: path -> {count, mean, M2} (Welford's algorithm)
        self.route_latency_stats = {}
        
        # Regex patterns for attack signatures (applied on decoded payloads)
        self.sqli_pattern = re.compile(
            r"(union\s+select|insert\s+into|select\s+.*\s+from|'\s*or\s*|--|xp_cmdshell|/\*|\*/|\'\s*=\s*\'|\"\s*=\s*\")", 
            re.IGNORECASE
        )
        self.xss_pattern = re.compile(
            r"(<script|javascript:|onerror\s*=|onload\s*=|alert\(|<img|<iframe)", 
            re.IGNORECASE
        )
        
        # Bad User Agents
        self.suspicious_agents = re.compile(
            r"(sqlmap|nikto|dirbuster|gobuster|nmap|hydra|acunetix|nessus)",
            re.IGNORECASE
        )

    def detect(self, event: dict, event_type: str) -> list[dict]:
        """
        Analyzes an incoming event and returns a list of flagged anomalies.
        event_type can be: "http-logs" or "security-events"
        """
        anomalies = []
        now = datetime.utcnow()
        
        # 1. Process HTTP requests logs
        if event_type == "http-logs":
            ip = event.get("ip_address", "unknown")
            path = event.get("path", "")
            method = event.get("method", "")
            status_code = event.get("status_code", 200)
            latency = event.get("response_time_ms", 0.0)
            user_agent = event.get("user_agent", "")
            query_params = event.get("query_params", "")
            trace_id = event.get("trace_id", "")
            
            # Decode URL-encoded path and query parameters for robust signature inspection
            path_decoded = urllib.parse.unquote(path)
            query_decoded = urllib.parse.unquote(query_params)
            
            # --- Signature Checks ---
            # SQL Injection Check
            if self.sqli_pattern.search(path_decoded) or self.sqli_pattern.search(query_decoded):
                anomalies.append({
                    "anomaly_id": str(uuid.uuid4()),
                    "timestamp": now.isoformat() + "Z",
                    "event_id": trace_id,
                    "event_type": "http-logs",
                    "severity": "CRITICAL",
                    "anomaly_type": "SQL_INJECTION",
                    "description": f"SQL Injection signature detected in path/query from IP {ip}",
                    "ip_address": ip,
                    "path": path,
                    "details": {"query_params": query_params, "method": method}
                })
                
            # XSS Check
            if self.xss_pattern.search(path_decoded) or self.xss_pattern.search(query_decoded):
                anomalies.append({
                    "anomaly_id": str(uuid.uuid4()),
                    "timestamp": now.isoformat() + "Z",
                    "event_id": trace_id,
                    "event_type": "http-logs",
                    "severity": "CRITICAL",
                    "anomaly_type": "XSS",
                    "description": f"XSS signature detected in path/query from IP {ip}",
                    "ip_address": ip,
                    "path": path,
                    "details": {"query_params": query_params, "method": method}
                })
                
            # Suspicious User Agent Check
            if self.suspicious_agents.search(user_agent):
                anomalies.append({
                    "anomaly_id": str(uuid.uuid4()),
                    "timestamp": now.isoformat() + "Z",
                    "event_id": trace_id,
                    "event_type": "http-logs",
                    "severity": "HIGH",
                    "anomaly_type": "SUSPICIOUS_AGENT",
                    "description": f"Request from known security scanner/tool User-Agent: {user_agent}",
                    "ip_address": ip,
                    "path": path,
                    "details": {"user_agent": user_agent}
                })

            # --- Volumetric/Behavioral Checks ---
            if ip != "unknown":
                # Rate limiting check (e.g., max 40 requests in 10 seconds)
                if ip not in self.ip_requests:
                    self.ip_requests[ip] = []
                self.ip_requests[ip].append(now)
                self.ip_requests[ip] = [t for t in self.ip_requests[ip] if (now - t).total_seconds() <= 10]
                if len(self.ip_requests[ip]) > 40:
                    anomalies.append({
                        "anomaly_id": str(uuid.uuid4()),
                        "timestamp": now.isoformat() + "Z",
                        "event_id": trace_id,
                        "event_type": "http-logs",
                        "severity": "HIGH",
                        "anomaly_type": "RATE_LIMIT_VIOLATION",
                        "description": f"Rate limit violation: {len(self.ip_requests[ip])} requests in 10s from IP {ip}",
                        "ip_address": ip,
                        "path": path,
                        "details": {"request_count_10s": len(self.ip_requests[ip])}
                    })

                # Path scanner fuzzing check (e.g., excessive 404s, >10 in 15 seconds)
                if status_code == 404:
                    if ip not in self.ip_404s:
                        self.ip_404s[ip] = []
                    self.ip_404s[ip].append(now)
                    self.ip_404s[ip] = [t for t in self.ip_404s[ip] if (now - t).total_seconds() <= 15]
                    if len(self.ip_404s[ip]) > 10:
                        anomalies.append({
                            "anomaly_id": str(uuid.uuid4()),
                            "timestamp": now.isoformat() + "Z",
                            "event_id": trace_id,
                            "event_type": "http-logs",
                            "severity": "HIGH",
                            "anomaly_type": "PATH_FUZZING",
                            "description": f"Path scanning/fuzzing suspected: {len(self.ip_404s[ip])} 404 errors in 15s from IP {ip}",
                            "ip_address": ip,
                            "path": path,
                            "details": {"404_count_15s": len(self.ip_404s[ip])}
                        })

            # --- Statistical Latency Checks ---
            if status_code == 200 and latency > 0:
                route_key = f"{method} {path}"
                if route_key not in self.route_latency_stats:
                    self.route_latency_stats[route_key] = {"count": 0, "mean": 0.0, "M2": 0.0}
                
                stats = self.route_latency_stats[route_key]
                stats["count"] += 1
                count = stats["count"]
                
                if count >= 15:
                    variance = stats["M2"] / (count - 1)
                    std_dev = math.sqrt(variance)
                    
                    if std_dev > 10.0: 
                        z_score = (latency - stats["mean"]) / std_dev
                        
                        if z_score > 3.5 and latency > 300: 
                            anomalies.append({
                                "anomaly_id": str(uuid.uuid4()),
                                "timestamp": now.isoformat() + "Z",
                                "event_id": trace_id,
                                "event_type": "http-logs",
                                "severity": "MEDIUM",
                                "anomaly_type": "HIGH_LATENCY",
                                "description": f"Abnormal response latency spike detected on {route_key}: {latency}ms (average is {round(stats['mean'], 1)}ms)",
                                "ip_address": ip,
                                "path": path,
                                "details": {"latency_ms": latency, "mean_ms": round(stats['mean'], 2), "z_score": round(z_score, 2)}
                            })
                
                delta = latency - stats["mean"]
                stats["mean"] += delta / count
                delta2 = latency - stats["mean"]
                stats["M2"] += delta * delta2

        # 2. Process Security events logs
        elif event_type == "security-events":
            ip = event.get("ip_address", "unknown")
            path = event.get("path", "")
            evt_type = event.get("event_type", "")
            details = event.get("details", "")
            event_id = event.get("event_id", "")
            
            # Login Brute Force Check
            if evt_type == "FAILED_LOGIN" and ip != "unknown":
                if ip not in self.ip_login_failures:
                    self.ip_login_failures[ip] = []
                self.ip_login_failures[ip].append(now)
                self.ip_login_failures[ip] = [t for t in self.ip_login_failures[ip] if (now - t).total_seconds() <= 30]
                
                if len(self.ip_login_failures[ip]) >= 5:
                    anomalies.append({
                        "anomaly_id": str(uuid.uuid4()),
                        "timestamp": now.isoformat() + "Z",
                        "event_id": event_id,
                        "event_type": "security-events",
                        "severity": "HIGH",
                        "anomaly_type": "BRUTE_FORCE",
                        "description": f"Brute force login attack suspected: {len(self.ip_login_failures[ip])} failed logins in 30s from IP {ip}",
                        "ip_address": ip,
                        "path": path,
                        "details": {"failed_attempts_30s": len(self.ip_login_failures[ip]), "msg": details}
                    })
            
            # Forward other high-severity security events
            if evt_type == "FORBIDDEN_ACCESS":
                anomalies.append({
                    "anomaly_id": str(uuid.uuid4()),
                    "timestamp": now.isoformat() + "Z",
                    "event_id": event_id,
                    "event_type": "security-events",
                    "severity": "HIGH",
                    "anomaly_type": "FORBIDDEN_ACCESS",
                    "description": f"Critical security alert: Unauthorized attempt to access admin interface from IP {ip}",
                    "ip_address": ip,
                    "path": path,
                    "details": {"msg": details}
                })

        return anomalies
