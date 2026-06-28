import time
import urllib.request
import urllib.error
import json

ECOMMERCE_URL = "http://127.0.0.1:8000"

def make_request(method, path, data=None):
    url = f"{ECOMMERCE_URL}{path}"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    body = None
    if data:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            print(f"SUCCESS: {method} {path} -> {resp.status}")
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        print(f"HTTP ERROR: {method} {path} -> {e.code}")
        return e.code, e.read().decode()
    except Exception as e:
        print(f"CONNECTION ERROR: {method} {path} -> {e}")
        return 0, str(e)

def run_test_suite():
    print("==================================================")
    print("   Starting Telemetry & Anomaly Detection Test    ")
    print("==================================================")
    
    # 1. Normal requests
    print("\n--- Sending Normal Traffic ---")
    make_request("GET", "/")
    time.sleep(1)
    
    # 2. SQL Injection Simulation
    print("\n--- Simulating SQL Injection Attack ---")
    make_request("GET", "/products/slug/test-product?q=%27%20UNION%20SELECT%20username,password%20FROM%20users%20--")
    time.sleep(1)

    # 3. XSS Injection Simulation
    print("\n--- Simulating XSS Script Attack ---")
    make_request("GET", "/products/slug/test-product?search=%3Cscript%3Ealert(%27HACKED%27)%3C/script%3E")
    time.sleep(1)
    
    # 4. Failed Login Brute Force Simulation
    print("\n--- Simulating Brute Force Logins (5 rapid failed requests) ---")
    for i in range(5):
        payload = {"email": "attack_victim@verify.dev", "password": f"incorrect-guess-{i}"}
        make_request("POST", "/auth/login", payload)
        time.sleep(0.1)
    time.sleep(1)
        
    # 5. Path Scanner / Directory Fuzzing Simulation (12 rapid 404 requests)
    print("\n--- Simulating Directory Fuzzing Scan (12 rapid 404s) ---")
    scanner_paths = [
        "/admin-portal", "/wp-login.php", "/phpmyadmin", "/.env", 
        "/config.yml", "/database.sql", "/shell.php", "/backup.zip",
        "/secret", "/config/db", "/v1/users", "/server-status"
    ]
    for p in scanner_paths:
        make_request("GET", p)
        time.sleep(0.05)
        
    print("\n==================================================")
    print("   Test traffic generation complete!              ")
    print("   Check your Cyber Dashboard for real-time alerts. ")
    print("==================================================")

if __name__ == "__main__":
    run_test_suite()
