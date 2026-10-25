import os
import sys
import json
import urllib.request
import urllib.error

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

def check_health(base_url="http://127.0.0.1:5000"):
    print("=" * 65)
    print(" CROSS-SITE SCRIPTING (XSS) ATTACK DETECTION - HEALTH & DEFENSE VERIFICATION")
    print("=" * 65)
    print(f"Target URL: {base_url}")
    print()

    # 1. Probe /health endpoint
    health_url = f"{base_url.rstrip('/')}/health"
    try:
        req = urllib.request.Request(health_url, headers={"User-Agent": "P211-HealthCheck/1.0"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            status_code = resp.status
            body = resp.read().decode("utf-8", errors="replace")
            headers = dict(resp.headers)
            
            if status_code != 200:
                print(f"[-] HTTP Status Error: {status_code}")
                return False
            
            data = json.loads(body)
            print("[+] Web Application: ONLINE (HTTP 200 OK)")
            print(f"    - Status: {data.get('status')}")
            print(f"    - Database Connected: {data.get('database')}")
            print(f"    - Timestamp: {data.get('timestamp')}")
    except urllib.error.URLError as e:
        print(f"[-] ERROR: Application is offline or unreachable at {health_url}.")
        print(f"    Reason: {e.reason}")
        print("    Tip: Start the application using 'run.bat' or 'python app.py'.")
        return False
    except Exception as ex:
        print(f"[-] Unexpected error connecting to {health_url}: {ex}")
        return False

    # 2. Check Security Headers
    print()
    print("[*] Verifying Defensive Security Headers on /health...")
    required_headers = [
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "X-Request-ID"
    ]
    missing = [h for h in required_headers if h not in headers and h.lower() not in headers]
    if missing:
        print(f"[-] Missing Security Headers: {', '.join(missing)}")
        return False
    print("[+] All Defensive Security Headers and X-Request-ID present.")

    # 3. Check ML Model Subsystem Availability
    print()
    print("[*] Inspecting ML Classifier Subsystem...")
    try:
        from ml.model_manager import ModelManager
        from ml.config import MLConfig
        mgr = ModelManager.get_instance()
        if mgr.is_available:
            print(f"[+] Machine Learning Layer: AVAILABLE (Mode: {MLConfig.MODE}, Version: {MLConfig.VERSION})")
        else:
            print(f"[!] Machine Learning Layer: OFFLINE ({mgr.load_error or 'Unknown reason'})")
            print("    (Note: Fail-safe mode active; deterministic engine remains authoritative)")
    except Exception as e:
        print(f"[!] ML subsystem check warning: {e}")

    # 4. Check Feature Endpoints
    print()
    print("[*] Probing Feature Endpoints...")
    endpoints = ["/", "/search", "/comments", "/profile", "/dashboard"]
    for ep in endpoints:
        url = f"{base_url.rstrip('/')}{ep}"
        try:
            r = urllib.request.Request(url, headers={"User-Agent": "P211-HealthCheck/1.0"})
            with urllib.request.urlopen(r, timeout=3.0) as res:
                print(f"    - {ep:<15} : HTTP {res.status} OK")
        except Exception as e:
            print(f"    - {ep:<15} : FAILED ({e})")
            return False

    print()
    print("[+] System Health Verification: ALL CHECKS PASSED.")
    return True

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000"
    success = check_health(url)
    sys.exit(0 if success else 1)
