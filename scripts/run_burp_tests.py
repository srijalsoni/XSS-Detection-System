import os
import sys
import argparse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from security_testing.config import SecurityTestingConfig
from security_testing.runner import SecurityTestRunner

def main():
    parser = argparse.ArgumentParser(description="Cross-Site Scripting (XSS) Attack Detection - Burp Suite Proxy-Mediated Testing")
    parser.add_argument("--url", default=SecurityTestingConfig.BASE_URL, help="Target application base URL")
    parser.add_argument("--proxy", default=SecurityTestingConfig.BURP_PROXY_URL, help="Burp proxy listener URL (default: http://127.0.0.1:8080)")
    parser.add_argument("--output", default="docs/burp_security_report.json", help="Path to save Burp proxy test report")
    args = parser.parse_args()

    print("=" * 70)
    print(" CROSS-SITE SCRIPTING (XSS) ATTACK DETECTION - BURP SUITE PROXY-MEDIATED TESTING")
    print("=" * 70)
    print(f"Target URL: {args.url}")
    print(f"Burp Proxy URL: {args.proxy}")
    print()

    runner = SecurityTestRunner(base_url=args.url, proxy_url=args.proxy)

    # 1. Check if Burp proxy listener is alive
    print(f"[*] Probing Burp Suite local proxy listener at {args.proxy}...")
    if not runner.check_burp_proxy_available():
        print(f"[-] NOTICE: Burp Suite proxy is NOT currently listening at {args.proxy}.")
        print("    If you wish to route automated traffic through Burp:")
        print("    1. Start Burp Suite Community edition locally.")
        print("    2. Ensure Proxy Listener is set to 127.0.0.1:8080 (Proxy -> Proxy settings).")
        print("    3. Ensure 'Intercept is off' so automated tests flow through smoothly.")
        print("    4. Re-run this script.")
        print("    Exiting gracefully without reporting false success.")
        sys.exit(2)

    print("[+] Burp Suite proxy listener detected and accessible.")

    # 2. Check application connectivity via Burp
    print("[*] Verifying target application reachability through Burp proxy...")
    if not runner.check_app_alive():
        print(f"[-] ERROR: Could not connect to target app via Burp proxy.")
        print("    Ensure the local Flask application is running at " + args.url)
        sys.exit(1)
    print("[+] Target application responded successfully through Burp.")

    # 3. Execute controlled tests via Burp proxy
    print("[*] Routing controlled security test payloads through Burp proxy...")
    report = runner.run_all()

    print()
    print(report.generate_markdown_summary())
    print()

    report.save_json(args.output)
    print(f"[+] Burp-mediated execution telemetry saved to: {args.output}")

    if report.failed_tests > 0:
        print(f"[-] FAILED: {report.failed_tests} tests failed.")
        sys.exit(1)
    else:
        print("[+] SUCCESS: All security tests passed through Burp Suite proxy.")
        sys.exit(0)

if __name__ == "__main__":
    main()
