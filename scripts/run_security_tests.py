import os
import sys
import argparse

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from security_testing.config import SecurityTestingConfig
from security_testing.runner import SecurityTestRunner

def main():
    parser = argparse.ArgumentParser(description="Cross-Site Scripting (XSS) Attack Detection - Automated Security Testing Runner")
    parser.add_argument("--url", default=SecurityTestingConfig.BASE_URL, help="Target application base URL (default: http://127.0.0.1:5000)")
    parser.add_argument("--proxy", default=None, help="HTTP proxy URL e.g. http://127.0.0.1:8080 (optional)")
    parser.add_argument("--output", default="docs/security_test_report.json", help="Path to save JSON test report")
    args = parser.parse_args()

    print("=" * 70)
    print(" CROSS-SITE SCRIPTING (XSS) ATTACK DETECTION - AUTOMATED SECURITY TESTING SUITE")
    print("=" * 70)
    print(f"Target URL: {args.url}")
    print(f"Proxy Mode: {'ENABLED (' + args.proxy + ')' if args.proxy else 'DIRECT (No Proxy)'}")
    print()

    runner = SecurityTestRunner(base_url=args.url, proxy_url=args.proxy)

    # 1. Health check
    print("[*] Checking local application connectivity...")
    if not runner.check_app_alive():
        print(f"[-] ERROR: Could not connect to application at {args.url}/health.")
        print("    Please ensure the Flask application is running (e.g., 'python app.py').")
        sys.exit(1)
    print("[+] Application is alive and responding.")

    # 2. Run all controlled tests
    print("[*] Executing controlled security tests against local endpoints...")
    report = runner.run_all()

    # 3. Print report
    print()
    print(report.generate_markdown_summary())
    print()

    # 4. Save JSON
    report.save_json(args.output)
    print(f"[+] Detailed execution telemetry saved to: {args.output}")

    if report.failed_tests > 0:
        print(f"[-] FAILED: {report.failed_tests} tests failed.")
        sys.exit(1)
    else:
        print("[+] SUCCESS: All security tests passed.")
        sys.exit(0)

if __name__ == "__main__":
    main()
