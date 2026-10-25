import urllib.request
import urllib.parse
import json
import sqlite3
import os
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Set
from security_testing.config import SecurityTestingConfig
from security_testing.payloads import TestPayload, CONTROLLED_PAYLOADS
from security_testing.assertions import SecurityAssertions
from security_testing.reporting import TestExecutionRecord, SecurityTestReport
from database.repositories import SecurityEventRepository
from database.connection import create_connection

class SecurityTestRunner:
    """
    Automated security testing runner that tests local endpoints directly
    or through a local HTTP proxy, retrieving genuine application telemetry
    using request correlation IDs.
    """

    def __init__(self, base_url: Optional[str] = None, proxy_url: Optional[str] = None, db_path: Optional[str] = None):
        self.base_url = (base_url or SecurityTestingConfig.BASE_URL).rstrip("/")
        self.proxy_url = proxy_url
        self.db_path = db_path or os.path.join(os.path.dirname(os.path.dirname(__file__)), "database", "app.db")

        # Build urllib opener
        if self.proxy_url:
            proxy_handler = urllib.request.ProxyHandler({
                "http": self.proxy_url,
                "https": self.proxy_url
            })
            self.opener = urllib.request.build_opener(proxy_handler)
        else:
            self.opener = urllib.request.build_opener()

    def check_burp_proxy_available(self) -> bool:
        """Check if Burp Suite local proxy is actively listening on TCP socket."""
        if not self.proxy_url:
            return False
        try:
            parsed = urllib.parse.urlparse(self.proxy_url)
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            res = sock.connect_ex((parsed.hostname, parsed.port or 8080))
            sock.close()
            return res == 0
        except Exception:
            return False

    def check_app_alive(self) -> bool:
        """Check if local Flask application is running and accessible."""
        try:
            req = urllib.request.Request(f"{self.base_url}/health")
            with self.opener.open(req, timeout=SecurityTestingConfig.REQUEST_TIMEOUT) as resp:
                return resp.status == 200
        except Exception:
            return False

    def fetch_actual_security_event(self, request_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves the genuine security event persisted by the application for this request ID.
        Uses the application's actual database connection and repository.
        """
        if not request_id:
            return None
        try:
            if os.path.exists(self.db_path):
                conn = create_connection(self.db_path)
                events = SecurityEventRepository.get_by_request_id(request_id, conn=conn)
                conn.close()
                if events:
                    return events[-1]  # Return the latest event for this request
        except Exception as e:
            pass
        return None

    def execute_payload(self, p: TestPayload) -> TestExecutionRecord:
        """Executes a single controlled security test payload and gathers real telemetry."""
        url = f"{self.base_url}{p.target_endpoint}"
        
        # Prepare form payload
        form_data = {p.field_name: p.input_value}
        if p.target_endpoint == "/comments":
            form_data.setdefault("author", "SecTester")
            form_data.setdefault("content", "Controlled test content")
        elif p.target_endpoint == "/profile":
            form_data.setdefault("display_name", "SecTester")
            form_data.setdefault("bio", "Controlled security profile")
            form_data.setdefault("website", "https://example.com")

        encoded_data = urllib.parse.urlencode(form_data).encode("utf-8")
        headers = {
            "User-Agent": "P211-Security-Test-Runner/1.0",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        req = urllib.request.Request(url, data=encoded_data, headers=headers, method=p.http_method)

        actual_status = 0
        resp_headers = {}
        resp_text = ""

        try:
            with self.opener.open(req, timeout=SecurityTestingConfig.REQUEST_TIMEOUT) as resp:
                actual_status = resp.status
                resp_headers = dict(resp.headers)
                resp_text = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            actual_status = e.code
            resp_headers = dict(e.headers)
            resp_text = e.read().decode("utf-8", errors="replace")
        except Exception as ex:
            return TestExecutionRecord(
                payload_id=p.payload_id,
                category=p.category,
                target_endpoint=p.target_endpoint,
                http_method=p.http_method,
                expected_status=p.expected_status_code,
                actual_status=0,
                expected_action=p.expected_action,
                actual_action="CONNECTION_ERROR",
                expected_risk=p.expected_min_risk,
                actual_risk="NONE",
                expected_rule_ids=p.expected_rule_id,
                actual_rule_ids=None,
                actual_ml_label=None,
                actual_ml_confidence=None,
                actual_ml_model_version=None,
                actual_ml_enabled=None,
                status_passed=False,
                action_passed=False,
                risk_passed=False,
                rule_passed=False,
                headers_verified=False,
                reflection_safe=False,
                correlation_id_verified=False,
                passed=False,
                notes=f"Failed to connect to {url}: {ex}"
            )

        # 1. Retrieve correlation ID
        request_id = resp_headers.get("X-Request-ID") or resp_headers.get("x-request-id")
        corr_assert = SecurityAssertions.assert_request_correlation_id(resp_headers)

        # 2. Query application for genuine security telemetry
        sec_event = self.fetch_actual_security_event(request_id) if request_id else None

        actual_risk = "NONE"
        actual_action = "ALLOW"
        actual_rule_ids = None
        actual_ml_label = None
        actual_ml_confidence = None
        actual_ml_model_version = None
        actual_ml_enabled = None

        if sec_event:
            actual_risk = sec_event.get("risk_level", "NONE")
            sec_action = sec_event.get("action", "")
            # Map database action to ResponseAction
            if sec_action == "BLOCKED":
                actual_action = "BLOCK"
            elif sec_action == "REJECTED":
                actual_action = "REJECT"
            elif sec_action == "SAFE_RENDERED":
                actual_action = "SAFE_RENDER"
            elif sec_action == "LOGGED":
                actual_action = "LOG_ONLY"
            else:
                actual_action = sec_action or "ALLOW"
            
            actual_rule_ids = sec_event.get("rule_id")

            details = sec_event.get("details") or {}
            ml_data = details.get("ml") or {}
            actual_ml_label = ml_data.get("label") or details.get("ml_label")
            actual_ml_confidence = ml_data.get("confidence") if ml_data.get("confidence") is not None else details.get("ml_confidence")
            actual_ml_model_version = ml_data.get("model_version") or details.get("ml_model_version")
            actual_ml_enabled = ml_data.get("enabled") if ml_data.get("enabled") is not None else details.get("ml_enabled")
        else:
            # If no security event was generated, this was evaluated as clean benign (ALLOW)
            if actual_status == 200:
                actual_action = "ALLOW"
                actual_risk = "NONE"
            elif actual_status == 400:
                actual_action = "REJECT"
            elif actual_status == 403:
                actual_action = "BLOCK"

        # 3. Assertions and comparisons
        status_passed = (actual_status == p.expected_status_code)
        action_passed = (actual_action == p.expected_action)
        risk_passed = (actual_risk == p.expected_min_risk) or (p.expected_min_risk == "NONE" and actual_risk == "NONE")
        
        # Rule comparison: check that expected rule (if specified) is among observed matched rules
        if p.expected_rule_id:
            actual_rules_set: Set[str] = set(r.strip() for r in (actual_rule_ids or "").split(",") if r.strip())
            rule_passed = p.expected_rule_id in actual_rules_set
        else:
            rule_passed = (actual_rule_ids is None)

        header_assert = SecurityAssertions.assert_security_headers(resp_headers)
        reflection_assert = SecurityAssertions.assert_no_executable_reflection(
            resp_text, [p.input_value]
        ) if p.is_attack else SecurityAssertions.assert_no_executable_reflection(
            resp_text, ["<script>", "onerror=", "onload="]
        )

        # Fix 5: overall_passed MUST strictly require all assertions including correlation ID
        overall_passed = (
            status_passed and
            action_passed and
            risk_passed and
            rule_passed and
            header_assert.passed and
            reflection_assert.passed and
            corr_assert.passed
        )

        return TestExecutionRecord(
            payload_id=p.payload_id,
            category=p.category,
            target_endpoint=p.target_endpoint,
            http_method=p.http_method,
            expected_status=p.expected_status_code,
            actual_status=actual_status,
            expected_action=p.expected_action,
            actual_action=actual_action,
            expected_risk=p.expected_min_risk,
            actual_risk=actual_risk,
            expected_rule_ids=p.expected_rule_id,
            actual_rule_ids=actual_rule_ids,
            actual_ml_label=actual_ml_label,
            actual_ml_confidence=actual_ml_confidence,
            actual_ml_model_version=actual_ml_model_version,
            actual_ml_enabled=actual_ml_enabled,
            status_passed=status_passed,
            action_passed=action_passed,
            risk_passed=risk_passed,
            rule_passed=rule_passed,
            headers_verified=header_assert.passed,
            reflection_safe=reflection_assert.passed,
            correlation_id_verified=corr_assert.passed,
            passed=overall_passed,
            request_id=request_id,
            notes=p.reason
        )

    def run_all(self, payloads: Optional[List[TestPayload]] = None) -> SecurityTestReport:
        """Runs all controlled payloads and returns a comprehensive report."""
        test_list = payloads or CONTROLLED_PAYLOADS
        records: List[TestExecutionRecord] = []

        for p in test_list:
            record = self.execute_payload(p)
            records.append(record)

        passed = sum(1 for r in records if r.passed)
        failed = len(records) - passed
        rate = (passed / len(records) * 100.0) if records else 0.0

        return SecurityTestReport(
            timestamp=datetime.now(timezone.utc).isoformat(),
            total_tests=len(records),
            passed_tests=passed,
            failed_tests=failed,
            pass_rate=rate,
            mode="BURP_PROXY" if self.proxy_url else "DIRECT",
            proxy_url=self.proxy_url,
            records=records
        )
