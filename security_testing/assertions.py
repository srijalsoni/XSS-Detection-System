from dataclasses import dataclass
from typing import Dict, Any, List, Optional
import html

@dataclass
class AssertionResult:
    passed: bool
    message: str
    details: Dict[str, Any]

class SecurityAssertions:
    """Reusable defensive security assertion helpers."""

    @staticmethod
    def assert_security_headers(headers: Dict[str, str]) -> AssertionResult:
        """Verify presence and strength of defense-in-depth HTTP security headers."""
        required = [
            ("Content-Security-Policy", "default-src 'self'"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
        ]
        
        missing = []
        for header, expected_val in required:
            actual = headers.get(header) or headers.get(header.lower())
            if not actual:
                missing.append(f"Missing header '{header}'")
            elif expected_val not in actual:
                missing.append(f"Header '{header}' does not contain expected '{expected_val}' (Actual: '{actual}')")

        if missing:
            return AssertionResult(passed=False, message="; ".join(missing), details={"missing": missing})
        return AssertionResult(passed=True, message="All security headers verified.", details={})

    @staticmethod
    def assert_no_executable_reflection(response_text: str, dangerous_strings: List[str]) -> AssertionResult:
        """Verify that unescaped dangerous strings do not appear reflected in HTML."""
        leaks = []
        for s in dangerous_strings:
            if s in response_text:
                leaks.append(f"Unescaped raw reflection of: '{s[:30]}...'")

        if leaks:
            return AssertionResult(passed=False, message="; ".join(leaks), details={"leaks": leaks})
        return AssertionResult(passed=True, message="No raw executable reflection detected.", details={})

    @staticmethod
    def assert_request_correlation_id(headers: Dict[str, str]) -> AssertionResult:
        """Verify that response contains a non-empty X-Request-ID."""
        req_id = headers.get("X-Request-ID") or headers.get("x-request-id")
        if not req_id:
            return AssertionResult(passed=False, message="Missing X-Request-ID header", details={})
        return AssertionResult(passed=True, message=f"Correlation ID verified: {req_id}", details={"request_id": req_id})
