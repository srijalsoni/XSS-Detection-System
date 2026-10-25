from dataclasses import dataclass
from typing import List, Dict, Any, Optional

@dataclass
class TestPayload:
    payload_id: str
    category: str
    input_value: str
    field_name: str
    target_endpoint: str
    http_method: str
    expected_min_risk: str        # NONE, LOW, MEDIUM, HIGH, CRITICAL
    expected_action: str          # ALLOW, LOG_ONLY, SAFE_RENDER, REJECT, BLOCK
    expected_status_code: int     # 200, 400, 403
    expected_rule_id: Optional[str] = None
    reason: str = ""
    is_attack: bool = True

CONTROLLED_PAYLOADS: List[TestPayload] = [
    # ---------------------------------------------------------
    # 1. Benign Negative Test Cases (Must NOT be blocked/rejected)
    # ---------------------------------------------------------
    TestPayload(
        payload_id="SEC-BENIGN-01",
        category="Benign Technical Discussion",
        input_value="JavaScript uses alert() functions in tutorials for user feedback.",
        field_name="query",
        target_endpoint="/search",
        http_method="POST",
        expected_min_risk="MEDIUM",
        expected_action="SAFE_RENDER",
        expected_status_code=200,
        expected_rule_id="XSS-006",
        reason="Technical discussion mentioning alert() is medium risk and permitted via safe template rendering in text context.",
        is_attack=False
    ),
    TestPayload(
        payload_id="SEC-BENIGN-02",
        category="Benign Mathematical Comparison",
        input_value="Evaluate whether x < 10 and y > 20 in the loop condition.",
        field_name="query",
        target_endpoint="/search",
        http_method="POST",
        expected_min_risk="NONE",
        expected_action="ALLOW",
        expected_status_code=200,
        expected_rule_id=None,
        reason="Mathematical angle brackets are not HTML tags and must be allowed.",
        is_attack=False
    ),
    TestPayload(
        payload_id="SEC-BENIGN-03",
        category="Benign Profile Biography",
        input_value="Application security engineer interested in browser defenses and CSP.",
        field_name="bio",
        target_endpoint="/profile",
        http_method="POST",
        expected_min_risk="NONE",
        expected_action="ALLOW",
        expected_status_code=200,
        expected_rule_id=None,
        reason="Ordinary security-related career description must be allowed.",
        is_attack=False
    ),
    TestPayload(
        payload_id="SEC-BENIGN-04",
        category="Benign Safe Web URL",
        input_value="https://example.com/docs/security/xss-defense",
        field_name="website",
        target_endpoint="/profile",
        http_method="POST",
        expected_min_risk="NONE",
        expected_action="ALLOW",
        expected_status_code=200,
        expected_rule_id=None,
        reason="Valid HTTPS scheme website URL must be accepted.",
        is_attack=False
    ),
    TestPayload(
        payload_id="SEC-BENIGN-05",
        category="Benign Normal Comment",
        input_value="Great article! The explanation of defensive coding was very clear.",
        field_name="content",
        target_endpoint="/comments",
        http_method="POST",
        expected_min_risk="NONE",
        expected_action="ALLOW",
        expected_status_code=200,
        expected_rule_id=None,
        reason="Standard benign user feedback must pass and be persisted.",
        is_attack=False
    ),

    # ---------------------------------------------------------
    # 2. Controlled Suspicious Test Cases (Explicit Known Indicators)
    # ---------------------------------------------------------
    TestPayload(
        payload_id="SEC-ATTACK-01",
        category="Basic HTML Script Tag",
        input_value="<script>alert(1)</script>",
        field_name="query",
        target_endpoint="/search",
        http_method="POST",
        expected_min_risk="CRITICAL",
        expected_action="BLOCK",
        expected_status_code=403,
        expected_rule_id="XSS-001",
        reason="Explicit script tag paired with execution sink constitutes a compound critical risk requiring a 403 block.",
        is_attack=True
    ),
    TestPayload(
        payload_id="SEC-ATTACK-02",
        category="Image Event Handler Pattern",
        input_value="<img src=x onerror=alert(document.cookie)>",
        field_name="content",
        target_endpoint="/comments",
        http_method="POST",
        expected_min_risk="CRITICAL",
        expected_action="BLOCK",
        expected_status_code=403,
        expected_rule_id="XSS-002",
        reason="Inline onerror event handler with JS sink requires critical blocking to protect stored comments.",
        is_attack=True
    ),
    TestPayload(
        payload_id="SEC-ATTACK-03",
        category="SVG Event Handler Pattern",
        input_value="<svg/onload=confirm(1)>",
        field_name="query",
        target_endpoint="/search",
        http_method="POST",
        expected_min_risk="CRITICAL",
        expected_action="BLOCK",
        expected_status_code=403,
        expected_rule_id="XSS-002",
        reason="SVG tag with inline onload handler represents critical risk.",
        is_attack=True
    ),
    TestPayload(
        payload_id="SEC-ATTACK-04",
        category="JavaScript Pseudo-Protocol",
        input_value="javascript:alert(window.origin)",
        field_name="website",
        target_endpoint="/profile",
        http_method="POST",
        expected_min_risk="CRITICAL",
        expected_action="BLOCK",
        expected_status_code=403,
        expected_rule_id="XSS-003",
        reason="Executable URI scheme submitted as website profile URL must be rejected.",
        is_attack=True
    ),
    TestPayload(
        payload_id="SEC-ATTACK-05",
        category="Attribute Breakout Pattern",
        input_value="\"><script>alert(1)</script>",
        field_name="display_name",
        target_endpoint="/profile",
        http_method="POST",
        expected_min_risk="CRITICAL",
        expected_action="BLOCK",
        expected_status_code=403,
        expected_rule_id="XSS-005",
        reason="Quote and bracket breakout into new script element triggers critical block.",
        is_attack=True
    ),
    TestPayload(
        payload_id="SEC-ATTACK-06",
        category="Dangerous Tag (Iframe / Embed)",
        input_value="<iframe src=\"javascript:alert(1)\"></iframe>",
        field_name="content",
        target_endpoint="/comments",
        http_method="POST",
        expected_min_risk="CRITICAL",
        expected_action="BLOCK",
        expected_status_code=403,
        expected_rule_id="XSS-004",
        reason="Iframe tag paired with javascript pseudo-protocol requires critical block.",
        is_attack=True
    ),
    TestPayload(
        payload_id="SEC-ATTACK-07",
        category="Mixed-Case Obfuscation",
        input_value="<sCrIpT>prompt(1)</sCrIpT>",
        field_name="query",
        target_endpoint="/search",
        http_method="POST",
        expected_min_risk="CRITICAL",
        expected_action="BLOCK",
        expected_status_code=403,
        expected_rule_id="XSS-001",
        reason="Mixed-case script tag must be normalized and blocked.",
        is_attack=True
    ),
    TestPayload(
        payload_id="SEC-ATTACK-08",
        category="Whitespace Variation Pattern",
        input_value="<img    src=x\tonerror=alert(1)>",
        field_name="content",
        target_endpoint="/comments",
        http_method="POST",
        expected_min_risk="CRITICAL",
        expected_action="BLOCK",
        expected_status_code=403,
        expected_rule_id="XSS-002",
        reason="Irregular tab and spaces in HTML tag must be normalized and blocked.",
        is_attack=True
    ),
    TestPayload(
        payload_id="SEC-ATTACK-09",
        category="Dangerous Scheme (VBScript)",
        input_value="vbscript:msgbox(1)",
        field_name="website",
        target_endpoint="/profile",
        http_method="POST",
        expected_min_risk="HIGH",
        expected_action="REJECT",
        expected_status_code=400,
        expected_rule_id="XSS-003",
        reason="VBScript executable scheme must be rejected on URL validation.",
        is_attack=True
    ),
    TestPayload(
        payload_id="SEC-ATTACK-10",
        category="Dangerous Scheme (Data URI HTML)",
        input_value="data:text/html,<script>alert(1)</script>",
        field_name="website",
        target_endpoint="/profile",
        http_method="POST",
        expected_min_risk="CRITICAL",
        expected_action="BLOCK",
        expected_status_code=403,
        expected_rule_id="XSS-001",
        reason="Data URI containing HTML script payload must be rejected.",
        is_attack=True
    ),
]
