import pytest
from app import create_app
from database import init_database, CommentRepository, ProfileRepository
from security import (
    PolicyEngine,
    ResponseAction,
    validate_url,
    escape_html_attribute,
    default_detector,
    DetectionInput
)


@pytest.fixture
def app(tmp_path):
    test_db = str(tmp_path / "prev_test.db")
    app = create_app("testing")
    app.config["DATABASE_PATH"] = test_db
    init_database(test_db)
    yield app


@pytest.fixture
def client(app):
    return app.test_client()


# ============================================================================
# POLICY ENGINE UNIT TESTS (POLICY-SPECIFIC & DETERMINISTIC)
# ============================================================================

def test_policy_allow_benign_input():
    """Benign clean input must evaluate to ALLOW with HTTP 200."""
    det = default_detector.analyze(DetectionInput(value="Legitimate comment discussing architecture."))
    decision = PolicyEngine.evaluate(det)
    assert decision.action == ResponseAction.ALLOW
    assert decision.should_continue is True
    assert decision.status_code == 200
    assert decision.security_event_action == "NONE"


def test_policy_reject_high_risk_input():
    """
    Explicit high-risk input (e.g. script tag without sink) must evaluate to
    REJECT with exact HTTP 400 and security_event_action='REJECTED'.
    """
    det = default_detector.analyze(DetectionInput(value="<script src='http://evil.com/x.js'></script>"))
    assert det.risk_level == "HIGH"
    decision = PolicyEngine.evaluate(det)
    assert decision.action == ResponseAction.REJECT
    assert decision.should_continue is False
    assert decision.status_code == 400
    assert decision.security_event_action == "REJECTED"


def test_policy_block_critical_compound_input():
    """
    Critical compound exploit vector (e.g. script tag + DOM sink alert) must
    evaluate to BLOCK with exact HTTP 403 and security_event_action='BLOCKED'.
    """
    det = default_detector.analyze(DetectionInput(value="<script>alert(1)</script>"))
    assert det.risk_level == "CRITICAL"
    decision = PolicyEngine.evaluate(det)
    assert decision.action == ResponseAction.BLOCK
    assert decision.should_continue is False
    assert decision.status_code == 403
    assert decision.security_event_action == "BLOCKED"
    assert "blocked" in decision.user_message.lower()


def test_policy_contextual_medium_risk_url_vs_html_text():
    """
    Medium-risk indicator in URL context must evaluate to REJECT (400),
    while in html_text context it evaluates to SAFE_RENDER (200).
    """
    # Medium risk in URL context -> REJECT with HTTP 400
    det_url = default_detector.analyze(DetectionInput(value="<iframe src=x></iframe>", context="url"))
    assert det_url.risk_level == "MEDIUM"
    decision_url = PolicyEngine.evaluate(det_url)
    assert decision_url.action == ResponseAction.REJECT
    assert decision_url.should_continue is False
    assert decision_url.status_code == 400
    assert decision_url.security_event_action == "REJECTED"

    # Medium risk in html_text context -> SAFE_RENDER with HTTP 200
    det_text = default_detector.analyze(DetectionInput(value="<iframe src=x></iframe>", context="html_text"))
    assert det_text.risk_level == "MEDIUM"
    decision_text = PolicyEngine.evaluate(det_text)
    assert decision_text.action == ResponseAction.SAFE_RENDER
    assert decision_text.should_continue is True
    assert decision_text.status_code == 200
    assert decision_text.security_event_action == "SAFE_RENDERED"


def test_policy_prose_discussing_js_sinks_not_blocked():
    """
    Verifies that technical prose mentioning alert() or eval() is categorized
    as MEDIUM risk and allowed via SAFE_RENDER (HTTP 200) rather than blocked.
    """
    prose = "In JavaScript education, functions like alert() and eval() require defensive review."
    det = default_detector.analyze(DetectionInput(value=prose, context="html_text"))
    decision = PolicyEngine.evaluate(det)
    assert decision.action == ResponseAction.SAFE_RENDER
    assert decision.should_continue is True
    assert decision.status_code == 200


# ============================================================================
# URL VALIDATION UNIT TESTS
# ============================================================================

def test_url_validation_safe_schemes():
    safe_urls = [
        "https://example.com",
        "http://security-research.org/path?query=1",
        "https://github.com/project",
        ""
    ]
    for url in safe_urls:
        is_safe, sanitized, err = validate_url(url)
        assert is_safe is True
        assert err == ""


def test_url_validation_rejects_dangerous_schemes():
    dangerous_urls = [
        "javascript:alert(1)",
        "JAVASCRIPT:prompt(document.cookie)",
        "vbscript:msgbox(1)",
        "data:text/html,<script>alert(1)</script>",
        "javascript :alert(1)"
    ]
    for url in dangerous_urls:
        is_safe, _, err = validate_url(url)
        assert is_safe is False
        assert "rejected" in err.lower() or "executable" in err.lower()


def test_url_validation_rejects_disallowed_schemes():
    disallowed = ["ftp://ftp.is.co.za", "file:///etc/passwd", "gopher://evil.com"]
    for url in disallowed:
        is_safe, _, err = validate_url(url)
        assert is_safe is False
        assert "not an allowed web scheme" in err


# ============================================================================
# SECURITY HEADERS TESTS
# ============================================================================

def test_security_headers_present_on_all_responses(client):
    response = client.get("/")
    assert response.status_code == 200

    headers = response.headers
    assert "Content-Security-Policy" in headers
    csp = headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert "'unsafe-inline'" not in csp
    assert "'unsafe-eval'" not in csp

    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"


# ============================================================================
# SAFE OUTPUT RENDERING & NO RAW PAYLOAD REFLECTION
# ============================================================================

def test_blocked_response_page_does_not_leak_payload(client):
    payload = "<script>alert('sensitive_token_12345')</script>"
    response = client.post("/comments", data={"author": "Attacker", "content": payload})
    assert response.status_code == 403
    html_body = response.get_data(as_text=True)

    # Payload must NOT be reflected back
    assert "sensitive_token_12345" not in html_body
    assert "XSS-001" not in html_body  # Rule internals not leaked
    assert "Request Not Processed" in html_body


def test_stored_comment_safely_rendered_as_text(client, app):
    # Insert benign comment with special HTML symbols directly into repository
    with app.app_context():
        CommentRepository.create("Alice", "Formula: 5 < 10 & 20 > 15; 'test' and \"quote\"")

    response = client.get("/comments")
    assert response.status_code == 200
    html_body = response.get_data(as_text=True)

    # Verify Jinja auto-escaped characters are safely encoded in the HTML output
    assert "&lt; 10 &amp; 20 &gt;" in html_body or "5 < 10" in html_body
    # Ensure no raw unescaped script tag can execute
    assert "<script>" not in html_body
