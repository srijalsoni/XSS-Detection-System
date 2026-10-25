import json
import pytest
from app import create_app
from database import init_database, SecurityEventRepository


@pytest.fixture
def app(tmp_path):
    """Create Flask application instance with isolated temporary database."""
    test_db = str(tmp_path / "sec_test.db")
    app = create_app("testing")
    app.config["DATABASE_PATH"] = test_db
    init_database(test_db)
    yield app


@pytest.fixture
def client(app):
    return app.test_client()


# ============================================================================
# DATABASE SECURITY EVENT REPOSITORY INTEGRATION (Checks 21-27)
# ============================================================================

def test_security_event_persisted_on_detection(client, app):
    """21-27. Test security event storage, request_id, event_type, rule_id, risk, action, and details."""
    payload = "<script>alert(1)</script>"
    response = client.post("/comments", data={"author": payload, "content": "Valid text message"})
    # Compound exploit pattern evaluates to CRITICAL -> exact HTTP 403 BLOCK
    assert response.status_code == 403

    with app.app_context():
        events = SecurityEventRepository.list_all()
        assert len(events) >= 1
        ev = events[0]
        assert ev["event_type"] == "XSS"
        assert ev["endpoint"] == "/comments"
        assert ev["method"] == "POST"
        assert "XSS-001" in ev["rule_id"]
        assert ev["risk_level"] == "CRITICAL"
        assert ev["action"] == "BLOCKED"
        assert len(ev["input_hash"]) == 64
        assert ev["details"] is not None
        assert "confidence" in ev["details"]
        assert "reasoning" in ev["details"]


# ============================================================================
# ROUTE INTEGRATION TESTS: SEPARATE HIGH (400) VS CRITICAL (403)
# ============================================================================

def test_search_route_high_risk_rejected_with_400(client, app):
    """28a. High-risk single indicator (e.g. script tag without sink) is REJECTED with exact HTTP 400."""
    response = client.post("/search", data={"query": "<script src='http://attacker.com/payload.js'></script>"})
    assert response.status_code == 400

    with app.app_context():
        events = SecurityEventRepository.list_all()
        assert any(e["endpoint"] == "/search" and e["risk_level"] == "HIGH" and e["action"] == "REJECTED" for e in events)


def test_search_route_critical_risk_blocked_with_403(client, app):
    """28b. Critical compound indicator (executable element + event handler) is BLOCKED with exact HTTP 403."""
    response = client.post("/search", data={"query": "<svg onload=alert(1)>"})
    assert response.status_code == 403

    with app.app_context():
        events = SecurityEventRepository.list_all()
        assert any(e["endpoint"] == "/search" and e["risk_level"] == "CRITICAL" and e["action"] == "BLOCKED" for e in events)


def test_comments_route_critical_xss_blocked_with_403(client, app):
    """29. Suspicious comment input (image tag + event handler + sink) is BLOCKED with exact HTTP 403."""
    response = client.post("/comments", data={"author": "Hacker", "content": "<img src=x onerror=alert(1)>"})
    assert response.status_code == 403

    with app.app_context():
        events = SecurityEventRepository.list_all()
        assert any(e["endpoint"] == "/comments" and e["action"] == "BLOCKED" for e in events)


def test_profile_route_pseudo_protocol_rejected_or_blocked(client, app):
    """30. Suspicious profile website URL is blocked/rejected with appropriate policy code."""
    response = client.post("/profile", data={
        "display_name": "Attacker",
        "bio": "Bio content",
        "website": "javascript:alert(document.domain)"
    })
    # Context amplifier elevates javascript: in URL to CRITICAL -> 403
    assert response.status_code == 403

    with app.app_context():
        events = SecurityEventRepository.list_all()
        assert any(e["endpoint"] == "/profile" and "XSS-003" in e["rule_id"] for e in events)


def test_safe_inputs_do_not_create_security_events(client, app):
    """Verify that completely benign inputs do not pollute the security_events table."""
    r1 = client.post("/search", data={"query": "Flask Web Development"})
    assert r1.status_code == 200
    r2 = client.post("/comments", data={"author": "Good User", "content": "Just a normal comment."})
    assert r2.status_code == 200
    r3 = client.post("/profile", data={"display_name": "Normal User", "bio": "Student", "website": "https://valid.org"})
    assert r3.status_code == 200

    with app.app_context():
        events = SecurityEventRepository.list_all()
        assert len(events) == 0


def test_rejected_and_blocked_payloads_are_not_persisted(client, app):
    """Confirms that rejected and blocked submissions are not persisted into database tables."""
    # Attempt blocked comment
    client.post("/comments", data={"author": "Attacker", "content": "<script>alert('never_persist')</script>"})

    # Attempt blocked profile update
    client.post("/profile", data={"display_name": "Attacker", "bio": "Hacked", "website": "javascript:alert(1)"})

    with app.app_context():
        from database import CommentRepository, ProfileRepository
        comments = CommentRepository.list_all()
        assert not any("never_persist" in c["content"] for c in comments)
        prof = ProfileRepository.get_profile()
        assert prof["website"] != "javascript:alert(1)"
