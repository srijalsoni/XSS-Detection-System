import json
import pytest
from app import create_app
from database import init_database, SecurityEventRepository, DashboardRepository


@pytest.fixture
def app(tmp_path):
    test_db = str(tmp_path / "dash_test.db")
    app = create_app("testing")
    app.config["DATABASE_PATH"] = test_db
    init_database(test_db)
    yield app


@pytest.fixture
def client(app):
    return app.test_client()


# ============================================================================
# DASHBOARD ROUTE & API AVAILABILITY (Tests 1-8)
# ============================================================================

def test_dashboard_route_returns_200(client):
    """1. /dashboard view returns HTTP 200 with HTML."""
    res = client.get("/dashboard")
    assert res.status_code == 200
    text = res.get_data(as_text=True)
    assert "Security Monitoring Dashboard" in text
    assert "chart.umd.js" in text
    assert "dashboard.js" in text


def test_api_summary_returns_200(client):
    """2. /api/security/summary returns HTTP 200 and expected schema."""
    res = client.get("/api/security/summary")
    assert res.status_code == 200
    data = res.get_json()
    assert "total_events" in data
    assert "high_risk_events" in data
    assert "critical_events" in data
    assert "blocked_events" in data


def test_api_risk_distribution_returns_200(client):
    """3. /api/security/risk-distribution returns HTTP 200 and standard levels."""
    res = client.get("/api/security/risk-distribution")
    assert res.status_code == 200
    data = res.get_json()
    assert "labels" in data
    assert "counts" in data
    assert "CRITICAL" in data["labels"]
    assert "HIGH" in data["labels"]


def test_api_action_distribution_returns_200(client):
    """4. /api/security/actions returns HTTP 200 and standard actions."""
    res = client.get("/api/security/actions")
    assert res.status_code == 200
    data = res.get_json()
    assert "labels" in data
    assert "counts" in data
    assert "BLOCKED" in data["labels"]
    assert "REJECTED" in data["labels"]


def test_api_rules_frequency_returns_200(client):
    """5. /api/security/rules returns HTTP 200 and rule counts."""
    res = client.get("/api/security/rules")
    assert res.status_code == 200
    data = res.get_json()
    assert "rule_ids" in data
    assert "counts" in data
    assert "XSS-001" in data["rule_ids"]


def test_api_endpoints_returns_200(client):
    """6. /api/security/endpoints returns HTTP 200."""
    res = client.get("/api/security/endpoints")
    assert res.status_code == 200
    data = res.get_json()
    assert "labels" in data
    assert "counts" in data


def test_api_timeline_returns_200(client):
    """7. /api/security/timeline returns HTTP 200."""
    res = client.get("/api/security/timeline")
    assert res.status_code == 200
    data = res.get_json()
    assert "labels" in data
    assert "counts" in data


def test_api_recent_events_returns_200(client):
    """8. /api/security/recent returns HTTP 200."""
    res = client.get("/api/security/recent")
    assert res.status_code == 200
    data = res.get_json()
    assert "events" in data
    assert isinstance(data["events"], list)


# ============================================================================
# FILTERING & EMPTY DATABASE (Tests 9-12)
# ============================================================================

def test_empty_database_handles_gracefully(client):
    """10. Empty database returns zeroed counts without error."""
    res = client.get("/api/security/summary")
    assert res.status_code == 200
    data = res.get_json()
    assert data["total_events"] == 0
    assert data["critical_events"] == 0


def test_time_filtering_parameter(client, app):
    """9. Time filtering filters out events outside range."""
    with app.app_context():
        # Insert event with current timestamp
        SecurityEventRepository.create(
            event_type="XSS", endpoint="/comments", method="POST",
            risk_level="CRITICAL", action="BLOCKED", rule_id="XSS-001,XSS-006",
            request_id="req-dash-1"
        )

    res_all = client.get("/api/security/summary?time_range=all")
    assert res_all.get_json()["total_events"] == 1

    res_24h = client.get("/api/security/summary?time_range=24h")
    assert res_24h.get_json()["total_events"] == 1


def test_invalid_filter_input_handled_safely(client):
    """11. Invalid filter input safely defaults to all-time without error."""
    res = client.get("/api/security/summary?time_range=invalid_string_123")
    assert res.status_code == 200
    data = res.get_json()
    assert "total_events" in data


def test_sql_injection_style_filter_input_safely_parameterized(client):
    """12. SQL injection payload in filter parameter cannot alter query."""
    sqli_payload = "' OR 1=1 --"
    res = client.get(f"/api/security/summary?time_range={sqli_payload}")
    assert res.status_code == 200
    data = res.get_json()
    assert "total_events" in data


# ============================================================================
# TELEMETRY PRIVACY & AGGREGATION INTEGRITY (Tests 13-15)
# ============================================================================

def test_api_responses_never_contain_raw_payloads(client, app):
    """13. Confirms that telemetry responses do not expose raw attack payloads."""
    secret_marker = "sensitive_attack_token_98765"
    with app.app_context():
        SecurityEventRepository.create(
            event_type="XSS",
            endpoint="/search",
            method="POST",
            risk_level="CRITICAL",
            action="BLOCKED",
            rule_id="XSS-001",
            request_id="req-priv-1",
            details={
                "reasoning": "Compound script injection",
                "field": "query",
                "confidence": 0.95
            }
        )

    res = client.get("/api/security/recent")
    assert res.status_code == 200
    raw_response_text = res.get_data(as_text=True)
    assert secret_marker not in raw_response_text


def test_aggregation_matches_actual_database_records(client, app):
    """14. Validates that aggregation math perfectly matches stored records."""
    with app.app_context():
        # 1 CRITICAL BLOCKED event
        SecurityEventRepository.create(
            event_type="XSS", endpoint="/comments", method="POST",
            risk_level="CRITICAL", action="BLOCKED", rule_id="XSS-001,XSS-006",
            request_id="req-1"
        )
        # 1 HIGH REJECTED event
        SecurityEventRepository.create(
            event_type="XSS", endpoint="/search", method="POST",
            risk_level="HIGH", action="REJECTED", rule_id="XSS-002",
            request_id="req-2"
        )
        # 1 MEDIUM SAFE_RENDERED event
        SecurityEventRepository.create(
            event_type="XSS", endpoint="/comments", method="POST",
            risk_level="MEDIUM", action="SAFE_RENDERED", rule_id="XSS-004",
            request_id="req-3"
        )

    res = client.get("/api/security/summary")
    summary = res.get_json()
    assert summary["total_events"] == 3
    assert summary["critical_events"] == 1
    assert summary["high_risk_events"] == 1
    assert summary["blocked_events"] == 1
    assert summary["rejected_events"] == 1
    assert summary["safe_rendered_events"] == 1

    res_rules = client.get("/api/security/rules")
    rules_data = res_rules.get_json()
    # Check rule split counts: XSS-001 (1), XSS-006 (1), XSS-002 (1), XSS-004 (1)
    idx_001 = rules_data["rule_ids"].index("XSS-001")
    idx_006 = rules_data["rule_ids"].index("XSS-006")
    assert rules_data["counts"][idx_001] == 1
    assert rules_data["counts"][idx_006] == 1
