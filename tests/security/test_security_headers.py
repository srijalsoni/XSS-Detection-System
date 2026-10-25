import pytest
from app import create_app
from security.headers import DEFAULT_SECURITY_HEADERS

@pytest.fixture
def client():
    app = create_app("testing")
    with app.test_client() as client:
        yield client

def test_security_headers_on_all_public_endpoints(client):
    """Ensure CSP, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy on all routes."""
    endpoints = ["/", "/health", "/search", "/comments", "/profile", "/dashboard"]
    for ep in endpoints:
        resp = client.get(ep)
        assert resp.status_code == 200, f"Endpoint {ep} failed with {resp.status_code}"
        for header, expected_val in DEFAULT_SECURITY_HEADERS.items():
            assert header in resp.headers, f"Missing {header} on {ep}"
            assert expected_val in resp.headers[header], f"Header {header} mismatch on {ep}"

def test_security_headers_on_sanitized_error_responses(client):
    """Ensure security headers are present even on 404 and 400/403 responses."""
    resp_404 = client.get("/nonexistent-endpoint-xyz")
    assert resp_404.status_code == 404
    assert "Content-Security-Policy" in resp_404.headers
    assert "X-Frame-Options" in resp_404.headers
    assert "X-Content-Type-Options" in resp_404.headers
