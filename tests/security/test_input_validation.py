import pytest
from app import create_app

@pytest.fixture
def client():
    app = create_app("testing")
    with app.test_client() as client:
        yield client

def test_search_length_boundary_validation(client):
    """Validate search query 100 character boundary limit."""
    # 1. Normal length (90 chars)
    resp = client.post("/search", data={"query": "A" * 90})
    assert resp.status_code == 200
    assert "Search query exceeds" not in resp.get_data(as_text=True)

    # 2. Exceeds boundary (101 chars)
    resp = client.post("/search", data={"query": "A" * 101})
    assert resp.status_code == 200
    assert "Search query exceeds maximum length of 100 characters" in resp.get_data(as_text=True)

def test_comments_length_and_presence_validation(client):
    """Validate comments author (50) and content (500) boundaries."""
    # Empty author
    resp = client.post("/comments", data={"author": "", "content": "Valid content"})
    assert resp.status_code == 200
    assert "Author name is required" in resp.get_data(as_text=True)

    # Empty content
    resp = client.post("/comments", data={"author": "Valid Author", "content": ""})
    assert resp.status_code == 200
    assert "Comment message cannot be empty" in resp.get_data(as_text=True)

    # Author > 50 chars
    resp = client.post("/comments", data={"author": "A" * 51, "content": "Valid content"})
    assert resp.status_code == 200
    assert "Author name must not exceed 50 characters" in resp.get_data(as_text=True)

    # Content > 500 chars
    resp = client.post("/comments", data={"author": "Valid Author", "content": "A" * 501})
    assert resp.status_code == 200
    assert "Comment message must not exceed 500 characters" in resp.get_data(as_text=True)

def test_profile_url_scheme_validation(client):
    """Validate profile website URL scheme restriction."""
    # Safe HTTP/HTTPS
    resp = client.post("/profile", data={
        "display_name": "ValidUser",
        "bio": "Valid Bio",
        "website": "https://example.com"
    })
    assert resp.status_code == 200
    assert "successfully" in resp.get_data(as_text=True).lower()

    # Disallowed scheme (e.g. ftp)
    resp = client.post("/profile", data={
        "display_name": "ValidUser",
        "bio": "Valid Bio",
        "website": "ftp://files.example.com"
    })
    assert resp.status_code == 200
    assert "not an allowed web scheme" in resp.get_data(as_text=True).lower()
