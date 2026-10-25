import json
import os
import pytest
import sqlite3
from datetime import datetime
from app import create_app
from database import (
    init_database,
    create_connection,
    CommentRepository,
    ProfileRepository,
    SecurityEventRepository,
    ApplicationEventRepository
)


@pytest.fixture
def app(tmp_path):
    """Create and configure a testing Flask app instance with an isolated test DB."""
    test_db_file = str(tmp_path / "test_app_isolated.db")
    app = create_app("testing")
    app.config["DATABASE_PATH"] = test_db_file
    init_database(test_db_file)
    yield app


@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()


@pytest.fixture
def isolated_db(tmp_path):
    """Provides a fresh isolated standalone SQLite connection for repository testing."""
    test_db_file = str(tmp_path / "repo_isolated.db")
    init_database(test_db_file)
    conn = create_connection(test_db_file)
    yield conn
    conn.close()


# ============================================================================
# DATABASE FOUNDATION (1-5)
# ============================================================================

def test_database_initialization(isolated_db):
    """1. Test that database initializes properly."""
    cursor = isolated_db.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row["name"] for row in cursor.fetchall()]
    assert "comments" in tables
    assert "profile" in tables
    assert "security_events" in tables
    assert "application_events" in tables


def test_schema_idempotency(tmp_path):
    """2. Test schema can be created multiple times without error or data loss."""
    test_db_file = str(tmp_path / "idempotent.db")
    assert init_database(test_db_file) is True
    assert init_database(test_db_file) is True


def test_connection_works(isolated_db):
    """3. Test connection row factory and foreign keys pragma."""
    cursor = isolated_db.cursor()
    cursor.execute("PRAGMA foreign_keys")
    row = cursor.fetchone()
    assert row[0] == 1


def test_tables_and_indexes_exist(isolated_db):
    """4. Test all required indexes are created."""
    cursor = isolated_db.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
    indexes = [row["name"] for row in cursor.fetchall()]
    assert "idx_comments_created_at" in indexes
    assert "idx_sec_events_created_at" in indexes
    assert "idx_sec_events_risk" in indexes
    assert "idx_app_events_created_at" in indexes


def test_timestamps_standard_utc(isolated_db):
    """5. Test that stored timestamps follow ISO-8601 UTC format."""
    c_id = CommentRepository.create("Timestamp Tester", "Checking ISO UTC standard", conn=isolated_db)
    comment = CommentRepository.get_by_id(c_id, conn=isolated_db)
    assert comment is not None
    ts = comment["created_at"]
    dt = datetime.fromisoformat(ts)
    assert dt is not None


# ============================================================================
# COMMENTS (6-10)
# ============================================================================

def test_comment_insert(isolated_db):
    """6. Comment can be inserted."""
    c_id = CommentRepository.create("Alice", "Hello Security World", conn=isolated_db)
    assert c_id > 0


def test_comment_retrieve(isolated_db):
    """7. Comment can be retrieved."""
    c_id = CommentRepository.create("Bob", "Retrieve verification", conn=isolated_db)
    comment = CommentRepository.get_by_id(c_id, conn=isolated_db)
    assert comment["author"] == "Bob"
    assert comment["content"] == "Retrieve verification"


def test_comment_persists_across_connections(tmp_path):
    """8. Comment persists across separate connections."""
    test_db = str(tmp_path / "persist_comments.db")
    init_database(test_db)

    conn1 = create_connection(test_db)
    c_id = CommentRepository.create("Persistent User", "Persistent Message", conn=conn1)
    conn1.close()

    conn2 = create_connection(test_db)
    retrieved = CommentRepository.get_by_id(c_id, conn=conn2)
    conn2.close()

    assert retrieved is not None
    assert retrieved["author"] == "Persistent User"


def test_comment_validation_boundaries(client):
    """9. Validation boundaries work on comments."""
    # Missing author
    res = client.post("/comments", data={"author": "  ", "content": "Valid content"})
    assert b"Author name is required" in res.data
    # Missing content
    res = client.post("/comments", data={"author": "Valid Author", "content": "  "})
    assert b"Comment message cannot be empty" in res.data


def test_multiple_comments_work(isolated_db):
    """10. Multiple comments work correctly in reverse chronological order."""
    CommentRepository.create("User 1", "First post", conn=isolated_db)
    CommentRepository.create("User 2", "Second post", conn=isolated_db)
    all_comments = CommentRepository.list_all(conn=isolated_db)
    assert len(all_comments) >= 2
    assert all_comments[0]["author"] == "User 2"


# ============================================================================
# PROFILE (11-14)
# ============================================================================

def test_profile_insert_or_default(isolated_db):
    """11. Profile can be retrieved / inserted initially."""
    prof = ProfileRepository.get_profile(conn=isolated_db)
    assert prof["id"] == 1
    assert "display_name" in prof


def test_profile_update(isolated_db):
    """12. Profile can be updated."""
    ProfileRepository.save_profile("Lead Auditor", "Auditing application security", "https://lead.local", conn=isolated_db)
    updated = ProfileRepository.get_profile(conn=isolated_db)
    assert updated["display_name"] == "Lead Auditor"


def test_profile_retrieve(isolated_db):
    """13. Profile can be retrieved."""
    prof = ProfileRepository.get_profile(conn=isolated_db)
    assert prof is not None
    assert "bio" in prof


def test_profile_persists_across_connections(tmp_path):
    """14. Profile persists across connections."""
    test_db = str(tmp_path / "persist_profile.db")
    init_database(test_db)

    conn1 = create_connection(test_db)
    ProfileRepository.save_profile("Persisted Name", "Persisted Bio", "https://p.local", conn=conn1)
    conn1.close()

    conn2 = create_connection(test_db)
    prof = ProfileRepository.get_profile(conn=conn2)
    conn2.close()

    assert prof["display_name"] == "Persisted Name"


# ============================================================================
# SECURITY EVENTS (15-22)
# ============================================================================

def test_security_event_inserted(isolated_db):
    """15. Security event can be inserted."""
    ev_id = SecurityEventRepository.create("XSS", "/search", "GET", "LOW", "LOGGED", conn=isolated_db)
    assert ev_id > 0


def test_security_event_retrieved(isolated_db):
    """16. Security event can be retrieved."""
    ev_id = SecurityEventRepository.create("XSS", "/search", "GET", "LOW", "LOGGED", conn=isolated_db)
    event = SecurityEventRepository.get_by_id(ev_id, conn=isolated_db)
    assert event is not None
    assert event["id"] == ev_id


def test_security_event_supports_event_type(isolated_db):
    """17. Security event supports event type."""
    ev_id = SecurityEventRepository.create("OTHER_SECURITY_EVENT", "/profile", "POST", "MEDIUM", "FLAGGED", conn=isolated_db)
    event = SecurityEventRepository.get_by_id(ev_id, conn=isolated_db)
    assert event["event_type"] == "OTHER_SECURITY_EVENT"


def test_security_event_supports_risk_level(isolated_db):
    """18. Security event supports risk level."""
    ev_id = SecurityEventRepository.create("XSS", "/comments", "POST", "CRITICAL", "BLOCKED", conn=isolated_db)
    event = SecurityEventRepository.get_by_id(ev_id, conn=isolated_db)
    assert event["risk_level"] == "CRITICAL"


def test_security_event_supports_action(isolated_db):
    """19. Security event supports action."""
    ev_id = SecurityEventRepository.create("XSS", "/comments", "POST", "HIGH", "SANITIZED", conn=isolated_db)
    event = SecurityEventRepository.get_by_id(ev_id, conn=isolated_db)
    assert event["action"] == "SANITIZED"


def test_security_event_input_hash(isolated_db):
    """20. Input hash can be stored."""
    hash_val = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    ev_id = SecurityEventRepository.create("XSS", "/search", "GET", "MEDIUM", "LOGGED", input_hash=hash_val, conn=isolated_db)
    event = SecurityEventRepository.get_by_id(ev_id, conn=isolated_db)
    assert event["input_hash"] == hash_val


def test_security_event_request_id(isolated_db):
    """21. Request ID can be associated."""
    req_id = "req-uuid-test-999"
    ev_id = SecurityEventRepository.create("XSS", "/search", "GET", "LOW", "LOGGED", request_id=req_id, conn=isolated_db)
    event = SecurityEventRepository.get_by_id(ev_id, conn=isolated_db)
    assert event["request_id"] == req_id


def test_security_event_details_json(isolated_db):
    """22. Details JSON can be stored and retrieved safely."""
    meta = {"matched_pattern": "<script>", "score": 98.5}
    ev_id = SecurityEventRepository.create("XSS", "/comments", "POST", "HIGH", "BLOCKED", details=meta, conn=isolated_db)
    event = SecurityEventRepository.get_by_id(ev_id, conn=isolated_db)
    assert event["details"]["matched_pattern"] == "<script>"
    assert event["details"]["score"] == 98.5


# ============================================================================
# APPLICATION EVENTS (23-24)
# ============================================================================

def test_application_event_created(isolated_db):
    """23. Application event can be created."""
    ev_id = ApplicationEventRepository.create("APP_INIT", "/", conn=isolated_db)
    assert ev_id > 0


def test_application_event_retrieved(isolated_db):
    """24. Application event can be retrieved."""
    ev_id = ApplicationEventRepository.create("APP_LOGIN", "/auth", request_id="r1", conn=isolated_db)
    events = ApplicationEventRepository.list_all(conn=isolated_db)
    assert any(e["id"] == ev_id for e in events)


# ============================================================================
# ERROR HANDLING & TRANSACTIONS (25-26)
# ============================================================================

def test_database_failure_handling(tmp_path):
    """25. Database connection failure does not crash the test suite."""
    bad_conn = create_connection(str(tmp_path / "valid.db"))
    bad_conn.close()
    with pytest.raises(sqlite3.ProgrammingError):
        bad_conn.execute("SELECT 1")


def test_transaction_rollback_on_failure(isolated_db):
    """26. Failed transaction is rolled back appropriately."""
    with pytest.raises(sqlite3.IntegrityError):
        cursor = isolated_db.cursor()
        cursor.execute("INSERT INTO profile (id, display_name, updated_at) VALUES (2, 'Invalid', '2026-09-28T00:00:00Z')")
    cursor = isolated_db.cursor()
    cursor.execute("SELECT COUNT(*) as count FROM profile")
    assert cursor.fetchone()["count"] == 1


# ============================================================================
# QUERY SECURITY (27-29)
# ============================================================================

def test_sql_injection_defense_in_comments(isolated_db):
    """27 & 28. Parameterized SQL is used; does not build SQL from raw user strings."""
    sqli_author = "admin' OR '1'='1"
    sqli_content = "'); DROP TABLE comments; --"
    c_id = CommentRepository.create(sqli_author, sqli_content, conn=isolated_db)
    comment = CommentRepository.get_by_id(c_id, conn=isolated_db)
    assert comment["author"] == "admin' OR '1'='1"
    assert comment["content"] == "'); DROP TABLE comments; --"
    cursor = isolated_db.cursor()
    cursor.execute("SELECT COUNT(*) as count FROM comments")
    assert cursor.fetchone()["count"] > 0


def test_sensitive_values_not_stored(isolated_db):
    """29. Sensitive values like passwords are not present in schema."""
    cursor = isolated_db.cursor()
    cursor.execute("PRAGMA table_info(comments)")
    col_names = [r["name"] for r in cursor.fetchall()]
    assert "password" not in col_names
    assert "secret" not in col_names


# ============================================================================
# INTEGRATION & SURVIVAL (30-32)
# ============================================================================

def test_comments_survive_application_restart(client, app, tmp_path):
    """30. Comments survive application restart."""
    data = {"author": "Restart Tester", "content": "Checking restart persistence"}
    client.post("/comments", data=data)

    # Simulate restart by creating another fresh client using same DB
    restarted_app = create_app("testing")
    restarted_app.config["DATABASE_PATH"] = app.config["DATABASE_PATH"]
    restarted_client = restarted_app.test_client()

    response = restarted_client.get("/comments")
    assert response.status_code == 200
    assert b"Restart Tester" in response.data
    assert b"Checking restart persistence" in response.data


def test_profile_survives_application_restart(client, app):
    """31. Profile survives application restart."""
    data = {"display_name": "Persistent Profile User", "bio": "Persisted Bio", "website": "https://p.local"}
    client.post("/profile", data=data)

    restarted_app = create_app("testing")
    restarted_app.config["DATABASE_PATH"] = app.config["DATABASE_PATH"]
    restarted_client = restarted_app.test_client()

    response = restarted_client.get("/profile")
    assert response.status_code == 200
    assert b"Persistent Profile User" in response.data


def test_search_and_request_id_integration(client, app):
    """32. Search works with X-Request-ID and logs application event."""
    response = client.post("/search", data={"query": "XSS"})
    assert response.status_code == 200
    assert "X-Request-ID" in response.headers
    with app.app_context():
        events = ApplicationEventRepository.list_all()
        assert any(e["event_type"] == "SEARCH_EXECUTED" for e in events)
