import json
import sqlite3
from datetime import datetime, timezone
from database.connection import get_db, create_connection


def utc_now_iso():
    """Return standard ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


# ============================================================================
# COMMENTS REPOSITORY
# ============================================================================

class CommentRepository:
    @staticmethod
    def create(author, content, conn=None):
        """Create a new comment using parameterized SQL."""
        db = conn or get_db()
        created_at = utc_now_iso()
        cursor = db.cursor()
        cursor.execute(
            """
            INSERT INTO comments (author, content, created_at)
            VALUES (?, ?, ?)
            """,
            (author, content, created_at)
        )
        db.commit()
        return cursor.lastrowid

    @staticmethod
    def list_all(conn=None):
        """Retrieve all comments sorted in reverse chronological order."""
        db = conn or get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id, author, content, created_at FROM comments ORDER BY id DESC")
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def get_by_id(comment_id, conn=None):
        """Retrieve a specific comment by id."""
        db = conn or get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id, author, content, created_at FROM comments WHERE id = ?", (comment_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


# ============================================================================
# PROFILE REPOSITORY
# ============================================================================

class ProfileRepository:
    @staticmethod
    def get_profile(conn=None):
        """Retrieve the demonstration researcher profile record."""
        db = conn or get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id, display_name, bio, website, updated_at FROM profile WHERE id = 1")
        row = cursor.fetchone()
        if row:
            return dict(row)
        return {
            "id": 1,
            "display_name": "Security Researcher",
            "bio": "Defensive application security researcher.",
            "website": "https://example.local",
            "updated_at": utc_now_iso()
        }

    @staticmethod
    def save_profile(display_name, bio, website, conn=None):
        """Save or update the single profile record with parameterized SQL."""
        db = conn or get_db()
        updated_at = utc_now_iso()
        cursor = db.cursor()
        cursor.execute(
            """
            INSERT INTO profile (id, display_name, bio, website, updated_at)
            VALUES (1, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                display_name = excluded.display_name,
                bio = excluded.bio,
                website = excluded.website,
                updated_at = excluded.updated_at
            """,
            (display_name, bio, website, updated_at)
        )
        db.commit()
        return True


# ============================================================================
# SECURITY EVENTS REPOSITORY
# ============================================================================

class SecurityEventRepository:
    @staticmethod
    def create(event_type, endpoint, method, risk_level, action, rule_id=None, input_hash=None, request_id=None, details=None, conn=None):
        """
        Record a security telemetry / detection event using parameterized SQL.
        Stores metadata and structured details safely without raw attack payloads.
        """
        db = conn or get_db()
        created_at = utc_now_iso()
        details_json = json.dumps(details) if details is not None else None

        cursor = db.cursor()
        cursor.execute(
            """
            INSERT INTO security_events (
                created_at, event_type, endpoint, method, risk_level, action,
                rule_id, input_hash, request_id, details_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (created_at, event_type, endpoint, method, risk_level, action, rule_id, input_hash, request_id, details_json)
        )
        db.commit()
        return cursor.lastrowid

    @staticmethod
    def list_all(limit=100, conn=None):
        """Retrieve security events in reverse chronological order."""
        db = conn or get_db()
        cursor = db.cursor()
        cursor.execute(
            """
            SELECT id, created_at, event_type, endpoint, method, risk_level, action,
                   rule_id, input_hash, request_id, details_json
            FROM security_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,)
        )
        rows = cursor.fetchall()
        results = []
        for r in rows:
            item = dict(r)
            if item.get("details_json"):
                try:
                    item["details"] = json.loads(item["details_json"])
                except Exception:
                    item["details"] = None
            else:
                item["details"] = None
            results.append(item)
        return results

    @staticmethod
    def get_by_id(event_id, conn=None):
        """Retrieve a security event by id."""
        db = conn or get_db()
        cursor = db.cursor()
        cursor.execute(
            """
            SELECT id, created_at, event_type, endpoint, method, risk_level, action,
                   rule_id, input_hash, request_id, details_json
            FROM security_events
            WHERE id = ?
            """,
            (event_id,)
        )
        row = cursor.fetchone()
        if not row:
            return None
        item = dict(row)
        if item.get("details_json"):
            try:
                item["details"] = json.loads(item["details_json"])
            except Exception:
                item["details"] = None
        else:
            item["details"] = None
        return item

    @staticmethod
    def get_by_request_id(request_id, conn=None):
        """Retrieve security events associated with a specific request correlation ID."""
        if not request_id:
            return []
        db = conn or get_db()
        cursor = db.cursor()
        cursor.execute(
            """
            SELECT id, created_at, event_type, endpoint, method, risk_level, action,
                   rule_id, input_hash, request_id, details_json
            FROM security_events
            WHERE request_id = ?
            ORDER BY id ASC
            """,
            (request_id,)
        )
        rows = cursor.fetchall()
        results = []
        for r in rows:
            item = dict(r)
            if item.get("details_json"):
                try:
                    item["details"] = json.loads(item["details_json"])
                except Exception:
                    item["details"] = None
            else:
                item["details"] = None
            results.append(item)
        return results


# ============================================================================
# APPLICATION EVENTS REPOSITORY
# ============================================================================

class ApplicationEventRepository:
    @staticmethod
    def create(event_type, endpoint, request_id=None, details=None, conn=None):
        """Record general application behavior telemetry."""
        db = conn or get_db()
        created_at = utc_now_iso()
        details_json = json.dumps(details) if details is not None else None

        cursor = db.cursor()
        cursor.execute(
            """
            INSERT INTO application_events (created_at, event_type, endpoint, request_id, details_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, event_type, endpoint, request_id, details_json)
        )
        db.commit()
        return cursor.lastrowid

    @staticmethod
    def list_all(limit=100, conn=None):
        """Retrieve application events."""
        db = conn or get_db()
        cursor = db.cursor()
        cursor.execute(
            """
            SELECT id, created_at, event_type, endpoint, request_id, details_json
            FROM application_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,)
        )
        rows = cursor.fetchall()
        results = []
        for r in rows:
            item = dict(r)
            if item.get("details_json"):
                try:
                    item["details"] = json.loads(item["details_json"])
                except Exception:
                    item["details"] = None
            else:
                item["details"] = None
            results.append(item)
        return results
