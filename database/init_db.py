import os
import sys
from datetime import datetime, timezone

# Ensure project root is in sys.path when running as script
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from database.connection import create_connection


def init_database(db_path=None):
    """
    Initialize SQLite database tables, indexes, and seed records safely.
    Can be run repeatedly without destroying existing data.
    """
    if db_path is None:
        db_path = os.path.join(project_root, "database", "app.db")

    conn = create_connection(db_path)
    try:
        schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
        with open(schema_path, "r", encoding="utf-8") as f:
            schema_sql = f.read()

        cursor = conn.cursor()
        cursor.executescript(schema_sql)

        # Seed initial profile if not present
        cursor.execute("SELECT id FROM profile WHERE id = 1")
        row = cursor.fetchone()
        if not row:
            now_utc = datetime.now(timezone.utc).isoformat()
            cursor.execute(
                """
                INSERT INTO profile (id, display_name, bio, website, updated_at)
                VALUES (1, ?, ?, ?, ?)
                """,
                (
                    "Security Researcher",
                    "Specializing in application security and defensive monitoring architecture.",
                    "https://example-security-lab.local",
                    now_utc
                )
            )

        # Seed initial comments if table is empty
        cursor.execute("SELECT COUNT(*) as count FROM comments")
        if cursor.fetchone()["count"] == 0:
            now_utc = datetime.now(timezone.utc).isoformat()
            cursor.execute(
                """
                INSERT INTO comments (author, content, created_at)
                VALUES (?, ?, ?)
                """,
                ("Alice Security", "Welcome to the persistent P_211 security database!", now_utc)
            )
            cursor.execute(
                """
                INSERT INTO comments (author, content, created_at)
                VALUES (?, ?, ?)
                """,
                ("Bob Developer", "Database persistence layer verified with SQLite.", now_utc)
            )

        conn.commit()
        return True
    finally:
        conn.close()


if __name__ == "__main__":
    target_path = sys.argv[1] if len(sys.argv) > 1 else None
    print(f"Initializing database at: {target_path or 'default'}")
    init_database(target_path)
    print("Database initialization completed successfully.")
