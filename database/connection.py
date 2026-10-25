import sqlite3
import os
from flask import g, current_app


def get_db_path():
    """Return the database path from Flask config or default fallback."""
    if current_app:
        return current_app.config.get("DATABASE_PATH", os.path.join("database", "app.db"))
    return os.path.join("database", "app.db")


def create_connection(db_path=None):
    """
    Establish a standalone SQLite database connection with row factory
    and foreign key constraints enabled.
    """
    if db_path is None:
        db_path = get_db_path()

    # Ensure parent directory exists
    parent_dir = os.path.dirname(db_path)
    if parent_dir and not os.path.exists(parent_dir):
        os.makedirs(parent_dir, exist_ok=True)

    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def get_db():
    """
    Get the SQLite connection bound to the current Flask application context.
    Creates a new connection if none exists for this request.
    """
    if "db" not in g:
        g.db = create_connection()
    return g.db


def close_db(e=None):
    """Close the database connection bound to the current Flask context."""
    db = g.pop("db", None)
    if db is not None:
        db.close()
