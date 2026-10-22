"""A small, safe example: the scanner should report no security issues here."""
import os
import secrets
import sqlite3


def get_user(conn: sqlite3.Connection, user_id: int):
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def new_token() -> str:
    return secrets.token_urlsafe(32)


DB_PASSWORD = os.environ.get("DB_PASSWORD")
