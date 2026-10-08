"""WSGI entrypoint for Vercel (Flask preset).

Vercel detects this file because it defines a top-level ``app`` Flask
instance. Local development is unchanged: keep running ``py App.py``.
This module mirrors the routes in ``App.py`` so the same frontend
(``Log-in-Window.HTML``) works on Vercel.

Storage note: Vercel's filesystem is ephemeral/mobile. The SQLite database
lives at ``/tmp/library.db`` there (reseeded from ``DB.SQL``), so data does
not persist across deployments/instances. For durable data, point
``BOOKS_DB_PATH`` at persistent storage or migrate to Postgres.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, jsonify, request, session

ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT / "DB.SQL"
PAGE_PATH = ROOT / "Log-in-Window.HTML"
LOAN_DAYS = 14
PASSWORD_ITERATIONS = 310_000


def database_path() -> Path:
    override = os.environ.get("BOOKS_DB_PATH")
    if override:
        return Path(override)
    if os.environ.get("VERCEL") == "1":
        return Path("/tmp/library.db")
    return ROOT / "library.db"


@contextmanager
def database_connection():
    connection = sqlite3.connect(str(database_path()), timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_database() -> None:
    path = database_path()
    if path.parent and str(path.parent) not in ("", "."):
        path.parent.mkdir(parents=True, exist_ok=True)
    with database_connection() as connection:
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(users)")
        }
        migrations = {
            "first_name": "TEXT NOT NULL DEFAULT ''",
            "last_name": "TEXT NOT NULL DEFAULT ''",
            "email": "TEXT NOT NULL DEFAULT ''",
            "role": "TEXT NOT NULL DEFAULT 'member'",
        }
        for name, declaration in migrations.items():
            if name not in columns:
                connection.execute(
                    f"ALTER TABLE users ADD COLUMN {name} {declaration}"
                )
        users = connection.execute(
            """
            SELECT id, display_name, first_name, last_name
            FROM users WHERE first_name = '' OR last_name = ''
            """
        ).fetchall()
        for user in users:
            name_parts = user["display_name"].strip().split(maxsplit=1)
            first_name = name_parts[0] if name_parts else "Member"
            last_name = name_parts[1] if len(name_parts) > 1 else ""
            connection.execute(
                """
                UPDATE users SET first_name = ?, last_name = ?
                WHERE id = ?
                """,
                (
                    user["first_name"] or first_name,
                    user["last_name"] or last_name,
                    user["id"],
                ),
            )
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique
            ON users(email COLLATE NOCASE) WHERE email <> ''
            """
        )
        connection.execute(
            """
            UPDATE users SET role = 'admin'
            WHERE id = (SELECT id FROM users ORDER BY id LIMIT 1)
              AND NOT EXISTS (SELECT 1 FROM users WHERE role = 'admin')
            """
        )


def user_payload(user: sqlite3.Row) -> dict[str, str]:
    return {
        "username": user["username"],
        "displayName": user["display_name"],
        "firstName": user["first_name"],
        "lastName": user["last_name"],
        "email": user["email"],
        "role": user["role"],
    }


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return f"{salt.hex()}:{digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_hex, digest_hex = stored_hash.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return hmac.compare_digest(actual, expected)


def clean_text(value: object, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} is required.")
    result = value.strip()
    if not result:
        raise ValueError(f"{field} is required.")
    if len(result) > maximum:
        raise ValueError(f"{field} must be between 1 and {maximum} characters.")
    return result


def error(message: str, status: int):
    return jsonify({"error": message}), status


def read_body() -> dict | None:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None
    return data


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with database_connection() as connection:
        return connection.execute(
            """
            SELECT id, username, display_name, first_name, last_name, email, role
            FROM users WHERE id = ?
            """,
            (user_id,),
        ).fetchone()


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-insecure-key-change-me")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
if os.environ.get("VERCEL") == "1":
    app.config["SESSION_COOKIE_SECURE"] = True

initialize_database()


@app.before_request
def _ensure_db():
    initialize_database()


@app.get("/")
def index():
    try:
        body = PAGE_PATH.read_bytes()
    except OSError:
        return error("The app page could not be read.", 500)
    response = app.response_class(body, mimetype="text/html")
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; connect-src 'self'; "
        "base-uri 'none'; frame-ancestors 'none'"
    )
    return response


@app.get("/api/session")
def api_session():
    user = current_user()
    return jsonify({"user": user_payload(user) if user else None})


@app.get("/api/books")
def api_books():
    if current_user() is None:
        return error("Please sign in first.", 401)
    with database_connection() as connection:
        rows = connection.execute(
            """
            SELECT b.id, b.title, b.author, b.category, b.isbn, b.copies,
                   b.created_at,
                   b.copies - (
                       SELECT COUNT(*) FROM loans l
                       WHERE l.book_id = b.id AND l.returned_at IS NULL
                   ) AS available
            FROM books b
            ORDER BY b.title COLLATE NOCASE, b.author COLLATE NOCASE
            """
        ).fetchall()
    return jsonify({"books": [dict(row) for row in rows]})


@app.get("/api/loans")
def api_loans():
    user = current_user()
    if user is None:
        return error("Please sign in first.", 401)
    with database_connection() as connection:
        if user["role"] == "admin":
            rows = connection.execute(
                """
                SELECT l.id, l.book_id, b.title, b.author, l.borrowed_at,
                       l.due_at, l.returned_at, u.first_name, u.last_name,
                       u.username
                FROM loans l
                JOIN books b ON b.id = l.book_id
                JOIN users u ON u.id = l.user_id
                WHERE l.returned_at IS NULL
                ORDER BY l.due_at
                """
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT l.id, l.book_id, b.title, b.author, l.borrowed_at,
                       l.due_at, l.returned_at, u.first_name, u.last_name,
                       u.username
                FROM loans l
                JOIN books b ON b.id = l.book_id
                JOIN users u ON u.id = l.user_id
                WHERE l.user_id = ? AND l.returned_at IS NULL
                ORDER BY l.due_at
                """,
                (user["id"],),
            ).fetchall()
    return jsonify({"loans": [dict(row) for row in rows]})


def _start_session(user_id: int, user: sqlite3.Row):
    session.clear()
    session["user_id"] = user_id
    return jsonify({"user": user_payload(user)})


@app.post("/api/register")
def api_register():
    data = read_body()
    if data is None:
        return error("Request body must be valid JSON.", 400)
    try:
        username = clean_text(data.get("username"), "Username", 32)
        first_name = clean_text(data.get("firstName"), "First name", 80)
        last_name = clean_text(data.get("lastName"), "Last name", 80)
        email = clean_text(data.get("email"), "Email", 254).lower()
        password_value = data.get("password")
        if (
            not isinstance(password_value, str)
            or not password_value
            or len(password_value) > 256
        ):
            raise ValueError("Password must be between 1 and 256 characters.")
        password = password_value
    except ValueError as exc:
        return error(str(exc), 400)
    display_name = f"{first_name} {last_name}"
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return error("Enter a valid email address.", 400)
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
        return error(
            "Username must be 3-32 letters, numbers, dots, dashes, or underscores.",
            400,
        )
    if len(password) < 8:
        return error("Password must be at least 8 characters.", 400)
    try:
        with database_connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            role = (
                "admin"
                if connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
                else "member"
            )
            cursor = connection.execute(
                """
                INSERT INTO users (
                    username, display_name, first_name, last_name,
                    email, role, password_hash
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    username,
                    display_name,
                    first_name,
                    last_name,
                    email,
                    role,
                    hash_password(password),
                ),
            )
            user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        return error("That username or email is already registered.", 409)
    except sqlite3.OperationalError:
        return error(
            "The account database needs an update. Stop and restart Local Books, then try again.",
            500,
        )
    with database_connection() as connection:
        user = connection.execute(
            """
            SELECT username, display_name, first_name, last_name, email, role
            FROM users WHERE id = ?
            """,
            (user_id,),
        ).fetchone()
    return _start_session(user_id, user)


@app.post("/api/login")
def api_login():
    data = read_body()
    if data is None:
        return error("Request body must be valid JSON.", 400)
    username = data.get("username")
    password = data.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        return error("Username and password are required.", 400)
    with database_connection() as connection:
        user = connection.execute(
            """
            SELECT id, username, display_name, first_name, last_name,
                   email, role, password_hash
            FROM users WHERE username = ? COLLATE NOCASE
            """,
            (username.strip(),),
        ).fetchone()
    if not user or not verify_password(password, user["password_hash"]):
        return error("Username or password is incorrect.", 401)
    return _start_session(user["id"], user)


@app.post("/api/logout")
def api_logout():
    session.clear()
    return jsonify({"ok": True})


@app.post("/api/books")
def api_add_book():
    user = current_user()
    if user is None:
        return error("Please sign in first.", 401)
    if user["role"] != "admin":
        return error("Only administrators can add books.", 403)
    data = read_body()
    if data is None:
        return error("Request body must be valid JSON.", 400)
    try:
        title = clean_text(data.get("title"), "Title", 160)
        author = clean_text(data.get("author"), "Author", 120)
        category_value = data.get("category", "")
        category = (
            clean_text(category_value, "Category", 60) if category_value else None
        )
        isbn_value = data.get("isbn", "")
        isbn = clean_text(isbn_value, "ISBN", 20) if isbn_value else None
        copies_value = data.get("copies", 1)
        if isinstance(copies_value, bool) or not isinstance(copies_value, int):
            raise ValueError("Copies must be a whole number.")
        if not 1 <= copies_value <= 999:
            raise ValueError("Copies must be between 1 and 999.")
    except ValueError as exc:
        return error(str(exc), 400)
    try:
        with database_connection() as connection:
            connection.execute(
                """
                INSERT INTO books (title, author, category, isbn, copies)
                VALUES (?, ?, ?, ?, ?)
                """,
                (title, author, category, isbn, copies_value),
            )
    except sqlite3.IntegrityError:
        return error("That ISBN is already in the catalog.", 409)
    return jsonify({"ok": True}), 201


@app.post("/api/borrow")
def api_borrow():
    user = current_user()
    if user is None:
        return error("Please sign in first.", 401)
    data = read_body()
    if data is None:
        return error("Request body must be valid JSON.", 400)
    book_id = data.get("bookId")
    if isinstance(book_id, bool) or not isinstance(book_id, int) or book_id < 1:
        return error("Choose a valid book.", 400)
    borrowed_at = datetime.now(timezone.utc)
    due_at = borrowed_at + timedelta(days=LOAN_DAYS)
    try:
        with database_connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            book = connection.execute(
                "SELECT copies FROM books WHERE id = ?", (book_id,)
            ).fetchone()
            if not book:
                return error("That book is not in the catalog.", 404)
            active_count = connection.execute(
                """
                SELECT COUNT(*) FROM loans
                WHERE book_id = ? AND returned_at IS NULL
                """,
                (book_id,),
            ).fetchone()[0]
            if active_count >= book["copies"]:
                return error("No copies are currently available.", 409)
            connection.execute(
                """
                INSERT INTO loans (user_id, book_id, borrowed_at, due_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    user["id"],
                    book_id,
                    borrowed_at.isoformat(timespec="seconds"),
                    due_at.isoformat(timespec="seconds"),
                ),
            )
    except sqlite3.IntegrityError:
        return error("The book could not be borrowed.", 409)
    return jsonify({"ok": True, "dueAt": due_at.isoformat(timespec="seconds")}), 201


@app.post("/api/loans/<int:loan_id>/return")
def api_return(loan_id: int):
    user = current_user()
    if user is None:
        return error("Please sign in first.", 401)
    if loan_id < 1:
        return error("Choose a valid loan.", 400)
    returned_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with database_connection() as connection:
        cursor = connection.execute(
            """
            UPDATE loans SET returned_at = ?
            WHERE id = ? AND returned_at IS NULL
              AND (? = 'admin' OR user_id = ?)
            """,
            (returned_at, loan_id, user["role"], user["id"]),
        )
    if cursor.rowcount != 1:
        return error("That active loan could not be found.", 404)
    return jsonify({"ok": True})


@app.post("/api/account")
def api_account():
    user = current_user()
    if user is None:
        return error("Please sign in first.", 401)
    data = read_body()
    if data is None:
        return error("Request body must be valid JSON.", 400)
    try:
        display_name = clean_text(data.get("displayName"), "Display name", 120)
    except ValueError as exc:
        return error(str(exc), 400)
    email = ""
    if data.get("email"):
        try:
            email = clean_text(data.get("email"), "Email", 254).lower()
        except ValueError as exc:
            return error(str(exc), 400)
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            return error("Enter a valid email address.", 400)
    with database_connection() as connection:
        connection.execute(
            """
            UPDATE users SET display_name = ?, email = ?
            WHERE id = ?
            """,
            (display_name, email, user["id"]),
        )
    return jsonify({"ok": True})
