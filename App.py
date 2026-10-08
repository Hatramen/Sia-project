"""A small, local-only book lending application."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent
DATABASE_PATH = Path(os.environ.get("BOOKS_DB_PATH", ROOT / "library.db"))
SCHEMA_PATH = ROOT / "DB.SQL"
PAGE_PATH = ROOT / "Log-in-Window.HTML"
LOAN_DAYS = 14
SESSION_SECONDS = 12 * 60 * 60
PASSWORD_ITERATIONS = 310_000

sessions: dict[str, tuple[int, float]] = {}
sessions_lock = threading.Lock()


def connect_db() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def database_connection() -> Generator[sqlite3.Connection, None, None]:
    connection = connect_db()
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_database() -> None:
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


class BooksHandler(BaseHTTPRequestHandler):
    server_version = "LocalBooks/1.0"

    def log_message(self, format_string: str, *args: object) -> None:
        print(f"{self.address_string()} - {format_string % args}")

    def send_json(
        self,
        status: HTTPStatus,
        payload: dict[str, object],
        cookie_header: str | None = None,
    ) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        if cookie_header:
            self.send_header("Set-Cookie", cookie_header)
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, status: HTTPStatus, message: str) -> None:
        self.send_json(status, {"error": message})

    def read_json(self) -> dict[str, object]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as error:
            raise ValueError("Invalid request length.") from error
        if length < 1 or length > 16_384:
            raise ValueError("Request body must be between 1 and 16384 bytes.")
        try:
            data = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise ValueError("Request body must be valid JSON.") from error
        if not isinstance(data, dict):
            raise ValueError("Request body must be a JSON object.")
        return data

    def session_id(self) -> str | None:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except CookieError:
            return None
        morsel = cookie.get("local_books_session")
        return morsel.value if morsel else None

    def current_user(self) -> sqlite3.Row | None:
        session_id = self.session_id()
        if not session_id:
            return None
        with sessions_lock:
            session = sessions.get(session_id)
            if session and session[1] <= time.time():
                del sessions[session_id]
                session = None
        if not session:
            return None
        with database_connection() as connection:
            return connection.execute(
                """
                SELECT id, username, display_name, first_name, last_name, email, role
                FROM users WHERE id = ?
                """,
                (session[0],),
            ).fetchone()

    def require_user(self) -> sqlite3.Row | None:
        user = self.current_user()
        if user is None:
            self.send_error_json(HTTPStatus.UNAUTHORIZED, "Please sign in first.")
        return user

    def do_GET(self) -> None:
        route = urlparse(self.path).path
        if route == "/":
            try:
                body = PAGE_PATH.read_bytes()
            except OSError:
                self.send_error_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR, "The app page could not be read."
                )
                return
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                "script-src 'self' 'unsafe-inline'; connect-src 'self'; "
                "base-uri 'none'; frame-ancestors 'none'",
            )
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "same-origin")
            self.end_headers()
            self.wfile.write(body)
            return
        if route == "/api/session":
            user = self.current_user()
            self.send_json(
                HTTPStatus.OK,
                {"user": user_payload(user) if user else None},
            )
            return
        if route == "/api/books":
            if self.require_user() is None:
                return
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
            self.send_json(HTTPStatus.OK, {"books": [dict(row) for row in rows]})
            return
        if route == "/api/loans":
            user = self.require_user()
            if user is None:
                return
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
            self.send_json(HTTPStatus.OK, {"loans": [dict(row) for row in rows]})
            return
        self.send_error_json(HTTPStatus.NOT_FOUND, "That page was not found.")

    def do_POST(self) -> None:
        route = urlparse(self.path).path
        if route == "/api/register":
            self.register()
        elif route == "/api/login":
            self.login()
        elif route == "/api/logout":
            self.logout()
        elif route == "/api/books":
            self.add_book()
        elif route == "/api/borrow":
            self.borrow_book()
        elif route.startswith("/api/loans/") and route.endswith("/return"):
            self.return_book(route)
        elif route == "/api/account":
            self.update_account()
        else:
            self.send_error_json(HTTPStatus.NOT_FOUND, "That page was not found.")

    def request_data(self) -> dict[str, object] | None:
        try:
            return self.read_json()
        except ValueError as error:
            self.send_error_json(HTTPStatus.BAD_REQUEST, str(error))
            return None

    def update_account(self) -> None:
        user = self.require_user()
        if user is None:
            return
        data = self.request_data()
        if data is None:
            return
        display_name_value = data.get("displayName")
        email_value = data.get("email")
        try:
            display_name = clean_text(display_name_value, "Display name", 120)
        except ValueError as error:
            self.send_error_json(HTTPStatus.BAD_REQUEST, str(error))
            return
        email = ""
        if email_value:
            try:
                email = clean_text(email_value, "Email", 254).lower()
            except ValueError as error:
                self.send_error_json(HTTPStatus.BAD_REQUEST, str(error))
                return
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
                self.send_error_json(HTTPStatus.BAD_REQUEST, "Enter a valid email address.")
                return
        with database_connection() as connection:
            connection.execute(
                """
                UPDATE users SET display_name = ?, email = ?
                WHERE id = ?
                """,
                (display_name, email, user["id"]),
            )
        self.send_json(HTTPStatus.OK, {"ok": True})

    def create_session_cookie(self, session_id: str, max_age: int) -> str:
        return (
            f"local_books_session={session_id}; Path=/; HttpOnly; "
            f"SameSite=Strict; Max-Age={max_age}"
        )

    def register(self) -> None:
        data = self.request_data()
        if data is None:
            return
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
        except ValueError as error:
            self.send_error_json(HTTPStatus.BAD_REQUEST, str(error))
            return
        display_name = f"{first_name} {last_name}"
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            self.send_error_json(HTTPStatus.BAD_REQUEST, "Enter a valid email address.")
            return
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
            self.send_error_json(
                HTTPStatus.BAD_REQUEST,
                "Username must be 3-32 letters, numbers, dots, dashes, or underscores.",
            )
            return
        if len(password) < 8:
            self.send_error_json(
                HTTPStatus.BAD_REQUEST, "Password must be at least 8 characters."
            )
            return
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
            self.send_error_json(
                HTTPStatus.CONFLICT, "That username or email is already registered."
            )
            return
        except sqlite3.OperationalError as error:
            print(f"Database error while creating account: {error}")
            self.send_error_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "The account database needs an update. Stop and restart Local Books, then try again.",
            )
            return
        with database_connection() as connection:
            user = connection.execute(
                """
                SELECT username, display_name, first_name, last_name, email, role
                FROM users WHERE id = ?
                """,
                (user_id,),
            ).fetchone()
        self.start_session(user_id, user)

    def login(self) -> None:
        data = self.request_data()
        if data is None:
            return
        username = data.get("username")
        password = data.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            self.send_error_json(HTTPStatus.BAD_REQUEST, "Username and password are required.")
            return
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
            self.send_error_json(HTTPStatus.UNAUTHORIZED, "Username or password is incorrect.")
            return
        self.start_session(user["id"], user)

    def start_session(self, user_id: int, user: sqlite3.Row) -> None:
        session_id = secrets.token_urlsafe(32)
        with sessions_lock:
            sessions[session_id] = (user_id, time.time() + SESSION_SECONDS)
        self.send_json(
            HTTPStatus.OK,
            {"user": user_payload(user)},
            self.create_session_cookie(session_id, SESSION_SECONDS),
        )

    def logout(self) -> None:
        session_id = self.session_id()
        if session_id:
            with sessions_lock:
                sessions.pop(session_id, None)
        self.send_json(
            HTTPStatus.OK,
            {"ok": True},
            self.create_session_cookie("", 0),
        )

    def add_book(self) -> None:
        user = self.require_user()
        if user is None:
            return
        if user["role"] != "admin":
            self.send_error_json(
                HTTPStatus.FORBIDDEN, "Only administrators can add books."
            )
            return
        data = self.request_data()
        if data is None:
            return
        try:
            title = clean_text(data.get("title"), "Title", 160)
            author = clean_text(data.get("author"), "Author", 120)
            category_value = data.get("category", "")
            category = (
                clean_text(category_value, "Category", 60)
                if category_value
                else None
            )
            isbn_value = data.get("isbn", "")
            isbn = clean_text(isbn_value, "ISBN", 20) if isbn_value else None
            copies_value = data.get("copies", 1)
            if isinstance(copies_value, bool) or not isinstance(copies_value, int):
                raise ValueError("Copies must be a whole number.")
            if not 1 <= copies_value <= 999:
                raise ValueError("Copies must be between 1 and 999.")
        except ValueError as error:
            self.send_error_json(HTTPStatus.BAD_REQUEST, str(error))
            return
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
            self.send_error_json(HTTPStatus.CONFLICT, "That ISBN is already in the catalog.")
            return
        self.send_json(HTTPStatus.CREATED, {"ok": True})

    def borrow_book(self) -> None:
        user = self.require_user()
        if user is None:
            return
        data = self.request_data()
        if data is None:
            return
        book_id = data.get("bookId")
        if isinstance(book_id, bool) or not isinstance(book_id, int) or book_id < 1:
            self.send_error_json(HTTPStatus.BAD_REQUEST, "Choose a valid book.")
            return
        borrowed_at = datetime.now(timezone.utc)
        due_at = borrowed_at + timedelta(days=LOAN_DAYS)
        try:
            with database_connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                book = connection.execute(
                    "SELECT copies FROM books WHERE id = ?", (book_id,)
                ).fetchone()
                if not book:
                    self.send_error_json(HTTPStatus.NOT_FOUND, "That book is not in the catalog.")
                    return
                active_count = connection.execute(
                    """
                    SELECT COUNT(*) FROM loans
                    WHERE book_id = ? AND returned_at IS NULL
                    """,
                    (book_id,),
                ).fetchone()[0]
                if active_count >= book["copies"]:
                    self.send_error_json(HTTPStatus.CONFLICT, "No copies are currently available.")
                    return
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
            self.send_error_json(HTTPStatus.CONFLICT, "The book could not be borrowed.")
            return
        self.send_json(
            HTTPStatus.CREATED,
            {"ok": True, "dueAt": due_at.isoformat(timespec="seconds")},
        )

    def return_book(self, route: str) -> None:
        user = self.require_user()
        if user is None:
            return
        try:
            loan_id = int(route.removeprefix("/api/loans/").removesuffix("/return"))
        except ValueError:
            self.send_error_json(HTTPStatus.BAD_REQUEST, "Choose a valid loan.")
            return
        if loan_id < 1:
            self.send_error_json(HTTPStatus.BAD_REQUEST, "Choose a valid loan.")
            return
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
            self.send_error_json(
                HTTPStatus.NOT_FOUND, "That active loan could not be found."
            )
            return
        self.send_json(HTTPStatus.OK, {"ok": True})

    def do_HEAD(self) -> None:
        if urlparse(self.path).path == "/":
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            return
        self.send_error_json(HTTPStatus.NOT_FOUND, "That page was not found.")


def main() -> None:
    initialize_database()
    host = os.environ.get("BOOKS_HOST", "127.0.0.1")
    port = int(os.environ.get("BOOKS_PORT", "8000"))
    server = ThreadingHTTPServer((host, port), BooksHandler)
    print(f"Local Books is running at http://{host}:{port}")
    print(f"Database: {DATABASE_PATH}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down Local Books.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
