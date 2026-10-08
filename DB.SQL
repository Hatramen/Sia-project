PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    display_name TEXT NOT NULL,
    first_name TEXT NOT NULL DEFAULT '',
    last_name TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member')),
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS books (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    author TEXT NOT NULL,
    category TEXT,
    isbn TEXT UNIQUE,
    copies INTEGER NOT NULL DEFAULT 1 CHECK (copies BETWEEN 1 AND 999),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS loans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    book_id INTEGER NOT NULL REFERENCES books(id),
    borrowed_at TEXT NOT NULL,
    due_at TEXT NOT NULL,
    returned_at TEXT,
    CHECK (due_at > borrowed_at)
);

CREATE INDEX IF NOT EXISTS idx_loans_active_book
    ON loans(book_id, returned_at);
CREATE INDEX IF NOT EXISTS idx_loans_user_active
    ON loans(user_id, returned_at);

INSERT OR IGNORE INTO books (title, author, category, isbn, copies)
SELECT 'Pride and Prejudice', 'Jane Austen', 'Classic fiction', '9780141439518', 2
WHERE NOT EXISTS (SELECT 1 FROM books WHERE title = 'Pride and Prejudice' AND author = 'Jane Austen');
INSERT OR IGNORE INTO books (title, author, category, isbn, copies)
SELECT 'The Adventures of Sherlock Holmes', 'Arthur Conan Doyle', 'Mystery', NULL, 1
WHERE NOT EXISTS (SELECT 1 FROM books WHERE title = 'The Adventures of Sherlock Holmes' AND author = 'Arthur Conan Doyle');
INSERT OR IGNORE INTO books (title, author, category, isbn, copies)
SELECT 'The Secret Garden', 'Frances Hodgson Burnett', 'Children''s fiction', '9780141321065', 1
WHERE NOT EXISTS (SELECT 1 FROM books WHERE title = 'The Secret Garden' AND author = 'Frances Hodgson Burnett');
INSERT OR IGNORE INTO books (title, author, category, isbn, copies)
SELECT 'A Brief History of Time', 'Stephen Hawking', 'Science', '9780553380163', 1
WHERE NOT EXISTS (SELECT 1 FROM books WHERE title = 'A Brief History of Time' AND author = 'Stephen Hawking');