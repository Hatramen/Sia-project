# Local Books

A small, self-hosted book catalog and lending app. Members can create accounts,
borrow available copies, see their due dates, and return books. Administrators
manage the catalog and can view all active loans.

## Run it

1. Install Python 3.10 or later if it is not already installed.
2. Open a terminal in this folder and run:

   ```powershell
   py App.py
   ```

3. Open <http://127.0.0.1:8000> in your browser and create an account with
   first name, last name, email, username, and password.
4. Stop the app with **Ctrl+C** in the terminal.

The app uses only the Python standard library; no package installation is
required. Its first launch creates `library.db` beside the app and adds a few
sample books. The first account is the administrator; later accounts are
members. The administrator has a separate dashboard for the catalog, library
statistics, and all active loans. Members have a personal-loans dashboard.
User accounts, catalog entries, and loan history persist in this database.
Existing installations are migrated on startup; if no administrator exists,
the oldest existing account is promoted. Sessions end when the server stops.

## Lending rules

- Each loan lasts **14 days** from the time it is created.
- A copy cannot be borrowed when all copies are checked out.
- Members can return only their own active loans.
- Returning a book makes the copy available to all members immediately.
- Only the administrator can add books to the shared catalog.
- The catalog can be filtered by title, author, category, availability, and
  sorted by title, author, or copies available.

## Local configuration

By default, the server listens only on `127.0.0.1` and port `8000`. Set
`BOOKS_PORT` to use another port, or set `BOOKS_DB_PATH` to store the SQLite
database at another path. `BOOKS_HOST` can change the listening address; keep it
at `127.0.0.1` unless you intentionally want other devices to connect.

The database schema and starter catalog are defined in [DB.SQL](./DB.SQL).

If you see a database-column error after updating the app, stop the running
server with **Ctrl+C** and start it again with `py App.py`. Startup applies the
account-field migration to the existing `library.db`; do not delete the database.

## Deploy on Vercel

Vercel runs the Flask entrypoint in [server.py](./server.py) (WSGI `app`;
dependencies in [requirements.txt](./requirements.txt)). It serves `/` and all
`/api/*` routes, so the previous `404` (no entrypoint) is fixed.

1. Import the repo in Vercel.
2. Set the `SECRET_KEY` environment variable to a long random value
   (it signs login cookies). Without it the app uses an insecure dev fallback.
3. Deploy. No build command is needed.

Limits: on Vercel the SQLite database lives at `/tmp/library.db` and is
reseeded from [DB.SQL](./DB.SQL), so data does not persist across
deployments or instances. Local `py App.py` behavior is unchanged and still
uses `./library.db`. For durable cloud data, use Postgres instead of SQLite.
