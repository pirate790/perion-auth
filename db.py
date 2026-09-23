import os
import sqlite3

DATABASE_URL = os.environ.get("DATABASE_URL")

# ============================================================
# POSTGRESQL (Production on Render)
# ============================================================
if DATABASE_URL:
    import psycopg
    from psycopg.rows import dict_row

    def get_db():
        return psycopg.connect(DATABASE_URL, row_factory=dict_row)

    def execute_query(cursor, query, params=None):
        cursor.execute(query, params)
        return cursor

    def init_db():
        conn = get_db()
        c = conn.cursor()
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret_encrypted TEXT,
                totp_enabled INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS backup_codes (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                code_hash TEXT NOT NULL,
                used INTEGER DEFAULT 0,
                used_at TIMESTAMP
            )
        """)
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS rate_limits (
                user_id INTEGER PRIMARY KEY,
                attempts INTEGER DEFAULT 0,
                last_attempt TIMESTAMP
            )
        """)
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS used_codes (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                code TEXT NOT NULL,
                used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            )
        """)
        conn.commit()
        conn.close()
        print("PostgreSQL database initialized.")

# ============================================================
# SQLITE (Local testing in Termux)
# ============================================================
else:
    DB_PATH = os.path.join(os.path.dirname(__file__), "auth.db")

    def get_db():
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

    def execute_query(cursor, query, params=None):
        # Convert %s (Postgres) to ? (SQLite)
        sqlite_query = query.replace("%s", "?")
        cursor.execute(sqlite_query, params)
        return cursor

    def init_db():
        conn = get_db()
        c = conn.cursor()
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret_encrypted TEXT,
                totp_enabled INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS backup_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                code_hash TEXT NOT NULL,
                used INTEGER DEFAULT 0,
                used_at TIMESTAMP
            )
        """)
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS rate_limits (
                user_id INTEGER PRIMARY KEY,
                attempts INTEGER DEFAULT 0,
                last_attempt TIMESTAMP
            )
        """)
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS used_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                code TEXT NOT NULL,
                used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        execute_query(c, """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            )
        """)
        conn.commit()
        conn.close()
        print("SQLite database initialized.")

if __name__ == "__main__":
    init_db()
