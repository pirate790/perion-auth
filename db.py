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

    def _column_exists(cursor, table, column):
        cursor.execute("""
            SELECT 1 FROM information_schema.columns
            WHERE table_name = %s AND column_name = %s
        """, (table, column))
        return cursor.fetchone() is not None

    def _add_column_safe(cursor, table, column, definition):
        if not _column_exists(cursor, table, column):
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def init_db():
        conn = get_db()
        c = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret_encrypted TEXT,
                totp_enabled INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        _add_column_safe(c, "users", "display_name", "TEXT")
        _add_column_safe(c, "users", "recovery_email", "TEXT")
        _add_column_safe(c, "users", "recovery_phone", "TEXT")
        _add_column_safe(c, "users", "session_length", "INTEGER DEFAULT 30")
        _add_column_safe(c, "users", "last_login", "TIMESTAMP")
        _add_column_safe(c, "users", "is_admin", "INTEGER DEFAULT 0")

        c.execute("""
            CREATE TABLE IF NOT EXISTS backup_codes (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                code_hash TEXT NOT NULL,
                used INTEGER DEFAULT 0,
                used_at TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS rate_limits (
                user_id INTEGER PRIMARY KEY,
                attempts INTEGER DEFAULT 0,
                last_attempt TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS used_codes (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                code TEXT NOT NULL,
                used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            )
        """)
        _add_column_safe(c, "sessions", "last_active", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
        _add_column_safe(c, "sessions", "device", "TEXT")

        c.execute("""
            CREATE TABLE IF NOT EXISTS login_history (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                event TEXT NOT NULL,
                device TEXT,
                ip TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id SERIAL PRIMARY KEY,
                key TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                owner_email TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active INTEGER DEFAULT 1,
                last_used TIMESTAMP,
                request_count INTEGER DEFAULT 0
            )
        """)
        _add_column_safe(c, "api_keys", "owner_user_id", "INTEGER")

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
        sqlite_query = query.replace("%s", "?")
        cursor.execute(sqlite_query, params)
        return cursor

    def _column_exists(cursor, table, column):
        cursor.execute(f"PRAGMA table_info({table})")
        return any(row[1] == column for row in cursor.fetchall())

    def _add_column_safe(cursor, table, column, definition):
        if not _column_exists(cursor, table, column):
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

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
        _add_column_safe(c, "users", "display_name", "TEXT")
        _add_column_safe(c, "users", "recovery_email", "TEXT")
        _add_column_safe(c, "users", "recovery_phone", "TEXT")
        _add_column_safe(c, "users", "session_length", "INTEGER DEFAULT 30")
        _add_column_safe(c, "users", "last_login", "TIMESTAMP")
        _add_column_safe(c, "users", "is_admin", "INTEGER DEFAULT 0")

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
        _add_column_safe(c, "sessions", "last_active", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
        _add_column_safe(c, "sessions", "device", "TEXT")

        execute_query(c, """
            CREATE TABLE IF NOT EXISTS login_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                event TEXT NOT NULL,
                device TEXT,
                ip TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        execute_query(c, """
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                owner_email TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active INTEGER DEFAULT 1,
                last_used TIMESTAMP,
                request_count INTEGER DEFAULT 0
            )
        """)
        _add_column_safe(c, "api_keys", "owner_user_id", "INTEGER")

        conn.commit()
        conn.close()
        print("SQLite database initialized.")


if __name__ == "__main__":
    init_db()
