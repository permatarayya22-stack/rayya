"""KOSPACE - Tabel pengguna.

DATABASE_URL `postgresql://...` -> Supabase Postgres (produksi).
DATABASE_URL `sqlite:///...`    -> SQLite lokal (mode preview).
"""

from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
import streamlit as st
from psycopg.rows import dict_row

BASE_DIR = Path(__file__).resolve().parent.parent
SQLITE_PREFIX = "sqlite:///"

PG_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              BIGSERIAL PRIMARY KEY,
    username        TEXT NOT NULL,
    password_hash   TEXT NOT NULL,
    is_active       BOOLEAN     NOT NULL DEFAULT TRUE,
    is_admin        BOOLEAN     NOT NULL DEFAULT FALSE,
    failed_attempts INTEGER     NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at   TIMESTAMPTZ
)
"""

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL,
    password_hash   TEXT NOT NULL,
    is_active       INTEGER NOT NULL DEFAULT 1,
    is_admin        INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at   TEXT
)
"""

USERNAME_INDEX = (
    "CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_idx "
    "ON users (lower(username))"
)


def database_url() -> str | None:
    """Ambil DATABASE_URL dari Streamlit secrets atau environment variable."""
    url = None
    try:
        if "DATABASE_URL" in st.secrets:
            url = st.secrets["DATABASE_URL"]
    except Exception:
        url = None
    return (url or os.environ.get("DATABASE_URL") or "").strip() or None


def is_sqlite() -> bool:
    return (database_url() or "").startswith("sqlite:")


def _sqlite_path() -> Path:
    url = database_url() or ""
    raw = url[len(SQLITE_PREFIX):] if url.startswith(SQLITE_PREFIX) else url.split("sqlite:", 1)[-1].lstrip("/")
    path = Path(raw)
    return path if path.is_absolute() else BASE_DIR / path


@contextmanager
def connection():
    url = database_url()
    if not url:
        raise RuntimeError("DATABASE_URL belum diatur.")
    if url.startswith("sqlite:"):
        conn = sqlite3.connect(_sqlite_path(), timeout=20)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    else:
        with psycopg.connect(url, row_factory=dict_row, connect_timeout=10) as conn:
            yield conn


def _sql(statement: str) -> str:
    return statement.replace("%s", "?") if is_sqlite() else statement


def _one(conn, statement: str, params: tuple = ()) -> dict | None:
    row = conn.execute(_sql(statement), params).fetchone()
    if row is None:
        return None
    return dict(row) if is_sqlite() else row


def _all(conn, statement: str, params: tuple = ()) -> list[dict]:
    rows = conn.execute(_sql(statement), params).fetchall()
    return [dict(row) for row in rows] if is_sqlite() else rows


def ensure_schema() -> None:
    with connection() as conn:
        conn.execute(SQLITE_SCHEMA if is_sqlite() else PG_SCHEMA)
        conn.execute(USERNAME_INDEX)


def count_users() -> int:
    with connection() as conn:
        row = conn.execute("SELECT COUNT(*) AS jumlah FROM users").fetchone()
        return int(row["jumlah"])


def find_by_username(username: str) -> dict | None:
    with connection() as conn:
        return _one(
            conn,
            "SELECT * FROM users WHERE lower(username) = lower(%s)",
            (username,),
        )


def list_users() -> list[dict]:
    with connection() as conn:
        return _all(
            conn,
            """
            SELECT id, username, is_active, is_admin, created_at, last_login_at
              FROM users
             ORDER BY username
            """,
        )


def insert_user(username: str, password_hash: str, is_admin: bool) -> dict:
    with connection() as conn:
        if is_sqlite():
            conn.execute(
                _sql(
                    "INSERT INTO users (username, password_hash, is_admin) "
                    "VALUES (%s, %s, %s)"
                ),
                (username, password_hash, int(bool(is_admin))),
            )
            return _one(
                conn,
                "SELECT id, username FROM users WHERE lower(username) = lower(%s)",
                (username,),
            )
        return conn.execute(
            """
            INSERT INTO users (username, password_hash, is_admin)
            VALUES (%s, %s, %s)
            RETURNING id, username
            """,
            (username, password_hash, is_admin),
        ).fetchone()


def set_password_hash(user_id: int, password_hash: str) -> None:
    with connection() as conn:
        conn.execute(
            _sql(
                """
                UPDATE users
                   SET password_hash = %s,
                       failed_attempts = 0,
                       locked_until = NULL,
                       updated_at = CURRENT_TIMESTAMP
                 WHERE id = %s
                """
            ),
            (password_hash, user_id),
        )


def set_active(user_id: int, active: bool) -> None:
    with connection() as conn:
        conn.execute(
            _sql(
                "UPDATE users SET is_active = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s"
            ),
            (int(active) if is_sqlite() else active, user_id),
        )


def record_login_success(user_id: int) -> None:
    with connection() as conn:
        conn.execute(
            _sql(
                """
                UPDATE users
                   SET failed_attempts = 0,
                       locked_until = NULL,
                       last_login_at = CURRENT_TIMESTAMP,
                       updated_at = CURRENT_TIMESTAMP
                 WHERE id = %s
                """
            ),
            (user_id,),
        )


def record_login_failure(user_id: int, maks_percobaan: int, menit_kunci: int) -> None:
    with connection() as conn:
        if is_sqlite():
            kunci_sampai = (
                datetime.now(timezone.utc) + timedelta(minutes=menit_kunci)
            ).strftime("%Y-%m-%d %H:%M:%S")
            conn.execute(
                _sql(
                    """
                    UPDATE users
                       SET failed_attempts = failed_attempts + 1,
                           locked_until = CASE
                               WHEN failed_attempts + 1 >= %s THEN %s
                               ELSE locked_until
                           END,
                           updated_at = CURRENT_TIMESTAMP
                     WHERE id = %s
                    """
                ),
                (maks_percobaan, kunci_sampai, user_id),
            )
            return
        conn.execute(
            """
            UPDATE users
               SET failed_attempts = failed_attempts + 1,
                   locked_until = CASE
                       WHEN failed_attempts + 1 >= %s
                       THEN now() + make_interval(mins => %s)
                       ELSE locked_until
                   END,
                   updated_at = now()
             WHERE id = %s
            """,
            (maks_percobaan, menit_kunci, user_id),
        )
