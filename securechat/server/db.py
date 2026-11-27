"""Persistencia SQLite. Ruta configurable con SECURECHAT_DB (por defecto data/server.db)."""
import os
import sqlite3
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    pw_salt BLOB NOT NULL, pw_hash BLOB NOT NULL,          -- Argon2id (nunca la contraseña)
    ik_sig_pub TEXT NOT NULL, ik_dh_pub TEXT NOT NULL,
    spk_pub TEXT NOT NULL, sig_spk TEXT NOT NULL,           -- solo claves públicas y firma
    created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,                            -- SHA-256 del token, no el token
    username TEXT NOT NULL, expires REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT NOT NULL, recipient TEXT NOT NULL,
    init TEXT,                                              -- cabecera X3DH (JSON) o NULL
    n INTEGER NOT NULL, ciphertext TEXT NOT NULL, ts REAL NOT NULL
);
"""


def db_path() -> str:
    path = os.getenv("SECURECHAT_DB", "data/server.db")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    return path


@contextmanager
def connect():
    conn = sqlite3.connect(db_path())
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)
