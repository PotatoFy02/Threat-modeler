import os
import psycopg2
from psycopg2 import pool
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

_pool = pool.ThreadedConnectionPool(1, 10, dsn=DATABASE_URL)


def get_conn():
    return _pool.getconn()


def put_conn(conn):
    _pool.putconn(conn)


def init_db():
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id        SERIAL PRIMARY KEY,
                    google_id TEXT UNIQUE NOT NULL,
                    email     TEXT NOT NULL,
                    name      TEXT,
                    plan      TEXT DEFAULT 'free',
                    created_at TIMESTAMP DEFAULT NOW()
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id            SERIAL PRIMARY KEY,
                    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    system_name   TEXT NOT NULL,
                    total_threats INTEGER DEFAULT 0,
                    high_count    INTEGER DEFAULT 0,
                    medium_count  INTEGER DEFAULT 0,
                    low_count     INTEGER DEFAULT 0,
                    scanned_at    TIMESTAMP DEFAULT NOW()
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS threats (
                    id                 SERIAL PRIMARY KEY,
                    scan_id            INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    stride_category    TEXT,
                    title              TEXT,
                    affected_component TEXT,
                    description        TEXT,
                    risk_level         TEXT,
                    mitigation         TEXT,
                    cve_reference      TEXT DEFAULT ''
                );
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_threats_scan_id ON threats(scan_id);")
        conn.commit()
    finally:
        put_conn(conn)


def save_scan(system_name, threats, user_id):
    if user_id is None:
        raise ValueError("user_id is required")
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            high = sum(1 for t in threats if t.risk_level == "HIGH")
            medium = sum(1 for t in threats if t.risk_level == "MEDIUM")
            low = sum(1 for t in threats if t.risk_level == "LOW")
            cur.execute("""
                INSERT INTO scans (user_id, system_name, total_threats,
                                   high_count, medium_count, low_count)
                VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
            """, (user_id, system_name, len(threats), high, medium, low))
            row = cur.fetchone()
            if row is None:
                conn.rollback()
                raise RuntimeError("Failed to retrieve scan id after insert")
            scan_id = row[0]
            for t in threats:
                cur.execute("""
                    INSERT INTO threats (scan_id, stride_category, title,
                        affected_component, description, risk_level,
                        mitigation, cve_reference)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (scan_id, t.stride_category, t.title, t.affected_component,
                      t.description, t.risk_level, t.mitigation,
                      getattr(t, "cve_reference", "")))
        conn.commit()
        return scan_id
    except Exception:
        conn.rollback()
        raise
    finally:
        put_conn(conn)


def get_all_scans(user_id):
    if user_id is None:
        raise ValueError("user_id is required")
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, system_name, scanned_at, total_threats,
                       high_count, medium_count, low_count
                FROM scans WHERE user_id = %s ORDER BY scanned_at DESC
            """, (user_id,))
            return cur.fetchall()
    finally:
        put_conn(conn)


def get_scan_threats(scan_id, user_id):
    if user_id is None:
        raise ValueError("user_id is required")
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT t.id, t.scan_id, t.stride_category, t.title,
                       t.affected_component, t.description, t.risk_level, t.mitigation
                FROM threats t
                JOIN scans s ON t.scan_id = s.id
                WHERE t.scan_id = %s AND s.user_id = %s
            """, (scan_id, user_id))
            return cur.fetchall()
    finally:
        put_conn(conn)