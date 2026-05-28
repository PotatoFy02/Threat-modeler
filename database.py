import sqlite3
from datetime import datetime

DB_FILE = "threats.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            system_name TEXT NOT NULL,
            scanned_at TEXT NOT NULL,
            total_threats INTEGER,
            high_count INTEGER,
            medium_count INTEGER,
            low_count INTEGER
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            stride_category TEXT,
            title TEXT,
            affected_component TEXT,
            description TEXT,
            risk_level TEXT,
            mitigation TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)
    conn.commit()
    conn.close()

def save_scan(system_name, threats):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    high = sum(1 for t in threats if t.risk_level == "HIGH")
    medium = sum(1 for t in threats if t.risk_level == "MEDIUM")
    low = sum(1 for t in threats if t.risk_level == "LOW")
    cursor.execute("""
        INSERT INTO scans (system_name, scanned_at, total_threats, high_count, medium_count, low_count)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (system_name, now, len(threats), high, medium, low))
    scan_id = cursor.lastrowid
    for t in threats:
        cursor.execute("""
            INSERT INTO threats (scan_id, stride_category, title, affected_component, description, risk_level, mitigation)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, t.stride_category, t.title, t.affected_component, t.description, t.risk_level, t.mitigation))
    conn.commit()
    conn.close()
    return scan_id

def get_all_scans():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY scanned_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_scan_threats(scan_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threats WHERE scan_id = ?", (scan_id,))
    rows = cursor.fetchall()
    conn.close()
    return rows