import psycopg2
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ.get('DATABASE_URL')

def get_conn():
    return psycopg2.connect(DATABASE_URL)

def init_db():
    pass

def save_scan(system_name, threats, user_id=None):
    conn = get_conn()
    cursor = conn.cursor()
    high = sum(1 for t in threats if t.risk_level == "HIGH")
    medium = sum(1 for t in threats if t.risk_level == "MEDIUM")
    low = sum(1 for t in threats if t.risk_level == "LOW")
    cursor.execute("""
        INSERT INTO scans (user_id, system_name, total_threats, high_count, medium_count, low_count)
        VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
    """, (user_id, system_name, len(threats), high, medium, low))
    result = cursor.fetchone()
    if result is None:
        conn.rollback()
        conn.close()
        raise RuntimeError("Failed to retrieve scan id after insert")
    scan_id = result[0]
    for t in threats:
        cursor.execute("""
            INSERT INTO threats (scan_id, stride_category, title, affected_component, description, risk_level, mitigation)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (scan_id, t.stride_category, t.title, t.affected_component, t.description, t.risk_level, t.mitigation))
    conn.commit()
    conn.close()
    return scan_id

def get_all_scans(user_id=None):
    conn = get_conn()
    cursor = conn.cursor()
    if user_id:
        cursor.execute("""
            SELECT id, system_name, scanned_at, total_threats, high_count, medium_count, low_count 
            FROM scans WHERE user_id = %s ORDER BY scanned_at DESC
        """, (user_id,))
    else:
        cursor.execute("""
            SELECT id, system_name, scanned_at, total_threats, high_count, medium_count, low_count 
            FROM scans ORDER BY scanned_at DESC
        """)
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_scan_threats(scan_id):
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threats WHERE scan_id = %s", (scan_id,))
    rows = cursor.fetchall()
    conn.close()
    return rows
def get_or_create_user(google_id, email, name):
    conn = get_conn()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, google_id, email, name FROM users WHERE google_id = %s", (google_id,))
    user = cursor.fetchone()
    
    if user is None:
        cursor.execute("""
            INSERT INTO users (google_id, email, name)
            VALUES (%s, %s, %s)
            RETURNING id, google_id, email, name
        """, (google_id, email, name))
        user = cursor.fetchone()
        conn.commit()
    
    conn.close()
    return user  