import sqlite3
from datetime import datetime

DB_PATH = "attack_memory.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            attack_type TEXT,
            severity TEXT,
            timestamp TEXT,
            log_sample TEXT,
            analysis TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_attack(ip, attack_type, severity, log_sample, analysis):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO attacks (ip, attack_type, severity, timestamp, log_sample, analysis)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (ip, attack_type, severity, datetime.now().isoformat(), log_sample, analysis))
    conn.commit()
    conn.close()

def get_ip_history(ip):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT attack_type, severity, timestamp, analysis
        FROM attacks
        WHERE ip = ?
        ORDER BY timestamp DESC
        LIMIT 5
    """, (ip,))
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_repeat_offenders():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT ip, COUNT(*) as count, MAX(timestamp) as last_seen
        FROM attacks
        GROUP BY ip
        HAVING count > 1
        ORDER BY count DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows