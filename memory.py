import sqlite3
from datetime import datetime

DB_PATH = "attack_memory.db"

#initializes the database and creates the necessary table if it doesn't exist
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


# saves an attack record to the database with details such as IP, attack type, severity, timestamp, log sample, and analysis
def save_attack(ip, attack_type, severity, log_sample, analysis):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO attacks (ip, attack_type, severity, timestamp, log_sample, analysis)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (ip, attack_type, severity, datetime.now().isoformat(), log_sample, analysis))
    conn.commit()
    conn.close()


# retrieves the attack history for a specific IP address, returning details such as attack type, severity, timestamp, and analysis for the last 5 attacks
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



# identifies IP addresses that have been involved in multiple attacks, returning the IP address, count of attacks, and the last seen timestamp for those that have more than one recorded attack
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


def check_kill_chain(ip: str, time_window_minutes: int = 10):
    """
    Check if this IP performed Port Scan followed by Brute Force
    within the time window. If yes, return kill chain details.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT attack_type, timestamp
        FROM attacks
        WHERE ip = ?
        ORDER BY timestamp ASC
    """, (ip,))
    rows = cursor.fetchall()
    conn.close()

    if len(rows) < 2:
        return None

    attack_types = [row[0] for row in rows]
    timestamps   = [datetime.fromisoformat(row[1]) for row in rows]

    has_port_scan   = "Port Scan" in attack_types
    has_brute_force = "Brute Force" in attack_types

    if has_port_scan and has_brute_force:
        ps_time = next(timestamps[i] for i, a in enumerate(attack_types) if a == "Port Scan")
        bf_time = next(timestamps[i] for i, a in enumerate(attack_types) if a == "Brute Force")
        diff = abs((bf_time - ps_time).total_seconds() / 60)
        if diff <= time_window_minutes:
            return {
                "ip"      : ip,
                "pattern" : "Port Scan → Brute Force",
                "severity": "Critical",
                "minutes" : round(diff, 1)
            }
    return None