import sqlite3
import json
from datetime import datetime
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "historico.db")

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asn TEXT,
            timestamp DATETIME,
            total_ips INTEGER,
            total_score INTEGER,
            results_json TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_scan(asn: str, total_ips: int, total_score: int, results: dict):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scans (asn, timestamp, total_ips, total_score, results_json)
        VALUES (?, ?, ?, ?, ?)
    ''', (asn, datetime.now().isoformat(), total_ips, total_score, json.dumps(results)))
    conn.commit()
    conn.close()

def get_latest_scans(asn: str, limit: int = 1) -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT results_json FROM scans
        WHERE asn = ?
        ORDER BY timestamp DESC
        LIMIT ?
    ''', (asn, limit))
    rows = cursor.fetchall()
    conn.close()

    results = []
    for row in rows:
        try:
            results.append(json.loads(row[0]))
        except json.JSONDecodeError:
            continue
    return results
