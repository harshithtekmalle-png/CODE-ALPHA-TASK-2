"""
PhishGuard Database Module
SQLite Data Store for Scan Records and Real-Time Dashboard Statistics
"""

import os
import json
import sqlite3
from typing import List, Dict, Any, Optional

DEFAULT_DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phishguard.db")


def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Return a configured SQLite connection with foreign keys and row factory."""
    path = db_path or DEFAULT_DB_FILE
    conn = sqlite3.connect(path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """Initialize the SQLite database schema if not present."""
    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    indicators TEXT NOT NULL,
                    explanation TEXT NOT NULL
                );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans (id DESC);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_type ON scans (scan_type);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_risk ON scans (risk_level);")
            conn.commit()
    finally:
        conn.close()


def save_scan(
    scan_type: str,
    target: str,
    score: int,
    risk_level: str,
    indicators: Any,
    explanation: str,
    timestamp: str,
    db_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Save a completed scan record to SQLite using parameterized queries.
    Returns the created record as a dictionary.
    """
    indicators_json = json.dumps(indicators) if not isinstance(indicators, str) else indicators

    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO scans (timestamp, scan_type, target, score, risk_level, indicators, explanation)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (timestamp, scan_type, target, int(score), risk_level, indicators_json, explanation)
            )
            scan_id = cursor.lastrowid
            conn.commit()
    finally:
        conn.close()

    return {
        "id": scan_id,
        "timestamp": timestamp,
        "scan_type": scan_type,
        "target": target,
        "score": int(score),
        "risk_level": risk_level,
        "indicators": indicators if not isinstance(indicators, str) else json.loads(indicators),
        "explanation": explanation
    }


def get_history(limit: int = 100, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve the most recent scan records ordered by ID descending."""
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp, scan_type, target, score, risk_level, indicators, explanation
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,)
        )
        rows = cursor.fetchall()

        results = []
        for row in rows:
            try:
                parsed_ind = json.loads(row["indicators"])
            except Exception:
                parsed_ind = []
            results.append({
                "id": row["id"],
                "timestamp": row["timestamp"],
                "scan_type": row["scan_type"],
                "target": row["target"],
                "score": row["score"],
                "risk_level": row["risk_level"],
                "indicators": parsed_ind,
                "explanation": row["explanation"]
            })
        return results
    finally:
        conn.close()


def clear_history(db_path: Optional[str] = None) -> int:
    """Clear all records from scans table."""
    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scans;")
            deleted_count = cursor.rowcount
            conn.commit()
        return deleted_count
    finally:
        conn.close()


def get_dashboard_stats(db_path: Optional[str] = None) -> Dict[str, int]:
    """
    Calculate and return real-time dashboard statistics directly from SQLite.
    Zero hardcoded values.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        
        # Overall counts
        cursor.execute("SELECT COUNT(*) AS total FROM scans;")
        total_scans = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) AS total FROM scans WHERE scan_type = 'url';")
        url_scans = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) AS total FROM scans WHERE scan_type = 'message';")
        message_scans = cursor.fetchone()["total"]

        # Risk level counts
        cursor.execute("SELECT COUNT(*) AS total FROM scans WHERE risk_level = 'Low Risk';")
        low_risk = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) AS total FROM scans WHERE risk_level = 'Suspicious';")
        suspicious = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) AS total FROM scans WHERE risk_level = 'High Risk';")
        high_risk = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) AS total FROM scans WHERE risk_level = 'Critical';")
        critical = cursor.fetchone()["total"]

        return {
            "total_scans": total_scans,
            "url_scans": url_scans,
            "message_scans": message_scans,
            "low_risk": low_risk,
            "suspicious": suspicious,
            "high_risk": high_risk,
            "critical": critical
        }
    finally:
        conn.close()
