import sqlite3
import json
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "forensix.db")


def init_db():
    """Creates the artifacts table if it doesn't already exist."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS artifacts (
            id TEXT PRIMARY KEY,
            source_file TEXT,
            type TEXT,
            raw TEXT,
            src_ip TEXT,
            iocs TEXT,
            suspicion_score REAL,
            anomaly_flag INTEGER
        )
    """)
    conn.commit()
    conn.close()


def save_artifacts(artifacts):
    """Wipes and re-inserts artifacts (fine for hackathon-scale re-runs)."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM artifacts")

    for a in artifacts:
        cursor.execute("""
            INSERT INTO artifacts (id, source_file, type, raw, src_ip, iocs, suspicion_score, anomaly_flag)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            a["id"],
            a["source_file"],
            a["type"],
            json.dumps(a["raw"]) if not isinstance(a["raw"], str) else a["raw"],
            a.get("src_ip"),
            json.dumps(a["iocs"]),
            a.get("suspicion_score"),
            int(a.get("anomaly_flag", False))
        ))

    conn.commit()
    conn.close()


def get_all_artifacts():
    """Reads all stored artifacts back out as a list of dicts."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM artifacts")
    rows = cursor.fetchall()
    conn.close()

    results = []
    for row in rows:
        results.append({
            "id": row["id"],
            "source_file": row["source_file"],
            "type": row["type"],
            "raw": row["raw"],
            "src_ip": row["src_ip"],
            "iocs": json.loads(row["iocs"]) if row["iocs"] else [],
            "suspicion_score": row["suspicion_score"],
            "anomaly_flag": bool(row["anomaly_flag"])
        })
    return results