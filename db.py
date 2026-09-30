import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

DB_PATH = "audit_findings.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    check_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    description TEXT,
    detected_at TEXT NOT NULL,
    scan_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    total_checks INTEGER DEFAULT 0,
    total_failures INTEGER DEFAULT 0
);
"""


# Context manager so every caller gets a connection that's guaranteed
# to close, even if a query raises. row_factory lets us read columns
# by name (row["severity"]) instead of by index.
@contextmanager
def get_connection(db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db(db_path: str = DB_PATH):
    with get_connection(db_path) as conn:
        conn.executescript(SCHEMA)
        conn.commit()


def start_scan(scan_id: str, db_path: str = DB_PATH):
    with get_connection(db_path) as conn:
        conn.execute(
            "INSERT INTO scans (scan_id, started_at) VALUES (?, ?)",
            (scan_id, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()


def finish_scan(scan_id: str, total_checks: int, total_failures: int, db_path: str = DB_PATH):
    with get_connection(db_path) as conn:
        conn.execute(
            """UPDATE scans
               SET finished_at = ?, total_checks = ?, total_failures = ?
               WHERE scan_id = ?""",
            (datetime.now(timezone.utc).isoformat(), total_checks, total_failures, scan_id),
        )
        conn.commit()


def record_finding(scan_id, resource_type, resource_id, check_name,
                    severity, status, description, db_path: str = DB_PATH):
    # Using ? placeholders (parameterized query) instead of an f-string
    # avoids SQL injection from any value that contains a stray quote.
    with get_connection(db_path) as conn:
        conn.execute(
            """INSERT INTO findings
               (resource_type, resource_id, check_name, severity, status,
                description, detected_at, scan_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (resource_type, resource_id, check_name, severity, status,
             description, datetime.now(timezone.utc).isoformat(), scan_id),
        )
        conn.commit()


def get_findings(scan_id=None, status=None, severity=None, db_path: str = DB_PATH):
    # WHERE 1=1 lets every filter below just be "AND ..." without
    # special-casing whether it's the first condition or not.
    query = "SELECT * FROM findings WHERE 1=1"
    params = []
    if scan_id:
        query += " AND scan_id = ?"
        params.append(scan_id)
    if status:
        query += " AND status = ?"
        params.append(status)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    query += " ORDER BY severity DESC, detected_at DESC"

    with get_connection(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]
