import sqlite3
import json
from contextlib import contextmanager
from config import DATABASE_URL


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_URL)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def db_cursor():
    conn = get_connection()
    try:
        cursor = conn.cursor()
        yield cursor
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    """Create tables if they don't exist."""
    with db_cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scan_sessions (
                session_id TEXT PRIMARY KEY,
                spec_filename TEXT,
                target_url TEXT,
                status TEXT DEFAULT 'running',
                created_at TEXT
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS fuzz_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                endpoint TEXT,
                attempt_number INTEGER,
                request TEXT,
                response_status INTEGER,
                response_body TEXT,
                timestamp TEXT,
                FOREIGN KEY (session_id) REFERENCES scan_sessions(session_id)
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS vuln_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                endpoint TEXT,
                attack_type TEXT,
                verdict TEXT,
                evidence TEXT,
                reasoning TEXT,
                FOREIGN KEY (session_id) REFERENCES scan_sessions(session_id)
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS patches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                target_file TEXT,
                language TEXT,
                code TEXT,
                instructions TEXT,
                attack_type TEXT,
                validated INTEGER DEFAULT 0,
                FOREIGN KEY (session_id) REFERENCES scan_sessions(session_id)
            )
        """)


# --- Session helpers ---

def create_session(session_id: str, spec_filename: str, target_url: str, created_at: str) -> None:
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO scan_sessions (session_id, spec_filename, target_url, created_at) VALUES (?, ?, ?, ?)",
            (session_id, spec_filename, target_url, created_at)
        )


def update_session_status(session_id: str, status: str) -> None:
    with db_cursor() as cur:
        cur.execute(
            "UPDATE scan_sessions SET status = ? WHERE session_id = ?",
            (status, session_id)
        )


# --- Fuzz log helpers ---

def save_fuzz_log(log) -> None:
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO fuzz_logs
               (session_id, endpoint, attempt_number, request, response_status, response_body, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                log.session_id,
                log.endpoint,
                log.attempt_number,
                json.dumps(log.request),
                log.response_status,
                log.response_body,
                log.timestamp,
            )
        )


def get_fuzz_logs(session_id: str) -> list[dict]:
    with db_cursor() as cur:
        cur.execute("SELECT * FROM fuzz_logs WHERE session_id = ?", (session_id,))
        rows = cur.fetchall()
        return [dict(r) for r in rows]


# --- Vuln result helpers ---

def save_vuln_result(result) -> None:
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO vuln_results
               (session_id, endpoint, attack_type, verdict, evidence, reasoning)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                result.session_id,
                result.endpoint,
                result.attack_type,
                result.verdict,
                result.evidence,
                result.reasoning,
            )
        )


# --- Patch helpers ---

def save_patch(patch) -> None:
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO patches
               (session_id, target_file, language, code, instructions, attack_type, validated)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                patch.session_id,
                patch.target_file,
                patch.language,
                patch.code,
                patch.instructions,
                patch.attack_type,
                int(patch.validated),
            )
        )


def mark_patch_validated(session_id: str) -> None:
    with db_cursor() as cur:
        cur.execute(
            "UPDATE patches SET validated = 1 WHERE session_id = ?",
            (session_id,)
        )


def delete_old_sessions(max_age_hours: int = 24) -> int:
    """
    Delete scan sessions (and all related logs/results/patches) older than
    max_age_hours. Returns the number of sessions deleted.

    This limits PII retention — response bodies stored in fuzz_logs may
    contain sensitive data leaked by the target API.
    """
    from datetime import datetime, timezone, timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=max_age_hours)).isoformat()

    with db_cursor() as cur:
        # Fetch session IDs to delete
        cur.execute(
            "SELECT session_id FROM scan_sessions WHERE created_at < ?",
            (cutoff,)
        )
        old_ids = [row[0] for row in cur.fetchall()]

    if not old_ids:
        return 0

    placeholders = ",".join("?" * len(old_ids))
    with db_cursor() as cur:
        cur.execute(f"DELETE FROM fuzz_logs     WHERE session_id IN ({placeholders})", old_ids)
        cur.execute(f"DELETE FROM vuln_results  WHERE session_id IN ({placeholders})", old_ids)
        cur.execute(f"DELETE FROM patches       WHERE session_id IN ({placeholders})", old_ids)
        cur.execute(f"DELETE FROM scan_sessions WHERE session_id IN ({placeholders})", old_ids)

    return len(old_ids)
