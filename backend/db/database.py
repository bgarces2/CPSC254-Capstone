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
