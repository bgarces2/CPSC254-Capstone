"""
security.py — Input validation and sanitization utilities for SlingShot.

Covers:
  - Target URL validation (SSRF prevention)
  - Response body sanitization before LLM injection (prompt injection prevention)
"""
import ipaddress
import re
from urllib.parse import urlparse

# ── SSRF Prevention ───────────────────────────────────────────────────────────

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / AWS metadata
    ipaddress.ip_network("100.64.0.0/10"),    # shared address space
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
]

_BLOCKED_HOSTNAMES = {
    "metadata.google.internal",
    "169.254.169.254",
    # Note: localhost is intentionally NOT blocked here — the victim API
    # runs on localhost by design. Loopback IPs (127.x) are still blocked
    # via _BLOCKED_NETWORKS to prevent numeric IP bypasses.
}

_ALLOWED_SCHEMES = {"http", "https"}


def _ip_is_blocked(hostname: str) -> tuple[bool, str]:
    """
    If hostname is a literal IP address, check it against blocked ranges.
    Returns (blocked: bool, reason: str).
    Non-IP hostnames always return (False, "").
    """
    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        return False, ""  # not a literal IP — hostname string, skip

    for network in _BLOCKED_NETWORKS:
        try:
            if addr in network:
                return True, (
                    f"Target IP {hostname!r} ({addr}) is in a private or reserved "
                    f"address range ({network}). SlingShot cannot scan internal networks."
                )
        except TypeError:
            continue  # mixed IPv4/IPv6 comparison

    return False, ""


def validate_target_url(url: str) -> str:
    """
    Validate that a target URL is safe to scan.

    Raises ValueError with a descriptive message if the URL:
      - Uses a non-http/https scheme
      - Points to a private, loopback, or link-local IP address (127.x, 10.x, 192.168.x, etc.)
      - Points to a known cloud metadata endpoint (169.254.169.254, metadata.google.internal)
      - Is malformed

    Returns the URL unchanged if it passes all checks.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        raise ValueError(f"Malformed URL: {url!r}")

    if not parsed.scheme:
        raise ValueError("URL must include a scheme (http:// or https://)")

    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        raise ValueError(
            f"Scheme {parsed.scheme!r} is not allowed. Only http and https are permitted."
        )

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL must include a hostname.")

    if hostname.lower() in _BLOCKED_HOSTNAMES:
        raise ValueError(
            f"Target hostname {hostname!r} is not allowed. "
            "SlingShot cannot scan localhost or cloud metadata endpoints."
        )

    blocked, reason = _ip_is_blocked(hostname)
    if blocked:
        raise ValueError(reason)

    return url


# ── Prompt Injection Prevention ───────────────────────────────────────────────

_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+a?\s+\w+", re.IGNORECASE),
    re.compile(r"(system|assistant|user)\s*:\s*", re.IGNORECASE),
    re.compile(r"<\s*(system|instruction|prompt)\s*>", re.IGNORECASE),
    re.compile(r"disregard\s+(your\s+)?(previous|prior|all)\s+", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
    re.compile(r"act\s+as\s+(if\s+you\s+are|a)\s+", re.IGNORECASE),
    re.compile(r"return\s+verdict\s*:\s*(EXPLOIT_CONFIRMED|NO_VULNERABILITY)", re.IGNORECASE),
    re.compile(r"your\s+(new\s+)?role\s+is\s+", re.IGNORECASE),
]

MAX_BODY_FOR_LLM: int = 600


def sanitize_response_body(body: str, max_length: int = MAX_BODY_FOR_LLM) -> str:
    """
    Sanitize an API response body before injecting it into an LLM prompt.

    1. Truncates to max_length characters.
    2. Scans for prompt injection patterns and replaces matches with a
       [REDACTED: possible prompt injection] placeholder.

    Returns the sanitized string.
    """
    truncated = body[:max_length]
    sanitized = truncated
    for pattern in _INJECTION_PATTERNS:
        sanitized = pattern.sub("[REDACTED: possible prompt injection]", sanitized)
    return sanitized
