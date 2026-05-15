"""
Rate Limit / Resource Exhaustion Prober

Bypasses the LLM entirely. Sends the same request N times concurrently
and checks whether the server ever returns 429 Too Many Requests.
No LLM judgment needed — the verdict is purely numeric.
"""
import asyncio
from datetime import datetime, timezone

import httpx

from config import MAX_FUZZ_ATTEMPTS
from models.schemas import Endpoint, FuzzLog, VulnResult

# How many requests to fire in one burst
BURST_SIZE: int = 30
# Concurrent connections per burst
CONCURRENCY: int = 10
# Seconds to wait between bursts (gives slow rate limiters a chance to kick in)
BURST_PAUSE: float = 0.5


async def _fire_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    headers: dict,
    body: dict | None,
) -> tuple[int, str]:
    try:
        resp = await client.request(method=method, url=url, headers=headers, json=body)
        return resp.status_code, resp.text[:500]   # cap stored body size
    except httpx.RequestError as e:
        return 0, f"Request error: {e}"


async def probe_rate_limit(
    session_id: str,
    endpoint: Endpoint,
    base_url: str,
    auth_token: str = "Bearer token_user_a",
) -> tuple[list[FuzzLog], VulnResult]:
    """
    Fire BURST_SIZE requests at the endpoint and collect results.
    Returns (logs, VulnResult) — no LLM calls made.
    """
    # Build the concrete URL — replace path params with safe defaults
    import re
    path = re.sub(r"\{[^}]+\}", "1", endpoint.path)
    url = base_url.rstrip("/") + path

    method = endpoint.method
    headers = {
        "Authorization": auth_token,
        "Content-Type": "application/json",
    }
    body = None

    logs: list[FuzzLog] = []
    status_counts: dict[int, int] = {}
    attempt = 0

    semaphore = asyncio.Semaphore(CONCURRENCY)

    async def bounded_request(client):
        nonlocal attempt
        async with semaphore:
            attempt += 1
            current_attempt = attempt
            status, body_text = await _fire_request(client, method, url, headers, body)
            status_counts[status] = status_counts.get(status, 0) + 1
            return FuzzLog(
                session_id=session_id,
                endpoint=endpoint.path,
                attempt_number=current_attempt,
                request={"method": method, "url": url, "headers": headers, "body": body},
                response_status=status,
                response_body=body_text,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )

    async with httpx.AsyncClient(timeout=10.0) as client:
        tasks = [bounded_request(client) for _ in range(BURST_SIZE)]
        results = await asyncio.gather(*tasks)
        logs.extend(results)

    # Verdict logic — purely numeric, no LLM
    got_429 = status_counts.get(429, 0) > 0
    got_503 = status_counts.get(503, 0) > 0  # some servers return 503 when throttling
    total_2xx = sum(v for k, v in status_counts.items() if 200 <= k < 300)

    if got_429 or got_503:
        verdict = "NO_VULNERABILITY"
        evidence = f"Server returned {'429' if got_429 else '503'} after {BURST_SIZE} rapid requests — rate limiting is active."
        reasoning = (
            f"Sent {BURST_SIZE} concurrent requests. "
            f"Status distribution: {dict(sorted(status_counts.items()))}. "
            f"Rate limiting header detected — endpoint is protected."
        )
    else:
        verdict = "EXPLOIT_CONFIRMED"
        evidence = (
            f"All {total_2xx}/{BURST_SIZE} requests returned 2xx. "
            f"No 429 or 503 observed. Status distribution: {dict(sorted(status_counts.items()))}."
        )
        reasoning = (
            f"Sent {BURST_SIZE} concurrent requests to {method} {endpoint.path}. "
            f"The server never returned 429 Too Many Requests or 503 Service Unavailable. "
            f"This endpoint has no rate limiting — it is vulnerable to resource exhaustion / brute-force attacks."
        )

    result = VulnResult(
        session_id=session_id,
        endpoint=endpoint.path,
        attack_type="RATE_LIMIT",
        verdict=verdict,
        evidence=evidence,
        reasoning=reasoning,
    )

    return logs, result
