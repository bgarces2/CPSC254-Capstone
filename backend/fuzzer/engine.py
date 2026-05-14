import json
import asyncio
from datetime import datetime, timezone
from typing import AsyncGenerator

import httpx
from openai import OpenAI

from config import OPENAI_API_KEY, OPENAI_MODEL, MAX_FUZZ_ATTEMPTS
from models.schemas import PayloadPair, FuzzLog

client = OpenAI(api_key=OPENAI_API_KEY)

# Tool definition given to the LLM — it "calls" this; the engine executes it
_MAKE_REQUEST_TOOL = {
    "type": "function",
    "function": {
        "name": "make_request",
        "description": "Execute an HTTP request against the target API and return the response.",
        "parameters": {
            "type": "object",
            "properties": {
                "method":  {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"]},
                "url":     {"type": "string", "description": "Full URL including base"},
                "headers": {"type": "object", "description": "HTTP headers"},
                "body":    {"type": ["object", "null"], "description": "JSON request body"},
                "description": {"type": "string", "description": "What this request is testing"},
            },
            "required": ["method", "url", "headers"],
        },
    },
}

_SYSTEM_PROMPT = """You are an API penetration tester running a live fuzzing session.
You have access to a make_request tool to send HTTP requests to the target API.
Your goal is to confirm or rule out the suspected vulnerability.
After each response, decide whether to try a variant or conclude the test.
Stop when you have enough evidence to make a determination."""


async def _execute_request(payload: dict) -> tuple[int, str]:
    """Actually send the HTTP request and return (status_code, response_body)."""
    async with httpx.AsyncClient(timeout=10.0) as http:
        method = payload.get("method", "GET").upper()
        url = payload["url"]
        headers = payload.get("headers", {})
        body = payload.get("body")

        response = await http.request(
            method=method,
            url=url,
            headers=headers,
            json=body,
        )
        try:
            body_text = response.text[:2000]  # cap response size
        except Exception:
            body_text = "<unreadable response>"

        return response.status_code, body_text


async def _run_and_log(
    session_id: str,
    endpoint_path: str,
    attempt: int,
    payload_dict: dict,
) -> FuzzLog:
    """Execute one request dict and return a FuzzLog."""
    try:
        status_code, response_body = await _execute_request(payload_dict)
    except httpx.RequestError as e:
        status_code = 0
        response_body = f"Request failed: {str(e)}"

    return FuzzLog(
        session_id=session_id,
        endpoint=endpoint_path,
        attempt_number=attempt,
        request={
            "method": payload_dict.get("method"),
            "url": payload_dict.get("url"),
            "headers": payload_dict.get("headers", {}),
            "body": payload_dict.get("body"),
        },
        response_status=status_code,
        response_body=response_body,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


async def run_fuzzing_session(
    session_id: str,
    pair: PayloadPair,
) -> AsyncGenerator[FuzzLog, None]:
    """
    Run the multi-turn fuzzing loop for one PayloadPair.

    Phase 1 — Deterministic: the engine directly executes the attacker's
    baseline and attack payloads (preserving auth headers exactly).

    Phase 2 — LLM-driven: the LLM reviews the results and may call
    make_request to try follow-up mutations, up to MAX_FUZZ_ATTEMPTS total.
    """
    attempt = 0
    b_status, b_body = 0, "unavailable"
    a_status, a_body = 0, "unavailable"

    # --- Phase 1: execute the attacker's payloads directly and capture results ---
    for i, (label, p) in enumerate([("baseline", pair.baseline), ("attack", pair.attack)]):
        attempt += 1
        payload_dict = {
            "method": p.method,
            "url": p.url,
            "headers": p.headers,
            "body": p.body,
            "description": p.description,
        }
        log = await _run_and_log(session_id, pair.endpoint_path, attempt, payload_dict)
        yield log

        # Capture results for Phase 2 context — no re-fetch needed
        if label == "baseline":
            b_status, b_body = log.response_status, log.response_body
        else:
            a_status, a_body = log.response_status, log.response_body

    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"I have already executed the baseline and attack requests for endpoint: {pair.endpoint_path}\n"
                f"Attack type: {pair.attack_type}\n\n"
                f"BASELINE result:\n"
                f"  {pair.baseline.method} {pair.baseline.url}\n"
                f"  Status: {b_status}\n"
                f"  Body: {b_body[:500]}\n\n"
                f"ATTACK result:\n"
                f"  {pair.attack.method} {pair.attack.url}\n"
                f"  Headers: {json.dumps(pair.attack.headers)}\n"
                f"  Body sent: {json.dumps(pair.attack.body)}\n"
                f"  Status: {a_status}\n"
                f"  Body: {a_body[:500]}\n\n"
                f"Based on these results, do you need to try any follow-up mutations to confirm or rule out the vulnerability? "
                f"If yes, use the make_request tool. If the results are already conclusive, stop. "
                f"IMPORTANT: always include the Authorization header from the attack request in any follow-up calls."
            ),
        },
    ]

    # --- Phase 2: LLM-driven follow-up mutations ---
    while attempt < MAX_FUZZ_ATTEMPTS:
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=messages,
            tools=[_MAKE_REQUEST_TOOL],
            tool_choice="auto",
        )

        message = response.choices[0].message

        # LLM decided results are conclusive — stop
        if not message.tool_calls:
            break

        tool_results = []
        for tool_call in message.tool_calls:
            if tool_call.function.name != "make_request":
                continue

            attempt += 1
            payload_dict = json.loads(tool_call.function.arguments)

            # Safety net: if the LLM dropped the auth header, inject it from the attack payload
            if "Authorization" not in payload_dict.get("headers", {}):
                payload_dict.setdefault("headers", {})
                payload_dict["headers"]["Authorization"] = pair.attack.headers.get("Authorization", "")

            log = await _run_and_log(session_id, pair.endpoint_path, attempt, payload_dict)
            yield log

            tool_results.append({
                "tool_call_id": tool_call.id,
                "role": "tool",
                "content": json.dumps({
                    "status_code": log.response_status,
                    "body": log.response_body,
                }),
            })

        messages.append(message)
        messages.extend(tool_results)
