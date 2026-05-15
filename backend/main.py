import asyncio
import json
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import httpx

from config import TARGET_BASE_URL, SESSION_MAX_AGE_HOURS
from security import validate_target_url
from db import (
    init_db,
    create_session,
    update_session_status,
    save_fuzz_log,
    get_fuzz_logs,
    save_vuln_result,
    save_patch,
    mark_patch_validated,
    delete_old_sessions,
)
from parser import parse_spec
from agents import generate_all_payload_pairs, judge_session, generate_patch
from fuzzer import run_fuzzing_session, probe_rate_limit, probe_sqli, probe_path_traversal

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="SlingShot API", version="1.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Vite dev server
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    init_db()
    # Purge sessions older than 24 hours on startup to limit PII retention
    delete_old_sessions(max_age_hours=SESSION_MAX_AGE_HOURS)


# ---------------------------------------------------------------------------
# POST /scan  — upload a spec and kick off a scan
# ---------------------------------------------------------------------------

@app.post("/scan")
@limiter.limit("10/minute")
async def start_scan(
    request: Request,
    spec_file: UploadFile = File(...),
    target_url: str = Form(default=TARGET_BASE_URL),
    stack: str = Form(default="express"),
):
    # Risk 2: validate target URL to prevent SSRF
    try:
        validate_target_url(target_url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    session_id = str(uuid.uuid4())
    spec_content = await spec_file.read()

    import tempfile, os
    suffix = ".yaml" if spec_file.filename.endswith((".yaml", ".yml")) else ".json"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(spec_content)
        tmp_path = tmp.name

    try:
        endpoints = parse_spec(tmp_path)
    except (FileNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        os.unlink(tmp_path)

    create_session(
        session_id=session_id,
        spec_filename=spec_file.filename,
        target_url=target_url,
        created_at=datetime.now(timezone.utc).isoformat(),
    )

    app.state.pending_scans = getattr(app.state, "pending_scans", {})
    app.state.pending_scans[session_id] = {
        "endpoints": endpoints,
        "target_url": target_url,
        "stack": stack,
    }

    high_value = [e for e in endpoints if e.is_high_value]
    return {
        "session_id": session_id,
        "total_endpoints": len(endpoints),
        "high_value_count": len(high_value),
        "endpoints": [
            {
                "method": e.method,
                "path": e.path,
                "is_high_value": e.is_high_value,
                "hints": e.attack_hints,
            }
            for e in endpoints
        ],
    }


# ---------------------------------------------------------------------------
# GET /scan/{session_id}/stream  — SSE stream of pipeline events
# ---------------------------------------------------------------------------

def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


async def _pipeline_generator(session_id: str, stack: str):
    pending = getattr(app.state, "pending_scans", {})
    scan = pending.get(session_id)
    if not scan:
        yield _sse("error", {"message": "Session not found"})
        return

    endpoints = [e for e in scan["endpoints"] if e.is_high_value]

    if not endpoints:
        yield _sse("done", {"message": "No high-value endpoints found in spec."})
        update_session_status(session_id, "completed")
        return

    for endpoint in endpoints:
        yield _sse("endpoint_classified", {
            "path": endpoint.path,
            "method": endpoint.method,
            "hints": endpoint.attack_hints,
        })
        await asyncio.sleep(0)

        # --- Attacker Agent: one PayloadPair per attack hint ---
        try:
            pairs = generate_all_payload_pairs(endpoint)
        except Exception as e:
            yield _sse("error", {"message": f"Attacker agent failed: {str(e)}", "endpoint": endpoint.path})
            continue

        for pair in pairs:
            yield _sse("payload_generated", {
                "endpoint": endpoint.path,
                "attack_type": pair.attack_type,
                "baseline": pair.baseline.description,
                "attack": pair.attack.description,
            })
            await asyncio.sleep(0)

            # --- Fuzzing Engine ---
            logs = []
            async for log in run_fuzzing_session(session_id, pair):
                save_fuzz_log(log)
                logs.append(log)
                yield _sse("fuzz_attempt", {
                    "attempt": log.attempt_number,
                    "method": log.request.get("method"),
                    "url": log.request.get("url"),
                    "status": log.response_status,
                    "body_preview": log.response_body[:200],
                })
                await asyncio.sleep(0)

            # --- Vulnerability Judge ---
            try:
                result = judge_session(session_id, endpoint.path, pair.attack_type, logs)
            except Exception as e:
                yield _sse("error", {"message": f"Judge failed: {str(e)}", "endpoint": endpoint.path})
                continue

            save_vuln_result(result)
            yield _sse("verdict", {
                "endpoint": endpoint.path,
                "attack_type": pair.attack_type,
                "verdict": result.verdict,
                "reasoning": result.reasoning,
                "evidence": result.evidence,
            })
            await asyncio.sleep(0)

            if result.verdict != "EXPLOIT_CONFIRMED":
                continue

            # --- Fixer Agent ---
            try:
                patch = generate_patch(result, stack=stack)
            except Exception as e:
                yield _sse("error", {"message": f"Fixer agent failed: {str(e)}", "endpoint": endpoint.path})
                continue

            save_patch(patch)
            yield _sse("patch_ready", {
                "endpoint": endpoint.path,
                "attack_type": patch.attack_type,
                "target_file": patch.target_file,
                "language": patch.language,
                "code": patch.code,
                "instructions": patch.instructions,
                "validated": patch.validated,
            })
            await asyncio.sleep(0)

        # --- Rate Limit Prober (no LLM — runs after all other attacks) ---
        yield _sse("fuzz_attempt", {
            "attempt": 0,
            "method": endpoint.method,
            "url": f"{scan['target_url']}{endpoint.path}",
            "status": 0,
            "body_preview": "[RATE_LIMIT] Firing 30 concurrent requests...",
        })
        await asyncio.sleep(0)

        try:
            rl_logs, rl_result = await probe_rate_limit(
                session_id=session_id,
                endpoint=endpoint,
                base_url=scan["target_url"],
            )
        except Exception as e:
            yield _sse("error", {"message": f"Rate limit probe failed: {str(e)}", "endpoint": endpoint.path})
        else:
            for log in rl_logs:
                save_fuzz_log(log)

            save_vuln_result(rl_result)
            yield _sse("verdict", {
                "endpoint": endpoint.path,
                "attack_type": "RATE_LIMIT",
                "verdict": rl_result.verdict,
                "reasoning": rl_result.reasoning,
                "evidence": rl_result.evidence,
            })
            await asyncio.sleep(0)

            if rl_result.verdict == "EXPLOIT_CONFIRMED":
                try:
                    patch = generate_patch(rl_result, stack=stack)
                    save_patch(patch)
                    yield _sse("patch_ready", {
                        "endpoint": endpoint.path,
                        "attack_type": patch.attack_type,
                        "target_file": patch.target_file,
                        "language": patch.language,
                        "code": patch.code,
                        "instructions": patch.instructions,
                        "validated": patch.validated,
                    })
                    await asyncio.sleep(0)
                except Exception as e:
                    yield _sse("error", {"message": f"Fixer failed for RATE_LIMIT: {str(e)}", "endpoint": endpoint.path})

        # --- SQL Injection Prober (no LLM) ---
        if "SQLI" in endpoint.attack_hints:
            yield _sse("fuzz_attempt", {
                "attempt": 0, "method": endpoint.method,
                "url": f"{scan['target_url']}{endpoint.path}",
                "status": 0,
                "body_preview": "[SQLI] Testing error-based, time-based, and log-based injection...",
            })
            await asyncio.sleep(0)
            try:
                sqli_logs, sqli_result = await probe_sqli(
                    session_id=session_id,
                    endpoint=endpoint,
                    base_url=scan["target_url"],
                )
            except Exception as e:
                yield _sse("error", {"message": f"SQLi probe failed: {str(e)}", "endpoint": endpoint.path})
            else:
                for log in sqli_logs:
                    save_fuzz_log(log)
                    yield _sse("fuzz_attempt", {
                        "attempt": log.attempt_number,
                        "method": log.request.get("method"),
                        "url": log.request.get("url"),
                        "status": log.response_status,
                        "body_preview": log.response_body[:200],
                    })
                    await asyncio.sleep(0)
                save_vuln_result(sqli_result)
                yield _sse("verdict", {
                    "endpoint": endpoint.path,
                    "attack_type": "SQLI",
                    "verdict": sqli_result.verdict,
                    "reasoning": sqli_result.reasoning,
                    "evidence": sqli_result.evidence,
                })
                await asyncio.sleep(0)
                if sqli_result.verdict == "EXPLOIT_CONFIRMED":
                    try:
                        patch = generate_patch(sqli_result, stack=stack)
                        save_patch(patch)
                        yield _sse("patch_ready", {
                            "endpoint": endpoint.path,
                            "attack_type": patch.attack_type,
                            "target_file": patch.target_file,
                            "language": patch.language,
                            "code": patch.code,
                            "instructions": patch.instructions,
                            "validated": patch.validated,
                        })
                        await asyncio.sleep(0)
                    except Exception as e:
                        yield _sse("error", {"message": f"Fixer failed for SQLI: {str(e)}", "endpoint": endpoint.path})

        # --- Path Traversal Prober (no LLM) ---
        if "PATH_TRAVERSAL" in endpoint.attack_hints:
            yield _sse("fuzz_attempt", {
                "attempt": 0, "method": endpoint.method,
                "url": f"{scan['target_url']}{endpoint.path}",
                "status": 0,
                "body_preview": "[PATH_TRAVERSAL] Injecting traversal sequences into path params...",
            })
            await asyncio.sleep(0)
            try:
                pt_logs, pt_result = await probe_path_traversal(
                    session_id=session_id,
                    endpoint=endpoint,
                    base_url=scan["target_url"],
                )
            except Exception as e:
                yield _sse("error", {"message": f"Path traversal probe failed: {str(e)}", "endpoint": endpoint.path})
            else:
                for log in pt_logs:
                    save_fuzz_log(log)
                    yield _sse("fuzz_attempt", {
                        "attempt": log.attempt_number,
                        "method": log.request.get("method"),
                        "url": log.request.get("url"),
                        "status": log.response_status,
                        "body_preview": log.response_body[:200],
                    })
                    await asyncio.sleep(0)
                save_vuln_result(pt_result)
                yield _sse("verdict", {
                    "endpoint": endpoint.path,
                    "attack_type": "PATH_TRAVERSAL",
                    "verdict": pt_result.verdict,
                    "reasoning": pt_result.reasoning,
                    "evidence": pt_result.evidence,
                })
                await asyncio.sleep(0)
                if pt_result.verdict == "EXPLOIT_CONFIRMED":
                    try:
                        patch = generate_patch(pt_result, stack=stack)
                        save_patch(patch)
                        yield _sse("patch_ready", {
                            "endpoint": endpoint.path,
                            "attack_type": patch.attack_type,
                            "target_file": patch.target_file,
                            "language": patch.language,
                            "code": patch.code,
                            "instructions": patch.instructions,
                            "validated": patch.validated,
                        })
                        await asyncio.sleep(0)
                    except Exception as e:
                        yield _sse("error", {"message": f"Fixer failed for PATH_TRAVERSAL: {str(e)}", "endpoint": endpoint.path})

    update_session_status(session_id, "completed")
    yield _sse("done", {"session_id": session_id, "message": "Scan complete."})


@app.get("/scan/{session_id}/stream")
async def stream_scan(session_id: str, stack: str = "express"):
    return StreamingResponse(
        _pipeline_generator(session_id, stack),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# GET /scan/{session_id}/results  — final results for a completed scan
# ---------------------------------------------------------------------------

@app.get("/scan/{session_id}/results")
def get_results(session_id: str):
    logs = get_fuzz_logs(session_id)
    return {"session_id": session_id, "logs": logs}


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok"}
