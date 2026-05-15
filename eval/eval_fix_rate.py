#!/usr/bin/env python3
"""
eval_fix_rate.py — SlingShot Fix Rate Evaluation Harness
=========================================================
Metric:
    Fix Rate = (# of patches that correctly address the vulnerability)
             / (total # of confirmed vulnerabilities submitted to the fixer)

The script feeds labeled VulnResult inputs to generate_patch() and
validates each output against hand-written acceptance criteria.

Test cases:
    TC-01  BOLA                     GET  /api/v1/invoices/{invoice_id}      (Proposal case 1)
    TC-02  MASS_ASSIGNMENT          PATCH /api/v1/user/profile               (Proposal case 2)
    TC-03  BFLA                     GET  /api/v1/admin/users
    TC-04  BFLA                     DELETE /api/v1/admin/users/{user_id}
    TC-05  EXCESSIVE_DATA_EXPOSURE  GET  /api/v1/reports/summary
    TC-06  EXCESSIVE_DATA_EXPOSURE  GET  /api/v1/reports/users/{user_id}
    TC-07  MISSING_AUTH             GET  /api/v1/reports/summary
    TC-08  RATE_LIMIT               POST /api/v1/auth/login
    TC-09  VERB_TAMPERING           DELETE /api/v1/invoices/{invoice_id}  (undocumented method)
    TC-10  SQLI                     GET  /api/v1/search  (query param)
    TC-11  SQLI                     GET  /api/v1/search/{product_id}  (path param)
    TC-12  PATH_TRAVERSAL           GET  /api/v1/files/{filename}

Usage:
    cd eval
    ../backend/venv/bin/python3 eval_fix_rate.py

Requirements:
    - OPENAI_API_KEY set in backend/.env (loaded automatically)
    - pip install -r backend/requirements.txt  (run once to set up the venv)
"""

import os
import re
import sys
import json
import time
from dataclasses import dataclass

# ── path setup ─────────────────────────────────────────────────────────────
# Support running from repo root or from backend/
_EVAL_DIR  = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_EVAL_DIR)
_BACKEND   = os.path.join(_REPO_ROOT, "backend")
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

# Load .env from repo root so config.py picks up OPENAI_API_KEY regardless
# of which directory the script is invoked from.
from dotenv import load_dotenv  # noqa: E402
load_dotenv(os.path.join(_REPO_ROOT, ".env"))

from models.schemas import VulnResult, Patch  # noqa: E402
from agents.fixer import generate_patch       # noqa: E402


# ── string-matching helpers ────────────────────────────────────────────────

def _has(code: str, *terms: str) -> bool:
    """True when code contains ALL terms (case-insensitive substring match)."""
    lower = code.lower()
    return all(t.lower() in lower for t in terms)


def _has_any(code: str, *terms: str) -> bool:
    """True when code contains ANY of the terms (case-insensitive)."""
    lower = code.lower()
    return any(t.lower() in lower for t in terms)


def _has_re(code: str, pattern: str) -> bool:
    """True when pattern matches anywhere in code (re.IGNORECASE)."""
    return bool(re.search(pattern, code, re.IGNORECASE))


# ── test-case definition ───────────────────────────────────────────────────

@dataclass
class TestCase:
    id: str
    description: str
    vuln: VulnResult
    stack: str                     # "express" | "fastapi"
    # Returns (passed: bool, failure_reason: str)
    # failure_reason is ignored when passed=True
    validator: object              # Callable[[Patch], tuple[bool, str]]
    expected_pass: bool = True     # True for all positive test cases here


_SESSION = "eval-session-001"

TEST_CASES: list[TestCase] = [

    # ── TC-01 ─────────────────────────────────────────────────────────────
    # Source: Project_Proposal.pdf — first demonstration case.
    # Victim API: routes/invoices.js — owner_id never checked.
    TestCase(
        id="TC-01",
        description="BOLA — GET /api/v1/invoices/{invoice_id}: User A reads User B's invoice",
        stack="express",
        vuln=VulnResult(
            session_id=_SESSION,
            endpoint="GET /api/v1/invoices/{invoice_id}",
            attack_type="BOLA",
            verdict="EXPLOIT_CONFIRMED",
            evidence=(
                "Attempt #2: GET /api/v1/invoices/999 with "
                "Authorization: Bearer token_user_a returned 200 OK with body "
                '{"id":999,"owner_id":2,"amount":4200.00,'
                '"client_email":"bob@example.com","ssn_last4":"7890"}'
            ),
            reasoning=(
                "Criterion 1 met: 200 OK. "
                "Criterion 2 met: full invoice object returned. "
                "Criterion 3 met: owner_id=2 != requester id=1 (token_user_a)."
            ),
        ),
        # A correct BOLA fix must compare the resource owner to the requester
        # and return 403 when they differ.
        validator=lambda p: (
            _has(p.code, "owner_id", "403")
            and _has_any(p.code, "req.user", "user.id", "userId"),
            "Patch must compare owner_id to req.user.id and return 403 Forbidden",
        ),
    ),

    # ── TC-02 ─────────────────────────────────────────────────────────────
    # Source: Project_Proposal.pdf — second demonstration case.
    # Victim API: routes/users.js — Object.assign(user, req.body) with no allow-list.
    TestCase(
        id="TC-02",
        description="MASS_ASSIGNMENT — PATCH /api/v1/user/profile: is_admin privilege escalation",
        stack="express",
        vuln=VulnResult(
            session_id=_SESSION,
            endpoint="PATCH /api/v1/user/profile",
            attack_type="MASS_ASSIGNMENT",
            verdict="EXPLOIT_CONFIRMED",
            evidence=(
                'Attempt #2: PATCH /api/v1/user/profile with body {"bio":"hacker","is_admin":true} '
                'returned 200 OK with body '
                '{"id":1,"email":"alice@example.com","bio":"hacker","is_admin":true}'
            ),
            reasoning=(
                "Criterion 1 met: 200 OK. "
                "Criterion 2 met: user object returned. "
                "Criterion 3 met: is_admin:true accepted and reflected in response."
            ),
        ),
        # A correct fix must restrict accepted fields to the documented allow-list
        # (bio, avatar) and explicitly exclude privileged fields like is_admin.
        validator=lambda p: (
            _has_any(p.code, "bio", "avatar")
            and _has_any(
                p.code,
                "is_admin",
                "allowlist",
                "allow_list",
                "whitelist",
                "allowedFields",
                "allowed_fields",
                "allowedKeys",
            ),
            "Patch must enforce an allow-list of {bio, avatar} and block is_admin",
        ),
    ),

    # ── TC-03 ─────────────────────────────────────────────────────────────
    # openapi.yaml: GET /api/v1/admin/users tagged [admin] — no role guard in victim API.
    TestCase(
        id="TC-03",
        description="BFLA — GET /api/v1/admin/users: non-admin lists all users with PII",
        stack="express",
        vuln=VulnResult(
            session_id=_SESSION,
            endpoint="GET /api/v1/admin/users",
            attack_type="BFLA",
            verdict="EXPLOIT_CONFIRMED",
            evidence=(
                "Attempt #2: GET /api/v1/admin/users with Authorization: Bearer token_user_a "
                "returned 200 OK with body "
                '{"users":[{"id":1,"email":"alice@example.com","salary":95000,"ssn":"123-45-6789"}]}'
            ),
            reasoning=(
                "Criterion 1 met: 200 OK. "
                "Criterion 2 met: full user list with salary/SSN returned. "
                "Criterion 3 met: no 401/403 — server applied no role check."
            ),
        ),
        # Correct fix: verify req.user.is_admin === true before processing; return 403 otherwise.
        validator=lambda p: (
            _has(p.code, "is_admin", "403"),
            "Patch must check req.user.is_admin and return 403 for non-admin callers",
        ),
    ),

    # ── TC-04 ─────────────────────────────────────────────────────────────
    # Same admin route family but for the destructive DELETE variant.
    TestCase(
        id="TC-04",
        description="BFLA — DELETE /api/v1/admin/users/{user_id}: non-admin deletes another account",
        stack="express",
        vuln=VulnResult(
            session_id=_SESSION,
            endpoint="DELETE /api/v1/admin/users/{user_id}",
            attack_type="BFLA",
            verdict="EXPLOIT_CONFIRMED",
            evidence=(
                "Attempt #2: DELETE /api/v1/admin/users/2 with Authorization: Bearer token_user_a "
                'returned 200 OK with body {"message":"User 2 deleted"}'
            ),
            reasoning=(
                "Criterion 1 met: 200 OK. "
                "Criterion 2 met: deletion acknowledged in response. "
                "Criterion 3 met: token_user_a is not an admin; no 403 was returned."
            ),
        ),
        validator=lambda p: (
            _has(p.code, "is_admin", "403"),
            "Patch must gate the DELETE handler behind an is_admin check returning 403",
        ),
    ),

    # ── TC-05 ─────────────────────────────────────────────────────────────
    # openapi.yaml ReportSummary schema includes api_key, db_connection_string, internal_notes.
    TestCase(
        id="TC-05",
        description=(
            "EXCESSIVE_DATA_EXPOSURE — GET /api/v1/reports/summary: "
            "leaks api_key and db_connection_string"
        ),
        stack="express",
        vuln=VulnResult(
            session_id=_SESSION,
            endpoint="GET /api/v1/reports/summary",
            attack_type="EXCESSIVE_DATA_EXPOSURE",
            verdict="EXPLOIT_CONFIRMED",
            evidence=(
                "Attempt #1: GET /api/v1/reports/summary returned 200 OK with body "
                '{"total_revenue":120000,"api_key":"sk-prod-abc123",'
                '"db_connection_string":"postgres://admin:secret@db.internal/prod",'
                '"internal_notes":"Q3 targets unmet"}'
            ),
            reasoning=(
                "Criterion 1 met: 200 OK. "
                "Criterion 2 met: api_key and db_connection_string are secret fields. "
                "Criterion 3 met: both contain real non-null values."
            ),
        ),
        # Fix must strip/delete the sensitive fields before the response leaves the server.
        validator=lambda p: (
            _has_any(p.code, "api_key", "db_connection_string", "internal_notes")
            and _has_any(p.code, "delete", "filter", "omit", "pick", "sanitize", "remove"),
            "Patch must delete api_key, db_connection_string, and internal_notes from response",
        ),
    ),

    # ── TC-06 ─────────────────────────────────────────────────────────────
    # openapi.yaml UserReport schema exposes salary and ssn_last4 to any caller.
    TestCase(
        id="TC-06",
        description=(
            "EXCESSIVE_DATA_EXPOSURE — GET /api/v1/reports/users/{user_id}: "
            "leaks salary and SSN to unelevated callers"
        ),
        stack="express",
        vuln=VulnResult(
            session_id=_SESSION,
            endpoint="GET /api/v1/reports/users/{user_id}",
            attack_type="EXCESSIVE_DATA_EXPOSURE",
            verdict="EXPLOIT_CONFIRMED",
            evidence=(
                "Attempt #1: GET /api/v1/reports/users/2 returned 200 OK with body "
                '{"user_id":2,"email":"bob@example.com","salary":120000,'
                '"ssn_last4":"7890","internal_notes":"PIP candidate"}'
            ),
            reasoning=(
                "Criterion 1 met: 200 OK. "
                "Criterion 2 met: salary and ssn_last4 are sensitive PII. "
                "Criterion 3 met: salary=120000 is a real value."
            ),
        ),
        validator=lambda p: (
            _has_any(p.code, "salary", "ssn")
            and _has_any(p.code, "delete", "filter", "omit", "pick", "sanitize", "remove"),
            "Patch must strip salary and ssn_last4 from the outgoing response body",
        ),
    ),

    # ── TC-07 ─────────────────────────────────────────────────────────────
    # openapi.yaml /api/v1/reports/summary has no security scheme — no auth guard in handler.
    TestCase(
        id="TC-07",
        description=(
            "MISSING_AUTH — GET /api/v1/reports/summary: "
            "revenue data returned without any Authorization header"
        ),
        stack="express",
        vuln=VulnResult(
            session_id=_SESSION,
            endpoint="GET /api/v1/reports/summary",
            attack_type="MISSING_AUTH",
            verdict="EXPLOIT_CONFIRMED",
            evidence=(
                "Attempt #1: GET /api/v1/reports/summary with no Authorization header "
                'returned 200 OK with body {"total_revenue":120000,"active_users":45}'
            ),
            reasoning=(
                "Criterion 1 met: request had no Authorization header. "
                "Criterion 2 met: 200 OK — server did not return 401. "
                "Criterion 3 met: real revenue data included in response."
            ),
        ),
        # Fix must inspect the Authorization header and reject the request with 401
        # when it is absent or malformed.
        validator=lambda p: (
            _has_any(p.code, "authorization", "bearer", "token")
            and _has(p.code, "401"),
            "Patch must validate the Authorization header and return 401 when absent/invalid",
        ),
    ),

    # ── TC-08 ─────────────────────────────────────────────────────────────
    # Simulates the rate_limit_prober.py finding: 30 concurrent requests, 0 throttling.
    TestCase(
        id="TC-08",
        description=(
            "RATE_LIMIT — POST /api/v1/auth/login: "
            "30 concurrent requests all return 200 — no throttling observed"
        ),
        stack="express",
        vuln=VulnResult(
            session_id=_SESSION,
            endpoint="POST /api/v1/auth/login",
            attack_type="RATE_LIMIT",
            verdict="EXPLOIT_CONFIRMED",
            evidence=(
                "30 concurrent POST /api/v1/auth/login requests all returned 200 OK within 1.2 s. "
                "No 429 Too Many Requests response was observed in any attempt."
            ),
            reasoning=(
                "All 30 requests succeeded without throttling, confirming the endpoint has no "
                "rate limiting. An attacker can brute-force credentials indefinitely."
            ),
        ),
        # Fix must apply express-rate-limit (or equivalent) that returns 429 after the threshold.
        validator=lambda p: (
            _has_any(
                p.code,
                "rateLimit",
                "rate_limit",
                "rateLimiter",
                "express-rate-limit",
                "slowapi",
                "windowMs",
                "window_size",
                "limiter",
            )
            and _has_any(p.code, "429", "too many", "rate"),
            (
                "Patch must implement express-rate-limit (or slowapi) with a "
                "sensible window and return 429 when the limit is exceeded"
            ),
        ),
    ),

    # ── TC-09 ─────────────────────────────────────────────────────────────
    # openapi.yaml documents only GET for /api/v1/invoices/{invoice_id}.
    # Fuzzer discovers DELETE is also accepted.
    TestCase(
        id="TC-09",
        description=(
            "VERB_TAMPERING — DELETE /api/v1/invoices/{invoice_id}: "
            "undocumented DELETE method accepted, allows unauthorized deletion"
        ),
        stack="express",
        vuln=VulnResult(
            session_id=_SESSION,
            endpoint="GET /api/v1/invoices/{invoice_id}",
            attack_type="VERB_TAMPERING",
            verdict="EXPLOIT_CONFIRMED",
            evidence=(
                "Attempt #2: DELETE /api/v1/invoices/1 with Authorization: Bearer token_user_a "
                'returned 200 OK with body {"message":"Invoice 1 deleted"}. '
                "The spec documents only GET for this path."
            ),
            reasoning=(
                "Criterion 1 met: DELETE is not in the OpenAPI spec for /api/v1/invoices/{invoice_id}. "
                "Criterion 2 met: 200 OK returned. "
                "Criterion 3 met: deletion confirmed by response body."
            ),
        ),
        # Fix must restrict the route to documented methods (GET only) and return 405 for all others.
        validator=lambda p: (
            _has_any(p.code, "405", "method not allowed", "allowedMethods", "allowed_methods")
            and _has_any(p.code, "GET", "get"),
            "Patch must whitelist GET and return 405 Method Not Allowed for all other HTTP verbs",
        ),
    ),

    # ── TC-10 ─────────────────────────────────────────────────────────────
    # openapi.yaml: /api/v1/search?q= described as "passed unsanitized to SQL LIKE clause".
    TestCase(
        id="TC-10",
        description=(
            "SQLI — GET /api/v1/search?q=: "
            "error-based injection via unsanitized LIKE clause parameter"
        ),
        stack="express",
        vuln=VulnResult(
            session_id=_SESSION,
            endpoint="GET /api/v1/search",
            attack_type="SQLI",
            verdict="EXPLOIT_CONFIRMED",
            evidence=(
                "Attempt #2: GET /api/v1/search?q=' OR '1'='1 returned 500 Internal Server Error "
                'with body {"error":"SQLITE_ERROR: near \\"\\\'\\": syntax error in '
                "SELECT * FROM products WHERE name LIKE '%' OR '1'='1%'\"}"
            ),
            reasoning=(
                "The error message exposes the raw SQL query, proving the q parameter is "
                "concatenated directly into the LIKE clause without escaping."
            ),
        ),
        # Fix must switch from string concatenation to a parameterized query with a bound placeholder.
        validator=lambda p: (
            _has_any(p.code, "?", ":q", ":query", "parameterized", "prepared", "placeholder"),
            "Patch must use a parameterized query (?, :q) instead of string concatenation for q",
        ),
    ),

    # ── TC-11 ─────────────────────────────────────────────────────────────
    # openapi.yaml: /api/v1/search/{product_id} — "time-based SQLi" in path parameter.
    TestCase(
        id="TC-11",
        description=(
            "SQLI — GET /api/v1/search/{product_id}: "
            "time-based blind injection via unsanitized integer path parameter"
        ),
        stack="express",
        vuln=VulnResult(
            session_id=_SESSION,
            endpoint="GET /api/v1/search/{product_id}",
            attack_type="SQLI",
            verdict="EXPLOIT_CONFIRMED",
            evidence=(
                "Attempt #3: GET /api/v1/search/1%3BSELECT%20SLEEP(3) took 3.14 s vs "
                "baseline 42 ms, confirming the injected SLEEP(3) executed inside the query."
            ),
            reasoning=(
                "Response latency of 3.14 s vs 42 ms baseline proves the SLEEP(3) ran, "
                "meaning the path parameter is interpolated into SQL without sanitization."
            ),
        ),
        # Fix must both parameterize the query AND validate that product_id is a valid integer,
        # rejecting non-numeric values with a 400 before the query is ever reached.
        validator=lambda p: (
            _has_any(p.code, "?", ":product_id", ":id", "parameterized", "prepared")
            and _has_any(p.code, "parseInt", "isNaN", "isInteger", "400", "invalid", "numeric"),
            (
                "Patch must use a parameterized query AND validate product_id "
                "is a valid integer (return 400 for non-numeric values)"
            ),
        ),
    ),

    # ── TC-12 ─────────────────────────────────────────────────────────────
    # openapi.yaml: /api/v1/files/{filename} — "not sanitized — vulnerable to path traversal".
    TestCase(
        id="TC-12",
        description=(
            "PATH_TRAVERSAL — GET /api/v1/files/{filename}: "
            "reads /etc/passwd via URL-encoded ../ sequences"
        ),
        stack="express",
        vuln=VulnResult(
            session_id=_SESSION,
            endpoint="GET /api/v1/files/{filename}",
            attack_type="PATH_TRAVERSAL",
            verdict="EXPLOIT_CONFIRMED",
            evidence=(
                "Attempt #2: GET /api/v1/files/..%2F..%2F..%2Fetc%2Fpasswd returned 200 OK "
                "with body starting: 'root:x:0:0:root:/root:/bin/bash\\ndaemon:x:1:1:...'"
            ),
            reasoning=(
                "Server resolved the traversal sequence and served /etc/passwd, proving the "
                "filename is passed directly to path.join() without canonical-path validation."
            ),
        ),
        # Fix must resolve the canonical path and confirm it stays within the allowed base dir.
        validator=lambda p: (
            _has_any(p.code, "path.resolve", "realpath", "resolve(", "path.join")
            and _has_any(p.code, "startsWith", "is_relative_to", "indexOf", "includes", "startswith")
            and _has(p.code, "403"),
            (
                "Patch must call path.resolve(), verify the result startsWith(BASE_DIR), "
                "and return 403 for any traversal outside the base directory"
            ),
        ),
    ),
]


# ── result container ───────────────────────────────────────────────────────

@dataclass
class EvalResult:
    tc_id: str
    description: str
    attack_type: str
    passed: bool
    failure_reason: str
    patch_snippet: str   # first 200 chars of generated code
    error: str           # set if generate_patch() raised


# ── runner ─────────────────────────────────────────────────────────────────

def run_evaluation(
    test_cases: list[TestCase],
    inter_call_delay: float = 1.5,
) -> list[EvalResult]:
    """
    Call generate_patch() for every test case and validate the output.
    inter_call_delay: seconds between OpenAI calls to avoid rate-limit 429s.
    """
    results: list[EvalResult] = []

    for i, tc in enumerate(test_cases, 1):
        print(f"\n[{i:>2}/{len(test_cases)}] {tc.id}  ({tc.vuln.attack_type})")
        print(f"       {tc.description}")

        passed = False
        failure_reason = ""
        snippet = ""
        error_str = ""

        try:
            patch: Patch = generate_patch(tc.vuln, stack=tc.stack)
            snippet = patch.code[:200].replace("\n", " ↵ ")
            passed, failure_reason = tc.validator(patch)
        except json.JSONDecodeError as exc:
            error_str = f"Fixer returned invalid JSON: {exc}"
        except Exception as exc:
            error_str = f"{type(exc).__name__}: {exc}"

        if error_str:
            passed = False
            failure_reason = error_str

        label = "✓ PASS" if passed else "✗ FAIL"
        print(f"       {label}  |  {failure_reason if not passed else 'criteria met'}")
        if snippet:
            print(f"       code: {snippet[:120]}…")

        results.append(EvalResult(
            tc_id=tc.id,
            description=tc.description,
            attack_type=tc.vuln.attack_type,
            passed=passed,
            failure_reason=failure_reason,
            patch_snippet=snippet,
            error=error_str,
        ))

        if i < len(test_cases):
            time.sleep(inter_call_delay)

    return results


# ── report ─────────────────────────────────────────────────────────────────

def print_report(results: list[EvalResult]) -> float:
    """Print a formatted summary and return the Fix Rate (0.0–1.0)."""
    total  = len(results)
    passed = sum(1 for r in results if r.passed)
    fix_rate = passed / total if total else 0.0

    bar = "─" * 74
    print(f"\n{bar}")
    print("  SLINGSHOT  —  Fix Rate Evaluation Report")
    print(bar)
    print(f"  {'ID':<8} {'Status':<8} {'Attack Type':<26} Description")
    print(bar)

    for r in results:
        status = "✓ PASS" if r.passed else "✗ FAIL"
        label  = r.description[:44]
        print(f"  {r.tc_id:<8} {status:<8} {r.attack_type:<26} {label}")

    print(bar)
    print(f"  Total vulnerabilities  : {total}")
    print(f"  Patches accepted       : {passed}  (pass criteria met)")
    print(f"  Patches rejected       : {total - passed}")
    print()
    print(f"  Fix Rate = {passed}/{total} = {fix_rate:.1%}")
    print(bar)

    failures = [r for r in results if not r.passed]
    if failures:
        print("\n  FAILURES:")
        for r in failures:
            msg = r.error or r.failure_reason
            print(f"    {r.tc_id}: {msg}")
        print()

    return fix_rate


# ── entry point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 74)
    print("  SlingShot — Fix Rate Evaluation Harness")
    print("  Metric : Fix Rate = correctly patched / total confirmed vulns")
    print(f"  Cases  : {len(TEST_CASES)}")
    print("=" * 74)

    results  = run_evaluation(TEST_CASES)
    fix_rate = print_report(results)

    # CI-friendly exit code: 0 if Fix Rate ≥ 80 %, else 1
    sys.exit(0 if fix_rate >= 0.80 else 1)