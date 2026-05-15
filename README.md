# SlingShot

An offensive-security agent that probes JSON REST APIs with OpenAPI specs for 9 classes of vulnerability — from authorization logic flaws like BOLA and BFLA to injection attacks like SQL Injection and Path Traversal — then automatically generates defensive middleware patches to fix what it finds.

---

## Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+
- An OpenAI API key

### 1. Set your API key

Copy the example env file and add your key:

```bash
cp .env.example .env
# then edit .env and set OPENAI_API_KEY=sk-...
```

### 2. Start the Victim API

```bash
cd victim-api
npm install
npm start
# Running on http://localhost:3000
```

### 3. Start the Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload
# Running on http://localhost:8000
```

### 4. Start the Frontend

```bash
cd frontend
npm install
npm run dev
# Running on http://localhost:5173
```

### 5. Run your first audit

1. Open **http://localhost:5173**
2. Upload `victim-api/openapi.yaml` as the spec file
3. Leave the target URL as `http://localhost:3000`
4. Click **Launch Scan**

Watch the Attacker Terminal stream live fuzzing attempts on the left. When an exploit is confirmed, the generated middleware patch appears on the right.

---

## Evaluation Metric

Fix Rate = (# of security holes AI successfully fixed) / (total # of holes AI found)

An evaluation script `eval_fix_rate.py` can be found in the `eval/` directory. The script contains 12 test cases, one for each attack vector. A test case passes if the Fixer Agent generates a patch that correctly addresses the specific vulnerability. A fix rate ≥ 80% exits with code 0.

Before running the evaluation script, ensure the backend venv is set up (`pip install -r backend/requirements.txt`). 

```bash
cd eval
../backend/venv/bin/python3 eval_fix_rate.py
```

Example output:
```
──────────────────────────────────────────────────────────────────────────
  SLINGSHOT  —  Fix Rate Evaluation Report
──────────────────────────────────────────────────────────────────────────
  ID       Status   Attack Type                Description
──────────────────────────────────────────────────────────────────────────
  TC-01    ✗ FAIL   BOLA                       BOLA — GET /api/v1/invoices/{invoice_id}: Us
  TC-02    ✗ FAIL   MASS_ASSIGNMENT            MASS_ASSIGNMENT — PATCH /api/v1/user/profile
  TC-03    ✗ FAIL   BFLA                       BFLA — GET /api/v1/admin/users: non-admin li
  TC-04    ✓ PASS   BFLA                       BFLA — DELETE /api/v1/admin/users/{user_id}:
  TC-05    ✓ PASS   EXCESSIVE_DATA_EXPOSURE    EXCESSIVE_DATA_EXPOSURE — GET /api/v1/report
  TC-06    ✓ PASS   EXCESSIVE_DATA_EXPOSURE    EXCESSIVE_DATA_EXPOSURE — GET /api/v1/report
  TC-07    ✓ PASS   MISSING_AUTH               MISSING_AUTH — GET /api/v1/reports/summary:
  TC-08    ✗ FAIL   RATE_LIMIT                 RATE_LIMIT — POST /api/v1/auth/login: 30 con
  TC-09    ✓ PASS   VERB_TAMPERING             VERB_TAMPERING — DELETE /api/v1/invoices/{in
  TC-10    ✓ PASS   SQLI                       SQLI — GET /api/v1/search?q=: error-based in
  TC-11    ✓ PASS   SQLI                       SQLI — GET /api/v1/search/{product_id}: time
  TC-12    ✓ PASS   PATH_TRAVERSAL             PATH_TRAVERSAL — GET /api/v1/files/{filename
──────────────────────────────────────────────────────────────────────────
  Total vulnerabilities  : 12
  Patches accepted       : 9  (pass criteria met)
  Patches rejected       : 3

  Fix Rate = 9/12 = 75.0%
──────────────────────────────────────────────────────────────────────────

  FAILURES:
    TC-01: Patch must compare owner_id to req.user.id and return 403 Forbidden
    TC-02: Patch must enforce an allow-list of {bio, avatar} and block is_admin
    TC-03: Patch must check req.user.is_admin and return 403 for non-admin callers
```

---

## Project Structure

```
slingshot/
├── backend/              # Python / FastAPI — pipeline orchestrator + agents
│   ├── agents/           # Attacker, Judge, and Fixer LLM agents
│   ├── fuzzer/           # Fuzzing engine + deterministic probers
│   │   ├── engine.py         # Multi-turn LLM fuzzing loop
│   │   ├── rate_limit_prober.py  # Fires 30 concurrent requests; checks for 429 throttling
│   │   ├── sqli_prober.py        # Error-based, time-based, and log-based SQL injection detection
│   │   └── path_traversal_prober.py  # Injects traversal sequences; checks for file content leaks
│   ├── parser/           # OpenAPI spec ingestion + endpoint classification
│   ├── models/           # Dataclass schemas (Endpoint, FuzzLog, VulnResult, Patch)
│   ├── db/               # SQLite persistence + session expiry
│   ├── security.py       # SSRF validation + prompt injection sanitization
│   └── main.py           # FastAPI app + SSE stream
│
├── frontend/             # React / Vite — Duel View UI
│   └── src/
│       └── components/   # AttackerTerminal + PatchViewer
│
├── victim-api/           # Intentionally vulnerable Express API (scan target)
│   ├── routes/
│   │   ├── invoices.js   # BOLA vulnerability
│   │   ├── users.js      # Mass Assignment vulnerability
│   │   ├── admin.js      # BFLA vulnerability
│   │   ├── reports.js    # Excessive Data Exposure + Missing Auth
│   │   ├── search.js     # SQL Injection vulnerability
│   │   └── files.js      # Path Traversal vulnerability
│   └── openapi.yaml      # Spec file to upload into SlingShot
│
└── eval/
    └── eval_fix_rate.py  # Fix Rate evaluation harness (12 test cases)
```

---

## How It Works

1. **Spec Parser** reads your OpenAPI file and classifies every endpoint by attack type — checking for ID path parameters (BOLA), mutation methods (Mass Assignment), admin path prefixes (BFLA), sensitive response schema fields (Excessive Data Exposure), and more.
2. **Attacker Agent** (GPT-4o) generates a baseline + attack `PayloadPair` for each LLM-driven attack type, with per-attack-type prompt instructions to ensure correct payload construction.
3. **Fuzzing Engine** executes payloads in a two-phase loop — Phase 1 runs the attacker's payloads directly (preserving auth headers), Phase 2 lets the LLM call a `make_request` tool to try follow-up mutations.
4. **Deterministic Probers** handle Rate Limiting, SQL Injection, and Path Traversal without LLM involvement — using concurrent request bursts, DB error pattern matching, response timing, and file content signatures.
5. **Vulnerability Judge** (GPT-4o) reviews the fuzzing logs using attack-type-specific verdict criteria to filter false positives.
6. **Fixer Agent** (GPT-4o) generates targeted middleware patches for confirmed exploits. Patches are AI-generated — review before applying to production.
7. **Safety layer** validates the target URL against SSRF risks (blocks private IPs, localhost, cloud metadata endpoints) and sanitizes API response bodies before injecting them into LLM prompts to prevent prompt injection.

---

## Supported Attack Vectors

| Attack | Type | Detection Method | Description |
|---|---|---|---|
| **BOLA** | Logic | LLM | Broken Object Level Authorization. Tests whether an authenticated user can access resources owned by another user by manipulating a resource ID in the path (e.g., `/invoices/999` as User A when 999 belongs to User B). |
| **Mass Assignment** | Logic | LLM | Tests whether the API accepts and applies fields that should be restricted — such as `is_admin: true` or `role: "admin"` — when they are included in a request body alongside legitimate fields. |
| **BFLA** | Logic | LLM | Broken Function Level Authorization. Tests whether a regular authenticated user can call endpoints that should be restricted to admins or privileged roles (e.g., `GET /admin/users`). |
| **Excessive Data Exposure** | Logic | LLM | Tests whether the API returns sensitive fields in its response that should never reach clients — such as `salary`, `ssn`, `api_key`, `password_hash`, or `internal_notes`. |
| **Missing Auth** | Logic | LLM | Tests whether an endpoint returns data to a caller with no `Authorization` header at all, confirming the endpoint has no authentication guard. |
| **Verb Tampering** | Logic | LLM | Tests whether the API accepts HTTP methods that are not documented in the OpenAPI spec for a given path (e.g., `DELETE` on a `GET`-only route), which may bypass authorization logic. |
| **Rate Limiting** | Availability | Deterministic | Fires 30 concurrent requests at the endpoint and checks whether the server ever returns `429 Too Many Requests`. No LLM involved — verdict is purely numeric. |
| **SQL Injection (Partial)** | Injection | Deterministic | Runs three techniques in sequence: error-based (injects metacharacters and scans responses for DB error strings), time-based blind (injects `SLEEP(5)` payloads and measures response latency), and log-based (tails a local DB query log for raw injected SQL). |
| **Path Traversal** | Injection | Deterministic | Injects 12 traversal sequences (`../../../etc/passwd`, URL-encoded variants, null bytes, Windows paths) into path parameters and query strings, then checks responses for known file content signatures and server-side path leak patterns. |

---

## Future Work

SlingShot's current architecture is intentionally constrained: it only observes HTTP responses and never touches the server it is scanning. This makes it safe to run against any target, but it rules out several attack classes that require either server-side visibility or a real browser runtime. Attacks I'd like to implement in the future: 
- Cross-Site Scripting (XSS)
- Server-Side Request Forgery (SSRF)
- Full SQL Injection (Read/Write Confirmation)
- Insecure Deserialization

In addition to these attacks, the current architecture only applies to the ready-to-implement Victim API. Future changes to architecture will need to include handling spec discovery, authentication flow, HTML response parsing, and spec-less endpoint classification if external scanning of websites is to be implemented. 
More details on future implementations can be found in `futurework.md`.

---

## Environmental Variables

| Variable | Default | Description |
|---|---|---|
| `OPENAI_API_KEY` | — | Required. Your OpenAI API key |
| `OPENAI_MODEL` | `gpt-4o` | Model to use for all agents |
| `TARGET_BASE_URL` | `http://localhost:3000` | Default scan target |
| `MAX_FUZZ_ATTEMPTS` | `10` | Max requests per fuzzing session |
| `DATABASE_URL` | `slingshot.db` | SQLite file path |
| `SESSION_MAX_AGE_HOURS` | `24` | Hours before scan sessions and their logs are automatically deleted |
