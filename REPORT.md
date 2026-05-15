# SlingShot — Project Report

---

## 1. What & Why

SlingShot is an offensive-security agent that audits JSON REST APIs for logic-level vulnerabilities and automatically generates middleware patches to fix what it finds. A user uploads an OpenAPI spec, points the tool at a running API, and SlingShot runs a full attack suite: BOLA, Mass Assignment, BFLA, Excessive Data Exposure, Missing Auth, Verb Tampering, Rate Limiting, SQL Injection, and Path Traversal. SlingShot then streams results live to a split-panel UI showing the attacker's activity on the left and proposed code fixes on the right.

The target users are backend engineers and AppSec teams who want to test their APIs against adversarial logic before deployment, without needing a dedicated security team.

Getting the AI behavior right is the hardest part of the project for two reasons. First, the Attacker Agent must generate payloads that are both syntactically valid HTTP requests and semantically meaningful attacks. It can't just guess random IDs or omit auth headers, or every request returns 401 and nothing is learned. Early versions did exactly this: the LLM generated plausible-looking payloads but dropped the `Authorization` header, making every attack fail before it could test the actual vulnerability. Second, the Vulnerability Judge must distinguish a true exploit from a false positive. A `200 OK` response is not sufficient evidence; the response body must contain real data belonging to a different user, or an unauthorized field reflected back. Without explicit per-attack-type criteria in the judge prompt, the model collapsed all verdicts to `NO_VULNERABILITY` when responses looked superficially similar to error cases.

---

## 2. Iterations

### V1 — Proposal Scope: BOLA and Mass Assignment

**Change:** The initial system implemented exactly the two attack types described in the project proposal. The Attacker Agent generated adversarial payloads for BOLA (Broken Object Level Authorization) and Mass Assignment vulnerabilities using a single shared prompt template. The Fuzzing Engine passed both the baseline and attack payloads to the LLM as instructions and asked it to call a `make_request` tool to execute them. The LLM was responsible for constructing the actual HTTP requests. The Vulnerability Judge used a single generic three-check rubric applied identically to both attack types.

**Motivating example:** On `GET /api/v1/invoices/{invoice_id}` (TC-01), the Attacker Agent correctly identified the BOLA scenario — User A accessing invoice 999 owned by User B. However, every fuzz attempt returned `401 Unauthorized`. Inspecting the logs showed the LLM was generating `make_request` tool calls without an `Authorization` header, re-deriving the request from scratch rather than preserving the payload it had been given.

**Delta (eval set: TC-01, TC-02):**

| Test Case | Before | After fix |
|---|---|---|
| TC-01 BOLA | 0/3 confirmed | 3/3 confirmed |
| TC-02 Mass Assignment | 3/3 confirmed | 3/3 confirmed |

Fix Rate on V1 eval set: **2/2 = 100%** (after the auth header fix was applied). Before the fix, TC-01 never confirmed the exploit, making the fixer unreachable — effective fix rate was 1/2 = 50%.

**Conclusion:** Delegating request construction to the LLM introduced an unreliable step. The model understood the attack conceptually but failed to preserve auth context when translating it into a tool call. The architectural fix was to have Phase 1 of the fuzzing engine execute the attacker's payloads directly (`engine.py`), capturing status and body without LLM involvement. The LLM only enters in Phase 2 to decide whether follow-up mutations are needed, with the auth header injected as a safety net. Mass Assignment worked from the start because it doesn't depend on a specific resource ID — the attack payload is self-contained in the request body.

---

### V2 — Expanded Attack Surface: BFLA, Excessive Data Exposure, Missing Auth, Verb Tampering, BOPLA, Rate Limiting

**Change:** Six new attack types were added to the system. BFLA (Broken Function Level Authorization), Excessive Data Exposure, Missing Auth, and Verb Tampering were routed through the existing LLM attacker/judge pipeline with new per-attack-type prompt instructions added to `_ATTACK_INSTRUCTIONS`. Rate Limiting was implemented as a deterministic prober (`rate_limit_prober.py`) that fires 30 concurrent requests and checks for a `429` response. BOPLA (Broken Object Property Level Authorization) was partially covered by the Excessive Data Exposure attack type, which checks whether sensitive fields like `salary`, `ssn`, and `api_key` are returned to callers who should not receive them.

The most significant change was replacing the generic judge prompt with per-attack-type verdict criteria (`_VERDICT_CRITERIA` in `judge.py`). The original judge applied BOLA-style ownership reasoning to every attack type regardless of category.

**Motivating example:** On `GET /api/v1/reports/summary` (TC-05, TC-07), the endpoint returns `200 OK` with `api_key` and `db_connection_string` in the body. The V1 judge returned `NO_VULNERABILITY` for both Excessive Data Exposure and Missing Auth because the response body did not contain data "belonging to a different user." It was using BOLA logic for attacks that have nothing to do with resource ownership.

**Delta (eval set: TC-01 through TC-07, TC-11, TC-12):**

| Test Case | V1 result | V2 result |
|---|---|---|
| TC-01 BOLA | ✓ | ✓ |
| TC-02 Mass Assignment | ✓ | ✓ |
| TC-03 BFLA (GET) | —  | ✓ |
| TC-04 BFLA (DELETE) | — | ✓ |
| TC-05 Excessive Data Exposure | — | ✓ |
| TC-06 Excessive Data Exposure | — | ✓ |
| TC-07 Missing Auth | — | ✓ |
| TC-08 Rate Limit | — | ✓ |
| TC-09 Verb Tampering | — | ✓ |

Fix Rate on V2 eval set: **9/9 = 100%**. No change on TC-01 or TC-02.

**Conclusion:** The per-attack-type criteria were the key unlock. Each attack type now has an explicit checklist the judge must satisfy — BFLA checks for the absence of a 403, Excessive Data Exposure checks for sensitive field names in the response body, Missing Auth checks that the request had no Authorization header before confirming the exploit. The tradeoff is that adding a new attack type requires writing explicit criteria, but vague criteria produce vague verdicts, so this is the right constraint. The Rate Limiting prober confirmed that bypassing the LLM entirely for mechanical tests produces faster and more reliable results than asking the model to reason about response timing.

---

### V3 — Server-Side Detection: SQL Injection and Path Traversal

**Change:** SQL Injection and Path Traversal were added as the first attack types that require inspecting server-side behavior rather than just HTTP response semantics. Both were implemented as deterministic probers that bypass the LLM entirely. The SQLi prober (`fuzzer/sqli_prober.py`) runs three techniques in sequence: error-based (scan response body for 20 known DB error string patterns across MySQL, PostgreSQL, SQLite, MSSQL, and Oracle), time-based blind (inject `SLEEP(5)` / `pg_sleep(5)` payloads and measure response time against a 4.5s threshold), and log-based (tail a local DB query log file for the raw injected SQL). The path traversal prober (`fuzzer/path_traversal_prober.py`) injects 12 traversal sequences into path parameters and query strings, then checks responses against 11 file content signatures and 6 server-side path leak patterns.

**Motivating example:** When SQL Injection was first routed through the LLM attacker pipeline, the prober crashed silently on every endpoint. The `_inject_into_url` function used `re.sub(pattern, payload, path)` to substitute the path parameter — but when the payload was `\\` (a backslash), Python's `re` module interpreted it as a regex backreference in the replacement string and raised `bad escape (end of pattern) at position 0`. The LLM also had no mechanism to measure response time, making time-based blind injection structurally impossible through the existing pipeline.

**Delta (eval set: TC-01 through TC-12):**

| Test Case | V2 result | V3 result |
|---|---|---|
| TC-01 through TC-09, TC-11, TC-12 | ✓ | ✓ |
...
| TC-10 SQLI (query param) | — | ✓ |
| TC-11 SQLI (path param, time-based) | — | ✓ |
| TC-12 Path Traversal | — | ✓ |

Fix Rate on V3 eval set (TC-01 through TC-12): **12/12 = 100%**.

**Conclusion:** The `re.sub` crash was fixed by switching to a lambda replacement (`lambda _: payload`) so the payload string is treated as a literal rather than a regex replacement pattern (`sqli_prober.py`). The broader lesson is that the LLM attacker/judge pipeline is well-suited for semantic authorization attacks — where the model needs to reason about ownership, roles, and field permissions — but is a poor fit for mechanical injection testing that requires precise payload delivery, timing measurement, or pattern matching against known signatures. Separating these concerns made both halves more reliable. The remaining gap is that the SQLi prober only tests endpoints the spec parser flags as having path or query parameters; endpoints with unsanitized inputs that aren't documented in the OpenAPI spec are not reached.


---

## 3. Code Walkthrough

**Trace: user uploads `openapi.yaml` and clicks Launch Scan.**

`POST /scan` (`main.py:44`) receives the uploaded file, writes it to a temp file, and calls `parse_spec(tmp_path)` (`parser/spec_parser.py`). The parser reads the YAML, iterates over every path and method, and calls `_classify_endpoint()` (`spec_parser.py:68`) which applies seven classification rules: checking for ID path parameters (BOLA), mutation methods (Mass Assignment), admin path prefixes (BFLA), sensitive response schema fields (Excessive Data Exposure), and so on. Each endpoint gets an `attack_hints` list. The parsed endpoints are stored in `app.state.pending_scans` keyed by `session_id` and the response returns immediately.

The frontend opens an `EventSource` to `GET /scan/{session_id}/stream`. This hits `stream_scan()` (`main.py:283`) which returns a `StreamingResponse` wrapping `_pipeline_generator()` (`main.py:100`). For each high value endpoint, the generator calls `generate_all_payload_pairs()` (`agents/attacker.py:130`) which skips prober-only hints and calls `generate_payload_pair()` once per LLM-driven hint. That function formats a prompt with per-attack-type instructions from `_ATTACK_INSTRUCTIONS` (`attacker.py:14`) and calls GPT-4o with `response_format: json_object` to get a structured `PayloadPair` back.

The pair is passed to `run_fuzzing_session()` (`fuzzer/engine.py:95`). Phase 1 executes the baseline and attack payloads directly via `_run_and_log()`, capturing status and body without re-fetching. Phase 2 feeds those results to the LLM with a `make_request` tool definition. The LLM decides whether to probe further; the engine executes any tool calls it makes. Each `FuzzLog` is yielded and streamed to the frontend as a `fuzz_attempt` SSE event.

After the loop, `judge_session()` (`agents/judge.py:72`) formats the logs and injects the attack-type-specific criteria from `_VERDICT_CRITERIA` into the prompt. The judge runs at `temperature=0` for determinism.

**Design decision:** The LLM is given a `make_request` tool definition but never has direct network access. The engine intercepts every tool call and executes the HTTP request itself (`engine.py:148–167`). This keeps the fuzzing loop auditable: every request is logged, auth headers can be injected as a safety net, and the LLM cannot make requests outside the scan scope.

**Alternative considered and rejected:** An earlier design let the LLM generate all requests upfront as a batch (a list of payloads), then executed them all at once. This was rejected because it eliminated the feedback loop. The LLM couldn't adjust its next payload based on what the previous response revealed. The multi-turn tool-calling loop is more expensive but produces meaningfully better attack coverage on endpoints where the first attempt returns an ambiguous response.

---

## 4. AI disclosure & safety

Gemini was used to create a design document for the project. This document was then used in building the architecture and fleshing out requirements via Kiro. Kiro was used in the majority of this project, from initial coding to patching security flaws. As this is a proof-of-concept application, most of Kiro's suggestions were approved. Claude was then used to generate an evaluation script to test the metric and the AI's behavior. Claude was also used to pentest for additional security flaws in the application.

There was a feedback loop in the second iteration where batch payload generation was suggested by Kiro so that users could see what call requests the LLM was making during the attack. This batch payload generation suggestion was rejected despite being cheaper than the multi-turn loop because it better explains the attack being implemented at the time, what calls are being made, and shows the user where exactly the AI hacker is probing in their API. 
The payload display was also having issues displaying due to the prober collecting ALL events before emitting them, resulting in what seemed to be the application hanging during SQLI events. I added visuals such as a pulsing blue dot that displayed until the event was completed, but the actual issue was also related to the feedback loop above. Now, events are streamed as they occur, allowing users to follow along with the AI hacker.

One safety risk is prompt injection in `engine.py`, where the fuzzing attempts can be injected with malicious instructions like "Ignore previous instructions." Sanitizing input fields as well as filtering content that seems to be system instructions were implemented.
