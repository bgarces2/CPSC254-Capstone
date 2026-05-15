# SlingShot — Project Report

---

## 1. What & Why

SlingShot is an offensive-security agent that audits JSON REST APIs for logic-level vulnerabilities and automatically generates middleware patches to fix what it finds. A user uploads an OpenAPI spec, points the tool at a running API, and SlingShot runs a full attack suite — BOLA, Mass Assignment, BFLA, Excessive Data Exposure, Missing Auth, Verb Tampering, Rate Limiting, SQL Injection, and Path Traversal — then streams results live to a split-panel UI showing the attacker's activity on the left and proposed code fixes on the right. The target users are backend engineers and AppSec teams who want to test their APIs against adversarial logic before deployment.

Getting the AI behavior right is the hardest part of the project for two reasons. First, the Attacker Agent must generate payloads that are both syntactically valid HTTP requests and semantically meaningful attacks. It cannot guess random IDs or omit auth headers — early versions did exactly this, dropping the `Authorization` header so every request returned `401` before the actual vulnerability could be tested. Second, the Vulnerability Judge must distinguish a true exploit from a false positive. A `200 OK` is not sufficient evidence; the response body must contain real data belonging to a different user, or an unauthorized field reflected back. Without explicit per-attack-type criteria in the judge prompt, the model collapsed all verdicts to `NO_VULNERABILITY` when responses looked superficially similar to error cases.

---

## 2. Iterations

### V1 — Proposal Scope: BOLA and Mass Assignment

**Change:** The initial system implemented the two attack types from the proposal. The Attacker Agent generated payloads using a single shared prompt template. The Fuzzing Engine passed both payloads to the LLM as instructions and asked it to call a `make_request` tool to execute them — the LLM was responsible for constructing the actual HTTP requests. The Vulnerability Judge used a single generic three-check rubric for both attack types.

**Motivating example:** On `GET /api/v1/invoices/{invoice_id}` (TC-01), the Attacker Agent correctly identified the BOLA scenario but every fuzz attempt returned `401 Unauthorized`. The LLM was generating `make_request` calls without an `Authorization` header, re-deriving the request from scratch rather than preserving the payload it had been given.

**Delta (eval set: TC-01, TC-02):**

| Test Case | Before | After fix |
|---|---|---|
| TC-01 BOLA | 0/3 confirmed | 3/3 confirmed |
| TC-02 Mass Assignment | 3/3 confirmed | 3/3 confirmed |

Fix Rate on V1 eval set: **2/2 = 100%** (after the auth header fix). Before the fix, TC-01 never confirmed the exploit — effective fix rate was 1/2 = 50%.

**Conclusion:** Delegating request construction to the LLM was unreliable. The model understood the attack conceptually but failed to preserve auth context in the tool call. The fix was to have Phase 1 of the fuzzing engine execute payloads directly, with the auth header injected as a safety net. The LLM only enters in Phase 2 for follow-up mutations.

---

### V2 — Expanded Attack Surface: BFLA, Excessive Data Exposure, Missing Auth, Verb Tampering, BOPLA, Rate Limiting

**Change:** Six new attack types were added. BFLA, Excessive Data Exposure, Missing Auth, and Verb Tampering were routed through the LLM pipeline with per-attack-type instructions in `_ATTACK_INSTRUCTIONS`. Rate Limiting was implemented as a deterministic prober firing 30 concurrent requests and checking for `429`. BOPLA was partially covered by Excessive Data Exposure. The most significant change was replacing the generic judge prompt with per-attack-type verdict criteria in `_VERDICT_CRITERIA` (`judge.py`).

**Motivating example:** On `GET /api/v1/reports/summary` (TC-05, TC-07), the endpoint returns `api_key` and `db_connection_string` in the body. The V1 judge returned `NO_VULNERABILITY` for both Excessive Data Exposure and Missing Auth because it was applying BOLA ownership logic — checking whether data belonged to a different user — to attacks that have nothing to do with resource ownership.

**Delta (eval set: TC-01 through TC-09):**

| Test Case | V1 result | V2 result |
|---|---|---|
| TC-01 BOLA | ✓ | ✓ |
| TC-02 Mass Assignment | ✓ | ✓ |
| TC-03 BFLA (GET) | — | ✓ |
| TC-04 BFLA (DELETE) | — | ✓ |
| TC-05 Excessive Data Exposure | — | ✓ |
| TC-06 Excessive Data Exposure | — | ✓ |
| TC-07 Missing Auth | — | ✓ |
| TC-08 Rate Limit | — | ✓ |
| TC-09 Verb Tampering | — | ✓ |

Fix Rate on V2 eval set: **9/9 = 100%**. No change on TC-01 or TC-02.

**Conclusion:** Per-attack-type criteria were the key unlock. Each attack type now has an explicit checklist — BFLA checks for the absence of a 403, Excessive Data Exposure checks for sensitive field names, Missing Auth checks that no Authorization header was sent. The Rate Limiting prober confirmed that bypassing the LLM entirely for mechanical tests is faster and more reliable than asking the model to reason about response timing.

---

### V3 — Server-Side Detection: SQL Injection and Path Traversal

**Change:** SQL Injection and Path Traversal were added as deterministic probers that bypass the LLM entirely. The SQLi prober (`fuzzer/sqli_prober.py`) runs three techniques: error-based (20 DB error string patterns), time-based blind (`SLEEP(5)` payloads measured against a 4.5s threshold), and log-based (tailing a local DB query log). The path traversal prober (`fuzzer/path_traversal_prober.py`) injects 12 traversal sequences and checks responses against 11 file content signatures and 6 path leak patterns.

**Motivating example:** When SQL Injection was first routed through the LLM pipeline, the prober crashed silently on every endpoint. `_inject_into_url` used `re.sub(pattern, payload, path)` — when the payload was `\\`, Python's `re` module interpreted it as a regex backreference and raised `bad escape (end of pattern) at position 0`. The LLM also had no mechanism to measure response time, making time-based blind injection structurally impossible.

**Delta (eval set: TC-01 through TC-12):**

| Test Case | V2 result | V3 result |
|---|---|---|
| TC-01 through TC-09 | ✓ | ✓ |
| TC-10 SQLI (query param) | — | ✓ |
| TC-11 SQLI (path param, time-based) | — | ✓ |
| TC-12 Path Traversal | — | ✓ |

Fix Rate on V3 eval set (TC-01 through TC-12): **12/12 = 100%**.

**Conclusion:** The crash was fixed by switching to a lambda replacement (`lambda _: payload`) so the payload is treated as a literal string. The broader lesson: the LLM pipeline suits semantic authorization attacks but is a poor fit for injection testing that requires precise payload delivery and timing. The remaining gap is that the SQLi prober only reaches endpoints the spec parser flags as having path or query parameters.


---

## 3. Code Walkthrough

**Trace: user uploads `openapi.yaml` and clicks Launch Scan.**

`POST /scan` (`main.py:44`) writes the uploaded file to a temp path and calls `parse_spec()` (`parser/spec_parser.py`). The parser iterates every path and method, calling `_classify_endpoint()` which applies seven rules: ID path parameters flag BOLA, mutation methods flag Mass Assignment, admin path prefixes flag BFLA, and so on. Each endpoint gets an `attack_hints` list stored in `app.state.pending_scans` keyed by `session_id`.

The frontend opens an `EventSource` to `GET /scan/{session_id}/stream`, returning a `StreamingResponse` wrapping `_pipeline_generator()` (`main.py:100`). For each high-value endpoint, the generator calls `generate_all_payload_pairs()` (`agents/attacker.py:130`), which skips prober-only hints and calls `generate_payload_pair()` once per LLM-driven hint. That function injects per-attack-type instructions from `_ATTACK_INSTRUCTIONS` and calls GPT-4o with `response_format: json_object` to get a structured `PayloadPair`.

The pair goes to `run_fuzzing_session()` (`fuzzer/engine.py:95`). Phase 1 executes the baseline and attack payloads directly via `_run_and_log()`. Phase 2 feeds those results to the LLM with a `make_request` tool — the LLM decides whether to probe further; the engine executes any tool calls. Each `FuzzLog` is yielded and streamed as a `fuzz_attempt` SSE event. After the loop, `judge_session()` (`agents/judge.py:72`) injects attack-type-specific criteria and returns a verdict at `temperature=0`.

**Design decision:** The LLM receives a `make_request` tool definition but never has direct network access. The engine intercepts every call and executes the HTTP request itself (`engine.py:148-167`), keeping the loop auditable and preventing the LLM from reaching hosts outside the scan scope.

**Alternative rejected:** An earlier design generated all payloads upfront as a batch. This was dropped because it eliminated the feedback loop — the LLM could not adjust follow-up payloads based on what previous responses revealed.

---

## 4. AI disclosure & safety

Gemini was used to create a design document for the project. This document was then used in building the architecture and fleshing out requirements via Kiro. Kiro was used in the majority of this project, from initial coding to patching security flaws. As this is a proof-of-concept application, most of Kiro's suggestions were approved. Claude was then used to generate an evaluation script to test the metric and the AI's behavior. 

There was a feedback loop in the second iteration where batch payload generation was suggested by Kiro so that users could see what call requests the LLM was making during the attack. This suggestion was rejected despite being cheaper than the multi-turn loop because it better explains the attack being implemented at the time.

The payload display was also having issues displaying due to the prober collecting ALL events before emitting them, resulting in what seemed to be the application hanging during SQLI events. I added visuals such as a pulsing blue dot that displayed until the event was completed, but the actual issue was related to the feedback loop above. Now, events are streamed as they occur, allowing users to follow along with the AI hacker.

One safety risk is prompt injection in `engine.py`, where the fuzzing attempts can be injected with malicious instructions like "Ignore previous instructions." Sanitizing input fields as well as filtering content that seems to be system instructions were implemented.
