## Future Work

SlingShot's current architecture is intentionally constrained: it only observes HTTP responses and never touches the server it is scanning. This makes it safe to run against any target, but it rules out several attack classes that require either server-side visibility or a real browser runtime. Below are the most impactful additions, what would need to change to implement them, and the security risks each introduces.

---

### Cross-Site Scripting (XSS)

**What it needs:** A headless browser (Playwright or Puppeteer). XSS requires JavaScript to execute — a JSON API response containing `<script>window.__xss=1</script>` is meaningless without a browser to render it. SlingShot would need to inject a payload, navigate to the affected page, and inspect the browser's JavaScript context to confirm execution.

**What would change:** A new `xss_prober.py` would launch a Playwright browser instance, inject payloads into form fields and URL parameters, and check `page.evaluate("window.__xss")` after navigation. The existing SSE pipeline would stream browser console events alongside HTTP logs.

**Security risks:** Running a headless browser inside the backend process significantly expands the attack surface. A malicious target page could attempt to exploit browser vulnerabilities, exfiltrate data via `fetch()` calls to external hosts, or use `window.open()` to pivot to other local services. Mitigation would require running the browser in a sandboxed subprocess with network egress restricted to the target origin only, and a strict Content Security Policy on the SlingShot frontend to prevent injected scripts from reaching back to the backend.

---

### Server-Side Request Forgery (SSRF)

**What it needs:** A local listener that can detect inbound connections. SSRF works by injecting a URL into a parameter and checking whether the server makes an outbound request to that URL. Without a listener, there is no way to confirm the server made the request — the HTTP response alone is not sufficient evidence.

**What would change:** A new `ssrf_prober.py` would spin up a lightweight TCP listener on a random local port before each probe, inject `http://127.0.0.1:{port}/ssrf-probe` as a URL parameter, and check whether the listener received a connection within a timeout window. An open-source DNS callback service like `interactsh` could also be run locally to catch DNS-based SSRF.

**Security risks:** The listener itself becomes an attack surface. A target server that successfully makes the SSRF request could send arbitrary data to the listener, potentially exploiting parsing vulnerabilities in the listener code. More critically, if SlingShot is ever run against a remote target (not just localhost), the injected callback URL must point to a publicly reachable address — which means SlingShot would need to expose a port to the internet, creating a new inbound attack vector. The SSRF validation added in `security.py` (which blocks private IPs in the target URL) would also need to be carefully scoped so it does not block the callback listener itself.

---

### Full SQL Injection (Read/Write Confirmation)

**What it needs:** Direct database query log access or a database connection. The current SQLi prober confirms injection via error messages and response timing, but cannot confirm that data was actually read or written. A `UNION SELECT` payload that returns data from another table, or a blind injection that exfiltrates data one bit at a time, requires reading the actual query results — which may not appear in the HTTP response.

**What would change:** The existing `sqli_prober.py` would be extended with a fourth technique: union-based extraction. After confirming injection via error-based or time-based methods, the prober would attempt `UNION SELECT` payloads to pull data from known system tables (`information_schema.tables` for MySQL, `sqlite_master` for SQLite) and check whether that data appears in the response body. For blind injection, a binary search loop would extract data one character at a time using `SUBSTRING()` comparisons.

**Security risks:** Union-based and blind extraction payloads are significantly more destructive than detection payloads — they actively read data from the database rather than just confirming the injection point exists. If SlingShot is misconfigured against a production database, these payloads could exfiltrate real user data. The extracted data would also be stored in `fuzz_logs`, potentially persisting sensitive database contents to disk. Mitigation would require a strict confirmation step before escalating from detection to extraction, explicit user consent, and immediate log scrubbing after the session.

---

### Insecure Deserialization

**What it needs:** Knowledge of the server's serialization format and runtime. Insecure deserialization attacks (e.g., Java gadget chains, Python `pickle` payloads, PHP object injection) require crafting a malicious serialized object that triggers code execution when the server deserializes it. The HTTP response alone cannot confirm whether deserialization occurred — the effect is server-side.

**What would change:** A new `deserialization_prober.py` would detect the serialization format from response headers (`Content-Type: application/x-java-serialized-object`, `X-Powered-By: PHP`, etc.) and inject known safe canary payloads — objects that, if deserialized, write a marker file to a known path or make a DNS callback. Confirmation would require either the SSRF listener (for DNS callbacks) or filesystem access (for marker files).

**Security risks:** Deserialization payloads are among the most dangerous in offensive security — a miscrafted payload can crash the server, corrupt data, or in the worst case achieve remote code execution on the target. Even "safe" canary payloads carry risk if the server's deserialization library has unexpected behavior. This attack type should only ever be run against an isolated test environment, never against a shared or production system. SlingShot would need a prominent warning and an explicit opt-in flag to enable deserialization probing.

---

### Zero-Config External URL Scanning

**The vision:** Paste a personal website URL directly into SlingShot and see real-time security risks without writing an OpenAPI spec or configuring anything.

**What currently blocks this:** SlingShot requires an OpenAPI spec to know what endpoints exist, what parameters they accept, and what HTTP methods are documented. Without a spec, the parser has nothing to classify and the attacker has no endpoints to target. Real-world websites also rarely use Bearer token authentication — they use session cookies, CSRF tokens, or OAuth flows that the current attacker agent doesn't know how to handle.

**What would need to change:**

1. **Spec auto-discovery.** A crawler would need to spider the target site, observe requests via a proxy (similar to Burp Suite's passive scanner), and synthesize an OpenAPI spec from the observed traffic. This is a significant addition — it requires a proxy layer, traffic recording, and a spec-generation step before any scanning begins.

2. **Auth flow handling.** The attacker agent currently injects hardcoded Bearer tokens. For a real website, SlingShot would need to accept a session cookie or walk through a login flow to obtain valid credentials before scanning. The frontend would need a credential input step, and the attacker prompts would need to be updated to use `Cookie:` headers instead of `Authorization:`.

3. **HTML response parsing.** The Vulnerability Judge is built to parse JSON response bodies. Many personal websites return HTML. The judge would need a second parsing path that can identify leaked data in HTML — for example, recognizing that a page returned another user's email address or account details embedded in markup.

4. **Spec-less endpoint classification.** Without a spec, the parser cannot flag endpoints as High Value. A heuristic classifier would need to infer attack hints from URL patterns alone — e.g., any path containing a numeric segment is a BOLA candidate, any form with a `role` or `admin` field is a Mass Assignment candidate.

**Security risks:** Scanning an external URL introduces risks that don't exist when scanning localhost. The crawler could inadvertently trigger destructive actions on the target (e.g., submitting forms, clicking delete buttons). If the target is a shared hosting environment, aggressive fuzzing could affect other tenants. The SSRF validator in `security.py` would need to be extended to prevent the crawler from following redirects to internal services. Most importantly, scanning a website you do not own or have explicit permission to test is illegal in most jurisdictions — SlingShot would need a prominent legal disclaimer and an acknowledgment checkbox before any external scan begins.
