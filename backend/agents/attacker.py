import json
from openai import OpenAI
from config import OPENAI_API_KEY, OPENAI_MODEL, TARGET_BASE_URL
from models.schemas import Endpoint, Payload, PayloadPair

client = OpenAI(api_key=OPENAI_API_KEY)

_SYSTEM_PROMPT = """You are an expert penetration tester specializing in API security.
Your job is to generate adversarial HTTP request payloads that test for logic flaws.
You must return ONLY valid JSON — no markdown, no explanation outside the JSON object."""

# Per-attack-type instructions injected into the shared prompt template
_ATTACK_INSTRUCTIONS = {
    "BOLA": """
For BOLA (Broken Object Level Authorization):
- BASELINE: User A accesses a resource they own (invoice_id 1).
- ATTACK: User A tries to access invoice_id 999, which is owned by User B.
- Always use Authorization: Bearer token_user_a for both requests.
- Use the exact IDs listed — do not invent IDs.""",

    "MASS_ASSIGNMENT": """
For MASS_ASSIGNMENT:
- BASELINE: User A sends a legitimate PATCH with only allowed fields (bio, avatar).
- ATTACK: User A sends the same PATCH but adds privilege fields like is_admin: true and role: "admin".
- Always include Authorization: Bearer token_user_a.""",

    "BFLA": """
For BFLA (Broken Function Level Authorization):
- BASELINE: User A calls the endpoint with their normal user token.
- ATTACK: User A calls the same endpoint — a regular user should NOT have access to admin/privileged paths.
  The goal is to confirm whether the server enforces role-based access or lets any authenticated user through.
- Always include Authorization: Bearer token_user_a.""",

    "EXCESSIVE_DATA_EXPOSURE": """
For EXCESSIVE_DATA_EXPOSURE:
- BASELINE: User A makes a normal authenticated request to the endpoint.
- ATTACK: Same request — the goal is to inspect whether the response contains sensitive fields
  (e.g., ssn, password_hash, internal_notes, salary, api_key) that should not be returned to clients.
- Always include Authorization: Bearer token_user_a.""",

    "MISSING_AUTH": """
For MISSING_AUTH:
- BASELINE: User A makes the request WITH a valid Authorization header.
- ATTACK: Make the exact same request WITHOUT any Authorization header at all.
  The goal is to confirm whether the endpoint enforces authentication or returns data to unauthenticated callers.
- The attack request must have NO Authorization header.""",

    "VERB_TAMPERING": """
For VERB_TAMPERING:
- BASELINE: User A calls the endpoint with its documented HTTP method.
- ATTACK: Try an undocumented method on the same path. Good candidates:
    - If the path is GET-only, try DELETE or PATCH.
    - If the path is PATCH-only, try DELETE.
  The goal is to find methods the server handles but didn't document, which may bypass authorization.
- Always include Authorization: Bearer token_user_a.""",
}

_USER_PROMPT_TEMPLATE = """
Given this API endpoint:
  Method: {method}
  Path: {path}
  Parameters: {parameters}
  Request Body Schema: {body_schema}
  Attack Type: {attack_type}
  Base URL: {base_url}

{attack_instructions}

Known resource IDs in the victim API:
  User A (token_user_a, user_id 1) owns: invoice_id 1, invoice_id 2
  User B (token_user_b, user_id 2) owns: invoice_id 999, invoice_id 998

Return ONLY this JSON structure — fill in real values, do not use placeholders like "http://...":
{{
  "baseline": {{
    "method": "string",
    "url": "string",
    "headers": {{"Authorization": "Bearer token_user_a", "Content-Type": "application/json"}},
    "body": null,
    "description": "string"
  }},
  "attack": {{
    "method": "string",
    "url": "string",
    "headers": {{}},
    "body": null,
    "description": "string"
  }},
  "attack_type": "{attack_type}"
}}
"""


def generate_payload_pair(endpoint: Endpoint) -> PayloadPair:
    """
    Use the Attacker Agent to generate a baseline + attack PayloadPair.
    Iterates through all attack hints on the endpoint and returns the first
    successfully generated pair. Falls back to BOLA if no hints exist.
    """
    attack_type = endpoint.attack_hints[0] if endpoint.attack_hints else "BOLA"
    instructions = _ATTACK_INSTRUCTIONS.get(attack_type, _ATTACK_INSTRUCTIONS["BOLA"])

    prompt = _USER_PROMPT_TEMPLATE.format(
        method=endpoint.method,
        path=endpoint.path,
        parameters=json.dumps(endpoint.parameters, indent=2),
        body_schema=json.dumps(endpoint.request_body, indent=2) if endpoint.request_body else "null",
        attack_type=attack_type,
        base_url=TARGET_BASE_URL,
        attack_instructions=instructions.strip(),
    )

    response = client.chat.completions.create(
        model=OPENAI_MODEL,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
    )

    raw = response.choices[0].message.content
    data = json.loads(raw)

    def _to_payload(d: dict) -> Payload:
        return Payload(
            method=d["method"],
            url=d["url"],
            headers=d.get("headers", {}),
            body=d.get("body"),
            description=d.get("description", ""),
        )

    return PayloadPair(
        baseline=_to_payload(data["baseline"]),
        attack=_to_payload(data["attack"]),
        attack_type=data.get("attack_type", attack_type),
        endpoint_path=endpoint.path,
    )


# Attack types handled by dedicated probers — skip LLM payload generation for these
_PROBER_ONLY_HINTS = {"RATE_LIMIT", "SQLI", "PATH_TRAVERSAL"}


def generate_all_payload_pairs(endpoint: Endpoint) -> list[PayloadPair]:
    """
    Generate one PayloadPair per attack hint on the endpoint.
    Skips hints that are handled by dedicated probers (no LLM needed).
    """
    pairs = []
    for hint in (endpoint.attack_hints or ["BOLA"]):
        if hint in _PROBER_ONLY_HINTS:
            continue  # handled by rate_limit_prober / sqli_prober / path_traversal_prober
        original_hints = endpoint.attack_hints
        endpoint.attack_hints = [hint] + [h for h in original_hints if h != hint]
        try:
            pairs.append(generate_payload_pair(endpoint))
        except Exception:
            pass
        finally:
            endpoint.attack_hints = original_hints
    return pairs
