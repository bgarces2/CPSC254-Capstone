import json
from openai import OpenAI
from config import OPENAI_API_KEY, OPENAI_MODEL
from models.schemas import FuzzLog, VulnResult

client = OpenAI(api_key=OPENAI_API_KEY)

_SYSTEM_PROMPT = """You are a security vulnerability analyst reviewing API fuzzing logs.
Your job is to determine whether an attack was successful — a TRUE vulnerability — or a false positive.
You must return ONLY valid JSON."""

# Per-attack-type verdict criteria injected into the shared judge prompt
_VERDICT_CRITERIA = {
    "BOLA": """
BOLA verdict criteria — ALL must be true:
1. The attack request returned a 2xx status code.
2. The response body contains real structured data (not an error like {"error": "..."}).
3. The data in the response belongs to a DIFFERENT user than the requester
   (look for owner_id, user_id, or email fields that don't match the attacker's identity).""",

    "MASS_ASSIGNMENT": """
MASS_ASSIGNMENT verdict criteria — ALL must be true:
1. The attack request returned a 2xx status code.
2. The response body contains structured data, not an error message.
3. An unauthorized field (is_admin, role, permissions, verified, etc.) was accepted
   AND is reflected back in the response body.""",

    "BFLA": """
BFLA verdict criteria — ALL must be true:
1. The attack request (regular user calling a privileged/admin endpoint) returned a 2xx status code.
2. The response contains real data, not an error or empty body.
3. There is no indication the server enforced role-based access control
   (i.e., it did NOT return 401 Unauthorized or 403 Forbidden).""",

    "EXCESSIVE_DATA_EXPOSURE": """
EXCESSIVE_DATA_EXPOSURE verdict criteria — ALL must be true:
1. The request returned a 2xx status code.
2. The response body contains at least one sensitive field that should not be
   returned to API clients, such as: password, password_hash, ssn, ssn_last4,
   credit_card, cvv, salary, internal_notes, api_key, private_key, dob, secret.
3. The sensitive field contains a real value (not null or empty string).""",

    "MISSING_AUTH": """
MISSING_AUTH verdict criteria — ALL must be true:
1. The attack request was sent WITHOUT an Authorization header.
2. The server returned a 2xx status code (not 401 Unauthorized).
3. The response body contains real data, not an error message.
If the server correctly returned 401, the verdict is NO_VULNERABILITY.""",

    "VERB_TAMPERING": """
VERB_TAMPERING verdict criteria — ALL must be true:
1. The attack used an HTTP method NOT documented in the spec for this path.
2. The server returned a 2xx or 3xx status code (not 405 Method Not Allowed).
3. The response suggests the server processed the request (returned data or made a change).
If the server returned 405, the verdict is NO_VULNERABILITY.""",
}

_USER_PROMPT_TEMPLATE = """
Review the following fuzzing session logs for endpoint: {endpoint}
Attack type attempted: {attack_type}

Logs (in order):
{logs}

{verdict_criteria}

A verdict of EXPLOIT_CONFIRMED requires ALL listed criteria to pass.
If any criterion fails, the verdict is NO_VULNERABILITY.

Return ONLY this JSON:
{{
  "verdict": "EXPLOIT_CONFIRMED" or "NO_VULNERABILITY",
  "evidence": "The specific log entry (attempt number + response) that proves your verdict",
  "reasoning": "Step-by-step explanation of how you applied each criterion"
}}
"""


def judge_session(session_id: str, endpoint: str, attack_type: str, logs: list[FuzzLog]) -> VulnResult:
    """
    Review all fuzz logs for a session and return a VulnResult verdict.
    Uses attack-type-specific criteria to minimize false positives.
    """
    formatted_logs = []
    for log in logs:
        formatted_logs.append(
            f"Attempt #{log.attempt_number}\n"
            f"  Request: {log.request.get('method')} {log.request.get('url')}\n"
            f"  Headers: {json.dumps({k: v for k, v in log.request.get('headers', {}).items() if k.lower() != 'authorization'})}\n"
            f"  Body sent: {json.dumps(log.request.get('body'))}\n"
            f"  Response Status: {log.response_status}\n"
            f"  Response Body: {log.response_body[:600]}"
        )

    criteria = _VERDICT_CRITERIA.get(attack_type, _VERDICT_CRITERIA["BOLA"])

    prompt = _USER_PROMPT_TEMPLATE.format(
        endpoint=endpoint,
        attack_type=attack_type,
        logs="\n\n".join(formatted_logs),
        verdict_criteria=criteria.strip(),
    )

    response = client.chat.completions.create(
        model=OPENAI_MODEL,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        temperature=0,  # deterministic — judgment call, not creative
    )

    raw = response.choices[0].message.content
    data = json.loads(raw)

    return VulnResult(
        session_id=session_id,
        endpoint=endpoint,
        attack_type=attack_type,
        verdict=data["verdict"],
        evidence=data.get("evidence", ""),
        reasoning=data.get("reasoning", ""),
    )
