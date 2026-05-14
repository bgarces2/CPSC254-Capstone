import json
from openai import OpenAI
from config import OPENAI_API_KEY, OPENAI_MODEL
from models.schemas import VulnResult, Patch

client = OpenAI(api_key=OPENAI_API_KEY)

_SYSTEM_PROMPT = """You are a senior backend security engineer.
Given a confirmed API vulnerability, you generate a targeted middleware patch to fix it.
The patch must address the specific logic flaw — not generic advice.
You must return ONLY valid JSON."""

_USER_PROMPT_TEMPLATE = """\
A vulnerability has been confirmed:

  Endpoint: {endpoint}
  Attack Type: {attack_type}
  Evidence: {evidence}
  Reasoning: {reasoning}
  Target Stack: {stack}

Generate a middleware patch for this specific vulnerability.

Rules:
- For BOLA: add an ownership check that compares the authenticated user's ID to the resource owner's ID.
  Return 403 Forbidden if they don't match.
- For MASS_ASSIGNMENT: add an allow-list that strips any fields not explicitly permitted.
  Only the fields defined in the original spec schema should be accepted.
- For BFLA: add a role/permission check middleware that verifies req.user.is_admin === true before
  allowing access. Return 403 Forbidden for non-admin users.
- For EXCESSIVE_DATA_EXPOSURE: add a response filter middleware that removes sensitive fields
  (password, ssn, salary, api_key, internal_notes, etc.) from the response before it is sent.
- For MISSING_AUTH: add an authentication guard middleware that checks for a valid Authorization
  header and returns 401 Unauthorized if it is absent or invalid.
- For VERB_TAMPERING: add a method restriction middleware that explicitly allows only the
  documented HTTP methods for the route and returns 405 Method Not Allowed for all others.
- For RATE_LIMIT: generate a rate limiting middleware using a token bucket or sliding window
  approach. For Express.js use express-rate-limit. For FastAPI use slowapi.
  Configure a sensible default (e.g., 60 requests per minute per IP).
- For SQLI: replace any raw string concatenation with parameterized queries / prepared statements.
  For Express.js with a SQL DB use parameterized queries (e.g., db.query('SELECT * FROM x WHERE id = ?', [id])).
  For FastAPI/SQLAlchemy use bound parameters (text("SELECT * FROM x WHERE id = :id"), dict(id=id)).
  Also add input validation to reject non-numeric values for integer parameters.
- For PATH_TRAVERSAL: add path sanitization middleware that:
  1. Resolves the canonical path using path.resolve() or os.path.realpath().
  2. Verifies the resolved path starts with the allowed base directory.
  3. Rejects any path containing '..' sequences or null bytes before resolution.
  For Express.js use path.resolve() and check startsWith(BASE_DIR).
  For FastAPI use pathlib.Path.resolve() and check is_relative_to(BASE_DIR).
- Do NOT suggest generic fixes like "add HTTPS" or "use an API key".
- The patch must be a self-contained middleware function that can be dropped into the route.
- For Express.js: export a function with signature (req, res, next).
- For FastAPI: use a Depends() dependency function.

Return ONLY this JSON (no extra keys, no markdown):
{{
  "target_file": "routes/example.js",
  "language": "javascript",
  "code": "// full middleware function here",
  "instructions": "Where and how to apply this patch."
}}
"""


def generate_patch(result: VulnResult, stack: str = "express") -> Patch:
    """
    Generate a middleware patch for a confirmed exploit.
    stack: "express" (Node.js) or "fastapi" (Python)
    """
    # Use str.replace for each field individually to avoid .format() choking
    # on curly braces inside evidence/reasoning strings from the judge.
    prompt = (
        _USER_PROMPT_TEMPLATE
        .replace("{endpoint}", result.endpoint)
        .replace("{attack_type}", result.attack_type)
        .replace("{evidence}", result.evidence)
        .replace("{reasoning}", result.reasoning)
        .replace("{stack}", stack)
    )

    response = client.chat.completions.create(
        model=OPENAI_MODEL,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        temperature=0.1,
    )

    raw = response.choices[0].message.content
    data = json.loads(raw)

    return Patch(
        session_id=result.session_id,
        target_file=data.get("target_file", ""),
        language=data.get("language", "javascript"),
        code=data.get("code", ""),
        instructions=data.get("instructions", ""),
        attack_type=result.attack_type,
        validated=False,
    )
