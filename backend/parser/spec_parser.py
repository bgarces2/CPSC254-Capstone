import json
import re
import yaml
from pathlib import Path
from models.schemas import Endpoint

# Fields in a request body that suggest privilege escalation risk
_PRIVILEGE_FIELDS = {"role", "is_admin", "admin", "permissions", "verified", "superuser"}

# Fields in a response schema that suggest sensitive data exposure
_SENSITIVE_FIELDS = {
    "password", "password_hash", "secret", "token", "ssn", "ssn_last4",
    "credit_card", "card_number", "cvv", "dob", "date_of_birth",
    "salary", "internal_notes", "private_key", "api_key",
}

# Path prefixes that suggest admin/privileged functionality
_ADMIN_PATH_HINTS = {"admin", "internal", "staff", "superuser", "management", "ops"}

# HTTP methods that mutate state
_MUTATION_METHODS = {"PATCH", "PUT", "DELETE"}

# All HTTP methods — used for verb tampering
_ALL_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}

import re as _re

def _has_id_param(path: str) -> bool:
    return bool(_re.search(r"\{[^}]*(id|uuid|slug)[^}]*\}", path, re.IGNORECASE))


def _is_admin_path(path: str) -> bool:
    parts = set(path.lower().strip("/").split("/"))
    return bool(parts & _ADMIN_PATH_HINTS)


def _body_has_privilege_fields(schema: dict) -> bool:
    if not schema:
        return False
    properties = schema.get("properties", {})
    return bool(_PRIVILEGE_FIELDS & set(k.lower() for k in properties.keys()))


def _response_has_sensitive_fields(operation: dict, spec: dict) -> bool:
    """Check if any 2xx response schema contains sensitive field names."""
    responses = operation.get("responses", {})
    for status, resp in responses.items():
        if not str(status).startswith("2"):
            continue
        content = resp.get("content", {})
        schema = content.get("application/json", {}).get("schema", {})
        if schema and "$ref" in schema:
            ref_path = schema["$ref"].lstrip("#/").split("/")
            resolved = spec
            for part in ref_path:
                resolved = resolved.get(part, {})
            schema = resolved
        props = set(k.lower() for k in schema.get("properties", {}).keys())
        if props & _SENSITIVE_FIELDS:
            return True
    return False


def _classify_endpoint(
    method: str,
    path: str,
    request_body: dict | None,
    operation: dict,
    spec: dict,
    documented_methods: set[str],
    parameters: list[dict],
) -> tuple[bool, list[str]]:
    """Return (is_high_value, attack_hints) for an endpoint."""
    hints = []
    m = method.upper()

    # BOLA — resource ownership via ID param
    if _has_id_param(path):
        hints.append("BOLA")

    # MASS_ASSIGNMENT — any mutation endpoint
    if m in _MUTATION_METHODS:
        hints.append("MASS_ASSIGNMENT")

    # BFLA — admin/privileged path accessible to regular users
    if _is_admin_path(path):
        hints.append("BFLA")

    # EXCESSIVE_DATA_EXPOSURE — response schema leaks sensitive fields
    if _response_has_sensitive_fields(operation, spec):
        hints.append("EXCESSIVE_DATA_EXPOSURE")

    # MISSING_AUTH — endpoint has no security requirement defined
    # (no securitySchemes reference and no global security)
    has_security = bool(operation.get("security")) or bool(spec.get("security"))
    if not has_security and m == "GET":
        hints.append("MISSING_AUTH")

    # VERB_TAMPERING — try undocumented HTTP methods on this path
    undocumented = _ALL_METHODS - documented_methods - {m}
    if undocumented:
        hints.append("VERB_TAMPERING")

    # RATE_LIMIT — every endpoint is a candidate; prober handles the actual test
    hints.append("RATE_LIMIT")

    # SQLI — any endpoint with path params or query params is a candidate
    if parameters or _has_id_param(path):
        hints.append("SQLI")

    # PATH_TRAVERSAL — endpoints with path params (traversal via ID is common)
    # or params whose names suggest file serving
    _file_param_hints = {"file", "path", "filename", "template", "doc", "document", "resource"}
    param_names = {p.get("name", "").lower() for p in parameters}
    if _has_id_param(path) or bool(param_names & _file_param_hints):
        hints.append("PATH_TRAVERSAL")

    # Deduplicate while preserving order
    seen = set()
    unique_hints = []
    for h in hints:
        if h not in seen:
            seen.add(h)
            unique_hints.append(h)

    return len(unique_hints) > 0, unique_hints


def _extract_body_schema(operation: dict, spec: dict) -> dict | None:
    """Pull the JSON schema from requestBody, resolving $ref if needed."""
    request_body = operation.get("requestBody", {})
    content = request_body.get("content", {})
    json_content = content.get("application/json", {})
    schema = json_content.get("schema", None)

    if schema and "$ref" in schema:
        ref_path = schema["$ref"].lstrip("#/").split("/")
        resolved = spec
        for part in ref_path:
            resolved = resolved.get(part, {})
        return resolved

    return schema


def _extract_parameters(operation: dict) -> list[dict]:
    params = []
    for p in operation.get("parameters", []):
        params.append({
            "name": p.get("name"),
            "in": p.get("in"),          # "path", "query", "header"
            "required": p.get("required", False),
            "schema": p.get("schema", {}),
        })
    return params


def parse_spec(file_path: str) -> list[Endpoint]:
    """
    Parse an OpenAPI 3.x JSON or YAML file and return a list of Endpoint objects.
    High Value endpoints are flagged and prioritized (sorted first).
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Spec file not found: {file_path}")

    raw = path.read_text(encoding="utf-8")

    if path.suffix in (".yaml", ".yml"):
        spec = yaml.safe_load(raw)
    elif path.suffix == ".json":
        spec = json.loads(raw)
    else:
        raise ValueError(f"Unsupported spec format: {path.suffix}. Use .json, .yaml, or .yml")

    paths = spec.get("paths", {})
    if not paths:
        raise ValueError("OpenAPI spec contains no paths.")

    endpoints: list[Endpoint] = []

    for path_str, path_item in paths.items():
        # Collect all documented methods for this path (for VERB_TAMPERING)
        documented_methods = {
            m.upper() for m in path_item.keys()
            if m.lower() in {"get", "post", "put", "patch", "delete"}
        }

        for method, operation in path_item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                continue  # skip non-operation keys like "parameters", "summary"

            body_schema = _extract_body_schema(operation, spec)
            parameters = _extract_parameters(operation)
            is_high_value, hints = _classify_endpoint(
                method, path_str, body_schema, operation, spec, documented_methods, parameters
            )

            endpoints.append(Endpoint(
                method=method.upper(),
                path=path_str,
                parameters=parameters,
                request_body=body_schema,
                is_high_value=is_high_value,
                attack_hints=hints,
            ))

    # High Value endpoints first
    endpoints.sort(key=lambda e: not e.is_high_value)
    return endpoints
