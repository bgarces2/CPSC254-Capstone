from __future__ import annotations
from dataclasses import dataclass, field
from typing import Literal


@dataclass
class Endpoint:
    """A single API endpoint extracted from an OpenAPI spec."""
    method: str                        # "GET", "PATCH", "DELETE", etc.
    path: str                          # "/api/v1/invoices/{invoice_id}"
    parameters: list[dict]             # path/query params with name + type
    request_body: dict | None          # JSON schema of the request body
    is_high_value: bool                # True if flagged for attack generation
    attack_hints: list[str]            # e.g. ["BOLA", "MASS_ASSIGNMENT"]


@dataclass
class Payload:
    """A single HTTP request payload ready to be executed."""
    method: str
    url: str
    headers: dict
    body: dict | None
    description: str                   # Human-readable intent


@dataclass
class PayloadPair:
    """A baseline + attack payload pair for one endpoint."""
    baseline: Payload
    attack: Payload
    attack_type: str                   # "BOLA" | "MASS_ASSIGNMENT"
    endpoint_path: str


@dataclass
class FuzzLog:
    """One request/response pair recorded during fuzzing."""
    session_id: str
    endpoint: str
    attempt_number: int
    request: dict                      # method, url, headers, body
    response_status: int
    response_body: str
    timestamp: str


@dataclass
class VulnResult:
    """The Vulnerability Judge's verdict for a single scan session."""
    session_id: str
    endpoint: str
    attack_type: str
    verdict: Literal["EXPLOIT_CONFIRMED", "NO_VULNERABILITY"]
    evidence: str                      # The log entry that proves the verdict
    reasoning: str                     # LLM chain-of-thought


@dataclass
class Patch:
    """A generated middleware patch for a confirmed exploit."""
    session_id: str
    target_file: str                   # e.g. "routes/invoices.js"
    language: str                      # "javascript" | "python"
    code: str                          # The middleware function code
    instructions: str                  # Where/how to apply it
    attack_type: str
    validated: bool = False            # True after 403 re-run confirms the fix
