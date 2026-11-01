"""The escape hatch: call any FENRIR endpoint the curated tools don't cover.
Registered in every mode; the verb set is mode-gated, the operation must exist
in FENRIR's OpenAPI spec, and the hard denylist applies — no mode unlocks it."""

from __future__ import annotations

from typing import Any

from .. import config, openapi_guard
from ..client import request
from . import tool


@tool("readonly")
async def fenrir_api(
    method: str,
    path: str,
    query: dict | None = None,
    body: dict | None = None,
) -> Any:
    """Direct FENRIR API call for endpoints not covered by curated tools.
    method: GET (readonly mode), +POST/PATCH/PUT (standard), +DELETE (full).
    path must start with /api/ and exist in FENRIR's OpenAPI spec. The denylist
    always applies: no byte downloads, no auth endpoints, and no credential
    management (API tokens, sessions, user passwords/roles/TOTP, SIEM and
    service keys), no SMTP / webhook / syslog config writes and no team-member
    adds — those are human-only, in the GUI or the fenrir-mcp CLI.
    Responses pass through unchanged (UTC ISO 8601 timestamps)."""
    openapi_guard.validate(method, path, config.mode())
    return await request(method.upper(), path, params=query, json=body)
