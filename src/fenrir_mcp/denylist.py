"""Single source of the hard denylist — enforced for curated tools AND the escape
hatch, in every mode. No mode unlocks it. See docs/TOOLS.md "Hard denylist".

Invariant: bytes flow toward FENRIR only. Plus: the MCP never mints credentials,
and auth endpoints have no MCP use.
"""

from __future__ import annotations

import re
from urllib.parse import unquote

_V = r"[^/]+"  # one path segment

# (methods, anchored regex, reason). methods "*" = every verb.
_DENY: list[tuple[str, str, str]] = [
    ("*", r"/api/auth(/.*)?", "auth endpoints are CLI-only (fenrir-mcp login)"),
    ("POST", r"/api/tokens", "token issuance is the interactive TOTP-verified CLI only"),
    ("POST", rf"/api/admin/tokens(/{_V})?", "token issuance is the interactive TOTP-verified CLI only"),
    ("*", r"/api/webhooks(/.*)?", "inbound SIEM webhooks are machine endpoints, not user-facing"),
    ("GET", rf"/api/exports/{_V}", "custody export bundle bytes"),
    ("GET", rf"/api/audit-exports/{_V}", "audit export bundle bytes"),
    ("GET", rf"/api/collections/{_V}", "collection package bytes"),
    ("*", rf"/api/le-package-ack/{_V}", "LE package retrieval/ack tokens are recipient-facing"),
    ("GET", rf"/api/incidents/{_V}/evidence/{_V}/photos/{_V}", "evidence photo bytes"),
]

# Fail-closed drift rule: any path whose last segment is "download" is denied
# unless explicitly allowlisted as a text-bodied export (owner ruling 2026-08-25).
_TEXT_DOWNLOAD_ALLOW: list[str] = [
    rf"/api/incidents/{_V}/detections/download",  # Sigma/YARA rule text, returned inline
]

_BINARY_CONTENT_TYPES = (
    "application/octet-stream",
    "application/zip",
    "application/pdf",
    "application/x-tar",
    "application/gzip",
    "image/",
    "video/",
    "audio/",
)


def normalize(path: str) -> str:
    p = unquote(unquote(path)).split("?")[0].split("#")[0]
    p = re.sub(r"/{2,}", "/", p)
    if not p.startswith("/"):
        p = "/" + p
    if len(p) > 1:
        p = p.rstrip("/")
    return p


def is_denied(method: str, path: str) -> str | None:
    """Return the denial reason, or None if the call is allowed."""
    m = method.upper()
    p = normalize(path)
    # Fail closed on dot-segments: legitimate FENRIR paths never contain them,
    # but httpx canonicalises "a/../b" per RFC 3986 BEFORE sending, so a path
    # the denylist reads as innocuous can hit a denied endpoint on the wire
    # (e.g. /api/incidents/x/../../tokens -> POST /api/tokens). Reject here.
    if any(seg in (".", "..") for seg in p.split("/")):
        return "path contains '.'/'..' segments — refused (fail closed)"
    for methods, pattern, reason in _DENY:
        if methods in ("*", m) and re.fullmatch(pattern, p):
            return reason
    if p.rsplit("/", 1)[-1] == "download":
        if not any(re.fullmatch(a, p) for a in _TEXT_DOWNLOAD_ALLOW):
            return "downloads are denied — bytes flow toward FENRIR only (docs/TOOLS.md invariant)"
    return None


def scan_spec_for_bytes(spec: dict) -> list[str]:
    """Drift check (threat model T4 / SbD action A3): find spec operations that
    declare binary response bodies but are NOT covered by this denylist."""
    violations = []
    for spec_path, ops in spec.get("paths", {}).items():
        concrete = re.sub(r"\{[^}]+\}", "x", spec_path)
        for verb, op in ops.items():
            if verb.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                continue
            for resp in (op.get("responses") or {}).values():
                for ctype in (resp.get("content") or {}):
                    if ctype.lower().startswith(_BINARY_CONTENT_TYPES) and not is_denied(verb, concrete):
                        violations.append(f"{verb.upper()} {spec_path} returns {ctype} but is not denylisted")
    return sorted(set(violations))
