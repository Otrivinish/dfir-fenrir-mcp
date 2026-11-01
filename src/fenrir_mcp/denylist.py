"""Single source of the hard denylist — enforced for curated tools AND the escape
hatch, in every mode. No mode unlocks it. See docs/TOOLS.md "Hard denylist".

Invariant: bytes flow toward FENRIR only. Plus: the MCP never mints credentials,
and auth endpoints have no MCP use. Plus (R150/R151): the model never receives a
secret and never grants access.
"""

from __future__ import annotations

import posixpath
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

# R150/R151 (owner principle 2026-10-07): through the MCP the model never RECEIVES a
# secret and never GRANTS access; actions that reduce or restore access, and reads,
# stay. Shared like _DENY: curated tools AND fenrir_api, every mode. Full match on the
# canonical path, lower-cased. The FENRIR GUI keeps every one of these.
_GRANT_WRITES = ("POST", "PUT", "PATCH")
_GRANT_OR_SECRET_DENY: list[tuple[tuple[str, ...] | str, str, str]] = [
    (_GRANT_WRITES, r"/api/users", "creating a user grants access and sets a password — FENRIR GUI only"),
    (("PUT", "PATCH"), rf"/api/users/{_V}", "role / active / TOTP changes can grant access — FENRIR GUI only"),
    ("*", rf"/api/users/{_V}/reset-password", "a password reset puts a credential in the model's hands — FENRIR GUI only"),
    ("*", r"/api/integrations/siem-key/generate", "returns the inbound SIEM key in clear — FENRIR GUI only"),
    (_GRANT_WRITES, r"/api/settings/api-keys(/[^/]+)?", "third-party service keys are secrets — FENRIR GUI only"),
    (_GRANT_WRITES, r"/api/integrations/(smtp|webhooks|syslog)",
     "SMTP / webhook / syslog config carries secrets and redirects outbound data — FENRIR GUI only"),
    (_GRANT_WRITES, rf"/api/teams/{_V}/members(/.*)?",
     "adding a team member grants incident access — FENRIR GUI only (removing one stays allowed)"),
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


# Escape hatch only (R146): credential and auth management stays human-initiated —
# the GUI, or the `fenrir-mcp login` / `tokens` CLI in a terminal. Curated tools
# don't take arbitrary paths, so this list gates `fenrir_api` (openapi_guard).
# Matched as a prefix on the canonical path (decoded, lower-case, dot-segments
# resolved), ending at a segment boundary. methods "*" = every verb.
_CRED_WRITES = ("POST", "PATCH", "PUT", "DELETE")
_CREDENTIAL_DENY: list[tuple[tuple[str, ...] | str, str]] = [
    ("*", r"/api/tokens"),                       # own tokens: create / list / revoke
    ("*", r"/api/admin/tokens"),                 # every user's tokens (admin)
    ("*", r"/api/sessions"),                     # own sessions: list / revoke / revoke-others / label
    ("*", r"/api/admin/sessions"),               # every session (admin)
    ("*", rf"/api/users/{_V}/sessions"),         # a user's sessions: list / revoke / revoke-all
    ("*", rf"/api/users/{_V}/reset-password"),
    ("*", rf"/api/users/{_V}/unlock"),
    (_CRED_WRITES, r"/api/users"),               # create (password + role), role / active / TOTP reset, delete
    ("*", r"/api/integrations/siem-key"),        # inbound SIEM key: generate returns the secret
    (("PUT", "DELETE"), r"/api/settings/api-keys"),  # third-party service keys
]
_CREDENTIAL_REASON = (
    "credential and auth management is human-only and never runs through the MCP "
    "— use the FENRIR GUI (Settings → Account → API tokens, Admin → Users / API Tokens / Sessions) "
    "or, for your own tokens, `fenrir-mcp tokens list|revoke` in a terminal"
)


def _unquote_all(path: str) -> str:
    """Percent-decode until stable, so no layer of encoding hides a path."""
    prev = None
    while prev != path:
        prev, path = path, unquote(path)
    return path


def normalize(path: str) -> str:
    # Strip query/fragment BEFORE decoding, as httpx does: an encoded "%3F"/"%23" stays
    # in the path on the wire, so it must not cut the path short here (R150: that let
    # "/api/x%3F/../tokens" pass as "/api/x" while httpx sent "/api/tokens").
    p = _unquote_all(path.split("?")[0].split("#")[0])
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
    for methods, pattern, reason in _GRANT_OR_SECRET_DENY:
        if (methods == "*" or m in methods) and re.fullmatch(pattern, p.lower()):
            return reason
    if p.rsplit("/", 1)[-1] == "download":
        if not any(re.fullmatch(a, p) for a in _TEXT_DOWNLOAD_ALLOW):
            return "downloads are denied — bytes flow toward FENRIR only (docs/TOOLS.md invariant)"
    return None


def credential_denied(method: str, path: str) -> str | None:
    """Escape-hatch gate (R146): the reason if method+path manages credentials/auth,
    else None. Every verb on the token and session endpoints is refused."""
    m = method.upper()
    p = posixpath.normpath(normalize(path)).lower()
    for methods, pattern in _CREDENTIAL_DENY:
        if (methods == "*" or m in methods) and re.match(pattern + r"(?![\w.-])", p):
            return _CREDENTIAL_REASON
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
