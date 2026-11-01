"""Identity, search, dashboard — tier RO."""

from __future__ import annotations

from typing import Literal

from .. import config, token_store
from ..client import request
from . import params, tool


@tool("readonly")
async def fenrir_whoami() -> dict:
    """Identity + connectivity self-check: current FENRIR user, the token's role
    cap, and the server mode. Use this first — a token role below what the mode
    needs (standard→analyst) means every write tool will 403."""
    user = await request("GET", "/api/users/me")
    meta = token_store.load_meta() or {}
    return {
        "user": user,
        "token": {k: meta.get(k) for k in ("role", "token_prefix", "issued_at", "storage")},
        "mode": config.mode(),
    }


@tool("readonly")
async def fenrir_search(q: str, limit: int | None = None) -> dict | list:
    """Global search across incidents, IOCs, entities and more. q is the query string."""
    return await request("GET", "/api/search", params=params(q=q, limit=limit))


@tool("readonly")
async def fenrir_dashboard(
    view: Literal[
        "summary", "activity", "trend", "workload", "top_tactics", "top_tags",
        "legal_summary", "metrics", "tags", "readiness",
    ] = "summary",
) -> dict | list:
    """Portfolio dashboards: summary, activity feed, incident trend, workload,
    top MITRE tactics, top tags, legal deadline summary, platform metrics, tag list.
    readiness: organisation-level preparation checks (admins and analysts; a viewer
    token gets 403) — {generated_at, summary{blockers_failing, warnings_failing,
    unknown, blockers_deferred, warnings_deferred}, checks[{id, title, level
    blocker|warning, status pass|fail|unknown, detail, csf[], fix_route, deferral
    {by_name, at, reason}|null}]}. Informational only: blockers never stop incident
    creation; unknown is never a pass. A deferred check (an admin accepted it) keeps
    its status but is left out of blockers_failing / warnings_failing. Admins defer
    with fenrir_api POST /api/readiness/deferrals {check_ids, reason?} and undo with
    DELETE /api/readiness/deferrals/{check_id} (full mode).
    All timestamps are UTC ISO 8601."""
    paths = {
        "summary": "/api/dashboard/summary",
        "activity": "/api/dashboard/activity",
        "trend": "/api/dashboard/trend",
        "workload": "/api/dashboard/workload",
        "top_tactics": "/api/dashboard/top-tactics",
        "top_tags": "/api/dashboard/top-tags",
        "legal_summary": "/api/dashboard/legal-summary",
        "metrics": "/api/metrics",
        "tags": "/api/tags",
        "readiness": "/api/readiness",
    }
    return await request("GET", paths[view])
