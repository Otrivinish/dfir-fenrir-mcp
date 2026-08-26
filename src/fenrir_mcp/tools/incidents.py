"""Incidents — list/get/audit (RO), create/update/close/reopen (STD)."""

from __future__ import annotations

from typing import Literal

from ..client import FenrirError, request
from . import params, project, tool


@tool("readonly")
async def fenrir_incident_list(
    filters: dict | None = None,
    limit: int | None = None,
    cursor: str | None = None,
    fields: list | None = None,
) -> dict:
    """List/filter incidents. filters are query params (e.g. {"status": "open",
    "severity": "critical"}). Returns {items, next_cursor}; timestamps are UTC ISO 8601.
    Pass fields (e.g. ["id","ref","title","severity","status"]) to keep responses small."""
    q = dict(filters or {})
    q.update(params(limit=limit, cursor=cursor))
    return project(await request("GET", "/api/incidents", params=q), fields)


@tool("readonly")
async def fenrir_incident_get(incident_id: str, snapshot: bool = False) -> dict:
    """Get one incident. snapshot=True returns the full incident snapshot
    (entities, IOCs, timeline counts, assignments) instead of the base record."""
    suffix = "/snapshot" if snapshot else ""
    return await request("GET", f"/api/incidents/{incident_id}{suffix}")


@tool("readonly")
async def fenrir_incident_audit(
    incident_id: str, limit: int | None = None, cursor: str | None = None
) -> dict | list:
    """Read the incident-scoped tamper-evident (hash-chained) audit log."""
    return await request(
        "GET", f"/api/incidents/{incident_id}/audit-log", params=params(limit=limit, cursor=cursor)
    )


@tool("standard")
async def fenrir_incident_write(
    action: Literal["create", "update", "close", "reopen"],
    incident_id: str | None = None,
    data: dict | None = None,
) -> dict:
    """Create/update/close/reopen an incident. create: data has title, severity
    (low|medium|high|critical), phase etc. update: PATCH fields in data.
    close/reopen: data may carry a reason. Severity uses FENRIR's internal scale."""
    if action == "create":
        return await request("POST", "/api/incidents", json=data or {})
    if not incident_id:
        raise FenrirError("incident_id is required for update/close/reopen")
    if action == "update":
        return await request("PATCH", f"/api/incidents/{incident_id}", json=data or {})
    return await request("POST", f"/api/incidents/{incident_id}/{action}", json=data or {})
