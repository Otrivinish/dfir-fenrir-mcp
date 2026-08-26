"""Incident timeline — list + LOLBin scan (RO), add/batch/update (STD)."""

from __future__ import annotations

from typing import Literal

from ..client import FenrirError, request
from . import params, project, tool


@tool("readonly")
async def fenrir_timeline_list(
    incident_id: str,
    lolbin_scan: bool = False,
    filters: dict | None = None,
    limit: int | None = None,
    cursor: str | None = None,
    fields: list | None = None,
) -> dict | list:
    """List timeline events for an incident (UTC ISO 8601). lolbin_scan=True runs
    the LOLBin/GTFOBin scan over the timeline instead of listing events. Use
    limit + fields (e.g. ["id","occurred_at","title","severity"]) — timelines
    can hold hundreds of events."""
    if lolbin_scan:
        return await request("GET", f"/api/incidents/{incident_id}/timeline/lolbin-scan")
    q = dict(filters or {})
    q.update(params(limit=limit, cursor=cursor))
    return project(await request("GET", f"/api/incidents/{incident_id}/timeline", params=q), fields)


@tool("standard")
async def fenrir_timeline_write(
    action: Literal["add", "add_batch", "update"],
    incident_id: str,
    event_id: str | None = None,
    data: dict | None = None,
    events: list | None = None,
) -> dict | list:
    """Add one event (data), add a batch (events list), or update one (event_id +
    data). Event timestamps must be UTC ISO 8601 (YYYY-MM-DDTHH:MM:SSZ)."""
    if action == "add":
        return await request("POST", f"/api/incidents/{incident_id}/timeline", json=data or {})
    if action == "add_batch":
        if not events:
            raise FenrirError("events list is required for add_batch")
        return await request("POST", f"/api/incidents/{incident_id}/timeline/batch", json={"events": events})
    if not event_id:
        raise FenrirError("event_id is required for update")
    return await request("PATCH", f"/api/incidents/{incident_id}/timeline/{event_id}", json=data or {})
