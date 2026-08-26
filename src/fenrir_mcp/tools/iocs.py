"""IOCs — list/links/export (RO), add/update/link (STD), enrichment (STD, serialized)."""

from __future__ import annotations

from typing import Literal

from ..client import FenrirError, request
from . import params, project, tool


@tool("readonly")
async def fenrir_ioc_list(
    incident_id: str,
    ioc_id: str | None = None,
    filters: dict | None = None,
    limit: int | None = None,
    cursor: str | None = None,
    fields: list | None = None,
) -> dict | list:
    """List IOCs for an incident. With ioc_id, returns that IOC's timeline links
    instead. Pass fields (e.g. ["id","type","value","verdict"]) to keep responses small."""
    if ioc_id:
        return await request("GET", f"/api/incidents/{incident_id}/iocs/{ioc_id}/timeline-links")
    q = dict(filters or {})
    q.update(params(limit=limit, cursor=cursor))
    return project(await request("GET", f"/api/incidents/{incident_id}/iocs", params=q), fields)


@tool("readonly")
async def fenrir_ioc_export(incident_id: str, fmt: str) -> str | dict:
    """Export incident IOCs in a platform format (e.g. csv, stix, defender, sentinel —
    FENRIR validates fmt). Returned inline as text, never written to disk."""
    return await request("GET", f"/api/incidents/{incident_id}/iocs/export/{fmt}")


@tool("standard")
async def fenrir_ioc_write(
    action: Literal["add", "add_batch", "update", "link_timeline"],
    incident_id: str,
    ioc_id: str | None = None,
    data: dict | None = None,
    iocs: list | None = None,
) -> dict | list:
    """Add one IOC (data: type, value, …), add a batch (iocs list), update one
    (ioc_id + data), or link an IOC to a timeline event (ioc_id + data with event_id)."""
    base = f"/api/incidents/{incident_id}/iocs"
    if action == "add":
        return await request("POST", base, json=data or {})
    if action == "add_batch":
        if not iocs:
            raise FenrirError("iocs list is required for add_batch")
        return await request("POST", f"{base}/batch", json={"iocs": iocs})
    if not ioc_id:
        raise FenrirError("ioc_id is required for update/link_timeline")
    if action == "update":
        return await request("PATCH", f"{base}/{ioc_id}", json=data or {})
    return await request("POST", f"{base}/{ioc_id}/timeline-links", json=data or {})


@tool("standard")
async def fenrir_ioc_enrich(
    action: Literal["enrich_one", "enrich_all", "scan_ti"],
    incident_id: str,
    ioc_id: str | None = None,
) -> dict:
    """Enrich one IOC, enrich all incident IOCs, or scan them against threat intel.
    These are slow, serialized calls — do not invoke repeatedly in parallel."""
    base = f"/api/incidents/{incident_id}/iocs"
    if action == "enrich_one":
        if not ioc_id:
            raise FenrirError("ioc_id is required for enrich_one")
        return await request("POST", f"{base}/{ioc_id}/enrich", expensive=True)
    if action == "enrich_all":
        return await request("POST", f"{base}/enrich-all", expensive=True)
    return await request("POST", f"{base}/scan-ti", expensive=True)
