"""IOCs — list/links/export (RO), add/update/link (STD), enrichment (STD, serialized)."""

from __future__ import annotations

from typing import Literal

from ..client import FenrirError, request
from . import params, project, tool


@tool("readonly")
async def fenrir_ioc_list(
    incident_id: str,
    ioc_id: str | None = None,
    entity_id: str | None = None,
    filters: dict | None = None,
    limit: int | None = None,
    cursor: str | None = None,
    fields: list | None = None,
) -> dict | list:
    """List IOCs for an incident. With ioc_id, returns that IOC's timeline links
    instead. entity_id = only the IOCs linked to that entity; filters may also hold
    type and tag. Each IOC carries first_seen_at / last_seen_at: the earliest and
    latest event_time of its linked timeline events (omitted when none is linked).
    Pass fields (e.g. ["id","type","value","first_seen_at","last_seen_at"]) to keep
    responses small."""
    if ioc_id:
        return await request("GET", f"/api/incidents/{incident_id}/iocs/{ioc_id}/timeline-links")
    q = dict(filters or {})
    q.update(params(entity_id=entity_id, limit=limit, cursor=cursor))
    return project(await request("GET", f"/api/incidents/{incident_id}/iocs", params=q), fields)


@tool("readonly")
async def fenrir_ioc_export(incident_id: str, fmt: str, ioc_ids: list[str] | None = None) -> str | dict:
    """Export incident IOCs in a platform format: mde-csv, mde-json (Defender; default action Block),
    crowdstrike, sentinelone, cortex-xdr, fortigate, panos, defanged-txt (FENRIR validates fmt).
    ioc_ids = export only those IOCs of the incident (at most 500; e.g. the ioc_ids an email
    containment returns). Returned inline as text, never written to disk."""
    if ioc_ids is not None and not ioc_ids:
        # An empty selection (e.g. a containment that only quarantined the message) is not "everything".
        raise FenrirError("ioc_ids is empty: nothing to export (omit ioc_ids to export every IOC)")
    q = {"ioc_id": list(ioc_ids)} if ioc_ids else None
    return await request("GET", f"/api/incidents/{incident_id}/iocs/export/{fmt}", params=q)


@tool("standard")
async def fenrir_ioc_write(
    action: Literal["add", "add_batch", "update", "link_timeline"],
    incident_id: str,
    ioc_id: str | None = None,
    data: dict | None = None,
    iocs: list | None = None,
) -> dict | list:
    """Add one IOC (data: type, value, …; evidence_id = the exhibit it was found in), add a
    batch (iocs: list of the same objects, 1-1000; sent as {"items": iocs}; returns created,
    skipped duplicates and errors), update one (ioc_id + data), or link an IOC to a timeline
    event (ioc_id + data with event_id)."""
    base = f"/api/incidents/{incident_id}/iocs"
    if action == "add":
        return await request("POST", base, json=data or {})
    if action == "add_batch":
        if not iocs:
            raise FenrirError("iocs list is required for add_batch")
        return await request("POST", f"{base}/batch", json={"items": iocs})
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
    confirm_outbound: bool = False,
) -> dict:
    """Enrich one IOC, enrich all incident IOCs, or scan them against threat intel.
    These are slow, serialized calls — do not invoke repeatedly in parallel.
    enrich_one / enrich_all send IOC values to outside OSINT services. On a TLP:RED or
    Dark Operation incident they fail with 409 outbound_confirmation_required (reason
    tlp_red | dark_operation): ask the operator, and only if they agree retry with
    confirm_outbound=True (audited as outbound_manual_lookup). scan_ti is local.
    enrich_one / enrich_all need the analyst role or higher (a viewer: 403 insufficient_role)."""
    base = f"/api/incidents/{incident_id}/iocs"
    if action == "enrich_one":
        if not ioc_id:
            raise FenrirError("ioc_id is required for enrich_one")
        return await request("POST", f"{base}/{ioc_id}/enrich", expensive=True,
                             params={"confirm_outbound": "true"} if confirm_outbound else None)
    if action == "enrich_all":
        return await request("POST", f"{base}/enrich-all", expensive=True,
                             json={"confirm_outbound": True} if confirm_outbound else None)
    return await request("POST", f"{base}/scan-ti", expensive=True)
