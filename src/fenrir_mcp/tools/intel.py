"""Knowledge & intel: MITRE, LOLBins, validated tools, threat actors/attributions,
correlations, detections, YARA, threat-intel feeds."""

from __future__ import annotations

from typing import Literal

from ..client import FenrirError, request
from . import params, tool


@tool("readonly")
async def fenrir_intel_lookup(
    view: Literal[
        "mitre_coverage", "mitre_global", "lolbins_lookup", "lolbins_search",
        "lolbins_check_text", "lolbins_status", "validated_tools", "threat_actors",
        "threat_actor_item", "actor_sync_status", "correlations_entities",
        "correlations_iocs", "detections", "detections_rules", "yara_rules",
        "yara_matches", "attributions", "attribution_suggest",
    ],
    incident_id: str | None = None,
    item_id: str | None = None,
    query: str | None = None,
) -> dict | list | str:
    """Reference lookups: incident MITRE coverage / global coverage, LOLBins
    (lookup/search/check_text take query), validated analysis tools, threat-actor
    catalog (+item), cross-incident shared entities/IOCs, the incident detection
    bundle (detections_rules returns Sigma/YARA rule TEXT inline), YARA rules and
    incident matches, incident attributions + suggestions."""
    per_incident = {
        "mitre_coverage": "mitre/coverage", "detections": "detections",
        "detections_rules": "detections/download", "yara_matches": "yara/matches",
        "attributions": "attributions", "attribution_suggest": "attributions/suggest",
    }
    if view in per_incident:
        if not incident_id:
            raise FenrirError(f"incident_id is required for view={view}")
        return await request("GET", f"/api/incidents/{incident_id}/{per_incident[view]}")
    if view == "threat_actor_item":
        if not item_id:
            raise FenrirError("item_id is required for view=threat_actor_item")
        return await request("GET", f"/api/threat-actors/{item_id}")
    q = params(q=query, query=query, text=query) if query else None
    paths = {
        "mitre_global": "/api/mitre/coverage",
        "lolbins_lookup": "/api/lolbins/lookup",
        "lolbins_search": "/api/lolbins/search",
        "lolbins_check_text": "/api/lolbins/check-text",
        "lolbins_status": "/api/lolbins/status",
        "validated_tools": "/api/validated-tools",
        "threat_actors": "/api/threat-actors",
        "actor_sync_status": "/api/threat-actors/sync-status",
        "correlations_entities": "/api/correlations/entities",
        "correlations_iocs": "/api/correlations/iocs",
        "yara_rules": "/api/yara",
    }
    return await request("GET", paths[view], params=q)


@tool("readonly")
async def fenrir_threat_intel(
    view: Literal["summary", "feeds", "iocs", "incident_matches"] = "summary",
    filters: dict | None = None,
    limit: int | None = None,
    cursor: str | None = None,
) -> dict | list:
    """Threat-intel reads: summary stats, configured feeds, global TI IOC browse,
    incidents matching TI IOCs."""
    paths = {
        "summary": "/api/threat-intel/summary",
        "feeds": "/api/threat-intel/feeds",
        "iocs": "/api/threat-intel/iocs",
        "incident_matches": "/api/threat-intel/incident-matches",
    }
    q = dict(filters or {})
    q.update(params(limit=limit, cursor=cursor))
    return await request("GET", paths[view], params=q or None)


@tool("standard")
async def fenrir_yara_write(
    action: Literal["create", "update", "scan", "match_to_timeline", "match_to_ioc"],
    rule_id: str | None = None,
    incident_id: str | None = None,
    match_id: str | None = None,
    data: dict | None = None,
) -> dict:
    """YARA: create/update global rules (rule text in data), scan an incident's
    artifacts (incident_id; slow, serialized), promote a match to the timeline or
    to an IOC (incident_id + match_id)."""
    body = data or {}
    if action == "create":
        return await request("POST", "/api/yara", json=body)
    if action == "update":
        if not rule_id:
            raise FenrirError("rule_id is required for update")
        return await request("PATCH", f"/api/yara/{rule_id}", json=body)
    if not incident_id:
        raise FenrirError(f"incident_id is required for {action}")
    if action == "scan":
        return await request("POST", f"/api/incidents/{incident_id}/yara/scan", json=body, expensive=True)
    if not match_id:
        raise FenrirError(f"match_id is required for {action}")
    seg = "to-timeline" if action == "match_to_timeline" else "to-ioc"
    return await request("POST", f"/api/incidents/{incident_id}/yara/matches/{match_id}/{seg}", json=body)


@tool("standard")
async def fenrir_attribution_write(
    action: Literal["actor_create", "actor_update", "attribution_add", "attribution_update"],
    actor_id: str | None = None,
    incident_id: str | None = None,
    attribution_id: str | None = None,
    data: dict | None = None,
) -> dict:
    """Threat-actor knowledge base writes (actor_create/actor_update) and incident
    attribution links (attribution_add/attribution_update, incident_id required)."""
    body = data or {}
    if action == "actor_create":
        return await request("POST", "/api/threat-actors", json=body)
    if action == "actor_update":
        if not actor_id:
            raise FenrirError("actor_id is required for actor_update")
        return await request("PATCH", f"/api/threat-actors/{actor_id}", json=body)
    if not incident_id:
        raise FenrirError(f"incident_id is required for {action}")
    if action == "attribution_add":
        return await request("POST", f"/api/incidents/{incident_id}/attributions", json=body)
    if not attribution_id:
        raise FenrirError("attribution_id is required for attribution_update")
    return await request("PATCH", f"/api/incidents/{incident_id}/attributions/{attribution_id}", json=body)
