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
    entity_id: str | None = None,
    ioc_id: str | None = None,
    ir_phase: Literal["preparation", "detection_and_analysis", "containment_eradication_recovery",
                      "post_incident", "none"] | None = None,
    origin: Literal["manual", "forensic_import", "system"] | None = None,
    key: bool | None = None,
    q: str | None = None,
    include_system: bool | None = None,
    sort: Literal["asc", "desc"] | None = None,
    limit: int | None = None,
    cursor: str | None = None,
    fields: list | None = None,
    export: Literal["rail", "horizon", "swimlanes", "ledger", "brief", "zigzag", "csv"] | None = None,
    tz: str | None = None,
    include_raw_logs: bool | None = None,
) -> dict | list | str:
    """List timeline events for an incident (UTC ISO 8601). lolbin_scan=True runs
    the LOLBin/GTFOBin scan over the timeline instead of listing events. Use
    limit + fields (e.g. ["id","event_time","description","key_event","linked_iocs"])
    — timelines can hold thousands of events. Server-side filters (AND): entity_id,
    ioc_id, ir_phase (an 800-61 phase key, or "none" = unset), origin (manual |
    forensic_import | system), key=True (key events: flagged is_key, ATT&CK-tagged or
    server-recorded), q (text in description, host, source, type, raw log, ATT&CK).
    sort: "asc" (oldest first, the default) or "desc" (newest first) by event_time.
    Paging: pass next_cursor back with the SAME filters and sort.
    Each event carries `entity` (the linked entity: id, type, value, compromised) and, when
    unlinked, `entity_match` (the entity its hostname names — a suggestion, never a link;
    case-insensitive value match, ties to the exact-case value then the host). entity_id=
    lists LINKED events only: link the suggested ones with fenrir_timeline_write
    action=link_entity.
    export= renders the filtered timeline server-side and returns the file text (large; prefer key=True):
    an HTML layout (rail | horizon | swimlanes | ledger | brief | zigzag; no script, carries TLP) or "csv"
    (18 columns, UTC). tz = IANA zone for HTML times (default UTC); include_raw_logs=True prints raw log
    lines (rail, ledger, zigzag, csv) — they can hold secrets. Not paged: >10 000 events is
    export_too_large. Audited as timeline_export."""
    if lolbin_scan:
        return await request("GET", f"/api/incidents/{incident_id}/timeline/lolbin-scan")
    qp = dict(filters or {})
    if export:
        qp.update(params(entity_id=entity_id, ioc_id=ioc_id, ir_phase=ir_phase, origin=origin, key=key, q=q,
                         include_system=include_system, tz=tz, include_raw_logs=include_raw_logs,
                         format="csv" if export == "csv" else "html",
                         layout=None if export == "csv" else export))
        return await request("GET", f"/api/incidents/{incident_id}/timeline/export", params=qp)
    qp.update(params(entity_id=entity_id, ioc_id=ioc_id, ir_phase=ir_phase, origin=origin, key=key, q=q,
                     include_system=include_system,
                     sort={"asc": "event_time", "desc": "-event_time"}.get(sort) if sort else None,
                     limit=limit, cursor=cursor))
    return project(await request("GET", f"/api/incidents/{incident_id}/timeline", params=qp), fields)


@tool("standard")
async def fenrir_timeline_write(
    action: Literal["add", "add_batch", "update", "link_entity"],
    incident_id: str,
    event_id: str | None = None,
    data: dict | None = None,
    events: list | None = None,
    entity_id: str | None = None,
    dry_run: bool = False,
    link_entities: bool | None = None,
) -> dict | list:
    """Add one event (data), add a batch (events list), or update one (event_id +
    data). Event timestamps must be UTC ISO 8601 (YYYY-MM-DDTHH:MM:SSZ).
    data.entity_id links the event to an entity of THIS incident (404 unknown,
    422 entity_other_incident; a batch item is skipped with an error); an empty
    hostname takes the entity's value. add_batch links each item that sends no entity_id to
    the entity its hostname names (result entities_linked); link_entities=false turns that off.
    A single add never links by itself. link_entity (entity_id) links every UNLINKED event whose
    hostname names that entity (the events listed with that entity_match); dry_run=true only
    counts them. Returns {entity_id, matched, linked}; audited once with the event ids; a
    repeat links 0; already-linked and server-recorded events are never touched. ir_phase: an 800-61 phase key. is_key=true flags a
    key event (allowed on imported events too). Link IOCs with fenrir_ioc_write. On update,
    entity_id / ir_phase sent as null unlink / clear. An event promoted from a
    timeline import (forensic_import_id set) keeps its facts: changing event_time,
    hostname, source, event_type, description or raw_log returns 409
    imported_fact_immutable; annotate it with ir_phase, ATT&CK or entity_id. An event the
    server recorded itself (server_generated=true: system_source closure, gate_override,
    milestone, triage, respond_action, respond_action_revert, decision, legal_deadline) can't
    be updated at all: 409 system_event_immutable — add a new annotation event instead."""
    if action == "add":
        return await request("POST", f"/api/incidents/{incident_id}/timeline", json=data or {})
    if action == "add_batch":
        if not events:
            raise FenrirError("events list is required for add_batch")
        return await request("POST", f"/api/incidents/{incident_id}/timeline/batch",
                             json={"events": events, **params(link_entities=link_entities)})
    if action == "link_entity":
        if not entity_id:
            raise FenrirError("entity_id is required for link_entity")
        return await request("POST", f"/api/incidents/{incident_id}/timeline/entity-links",
                             json={"entity_id": entity_id, "dry_run": dry_run})
    if not event_id:
        raise FenrirError("event_id is required for update")
    return await request("PATCH", f"/api/incidents/{incident_id}/timeline/{event_id}", json=data or {})
