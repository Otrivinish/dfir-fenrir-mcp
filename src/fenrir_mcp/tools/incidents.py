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
async def fenrir_incident_get(incident_id: str, snapshot: bool = False, gates: bool = False) -> dict:
    """Get one incident. snapshot=True returns counts instead of the base record: iocs,
    entities, evidence, timeline, affected_systems, assignments, playbook_total/done/skipped,
    files, respond_open (open or in progress) / respond_total, handoffs_pending.
    gates=True returns the phase-gate status instead: {incident_id, items: [{gate, label,
    met, exempt, unmet[], carried_forward[]}]} for gate "post_incident" (Gate 1, checked
    on any move into post_incident) and "close" (Gate 2, checked on close; exempt for a
    false/benign positive). Each unmet item has key, label, detail, fix_hint, route.
    Check it before resolving or closing."""
    if snapshot and gates:
        raise FenrirError("pass snapshot=True or gates=True, not both")
    suffix = "/snapshot" if snapshot else "/gates" if gates else ""
    return await request("GET", f"/api/incidents/{incident_id}{suffix}")


@tool("readonly")
async def fenrir_incident_audit(
    incident_id: str, limit: int | None = None, cursor: str | None = None
) -> dict | list:
    """Read the incident-scoped tamper-evident (hash-chained) audit log. Incident lead
    only: an admin, or an analyst assigned as Incident Commander or Deputy on this
    incident (403 not_incident_lead; see fenrir_people_list view=incident_access). Every
    page a non-admin reads is itself audited (incident_audit_view)."""
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
    (low|medium|high|critical), phase etc.; phase must be detection_and_analysis
    or containment_eradication_recovery (others 422). Pass detected_at (UTC ISO
    8601) on create; the server never fills it in. detected_at before
    occurred_at or in the future is 422 (create and update).
    dark_operation: true opens it dark (no Teams/Slack/email alerts).
    update: PATCH fields in data; "resolve" = update phase=post_incident (stays open).
    Phase gates (see fenrir_incident_get gates=True): phase=preparation is 409
    phase_transition_invalid; moving to an earlier phase needs data.phase_reason
    (≥10 chars, else 422 phase_reason_required); any move into post_incident runs
    Gate 1 and is 409 gate_unmet (the message lists what is missing) until it is met.
    Override only when the operator explicitly decides to: data.override_gate=true +
    phase_reason (audited, posted to the timeline); a reason alone never overrides.
    override_gate (here and on close) needs incident-lead rights (admin, or an analyst
    assigned IC/Deputy on this incident): 403 not_incident_lead otherwise. team_ids
    (replace the incident's teams) is lead-only too; only an admin may clear a
    restricted incident's teams (409 would_unrestrict); a non-admin lead may only add
    teams they belong to and must keep one of their own (409 would_lock_out).
    triage_state false_positive/benign_positive outside detection_and_analysis needs
    data.triage_reason (≥10 chars, else 422 triage_reason_required). Milestones
    (contained_at/eradicated_at/recovered_at) can't precede detected_at (422).
    close (sign-off): data={"reason": ≥10 chars}, required (422 reason_required);
    phase must be post_incident (409 phase_not_post_incident) unless triage_state
    is false_positive/benign_positive (those skip Gate 2). Otherwise Gate 2 must be
    met (409 gate_unmet), or data.override_gate=true with the reason as justification
    (operator's decision only). Once closed, lessons-learned action_items stay
    editable, and so do costs and the business-impact record (realised costs arrive
    later) and legal deadline status/notes; the rest of lessons learned, the checklist
    and the incident fields are 409 incident_closed.
    reopen: data={"reason": ≥10 chars, "phase": detection_and_analysis|
    containment_eradication_recovery|post_incident}, both required (422).
    Severity uses FENRIR's internal scale."""
    if action == "create":
        return await request("POST", "/api/incidents", json=data or {})
    if not incident_id:
        raise FenrirError("incident_id is required for update/close/reopen")
    if action == "update":
        return await request("PATCH", f"/api/incidents/{incident_id}", json=data or {})
    return await request("POST", f"/api/incidents/{incident_id}/{action}", json=data or {})
