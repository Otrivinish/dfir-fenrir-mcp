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
async def fenrir_incident_get(
    incident_id: str, snapshot: bool = False, gates: bool = False, start_checks: bool = False,
    phase_history: bool = False,
) -> dict:
    """Get one incident. snapshot=True returns counts instead of the base record: iocs,
    entities, evidence, timeline, affected_systems, assignments, playbook_total/done/skipped,
    files, respond_open (open or in progress) / respond_total, respond_containment and
    respond_eradication_recovery ({total, done, open}), decisions, handoffs_pending, the
    recovery / notifications / start_checks roll-ups, and phase_history (time in phase, from
    the audit log: {phase, entered_at = start of the current period, closed, periods[{phase,
    entered_at, left_at, duration_seconds, ended_by}], completed[{phase, seconds, periods}]}).
    phase_history=True returns only that phase_history object (cheaper than the snapshot;
    left_at / duration_seconds are null on the current period).
    start_checks=True returns only the incident-start checks: {total, ok, warning, overdue,
    overdue_after_minutes, overdue_at, items: [{key, label, status ok|warning|overdue, detail,
    route}]} — IC / Comms Lead / Legal Liaison assigned, detection time, type set (a SIEM
    alert with no mappable category opens without one), playbook applied
    (detail names suggested templates), legal initialised (ransomware/data_breach/bec or
    personal data), Dark Operation decided (phishing/bec), no notification overdue. A missing
    check turns overdue 60 min after creation. Warnings only, nothing blocks.
    gates=True returns the phase-gate status instead: {incident_id, items: [{gate, label,
    met, exempt, unmet[], warnings[], checks[], carried_forward[], sign_offs_required[],
    sign_offs[], state_sha256}]} for gate "post_incident" (Gate 1, checked on any move into
    post_incident) and "close" (Gate 2, checked on close; exempt for a false/benign
    positive). Every check has key, label, level (block|warn), status (met|unmet), detail,
    fix_hint, route. unmet[] = unmet block-level checks (they stop the move: 409 gate_unmet;
    met is true when it is empty); warnings[] = unmet warn-level checks (hygiene: shown and
    recorded in the audit row, never blocking). Gate 1 blocks also on in-scope systems not
    validated, required stakeholder notifications not logged, and for a personal-data breach
    no GDPR/NIS2 obligation or a waived one without the DPO's sign-off. Gate 2 blocks also on
    exhibits without custodian or legal hold, open working-copy downloads, unacknowledged LE
    packages, and the missing IC (and breach: DPO) sign-off. Check it before resolving or
    closing; report warnings to the operator, don't treat them as blockers."""
    if snapshot + gates + start_checks + phase_history > 1:
        raise FenrirError("pass only one of snapshot=True, gates=True, start_checks=True, phase_history=True")
    suffix = ("/snapshot" if snapshot else "/gates" if gates else "/start-checks" if start_checks
              else "/phase-history" if phase_history else "")
    return await request("GET", f"/api/incidents/{incident_id}{suffix}")


@tool("readonly")
async def fenrir_incident_audit(
    incident_id: str, limit: int | None = None, cursor: str | None = None, fields: list | None = None
) -> dict | list:
    """Read the incident-scoped tamper-evident (hash-chained) audit log. Incident lead
    only: an admin, or an analyst assigned as Incident Commander or Deputy on this
    incident (403 not_incident_lead; see fenrir_people_list view=incident_access). Every
    page a non-admin reads is itself audited (incident_audit_view).
    Each entry: id, timestamp (UTC), user_id, username, role_at_time, action, outcome,
    resource_type/id/label, details, ip_address (the real client IP; none = a system/background
    write), user_agent (the client's User-Agent, sanitised, at most 512 chars; hash-protected
    from hash v3), request_method, request_path, request_id, row_hash, prev_hash.
    Pass fields (e.g. ["timestamp","username","action","ip_address","user_agent"]) to keep it small."""
    return project(await request(
        "GET", f"/api/incidents/{incident_id}/audit-log", params=params(limit=limit, cursor=cursor)
    ), fields)


@tool("standard")
async def fenrir_incident_write(
    action: Literal["create", "update", "close", "reopen", "sign_off"],
    incident_id: str | None = None,
    data: dict | None = None,
) -> dict:
    """Create/update/close/reopen an incident. create REQUIRES data.title, severity
    (low|medium|high|critical), incident_type, detection_method and detected_at (UTC ISO
    8601; the server never fills it in) — any missing is 422 required_fields_missing with
    fields[]. phase must be detection_and_analysis or containment_eradication_recovery
    (others 422). detected_at before occurred_at or in the future is 422 (create and update).
    Optional intake on create: ic_user_id (assigns the Incident Commander; 404
    user_not_found / 422 assignee_no_access), functional_impact (none|low|medium|high),
    information_impact (none|privacy|proprietary|integrity), recoverability
    (regular|supplemented|extended|not_recoverable), severity_rationale, alert_reference,
    first_host (adds a compromised host entity), first_ioc {type, value} (adds an IOC) — one
    transaction. The impact fields, severity_rationale and alert_reference are also
    updatable (null clears). Check fenrir_incident_get start_checks=True after creating.
    dark_operation: true opens it dark (no Teams/Slack/email alerts); sending it (true or
    false) records the Dark Operation decision. team_ids on create
    restricts it to those teams from the start: an admin any team, an analyst only teams
    they belong to (409 would_lock_out); unknown team 422 team_not_found; never dropped.
    Creating it as triage_state false_positive/benign_positive outside
    detection_and_analysis needs data.triage_reason (≥10 chars, else 422
    triage_reason_required).
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
    data.triage_reason (≥10 chars, else 422 triage_reason_required), and so does a
    phase change that moves a false/benign positive out of detection_and_analysis.
    dark_operation can't be changed by update (422 use_dark_operation_endpoint): use
    fenrir_comms_write action=dark_operation. Milestones
    (contained_at/eradicated_at/recovered_at, UTC) are declared by update: setting one for
    the first time adds a system timeline event ("Containment declared" …); they can't
    precede detected_at (422), and Gate 1 needs all three. Declare only times the operator
    confirms.
    close (sign-off): data={"reason": ≥10 chars}, required (422 reason_required);
    phase must be post_incident (409 phase_not_post_incident) unless triage_state
    is false_positive/benign_positive (those skip Gate 2). Otherwise Gate 2 must be
    met (409 gate_unmet), or data.override_gate=true with the reason as justification
    (operator's decision only). Once closed, lessons-learned action_items stay
    editable, and so do costs and the business-impact record (realised costs arrive
    later) and legal deadline status/notes; the rest of lessons learned, the checklist
    and the incident fields are 409 incident_closed.
    reopen: data={"reason": ≥10 chars, "phase": detection_and_analysis|
    containment_eradication_recovery|post_incident}, both required (422). Re-opening
    into post_incident an incident closed in another phase runs Gate 1 (409 gate_unmet);
    data.override_gate=true (incident lead only, 403 not_incident_lead otherwise) re-opens
    anyway with the reason as justification (operator's decision only).
    sign_off: data={"gate": "post_incident"|"close", "role": "ic"|"dpo", "statement": ≥10
    chars} records the operator's own sign-off on that gate (append-only, audited, with a
    hash of the gate's blocking checks); only when the operator explicitly signs, in their
    words. ic = incident lead (IC/Deputy) or admin (403 not_incident_lead); dpo = the
    analyst assigned Data Protection Officer or admin (403 not_incident_dpo); 409
    sign_off_not_required when the gate's sign_offs_required lacks the role.
    Severity uses FENRIR's internal scale."""
    if action == "create":
        return await request("POST", "/api/incidents", json=data or {})
    if not incident_id:
        raise FenrirError("incident_id is required for update/close/reopen/sign_off")
    if action == "update":
        return await request("PATCH", f"/api/incidents/{incident_id}", json=data or {})
    if action == "sign_off":
        body = dict(data or {})
        gate = body.pop("gate", None)
        if gate not in ("post_incident", "close"):
            raise FenrirError('sign_off needs data.gate "post_incident" or "close"')
        return await request("POST", f"/api/incidents/{incident_id}/gates/{gate}/sign-off", json=body)
    return await request("POST", f"/api/incidents/{incident_id}/{action}", json=data or {})
