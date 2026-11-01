"""Legal deadlines, stakeholders, stakeholder matrix, costs, business impact."""

from __future__ import annotations

from typing import Literal

from ..client import FenrirError, request
from . import tool


@tool("readonly")
async def fenrir_legal_list(
    view: Literal["deadlines", "templates", "stakeholders", "matrix", "notifications"],
    incident_id: str | None = None,
    status: Literal["pending", "notified", "not_required"] | None = None,
    active: bool | None = None,
) -> dict | list:
    """Legal/stakeholder reads: regulatory deadlines + templates and incident
    stakeholders (incident_id required), or the global stakeholder-matrix rules
    (each with incident_types; empty = every type).
    Deadline timestamps are UTC ISO 8601; breach_detected_at is each deadline's
    anchor. internal_target=true marks a planning target, not a statutory
    deadline (GDPR Art. 34); deadline_months marks a calendar-month window.
    view=notifications: the incident's stakeholder notification tracker -- one
    obligation per matrix rule matching its severity (and type): role, due_at
    (clock_start_at = when the incident first reached that severity), status
    pending/notified/not_required, overdue, superseded; plus summary
    {required_total, notified, overdue, not_required, next_due_at} (required rules
    only) and severity_levels. Filters: status, active (false = superseded only)."""
    if view == "matrix":
        return await request("GET", "/api/stakeholder-matrix")
    if not incident_id:
        raise FenrirError(f"incident_id is required for view={view}")
    base = f"/api/incidents/{incident_id}"
    if view == "notifications":
        q = {k: v for k, v in (("status", status), ("active", None if active is None else str(active).lower()))
             if v is not None}
        return await request("GET", f"{base}/stakeholder-notifications", params=q or None)
    if status is not None or active is not None:
        raise FenrirError("status / active filter only apply to view=notifications")
    paths = {
        "deadlines": f"{base}/legal/deadlines",
        "templates": f"{base}/legal/templates",
        "stakeholders": f"{base}/stakeholders",
    }
    return await request("GET", paths[view])


@tool("standard")
async def fenrir_legal_write(
    action: Literal[
        "deadline_add", "deadline_update", "deadlines_initialize",
        "stakeholder_add", "stakeholder_bulk", "stakeholder_update",
        "matrix_add", "matrix_update", "notification_update",
    ],
    incident_id: str | None = None,
    item_id: str | None = None,
    data: dict | None = None,
) -> dict | list:
    """Legal/stakeholder writes: add/update regulatory deadlines, initialize
    deadlines from templates (e.g. GDPR 72 h), add stakeholders (single or bulk),
    update one, and manage stakeholder-matrix rules (global; no incident_id).
    deadlines_initialize data: {regulations: [GDPR, NIS2, ...], breach_detected_at?,
    anchors?: {NIS2: ts}}; the anchor defaults to the incident's detected_at (422
    anchor_required if none); re-running only adds missing rows. deadline_add
    breach_detected_at also defaults to detected_at. deadline_update: waiving
    (status=waived) needs completion_notes >= 10 chars (422 notes_required);
    re-anchor = {breach_detected_at, reason >= 10 chars}. An anchor in the future
    (2 min skew allowance) is 422 anchor_in_future. Closed incident: add,
    initialize and re-anchor give 409 incident_closed; status/notes still work.
    Deleting a deadline: fenrir_delete with reason.
    matrix_add/matrix_update data may include incident_types (list; [] = every type);
    a rule change re-derives the notification tracker of every open incident.
    notification_update (item_id = notification id): record a stakeholder
    notification -- data {status: "notified", channel: phone|email|in_person|oob|other,
    notified_at? (UTC, default now, not in the future: 422 time_in_future),
    stakeholder_id?, oob_log_id?, note?}; or {status: "not_required",
    not_required_reason}; undo (status: "pending") or correct a recorded one needs
    reason. FENRIR sends nothing: record only what a person did. Closed incident:
    only pending -> notified is allowed (else 409 incident_closed)."""
    body = data or {}
    if action in ("matrix_add", "matrix_update"):
        if action == "matrix_add":
            return await request("POST", "/api/stakeholder-matrix", json=body)
        if not item_id:
            raise FenrirError("item_id (rule id) is required for matrix_update")
        return await request("PATCH", f"/api/stakeholder-matrix/{item_id}", json=body)
    if not incident_id:
        raise FenrirError(f"incident_id is required for {action}")
    base = f"/api/incidents/{incident_id}"
    if action == "notification_update":
        if not item_id:
            raise FenrirError("item_id (notification id) is required for notification_update")
        return await request("PATCH", f"{base}/stakeholder-notifications/{item_id}", json=body)
    if action == "deadline_add":
        return await request("POST", f"{base}/legal/deadlines", json=body)
    if action == "deadlines_initialize":
        return await request("POST", f"{base}/legal/deadlines/initialize", json=body)
    if action == "deadline_update":
        if not item_id:
            raise FenrirError("item_id (deadline id) is required")
        return await request("PATCH", f"{base}/legal/deadlines/{item_id}", json=body)
    if action == "stakeholder_add":
        return await request("POST", f"{base}/stakeholders", json=body)
    if action == "stakeholder_bulk":
        return await request("POST", f"{base}/stakeholders/bulk", json=body)
    if not item_id:
        raise FenrirError("item_id (stakeholder id) is required")
    return await request("PATCH", f"{base}/stakeholders/{item_id}", json=body)


@tool("readonly")
async def fenrir_costs_list(
    incident_id: str, view: Literal["costs", "summary", "business_impact"] = "costs"
) -> dict | list:
    """Incident cost reads: line items, cost summary, business-impact assessment.
    summary.by_currency has totals per currency; with mixed currencies the top-level totals/currency are null."""
    paths = {
        "costs": f"/api/incidents/{incident_id}/costs",
        "summary": f"/api/incidents/{incident_id}/costs/summary",
        "business_impact": f"/api/incidents/{incident_id}/business-impact",
    }
    return await request("GET", paths[view])


@tool("standard")
async def fenrir_costs_write(
    action: Literal["cost_add", "cost_update", "business_impact_update"],
    incident_id: str,
    cost_id: str | None = None,
    data: dict | None = None,
) -> dict:
    """Add/update cost line items; update the business-impact assessment. currency must
    be an ISO 4217 code (422 invalid_currency)."""
    body = data or {}
    if action == "cost_add":
        return await request("POST", f"/api/incidents/{incident_id}/costs", json=body)
    if action == "cost_update":
        if not cost_id:
            raise FenrirError("cost_id is required for cost_update")
        return await request("PATCH", f"/api/incidents/{incident_id}/costs/{cost_id}", json=body)
    return await request("PATCH", f"/api/incidents/{incident_id}/business-impact", json=body)
