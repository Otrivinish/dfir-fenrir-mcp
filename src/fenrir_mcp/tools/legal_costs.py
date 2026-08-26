"""Legal deadlines, stakeholders, stakeholder matrix, costs, business impact."""

from __future__ import annotations

from typing import Literal

from ..client import FenrirError, request
from . import tool


@tool("readonly")
async def fenrir_legal_list(
    view: Literal["deadlines", "templates", "stakeholders", "matrix"],
    incident_id: str | None = None,
) -> dict | list:
    """Legal/stakeholder reads: regulatory deadlines + templates and incident
    stakeholders (incident_id required), or the global stakeholder-matrix rules.
    Deadline timestamps are UTC ISO 8601."""
    if view == "matrix":
        return await request("GET", "/api/stakeholder-matrix")
    if not incident_id:
        raise FenrirError(f"incident_id is required for view={view}")
    base = f"/api/incidents/{incident_id}"
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
        "matrix_add", "matrix_update",
    ],
    incident_id: str | None = None,
    item_id: str | None = None,
    data: dict | None = None,
) -> dict | list:
    """Legal/stakeholder writes: add/update regulatory deadlines, initialize
    deadlines from templates (e.g. GDPR 72 h), add stakeholders (single or bulk),
    update one, and manage stakeholder-matrix rules (global; no incident_id)."""
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
    """Incident cost reads: line items, cost summary, business-impact assessment."""
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
    """Add/update cost line items; update the business-impact assessment."""
    body = data or {}
    if action == "cost_add":
        return await request("POST", f"/api/incidents/{incident_id}/costs", json=body)
    if action == "cost_update":
        if not cost_id:
            raise FenrirError("cost_id is required for cost_update")
        return await request("PATCH", f"/api/incidents/{incident_id}/costs/{cost_id}", json=body)
    return await request("PATCH", f"/api/incidents/{incident_id}/business-impact", json=body)
