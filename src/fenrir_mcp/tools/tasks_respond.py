"""Playbook tasks + response actions/decisions — RO reads, STD writes."""

from __future__ import annotations

from typing import Literal

from ..client import FenrirError, request
from . import tool


@tool("readonly")
async def fenrir_task_list(
    incident_id: str | None = None,
    view: Literal["tasks", "templates", "template_item"] = "tasks",
    template_id: str | None = None,
) -> dict | list:
    """Playbook reads: incident tasks (incident_id required), the template catalog,
    or one template (template_id). Built-in templates follow the CISA IR playbooks."""
    if view == "tasks":
        if not incident_id:
            raise FenrirError("incident_id is required for view=tasks")
        return await request("GET", f"/api/incidents/{incident_id}/playbook/tasks")
    if view == "template_item":
        if not template_id:
            raise FenrirError("template_id is required for view=template_item")
        return await request("GET", f"/api/playbook-templates/{template_id}")
    return await request("GET", "/api/playbook-templates")


@tool("standard")
async def fenrir_task_write(
    action: Literal["add", "update", "instantiate_template"],
    incident_id: str,
    task_id: str | None = None,
    data: dict | None = None,
) -> dict | list:
    """Add a custom playbook task, update one (task_id + data — e.g. status/assignee),
    or instantiate a playbook template onto the incident (data with template_id)."""
    base = f"/api/incidents/{incident_id}/playbook"
    if action == "add":
        return await request("POST", f"{base}/tasks", json=data or {})
    if action == "instantiate_template":
        return await request("POST", f"{base}/instantiate", json=data or {})
    if not task_id:
        raise FenrirError("task_id is required for update")
    return await request("PATCH", f"{base}/tasks/{task_id}", json=data or {})


@tool("readonly")
async def fenrir_respond_list(
    incident_id: str, view: Literal["actions", "decisions"] = "actions"
) -> dict | list:
    """Response reads: containment/eradication/recovery actions, or the decision log
    (NIST SP 800-61 R3 Containment, Eradication & Recovery phase records)."""
    return await request("GET", f"/api/incidents/{incident_id}/respond/{view}")


@tool("standard")
async def fenrir_respond_write(
    action: Literal["action_add", "action_update", "action_revert", "decision_add", "decision_update"],
    incident_id: str,
    item_id: str | None = None,
    data: dict | None = None,
) -> dict:
    """Log/update response actions (action_revert marks an action reverted) and
    record/update decisions. item_id is the action/decision id for update/revert."""
    base = f"/api/incidents/{incident_id}/respond"
    body = data or {}
    if action == "action_add":
        return await request("POST", f"{base}/actions", json=body)
    if action == "decision_add":
        return await request("POST", f"{base}/decisions", json=body)
    if not item_id:
        raise FenrirError("item_id is required for update/revert")
    if action == "action_update":
        return await request("PATCH", f"{base}/actions/{item_id}", json=body)
    if action == "action_revert":
        return await request("POST", f"{base}/actions/{item_id}/revert", json=body)
    return await request("PATCH", f"{base}/decisions/{item_id}", json=body)
