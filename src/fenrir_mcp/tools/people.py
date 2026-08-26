"""Assignments, roster, on-call, presence, handoffs, teams, operational roles.

Unassigning a role is an operational (reversible) act and deliberately stays in
STD rather than fenrir_delete (docs/TOOLS.md footnote)."""

from __future__ import annotations

from typing import Literal

from ..client import FenrirError, request
from . import tool


@tool("readonly")
async def fenrir_people_list(
    view: Literal[
        "assignments", "assignable_users", "roster", "on_call", "on_call_current",
        "presence", "handoffs", "handoffs_pending", "teams", "team_members", "operational_roles",
    ],
    incident_id: str | None = None,
    team_id: str | None = None,
) -> dict | list:
    """People/coordination reads: per-incident role assignments, assignable users,
    responder roster, on-call schedule + current, incident page viewers, incident
    handoffs, my pending handoffs, teams (+members with team_id), and the
    operational role catalog (CISA IR roles)."""
    per_incident = {
        "assignments": "assignments", "presence": "presence/viewers", "handoffs": "handoffs",
    }
    if view in per_incident:
        if not incident_id:
            raise FenrirError(f"incident_id is required for view={view}")
        return await request("GET", f"/api/incidents/{incident_id}/{per_incident[view]}")
    if view == "team_members":
        if not team_id:
            raise FenrirError("team_id is required for view=team_members")
        return await request("GET", f"/api/teams/{team_id}/members")
    paths = {
        "assignable_users": "/api/users/assignable",
        "roster": "/api/roster",
        "on_call": "/api/on-call",
        "on_call_current": "/api/on-call/current",
        "handoffs_pending": "/api/handoffs/pending",
        "teams": "/api/teams",
        "operational_roles": "/api/operational-roles",
    }
    return await request("GET", paths[view])


@tool("standard")
async def fenrir_people_write(
    action: Literal[
        "assign_role", "unassign_role", "handoff_create", "handoff_acknowledge",
        "on_call_add", "on_call_update", "roster_update",
    ],
    incident_id: str | None = None,
    item_id: str | None = None,
    user_id: str | None = None,
    data: dict | None = None,
) -> dict:
    """People/coordination writes: assign an operational role (data: user + role),
    unassign one (item_id = assignment id; reversible, hence not a delete-tier op),
    create/acknowledge handoffs, manage on-call entries, update a roster entry
    (user_id + data)."""
    body = data or {}
    if action in ("assign_role", "unassign_role", "handoff_create", "handoff_acknowledge"):
        if not incident_id:
            raise FenrirError(f"incident_id is required for {action}")
        base = f"/api/incidents/{incident_id}"
        if action == "assign_role":
            return await request("POST", f"{base}/assignments", json=body)
        if action == "unassign_role":
            if not item_id:
                raise FenrirError("item_id (assignment id) is required")
            return await request("DELETE", f"{base}/assignments/{item_id}")
        if action == "handoff_create":
            return await request("POST", f"{base}/handoffs", json=body)
        if not item_id:
            raise FenrirError("item_id (handoff id) is required")
        return await request("PATCH", f"{base}/handoffs/{item_id}/acknowledge", json=body)
    if action == "on_call_add":
        return await request("POST", "/api/on-call", json=body)
    if action == "on_call_update":
        if not item_id:
            raise FenrirError("item_id (on-call entry id) is required")
        return await request("PATCH", f"/api/on-call/{item_id}", json=body)
    if not user_id:
        raise FenrirError("user_id is required for roster_update")
    return await request("PATCH", f"/api/roster/{user_id}", json=body)
