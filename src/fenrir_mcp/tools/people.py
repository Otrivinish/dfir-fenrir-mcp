"""Assignments, roster, on-call, presence, handoffs, teams, operational roles, Contacts directory.

Unassigning a role is an operational (reversible) act and deliberately stays in
STD rather than fenrir_delete (docs/TOOLS.md footnote)."""

from __future__ import annotations

from typing import Literal

from .. import refcache
from ..client import FenrirError, request
from . import params, project, tool

_OOB = "oob_contact_methods"


def _strip_oob(result):
    """Drop responders' out-of-band contacts from a roster / on-call result (items[], current, or
    the single entry): personal data that should not enter the model's context unasked."""
    def drop(d):
        return {k: v for k, v in d.items() if k != _OOB} if isinstance(d, dict) else d

    if isinstance(result, list):
        return [drop(i) for i in result]
    if not isinstance(result, dict):
        return result
    out = drop(result)
    if isinstance(out.get("items"), list):
        out["items"] = [drop(i) for i in out["items"]]
    if isinstance(out.get("current"), dict):
        out["current"] = drop(out["current"])
    return out


@tool("readonly")
async def fenrir_people_list(
    view: Literal[
        "assignments", "assignable_users", "roster", "on_call", "on_call_current",
        "presence", "handoffs", "handoffs_pending", "handoff_prefill", "teams", "team_members",
        "operational_roles", "incident_access", "contacts",
    ],
    incident_id: str | None = None,
    writers_only: bool = False,
    team_id: str | None = None,
    contact_type: str | None = None,
    q: str | None = None,
    limit: int | None = None,
    cursor: str | None = None,
    fields: list | None = None,
) -> dict | list:
    """People/coordination reads: per-incident role assignments, assignable users,
    responder roster, on-call schedule + current, incident page viewers, incident
    handoffs, my pending handoffs, teams (+members with team_id), and the
    operational role catalog (CISA IR roles).
    assignable_users: active users (id, username, full_name). With incident_id, only those
    who can see that incident: the people its assignee / decider / witness / handoff
    recipient fields accept (others get 422 assignee_no_access); 404 if you can't see it.
    writers_only=True leaves out viewers: use it for a handoff recipient (a viewer can't
    acknowledge; 422 recipient_read_only).
    handoff_prefill (incident_id): what a new handoff starts from -- the open Respond actions
    and the open playbook tasks of the current phase, [{id, title, owner, status, category |
    phase}]; the same lists are stored in each handoff's snapshot_data.open_actions/open_tasks.
    incident_access (incident_id): my rights on that incident, {is_lead, capabilities[]}.
    The incident lead is an admin, or an analyst (token role cap applies) assigned as
    Incident Commander or Deputy there; it gets read_audit_log, manage_le_package,
    set_teams, override_gate, remove_any_assignment. assign_lead_roles = may assign or
    remove IC/Deputy. Check it before those calls instead of guessing from your role.
    roster / on_call / on_call_current: each responder's oob_contact_methods (out-of-band
    phone etc.; personal data) is stripped from the result unless you name it in fields,
    e.g. fields=["username","oob_contact_methods"] (on_call: fields apply to items[]; current
    then keeps its own). Ask for it only when you must reach someone out of band, and keep
    it out of reports. Viewer tokens never get it.
    contacts: the org Contacts directory (supervisory authority, CSIRT, police, insurer, IR
    retainer, PR, ...), {items, next_cursor}; filter contact_type (a stakeholder type, e.g.
    supervisory_authority, csirt, law_enforcement, insurer, ir_firm, media_pr) and q (name /
    organization / title); page with limit + cursor. last_verified_at = server time of the
    last check. Analysts and admins; viewers 403."""
    per_incident = {
        "assignments": "assignments", "presence": "presence/viewers", "handoffs": "handoffs",
        "incident_access": "access", "handoff_prefill": "handoffs/prefill",
    }
    if view in per_incident:
        if not incident_id:
            raise FenrirError(f"incident_id is required for view={view}")
        return await request("GET", f"/api/incidents/{incident_id}/{per_incident[view]}")
    if view == "contacts":
        return project(await request("GET", "/api/contacts", params=params(
            type=contact_type, q=q, limit=limit, cursor=cursor)), fields)
    if view == "team_members":
        if not team_id:
            raise FenrirError("team_id is required for view=team_members")
        return await request("GET", f"/api/teams/{team_id}/members")
    if view in ("roster", "on_call", "on_call_current"):
        path = {"roster": "/api/roster", "on_call": "/api/on-call",
                "on_call_current": "/api/on-call/current"}[view]
        result = await request("GET", path)
        if fields and _OOB in fields:
            return project(result, fields)
        return project(_strip_oob(result), fields)
    if view == "assignable_users":
        iid = incident_id
        if iid and refcache.REF_RE.match(iid):   # a ref: query params aren't rewritten, so resolve it
            iid = (await request("GET", f"/api/incidents/{iid}"))["id"]
        return await request("GET", "/api/users/assignable",
                             params=params(incident_id=iid, writers_only="true" if writers_only else None))
    paths = {
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
        "contact_add", "contact_update", "contact_verify",
    ],
    incident_id: str | None = None,
    item_id: str | None = None,
    user_id: str | None = None,
    data: dict | None = None,
) -> dict:
    """People/coordination writes: assign an operational role (data: user_id + role_id),
    unassign one (item_id = assignment id; reversible, hence not a delete-tier op),
    create/acknowledge handoffs, manage on-call entries, update a roster entry
    (user_id + data; data.oob_contact_methods = [{channel, value, preferred?, notes?}]
    replaces your out-of-band contacts, [] clears them; only your own unless admin, else 403).
    Contacts directory (admin only; others 403): contact_add (data: name, type, organization?,
    title?, contact_methods?, notes?, available_hours?), contact_update (item_id = contact id +
    data), contact_verify (item_id; stamps last_verified_at with the server time and you as
    verifier; do it only after the entry was actually checked). Add a directory contact to an
    incident with fenrir_comms_write(action="stakeholder_add", data={"contact_id": ...}).
    assign_role / unassign_role: Incident Commander and Deputy make an analyst the
    incident lead, so only the lead or an admin can assign or remove them (while the
    incident has no lead: its creator or today's on-call analyst); else 403
    not_incident_lead. The assignee must already see the incident (422
    assignee_no_access: an assignment grants no access) and is notified. You may
    unassign yourself; the lead may unassign anyone. Unknown user_id: 404 user_not_found.
    handoff_create: data.incoming_user_id (+ note, current_hypothesis, ...) must be an
    active analyst or admin who can see the incident, not yourself (404 user_not_found, 422
    assignee_no_access, 422 recipient_read_only for a viewer; view=assignable_users with
    incident_id + writers_only=True lists who qualifies). data.next_steps [{action, priority,
    create_task?}]: create_task=true also makes that line a playbook task (current phase)
    assigned to the recipient; the stored line gets task_id. data.transfer_ic=true (only the
    IC, Deputy IC or an admin; else 403 not_incident_lead) moves the Incident Commander
    assignment to the recipient when they acknowledge (audited, old IC notified, timeline
    event; the handoff's ic_transferred_at is then set)."""
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
    if action == "contact_add":
        return await request("POST", "/api/contacts", json=body)
    if action in ("contact_update", "contact_verify"):
        if not item_id:
            raise FenrirError(f"item_id (contact id) is required for {action}")
        payload = {"verified": True} if action == "contact_verify" else body
        return await request("PATCH", f"/api/contacts/{item_id}", json=payload)
    if action == "on_call_add":
        return await request("POST", "/api/on-call", json=body)
    if action == "on_call_update":
        if not item_id:
            raise FenrirError("item_id (on-call entry id) is required")
        return await request("PATCH", f"/api/on-call/{item_id}", json=body)
    if not user_id:
        raise FenrirError("user_id is required for roster_update")
    return await request("PATCH", f"/api/roster/{user_id}", json=body)
