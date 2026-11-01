"""Playbook tasks + response actions/decisions — RO reads, STD writes."""

from __future__ import annotations

from typing import Literal

from ..client import FenrirError, request
from . import params, tool


@tool("readonly")
async def fenrir_task_list(
    incident_id: str | None = None,
    view: Literal["tasks", "templates", "template_item"] = "tasks",
    template_id: str | None = None,
    incident_type: str | None = None,
    include_archived: bool = False,
) -> dict | list:
    """Playbook reads: incident tasks (incident_id required), the template catalog,
    or one template (template_id). Built-in templates follow the CISA IR playbooks.
    Tasks come in NIST 800-61 R3 phase order, each with due_at and overdue;
    include_archived=True adds the read-only Done/Skipped history of replaced plans
    (archived_at, archive_reason). view=templates with incident_type (e.g. ransomware)
    lists only the templates suggested for that type; each template carries
    incident_types and last_reviewed_at/last_reviewed_by (null = never reviewed).
    Each task has linked_actions [{id, title, category, status}] (Respond actions whose
    task_id is this task) and handoff_id (made from a handoff next step)."""
    if incident_type and view != "templates":
        raise FenrirError("incident_type applies to view=templates only")
    if view == "tasks":
        if not incident_id:
            raise FenrirError("incident_id is required for view=tasks")
        return await request("GET", f"/api/incidents/{incident_id}/playbook/tasks",
                             params={"include_archived": "true"} if include_archived else None)
    if view == "template_item":
        if not template_id:
            raise FenrirError("template_id is required for view=template_item")
        return await request("GET", f"/api/playbook-templates/{template_id}")
    return await request("GET", "/api/playbook-templates",
                         params={"incident_type": incident_type} if incident_type else None)


@tool("standard")
async def fenrir_task_write(
    action: Literal["add", "update", "instantiate_template"],
    incident_id: str,
    task_id: str | None = None,
    data: dict | None = None,
) -> dict | list:
    """Add a custom playbook task, update one (task_id + data — e.g. status/assignee/due_at),
    or instantiate a playbook template onto the incident (data: template_id, mode, reason).
    instantiate_template: mode "append" (default, any analyst) adds the template's tasks,
    skipping ones of the same template already in the plan; mode "replace" is for the
    incident lead (IC/Deputy) or an admin only (403 not_incident_lead) and needs data.reason
    (422 reason_required) — Done/Skipped tasks become read-only history, Open/In-progress
    ones are removed. Update: status "skipped" needs data.skip_reason (422
    skip_reason_required); data.due_at is UTC ISO 8601 (null clears); archived tasks
    can't change (409 task_archived).
    data.assignee_id must be an active user who can see the incident (404
    user_not_found, 422 assignee_no_access; fenrir_people_list view=assignable_users
    with incident_id lists who qualifies). On update, "assignee_id": null unassigns;
    leave it out to keep the current assignee (who stays shown even if since deactivated)."""
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
    incident_id: str,
    view: Literal["actions", "decisions", "recovery"] = "actions",
    entity_id: str | None = None,
    ioc_id: str | None = None,
    state: Literal["not_started", "restoring", "restored", "validated", "not_required"] | None = None,
    limit: int | None = None,
    cursor: str | None = None,
) -> dict | list:
    """Response reads: containment/eradication/recovery actions, the decision log, or the
    recovery tracker (NIST SP 800-61 R3 Containment, Eradication & Recovery phase records).
    view=actions only: entity_id / ioc_id return just the actions linked to that
    entity / IOC. view=recovery: every in-scope system (compromised host / service /
    network_range entity) with its record -- state, restore point, restored/validated
    at+by, same_person_validation (warning), validation method/checklist, monitoring
    window, allowed_transitions -- plus `summary` (per-state counts, complete,
    can_declare_recovered); `state` filters; entity_id returns that one system.
    Paged: limit (actions/decisions 1-200, default 100; recovery 1-500, default 200);
    pass next_cursor as cursor for the next page (null = no more).
    Links: each action has decision_id (approving decision) and task_id (playbook task);
    each decision has linked_actions [{id, title, category, status}] and, when promoted
    from a message, promoted_from_kind (warroom | comment) + promoted_from_id."""
    if view == "decisions" and (entity_id or ioc_id):
        raise FenrirError("entity_id / ioc_id filter view=actions only")
    if state and view != "recovery":
        raise FenrirError("state filters view=recovery only")
    if view == "recovery":
        if ioc_id:
            raise FenrirError("ioc_id does not apply to view=recovery")
        if entity_id:
            return await request("GET", f"/api/incidents/{incident_id}/recovery/{entity_id}")
        return await request("GET", f"/api/incidents/{incident_id}/recovery",
                             params=params(state=state, limit=limit, cursor=cursor))
    return await request("GET", f"/api/incidents/{incident_id}/respond/{view}",
                         params=params(entity_id=entity_id, ioc_id=ioc_id, limit=limit, cursor=cursor))


@tool("standard")
async def fenrir_respond_write(
    action: Literal["action_add", "action_update", "action_revert", "decision_add", "decision_update",
                    "recovery_update"],
    incident_id: str,
    item_id: str | None = None,
    data: dict | None = None,
) -> dict:
    """Log/update response actions (action_revert marks an action reverted) and
    record/update decisions. item_id is the action/decision id for update/revert.
    Action data may link the target: entity_id / ioc_id (same incident; an empty
    details.target is filled from its value; null on update unlinks) and template_id
    (e.g. isolate_host, block_ip, disable_account). A linked containment action sets
    that entity's / IOC's containment state: open/in_progress -> pending, done ->
    isolated / disabled / blocked, reverted -> cleared. Such a template links only its
    kind of target (isolate -> host entity; disable/reset/revoke -> user or email entity;
    block_ip -> ip IOC or ip/network_range entity; block_domain/url/hash -> that IOC type;
    block_sender -> email/domain), else 422 target_type_mismatch.
    Links (records only; finishing a task never finishes an action): action data.decision_id
    (the decision that approved it) and data.task_id (the playbook task it carries out), same
    incident (404 decision_not_found / task_not_found, 422 *_other_incident / task_archived);
    null on update unlinks. decision data.action_ids = the actions it approves (sets their
    decision_id; on update the list replaces the links, [] unlinks all; omit to keep).
    People: action data.assignee_id and decision data.decided_by_id must be an active user
    who can see the incident (404 user_not_found, 422 assignee_no_access; see
    fenrir_people_list view=assignable_users with incident_id). On update, null
    unassigns / clears the decider; leave the field out to keep it.
    A deferred action takes data.defer_reason (why; blank clears): Gate 1 warns, not
    blocks, on a deferred containment/eradication/recovery action without one.
    recovery_update (item_id = the system's entity_id): PATCH its recovery record. data:
    state moves one step -- not_started -> restoring | not_required (+ not_required_reason);
    restoring -> restored (needs restore_point_ref; restored_at defaults to now, you are
    restored_by); restored -> validated (needs validation_method; you are validated_by --
    validating your own restore is allowed but flagged same_person_validation). Going back
    (restoring -> not_started, restored/validated -> restoring, not_required -> not_started)
    needs data.reason. Other fields: restore_point_at, validation_checklist [{item, done}],
    monitoring_start / monitoring_end (end >= start), notes; null clears. 409
    invalid_transition (with allowed) / not_in_scope / incident_closed; 422 names the rule.
    Never sets recovered_at: when the summary says can_declare_recovered, declare it with
    fenrir_incident_write (recovered_at)."""
    if action == "recovery_update":
        if not item_id:
            raise FenrirError("item_id (the system's entity_id) is required for recovery_update")
        return await request("PATCH", f"/api/incidents/{incident_id}/recovery/{item_id}", json=data or {})
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
