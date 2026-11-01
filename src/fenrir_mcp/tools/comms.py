"""Comments, case notes (+ legacy scratchpads, read-only), OOB comms log, war room (REST slice), notifications.

The OOB passphrase endpoints (read + regenerate) are deliberately NOT curated —
pulling that secret into context must be an explicit fenrir_api act (owner
ruling 2026-08-25)."""

from __future__ import annotations

from typing import Literal

from ..client import FenrirError, request
from . import params, project, tool


@tool("readonly")
async def fenrir_comms_list(
    incident_id: str | None = None,
    view: Literal[
        "comments", "case_notes", "case_note", "case_note_revisions", "scratchpads", "oob_log", "warroom",
        "warroom_online", "notifications"
    ] = "comments",
    note_id: str | None = None,
    filters: dict | None = None,
    limit: int | None = None,
    cursor: str | None = None,
    fields: list | None = None,
) -> dict | list:
    """Comms reads: incident comments, case notes, out-of-band comms log, war-room
    message history + online count, and my notifications (view=notifications needs no
    incident_id). view=case_notes: the shared case notes, every revision, oldest first;
    filters (AND) = {current?, author_id?, evidence_id?, entity_id?, ioc_id?, timeline_event_id?};
    current=true lists only each note's current revision, in the order the notes were first
    written (use it to read the notes as they stand). Each item has root_id (the note),
    revision, root_author_id (the note's author), its signature (signed_name, signed_as),
    content_sha256, corrects_id and corrected_by_id (the next revision, if any).
    view=case_note: one entry (note_id). view=case_note_revisions: every revision of the note
    that note_id belongs to, revision 1 first, each signed by whoever saved it. view=scratchpads: legacy per-analyst scratchpads, read-only (your
    private one only to you) -- post one with fenrir_comms_write(case_note_add,
    data={source_scratchpad_id}). view=warroom: the first page is the newest `limit`
    messages (items oldest-first within the page); pass next_cursor as cursor for the
    next OLDER page."""
    if view == "notifications":
        return await request("GET", "/api/notifications", params=params(limit=limit, cursor=cursor))
    if not incident_id:
        raise FenrirError(f"incident_id is required for view={view}")
    base = f"/api/incidents/{incident_id}"
    if view == "case_note":
        if not note_id:
            raise FenrirError("note_id is required for view=case_note")
        return project(await request("GET", f"{base}/case-notes/{note_id}"), fields)
    if view == "case_note_revisions":
        if not note_id:
            raise FenrirError("note_id is required for view=case_note_revisions")
        return project(await request("GET", f"{base}/case-notes/{note_id}/revisions",
                                     params=params(limit=limit, cursor=cursor)), fields)
    if view == "case_notes":
        q = {k: v for k, v in (filters or {}).items()
             if k in ("current", "author_id", "evidence_id", "entity_id", "ioc_id", "timeline_event_id") and v}
        return project(await request("GET", f"{base}/case-notes", params=params(limit=limit, cursor=cursor, **q)),
                       fields)
    paths = {
        "comments": f"{base}/comments",
        "scratchpads": f"{base}/notes",
        "oob_log": f"{base}/oob/log",
        "warroom": f"{base}/warroom/messages",
        "warroom_online": f"{base}/warroom/online",
    }
    return project(await request("GET", paths[view], params=params(limit=limit, cursor=cursor)), fields)


@tool("standard")
async def fenrir_comms_write(
    action: Literal[
        "comment_add", "comment_update", "case_note_add", "case_note_edit", "oob_log_add", "dark_operation",
        "warroom_post", "notification_read", "notification_read_all", "stakeholder_add", "promote",
    ],
    incident_id: str | None = None,
    item_id: str | None = None,
    data: dict | None = None,
) -> dict:
    """Comms writes: add/edit comments, add a case note, append an OOB comms log
    entry, toggle dark-operation mode (data: {enabled: bool}; every call records an explicit,
    audited decision — enabled=false on an incident already off records "stay off"), post a war-room
    message (Claude appears via its posts, attributed to the operator), mark one
    (item_id) or all notifications read.
    stakeholder_add: add a stakeholder to the incident. data={"contact_id": <Contacts
    directory id from fenrir_people_list(view="contacts")>} copies that entry (any other
    non-null field you send overrides the copy; the incident keeps its own copy), or type it in
    full: {name, type, organization?, title?, contact_methods?, notes?, available_hours?}.
    Closed incident: 409. Unknown contact_id: 422 contact_not_found.
    case_note_add: add a shared case note, signed as the operator (name + incident roles, in its
    hash). data={body, evidence_ids?, entity_ids?, ioc_ids?, timeline_event_ids? (ids of THIS
    incident, else 422 invalid_link)}, or {source_scratchpad_id} instead of body to post your
    legacy scratchpad. Closed incident: 409 incident_closed.
    case_note_edit: edit a note -- saves its next revision (nothing stored is changed; every
    revision stays). item_id = the note's CURRENT revision id; data={body, links...} is the full
    new text and link set (send the links again to keep them). Only the note's author or an admin
    (403 not_author); 409 already_corrected with corrected_by_id when item_id is no longer
    current (re-read and edit that one).
    promote: make a war-room message or a comment of this incident a timeline event or a
    decision. data={source_kind: warroom|comment, source_id, target: timeline_event|decision,
    text? (default: the message), event_time? (UTC; default: the message time), outcome?,
    rationale? (decision)}. The record keeps promoted_from_kind/_id; audited. 404
    message_not_found, 409 already_promoted / incident_closed. Returns {target, id, ...}."""
    body = data or {}
    if action == "notification_read":
        if not item_id:
            raise FenrirError("item_id (notification id) is required")
        return await request("PATCH", f"/api/notifications/{item_id}/read")
    if action == "notification_read_all":
        return await request("POST", "/api/notifications/read-all")
    if not incident_id:
        raise FenrirError(f"incident_id is required for {action}")
    base = f"/api/incidents/{incident_id}"
    if action == "comment_add":
        return await request("POST", f"{base}/comments", json=body)
    if action == "comment_update":
        if not item_id:
            raise FenrirError("item_id (comment id) is required")
        return await request("PATCH", f"{base}/comments/{item_id}", json=body)
    if action == "case_note_add":
        return await request("POST", f"{base}/case-notes", json=body)
    if action == "case_note_edit":
        if not item_id:
            raise FenrirError("item_id (the note's current revision id) is required")
        return await request("POST", f"{base}/case-notes", json={**body, "corrects_id": item_id})
    if action == "oob_log_add":
        return await request("POST", f"{base}/oob/log", json=body)
    if action == "dark_operation":
        return await request("PATCH", f"{base}/oob/dark-operation", json=body)
    if action == "stakeholder_add":
        return await request("POST", f"{base}/stakeholders", json=body)
    if action == "promote":
        return await request("POST", f"{base}/promote", json=body)
    return await request("POST", f"{base}/warroom/messages", json=body)
