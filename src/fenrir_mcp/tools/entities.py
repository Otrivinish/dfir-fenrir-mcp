"""Entities, relations, asset log, affected systems, file store — RO/STD."""

from __future__ import annotations

from typing import Literal

from .. import config
from ..client import FenrirError, request
from . import params, project, tool


@tool("readonly")
async def fenrir_entity_list(
    incident_id: str,
    view: Literal[
        "entities", "relations", "asset_log", "affected_systems", "entity_files", "incident_files",
        "file_exhibit_prefill",
    ] = "entities",
    entity_id: str | None = None,
    file_id: str | None = None,
    compromised: bool | None = None,
    match: str | None = None,
    linked_type: Literal["exhibit", "timeline_event", "ioc"] | None = None,
    linked_id: str | None = None,
    limit: int | None = None,
    cursor: str | None = None,
    fields: list | None = None,
) -> dict | list:
    """Entity-side reads: entities, entity relations, per-entity asset log
    (entity_id required for asset_log/entity_files), affected systems, and the
    incident file store (metadata only — file bytes never leave FENRIR).
    Affected systems ARE the compromised entities: prefer view=entities with
    compromised=True (paginated); view=affected_systems is the deprecated old
    shape (id = entity id, plus entity_id/entity_type, not paginated).
    match (view=entities) returns only the entity a typed name resolves to (0 or 1 item), by the
    rule timeline suggestions and imports use: case-insensitive value, ties to the exact-case
    value then the host.
    Files (incident_files / entity_files) carry their capture record (captured_at, captured_by_id /
    _name, capture_tool / _version, capture_method, capture_source, capture_url, capture_context,
    capture_sha256) and `links` [{id, target_type, target_id, target_label, note, ...}]: what each
    corroborates. linked_type + linked_id (view=incident_files, both or neither) list only the files
    linked to that exhibit (evidence id), timeline event or IOC.
    file_exhibit_prefill (file_id required): what fenrir_entity_write(register_exhibit) would
    pre-fill on a NEW draft exhibit from the file's capture record, without registering: acquired_at,
    acquisition tool/version, source_system, source_path (+ style), screen_state; null = no capture
    value; `left_empty` = source fields the source check would refuse. If the incident already holds
    an exhibit with the same SHA-256, registering links that one and pre-fills nothing."""
    base = f"/api/incidents/{incident_id}"
    if view == "file_exhibit_prefill":
        if not file_id:
            raise FenrirError("file_id is required for view=file_exhibit_prefill")
        return await request("GET", f"{base}/files/{file_id}/exhibit-prefill")
    if compromised is not None and view != "entities":
        raise FenrirError("compromised filters view=entities only")
    if match is not None and view != "entities":
        raise FenrirError("match filters view=entities only")
    if (linked_type is not None or linked_id is not None) and view != "incident_files":
        raise FenrirError("linked_type / linked_id filter view=incident_files only")
    if view in ("asset_log", "entity_files"):
        if not entity_id:
            raise FenrirError(f"entity_id is required for view={view}")
        sub = "asset-log" if view == "asset_log" else "files"
        return await request("GET", f"{base}/entities/{entity_id}/{sub}")
    paths = {
        "entities": f"{base}/entities",
        "relations": f"{base}/entity-relations",
        "affected_systems": f"{base}/affected-systems",
        "incident_files": f"{base}/files",
    }
    return project(
        await request("GET", paths[view], params=params(limit=limit, cursor=cursor, compromised=compromised,
                                                        match=match, linked_type=linked_type,
                                                        linked_id=linked_id)), fields
    )


@tool("standard")
async def fenrir_entity_write(
    action: Literal[
        "create_entity", "update_entity", "create_relation", "add_asset_log",
        "create_affected_system", "update_affected_system", "file_update", "register_exhibit",
        "link_file", "unlink_file",
    ],
    incident_id: str,
    entity_id: str | None = None,
    system_id: str | None = None,
    file_id: str | None = None,
    link_id: str | None = None,
    data: dict | None = None,
) -> dict:
    """Create/update entities, add relations, append asset-log events (entity_id
    required), create/update affected systems (system_id for update).
    create_entity data may set compromised=true: that IS adding an affected
    system (preferred). Deprecated create_affected_system upserts a compromised
    entity (type from system_type); update_affected_system edits that entity
    (system_id = entity id or an old affected-system id). Un-flag with
    update_entity data={"compromised": false}.
    file_update (file_id required; ids from fenrir_entity_list view=incident_files)
    edits a Supporting-documents file: data={"include_in_report": true,
    "report_caption": "..."} makes it a numbered figure in generated reports (PNG,
    JPEG, GIF or WebP by content only, else 422 unsupported_report_image; caption
    max 512, null/"" clears); also original_name / entity_id (null unlinks). A rename
    (original_name) needs data.reason (10-2000 chars; 422 reason_required), audited
    with the old and new name.
    file_update also edits the capture record (only the keys sent change; null/"" clears;
    audited from/to; no reason needed): captured_at (ISO 8601 with offset or Z, not in the
    future; else 422 invalid_captured_at), captured_by_id (a user who can see the incident)
    or captured_by_name (not both: 422 captured_by_conflict; setting one clears the other),
    capture_tool, capture_tool_version, capture_method (screen | window | region | full_page
    | scrolling | photo_of_screen | other), capture_source, capture_url, capture_context.
    capture_sha256 can't be changed (422 capture_sha256_read_only).
    register_exhibit (file_id required) registers the file as an exhibit with chain of
    custody: re-encrypted into the evidence store and its server SHA-256 re-checked
    (409 file_hash_mismatch: nothing created); links the incident's active exhibit with
    the same SHA-256 instead (exhibit_link sha256_match), else creates an unsealed DRAFT
    (registered; complete it with fenrir_evidence_register action=acquisition_record,
    then fenrir_evidence_custody action=seal). Idempotent
    (already_registered). The file stays a supporting document. A new draft is pre-filled
    from the capture record (response `prefill`): acquired_at ← captured_at, acquisition
    tool/version ← capture tool/version, source_system ← capture_source, source_path ←
    capture_url (style cloud_uri for https/s3/gs/az/abfss, else other), screen_state ←
    capture_context, acquisition_hash_target ← capture_sha256 with upload_hash_check
    match; a source value the source check refuses is left empty
    (prefill.left_empty), never a refused registration. Preview it first with
    fenrir_entity_list(view="file_exhibit_prefill").
    link_file (file_id required) records that the file corroborates an exhibit, timeline
    event or IOC of the same incident: data={"target_type": "exhibit"|"timeline_event"|"ioc",
    "target_id": "<evidence / event / IOC id>", "note": "..."} (404 evidence_not_found /
    timeline_event_not_found / ioc_not_found for another incident's; 409 already_linked).
    Not the same as register_exhibit; a linked file can't be deleted until unlinked.
    unlink_file (file_id + link_id from the file's `links`; 404 link_not_found) removes one.
    Closed incident: 409. Screenshots can hold personal or TLP:RED data — they
    travel with the report."""
    base = f"/api/incidents/{incident_id}"
    body = data or {}
    if action == "file_update":
        if not file_id:
            raise FenrirError("file_id is required for file_update")
        return await request("PATCH", f"{base}/files/{file_id}", json=body)
    if action == "register_exhibit":
        if not file_id:
            raise FenrirError("file_id is required for register_exhibit")
        return await request("POST", f"{base}/files/{file_id}/register-exhibit")
    if action in ("link_file", "unlink_file"):
        if not file_id:
            raise FenrirError(f"file_id is required for {action}")
        if action == "link_file":
            return await request("POST", f"{base}/files/{file_id}/links", json=body)
        if not link_id:
            raise FenrirError("link_id is required for unlink_file (ids in the file's links)")
        return await request("DELETE", f"{base}/files/{file_id}/links/{link_id}")
    if action == "create_entity":
        return await request("POST", f"{base}/entities", json=body)
    if action == "update_entity":
        if not entity_id:
            raise FenrirError("entity_id is required for update_entity")
        return await request("PATCH", f"{base}/entities/{entity_id}", json=body)
    if action == "create_relation":
        return await request("POST", f"{base}/entity-relations", json=body)
    if action == "add_asset_log":
        if not entity_id:
            raise FenrirError("entity_id is required for add_asset_log")
        return await request("POST", f"{base}/entities/{entity_id}/asset-log", json=body)
    if action == "create_affected_system":
        return await request("POST", f"{base}/affected-systems", json=body)
    if not system_id:
        raise FenrirError("system_id is required for update_affected_system")
    return await request("PATCH", f"{base}/affected-systems/{system_id}", json=body)


@tool("standard")
async def fenrir_file_upload(
    incident_id: str,
    file_path: str,
    entity_id: str | None = None,
    fields: dict | None = None,
) -> dict:
    """Upload a local file into the incident file store (or an entity's files when
    entity_id is set). file_path must be inside FENRIR_MCP_UPLOAD_DIRS. FENRIR records the
    file's SHA-256, SHA-1 and MD5 at upload (in the response) and stores it AES-256-GCM
    encrypted. A supporting document, not an exhibit (no chain of custody).
    fields = optional form fields, exactly these (anything else is ignored by FENRIR):
    the capture record of a screenshot or similar — captured_at (ISO 8601 with offset or Z,
    not in the future; else 422 invalid_captured_at), captured_by_id (a user who can see the
    incident) or captured_by_name (not both: 422 captured_by_conflict; neither = not
    recorded, never assumed to be you), capture_tool, capture_tool_version, capture_method
    (screen | window | region | full_page | scrolling | photo_of_screen | other),
    capture_source (host / device / display), capture_url, capture_context (window title,
    application, what is visible), capture_sha256 (the hash taken at capture: compared with
    the bytes before anything is stored; a mismatch is 422 capture_hash_mismatch, audited,
    nothing stored). Without entity_id, fields.entity_id links the file to an entity."""
    target = (
        f"/api/incidents/{incident_id}/entities/{entity_id}/files"
        if entity_id
        else f"/api/incidents/{incident_id}/files"
    )
    return await request(
        "POST", target, files={"file": config.read_upload(file_path)}, data=fields or {}, expensive=True
    )
