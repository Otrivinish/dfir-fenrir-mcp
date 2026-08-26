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
        "entities", "relations", "asset_log", "affected_systems", "entity_files", "incident_files"
    ] = "entities",
    entity_id: str | None = None,
    limit: int | None = None,
    cursor: str | None = None,
    fields: list | None = None,
) -> dict | list:
    """Entity-side reads: entities, entity relations, per-entity asset log
    (entity_id required for asset_log/entity_files), affected systems, and the
    incident file store (metadata only — file bytes never leave FENRIR)."""
    base = f"/api/incidents/{incident_id}"
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
    return project(await request("GET", paths[view], params=params(limit=limit, cursor=cursor)), fields)


@tool("standard")
async def fenrir_entity_write(
    action: Literal[
        "create_entity", "update_entity", "create_relation", "add_asset_log",
        "create_affected_system", "update_affected_system",
    ],
    incident_id: str,
    entity_id: str | None = None,
    system_id: str | None = None,
    data: dict | None = None,
) -> dict:
    """Create/update entities, add relations, append asset-log events (entity_id
    required), create/update affected systems (system_id for update)."""
    base = f"/api/incidents/{incident_id}"
    body = data or {}
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
    entity_id is set). file_path must be inside FENRIR_MCP_UPLOAD_DIRS. FENRIR
    hashes and encrypts server-side. Optional form fields (e.g. description) via fields."""
    target = (
        f"/api/incidents/{incident_id}/entities/{entity_id}/files"
        if entity_id
        else f"/api/incidents/{incident_id}/files"
    )
    return await request(
        "POST", target, files={"file": config.read_upload(file_path)}, data=fields or {}, expensive=True
    )
