"""Comments, notes, OOB comms log, war room (REST slice), notifications.

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
        "comments", "notes", "note_versions", "oob_log", "warroom", "warroom_online", "notifications"
    ] = "comments",
    note_id: str | None = None,
    limit: int | None = None,
    cursor: str | None = None,
    fields: list | None = None,
) -> dict | list:
    """Comms reads: incident comments, notes (+versions with note_id), out-of-band
    comms log, war-room message history + online count, and my notifications
    (view=notifications needs no incident_id)."""
    if view == "notifications":
        return await request("GET", "/api/notifications", params=params(limit=limit, cursor=cursor))
    if not incident_id:
        raise FenrirError(f"incident_id is required for view={view}")
    base = f"/api/incidents/{incident_id}"
    if view == "note_versions":
        if not note_id:
            raise FenrirError("note_id is required for view=note_versions")
        return await request("GET", f"{base}/notes/{note_id}/versions")
    paths = {
        "comments": f"{base}/comments",
        "notes": f"{base}/notes",
        "oob_log": f"{base}/oob/log",
        "warroom": f"{base}/warroom/messages",
        "warroom_online": f"{base}/warroom/online",
    }
    return project(await request("GET", paths[view], params=params(limit=limit, cursor=cursor)), fields)


@tool("standard")
async def fenrir_comms_write(
    action: Literal[
        "comment_add", "comment_update", "note_save", "oob_log_add", "dark_operation",
        "warroom_post", "notification_read", "notification_read_all",
    ],
    incident_id: str | None = None,
    item_id: str | None = None,
    data: dict | None = None,
) -> dict:
    """Comms writes: add/edit comments, save your note, append an OOB comms log
    entry, toggle dark-operation mode (data: {enabled: bool}), post a war-room
    message (Claude appears via its posts, attributed to the operator), mark one
    (item_id) or all notifications read."""
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
    if action == "note_save":
        return await request("POST", f"{base}/notes", json=body)
    if action == "oob_log_add":
        return await request("POST", f"{base}/oob/log", json=body)
    if action == "dark_operation":
        return await request("PATCH", f"{base}/oob/dark-operation", json=body)
    return await request("POST", f"{base}/warroom/messages", json=body)
