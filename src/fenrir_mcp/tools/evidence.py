"""Evidence & chain of custody — METADATA AND CUSTODY OPERATIONS ONLY.

Raw evidence bytes never reach this machine (locked decision 2026-08-25,
docs/TOOLS.md invariant; the denylist enforces it independently of this module).
Disposal is full-mode with a mandatory confirm parameter."""

from __future__ import annotations

from typing import Literal

from .. import config
from ..client import FenrirError, request
from . import params, tool


@tool("readonly")
async def fenrir_evidence_list(
    incident_id: str,
    view: Literal[
        "list", "item", "custody", "custody_log", "provenance", "working_copies",
        "exports", "export_item",
    ] = "list",
    evidence_id: str | None = None,
    export_id: str | None = None,
    limit: int | None = None,
    cursor: str | None = None,
) -> dict | list:
    """Evidence metadata reads: inventory, one item, its custody trail, the
    incident custody log, provenance, working-copy list, export-bundle list.
    Metadata only — bundle/file bytes are retrieved via the GUI, never here."""
    base = f"/api/incidents/{incident_id}/evidence"
    needs_id = {"item": "", "custody": "/custody", "provenance": "/provenance", "working_copies": "/working-copies"}
    if view in needs_id:
        if not evidence_id:
            raise FenrirError(f"evidence_id is required for view={view}")
        return await request("GET", f"{base}/{evidence_id}{needs_id[view]}")
    if view == "export_item":
        if not export_id:
            raise FenrirError("export_id is required for view=export_item")
        return await request("GET", f"{base}/exports/{export_id}")
    paths = {"list": base, "custody_log": f"{base}/custody-log", "exports": f"{base}/exports"}
    return await request("GET", paths[view], params=params(limit=limit, cursor=cursor))


@tool("standard")
async def fenrir_evidence_register(
    action: Literal["digital", "physical", "update", "photo_upload"],
    incident_id: str,
    evidence_id: str | None = None,
    data: dict | None = None,
    file_path: str | None = None,
) -> dict:
    """Register digital/physical evidence (data per FENRIR's ISO 27037 collection
    fields), update metadata, or upload a CoC photo of physical evidence
    (photo_upload: evidence_id + file_path inside FENRIR_MCP_UPLOAD_DIRS)."""
    base = f"/api/incidents/{incident_id}/evidence"
    if action in ("digital", "physical"):
        return await request("POST", f"{base}/{action}", json=data or {})
    if not evidence_id:
        raise FenrirError("evidence_id is required for update/photo_upload")
    if action == "update":
        return await request("PATCH", f"{base}/{evidence_id}", json=data or {})
    if not file_path:
        raise FenrirError("file_path is required for photo_upload")
    return await request(
        "POST", f"{base}/{evidence_id}/photos", files={"file": config.read_upload(file_path)}, data=data or {}
    )


@tool("standard")
async def fenrir_evidence_custody(
    action: Literal[
        "seal", "transfer", "examine", "verify", "examination_session",
        "working_copy_create", "custody_log_verify", "export_create",
    ],
    incident_id: str,
    evidence_id: str | None = None,
    data: dict | None = None,
) -> dict:
    """Chain-of-custody operations: seal, transfer, examine, verify hashes,
    open an examination session, create a working copy (server-side), verify the
    whole custody chain, or create an export bundle (stays server-side; retrieval
    is GUI-only). Every action lands in the hash-chained audit log."""
    base = f"/api/incidents/{incident_id}/evidence"
    body = data or {}
    if action == "custody_log_verify":
        return await request("POST", f"{base}/custody-log/verify", json=body)
    if action == "export_create":
        return await request("POST", f"{base}/exports", json=body)
    if not evidence_id:
        raise FenrirError(f"evidence_id is required for {action}")
    seg = {
        "seal": "seal", "transfer": "transfer", "examine": "examine", "verify": "verify",
        "examination_session": "examination-session", "working_copy_create": "working-copy",
    }[action]
    return await request("POST", f"{base}/{evidence_id}/{seg}", json=body)


@tool("full")
async def fenrir_evidence_dispose(
    incident_id: str, evidence_id: str, confirm: bool = False, data: dict | None = None
) -> dict:
    """Dispose of evidence — a chain-of-custody-TERMINAL act. Requires confirm=true,
    set only after the operator has explicitly approved disposal of THIS evidence
    item. data carries the disposal method/reason per FENRIR's disposal schema."""
    if not confirm:
        raise FenrirError(
            "disposal requires confirm=true — ask the operator to explicitly confirm "
            "disposing this specific evidence item first"
        )
    return await request("POST", f"/api/incidents/{incident_id}/evidence/{evidence_id}/dispose", json=data or {})
