"""Evidence & chain of custody — METADATA AND CUSTODY OPERATIONS ONLY.

Raw evidence bytes never reach this machine (locked decision 2026-08-25,
docs/TOOLS.md invariant; the denylist enforces it independently of this module).
Bytes flow toward FENRIR only: digital registration uploads a local file.
Disposal is full-mode with a mandatory confirm parameter."""

from __future__ import annotations

import json
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


def _form(data: dict | None) -> dict:
    """Multipart form fields: lists/objects as JSON text (FENRIR parses device_types,
    decision_factors, device_details), booleans as true/false, None dropped."""
    out = {}
    for k, v in (data or {}).items():
        if v is None:
            continue
        if isinstance(v, bool):
            out[k] = "true" if v else "false"
        elif isinstance(v, (dict, list)):
            out[k] = json.dumps(v)
        else:
            out[k] = str(v)
    return out


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
    (photo_upload: evidence_id + file_path inside FENRIR_MCP_UPLOAD_DIRS).
    digital: file_path (inside FENRIR_MCP_UPLOAD_DIRS) is uploaded multipart; data
    needs name + identifier, optionally acquired_at (UTC ISO, when the image was
    taken), acquisition_hash_target / _source (MD5, SHA-1 or SHA-256 hex from the
    imaging tool) and target_hash_scope: uploaded_file (default — FENRIR compares
    the target hash with the file and refuses a mismatch: 422 hash_mismatch,
    nothing stored) or container_media (an E01/AFF4 media hash; advisory)."""
    base = f"/api/incidents/{incident_id}/evidence"
    if action == "digital":
        if not file_path:
            raise FenrirError("file_path is required for digital (the file is uploaded multipart)")
        return await request(
            "POST", f"{base}/digital", files={"file": config.read_upload(file_path)},
            data=_form(data), expensive=True,
        )
    if action == "physical":
        return await request("POST", f"{base}/physical", json=data or {})
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
        "seal", "transfer", "transfer_accept", "transfer_decline", "examine", "verify",
        "examination_session", "working_copy_create", "custody_log_verify", "export_create",
    ],
    incident_id: str,
    evidence_id: str | None = None,
    data: dict | None = None,
) -> dict:
    """Chain-of-custody operations: seal, transfer, examine, verify hashes,
    open an examination session, create a working copy (server-side), verify the
    whole custody chain, or create an export bundle (stays server-side; retrieval
    is GUI-only). Every action lands in the hash-chained audit log.
    transfer (custodian or admin only): data {to_user_id | to_external{name,
    organisation, contact}, reason, transport_method, seal_id, courier_ref}. To a
    user it is only a REQUEST — custody does not change until THAT user runs
    transfer_accept; the item shows pending_custodian_id. To an external party it is
    one step. Taking an item back from external custody: to_user_id = yourself plus
    condition_on_receipt and seals_intact. transfer_accept (the recipient only,
    never an admin for them): data {condition_on_receipt, seals_intact}.
    transfer_decline (recipient, requester or admin): data {reason}. While a
    transfer is pending, transfer/seal/dispose return 409 transfer_pending."""
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
        "transfer_accept": "transfer/accept", "transfer_decline": "transfer/decline",
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
