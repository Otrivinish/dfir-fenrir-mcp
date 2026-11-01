"""Evidence & chain of custody — METADATA AND CUSTODY OPERATIONS ONLY.

Raw evidence bytes never reach this machine (locked decision 2026-08-25,
docs/TOOLS.md invariant; the denylist enforces it independently of this module).
Bytes flow toward FENRIR only: digital registration streams a local file (chunked upload session).
Disposal is full-mode with a mandatory confirm parameter."""

from __future__ import annotations

from typing import Literal

from .. import config
from ..client import FenrirError, request, upload_file
from . import params, tool


@tool("readonly")
async def fenrir_evidence_list(
    incident_id: str,
    view: Literal[
        "list", "item", "custody", "custody_log", "provenance", "working_copies", "seal_record", "manifest",
        "exports", "export_item", "disclosures", "disclosure_item",
    ] = "list",
    evidence_id: str | None = None,
    export_id: str | None = None,
    limit: int | None = None,
    cursor: str | None = None,
    disclosure_id: str | None = None,
    purpose: Literal["internal", "law_enforcement", "regulator"] | None = None,
    q: str | None = None,
) -> dict | list:
    """Evidence metadata reads: inventory, one item, its custody trail, the
    incident custody log, provenance, working-copy list, export-bundle list.
    Metadata only — bundle/file bytes are retrieved via the GUI, never here.
    working_copies (G5): each copy's kind (download | lab_copy | export | legacy_record), identifier
    (<exhibit>-WC-n), status, its own sha256/sha1/md5, verified_against_master and
    usable_for_examination (what examination_session may name). An item shows legal_hold,
    legal_hold_since / _by_id / _reason. custody_log events name their exhibit (exhibit_identifier,
    exhibit_name). An item's photos carry sha256, size and their record (taken_at, taken_by_id /
    taken_by_name, camera, context, original_filename); a taken_at stored before it was checked is in
    taken_at_unparsed.
    seal_record (S3; evidence_id): what the seal binds — seal_record_sha256 (SHA-256 of the canonical
    record v1: hashes, acquisition and source records, photo hashes), sealed_record (its exact text, from
    the hash-chained evidence_seal row), seal_tst_subject (what the RFC 3161 token covers: record_v1 |
    file_sha256 for a seal made before record binding | null = no token), recomputed_now_sha256 and
    changed_since_seal (true after an audited amendment after the seal or a photo added — reported, not
    tampering; null for an old seal). 409 evidence_not_sealed before the seal.
    manifest (S6; evidence_id; limit <= 1000, cursor, q = case-insensitive substring of the entry or source path): a
    container exhibit's members as FENRIR read them from the stored ZIP / TAR, in container order — {items: [{seq,
    entry_path (verbatim), entry_name_encoding (utf8 | cp437 | other), entry_path_raw_b64, source_path (from the
    tool's listing), entry_type, size, compressed_size, times {m, a, c, b: {utc, as_recorded, basis}, source: the
    tool listing's times}, md5, sha1, sha256 (FENRIR's, of the member bytes), tool_hash {algorithm, value},
    tool_hash_match, encrypted, notes}], next_cursor}. The item shows container_format, manifest_status (pending |
    built | failed | not_indexed), manifest_sha256, manifest_entries, manifest_builder, manifest_error and
    manifest_listing (each tool listing: merged or why not, tool-hash matches / mismatches). 409 manifest_not_built
    unless built. Metadata only: no member bytes.
    K1 disclosures (incident lead or admin, else 403 not_incident_lead): the disclosure packages (optionally
    by purpose: internal | law_enforcement | regulator), or one (disclosure_id): record, exhibits (item_ids),
    hashes, signature_kind, audit anchor hash, download status, receipt. Never the password. exports /
    export_item are deprecated (same rights)."""
    base = f"/api/incidents/{incident_id}/evidence"
    needs_id = {"item": "", "custody": "/custody", "provenance": "/provenance", "working_copies": "/working-copies",
                "seal_record": "/seal-record", "manifest": "/manifest"}
    if q is not None and view != "manifest":
        raise FenrirError("q filters view=manifest only")
    if view in needs_id:
        if not evidence_id:
            raise FenrirError(f"evidence_id is required for view={view}")
        if view == "manifest":
            return await request("GET", f"{base}/{evidence_id}/manifest",
                                 params=params(limit=limit, cursor=cursor, q=q))
        return await request("GET", f"{base}/{evidence_id}{needs_id[view]}")
    if view == "export_item":
        if not export_id:
            raise FenrirError("export_id is required for view=export_item")
        return await request("GET", f"{base}/exports/{export_id}")
    disclosures = f"/api/incidents/{incident_id}/disclosures"
    if view == "disclosure_item":
        if not disclosure_id:
            raise FenrirError("disclosure_id is required for view=disclosure_item")
        return await request("GET", f"{disclosures}/{disclosure_id}")
    if view == "disclosures":
        return await request("GET", disclosures, params=params(purpose=purpose, limit=limit, cursor=cursor))
    paths = {"list": base, "custody_log": f"{base}/custody-log", "exports": f"{base}/exports"}
    return await request("GET", paths[view], params=params(limit=limit, cursor=cursor))


@tool("standard")
async def fenrir_evidence_register(
    action: Literal["digital", "physical", "update", "acquisition_record", "photo_upload"],
    incident_id: str,
    evidence_id: str | None = None,
    data: dict | None = None,
    file_path: str | None = None,
) -> dict:
    """Register digital/physical evidence (data per FENRIR's ISO 27037 collection
    fields), update metadata, or upload a CoC photo of an exhibit
    (photo_upload: evidence_id + file_path inside FENRIR_MCP_UPLOAD_DIRS; data = the photo record, below).
    digital: file_path (inside FENRIR_MCP_UPLOAD_DIRS) is streamed to FENRIR in 8 MiB chunks
    through an upload session (encrypted as it arrives; nothing stored until the whole file is
    in and its SHA-256 — computed here first — matches; the file is never read whole); data
    (JSON: lists / objects / booleans as such) needs name; identifier is optional (digital and
    physical): leave it out / null / blank and FENRIR assigns the next one from the admin's naming
    convention (default {incident}-{date}-{seq:3}, e.g. INC-2026-00009-20261101-001; the created
    evidence carries it; an assigned one never 409s). Preview it with fenrir_api GET
    /api/incidents/{id}/evidence/next-identifier; the convention is read / set (admin) with fenrir_api
    GET / PATCH /api/settings/evidence-identifier {template}. Optionally acquired_at
    (UTC ISO, when the image was
    taken), acquisition_hash_target / _source (MD5, SHA-1 or SHA-256 hex from the
    imaging tool) and target_hash_scope: uploaded_file (default — FENRIR compares
    the target hash with the file and refuses a mismatch: 422 hash_mismatch,
    nothing stored) or container_media (an E01/AFF4 media hash; advisory).
    witness_user_id (digital and physical) must be an active user who can see the
    incident (404 user_not_found, 422 assignee_no_access, checked before the upload is
    stored); witness_name is free text for a witness without an account. A typed identifier already
    used → 409 identifier_exists (nothing stored). Returns the created evidence.
    system_time_offset (text, §6.6) is kept as written and never interpreted;
    system_time_offset_seconds (digital, physical or update) is the device clock minus
    true UTC in whole seconds (+120 = 2 min ahead; |x| <= 100 years) — imports from the
    exhibit subtract it and keep the recorded time. update with
    {"system_time_offset_seconds": null} clears it; a change is audited and imports
    already made keep their offset (re-import to apply).
    acquisition_record (G3): complete the acquisition record of an UNSEALED item (evidence_id; data
    = only the fields to set: lawful_basis, device_types, acquisition_tool / _version, hashes +
    target_hash_scope, acquired_at, witness_user_id, system_state, …; null clears one) — e.g. a draft
    exhibit an Email / PCAP / Browser history upload registered — then seal it with
    fenrir_evidence_custody(action="seal"). The stored file never changes; a target hash is compared
    with it (422 hash_mismatch, nothing changed). Collector, custodian or admin only (403); sealed
    item → 409 evidence_sealed; transfer pending → 409.
    Source record (S2; digital, acquisition_record, update — physical takes make / model / serial,
    source_system, source_details): make / model / serial (also a digital exhibit's source device);
    source_system (host / FQDN / tenant / mailbox owner, verbatim); source_path (original full path
    exactly as recorded, never trimmed; <= 32768 chars, no NUL: 422 invalid_source_path) +
    source_path_style (windows | unc | posix | macos | android | ios | cloud_uri | mail_store | device |
    other; required with a path, shape checked: 422 source_path_style_required / _mismatch);
    source_details {filename_on_source, volume{label, serial, filesystem, partition}, os, asset_tag,
    times{m, a, c, b: {utc, as_recorded}, basis, tz_basis, read_by, read_at} (a time needs basis +
    read_by), owner{id, name}, stream, link_target, provider{provider, tenant_or_account, site_or_bucket,
    item_id, version_id, etag, export_id, provider_hash{algorithm, value}}, mail{mailbox, folder_path,
    message_id, item_id}, namespace, path_raw_b64, note} (unknown keys 422); source_unknown_reason
    (>= 10 chars, when the source can't be stated). Never send source_path_norm (server-derived, 422).
    file_path is the analyst's copy: it never fills these. On a sealed item, update amends (audited).
    S3: sealing a DIGITAL item needs its source — the device (entity_id, source_system or serial; make /
    model alone are not enough) and the path its handling needs (a full image: style device; live data
    and email_export / vendor_report / network_capture exports: none; anything else: path + style) — or
    source_unknown_reason; else seal is 422 seal_fields_missing with missing source_device / source_path
    / source_path_style.
    container_format (S6; digital and acquisition_record, unsealed): the file is a tool-made logical container (one
    exhibit per container): zip | tar (FENRIR builds a per-file manifest in the background: manifest_status pending →
    built | failed; tar includes .tar.gz / .tgz / .tar.bz2 / .tar.xz) | ad1 | l01 | aff4l | other (not_indexed).
    A KAPE *_CopyLog.csv or Velociraptor uploads.json inside a ZIP is merged (source paths, times, tool hashes). Seal
    is 409 manifest_pending while it is built; a built manifest's SHA-256 is bound by the seal and its format can't
    change (409 manifest_built); a physical item is 422 container_format_not_applicable. Read it with
    fenrir_evidence_list(view="manifest").
    photo_upload (S4): data = optional multipart form fields: caption; taken_at (ISO 8601 with an offset
    or Z, stored as UTC …Z; anything else 422 invalid_taken_at); the photographer: taken_by_id (a user who
    can see the incident) or taken_by_name (free text, <= 128) — neither = you, both = 422
    taken_by_conflict; camera (make / model / serial or phone IMEI, <= 256); context (what it shows,
    <= 2000). FENRIR keeps the file's name (original_filename), SHA-256 and size. Allowed after the seal
    (photos are added, never changed); update {photos: [{id, url, <fields to change>}]} edits them
    before the seal (only the fields sent change)."""
    base = f"/api/incidents/{incident_id}/evidence"
    if action == "digital":
        if not file_path:
            raise FenrirError("file_path is required for digital (the file is streamed to FENRIR)")
        done = await upload_file(incident_id, file_path, "evidence", data or {})
        return done.get("evidence", done)
    if action == "physical":
        return await request("POST", f"{base}/physical", json=data or {})
    if not evidence_id:
        raise FenrirError("evidence_id is required for update/acquisition_record/photo_upload")
    if action == "update":
        return await request("PATCH", f"{base}/{evidence_id}", json=data or {})
    if action == "acquisition_record":
        if not data:
            raise FenrirError("acquisition_record takes data={…the acquisition fields to set…}")
        return await request("PATCH", f"{base}/{evidence_id}/acquisition-record", json=data)
    if not file_path:
        raise FenrirError("file_path is required for photo_upload")
    return await request(
        "POST", f"{base}/{evidence_id}/photos", files={"file": config.read_upload(file_path)}, data=data or {}
    )


@tool("standard")
async def fenrir_evidence_custody(
    action: Literal[
        "seal", "transfer", "transfer_accept", "transfer_decline", "examine", "verify",
        "examination_session", "working_copy_record", "working_copy_create", "working_copy_issue",
        "legal_hold_set", "legal_hold_release", "custody_log_verify", "export_create",
        "disclosure_create", "manifest_rebuild",
    ],
    incident_id: str,
    evidence_id: str | None = None,
    data: dict | None = None,
    confirm: bool = False,
    include_unsealed_drafts: bool | None = None,
) -> dict:
    """Chain-of-custody operations: seal, transfer, examine, verify hashes,
    open an examination session, create a working copy (server-side), verify the
    whole custody chain, or create an export bundle (stays server-side; retrieval
    is GUI-only). Every action lands in the hash-chained audit log.
    seal (S3): a digital item needs its source device and path, or source_unknown_reason (see
    fenrir_evidence_register; else 422 seal_fields_missing, body.missing names them); the seal binds the
    canonical record (seal_record_sha256; fenrir_evidence_list view=seal_record).
    transfer (custodian or admin only): data {to_user_id | to_external{name,
    organisation, contact}, reason, transport_method, seal_id, courier_ref}. To a
    user it is only a REQUEST — custody does not change until THAT user runs
    transfer_accept; the item shows pending_custodian_id. To an external party it is
    one step. Taking an item back from external custody: to_user_id = yourself plus
    condition_on_receipt and seals_intact. transfer_accept (the recipient only,
    never an admin for them): data {condition_on_receipt, seals_intact}.
    transfer_decline (recipient, requester or admin): data {reason}. While a
    transfer is pending, transfer/seal/dispose return 409 transfer_pending.
    G5 working copies (ISO 27037 §7.1.3.1.1; the master is never downloadable):
    working_copy_record (alias working_copy_create): a copy made OUTSIDE FENRIR — data {purpose,
    copy_sha256 | copy_sha1 | copy_md5 (the hash the copying tool reported for THAT copy; at least
    one, else 422 copy_hash_required), copy_tool?, destination_note?}; compared with the master's
    recorded hash → status verified | mismatch (flagged, never verified).
    working_copy_issue: data {purpose, destination_note?} → {copy, download_url, token_expires_at}.
    The bytes are NOT fetched here (bytes flow toward FENRIR only): give the operator the
    download_url to open in their browser while logged in as the same user, within 10 minutes,
    once. FENRIR hashes what it sends and records it on the copy (fenrir_evidence_list
    view=working_copies). Both: analyst with access; item active (not frozen), internal custody,
    no transfer pending (409); allowed on a closed incident.
    examine / examination_session on a DIGITAL item: data.working_copy_id = a usable copy, or
    examined_in_place=true + in_place_reason (422 working_copy_required otherwise). The session
    also needs post_exam_copy_hash (the copy's hash after the exam; optional pre_exam_copy_hash),
    compared with the copy's recorded hash; it no longer re-hashes the master (use verify).
    legal_hold_set (any analyst with access) / legal_hold_release (incident lead or admin, else
    403 not_incident_lead): data {reason}. legal_hold_release also needs confirm=true, set only after
    the operator explicitly approved releasing the hold on THIS item. A held item can't be destroyed
    (409 legal_hold_active). update with legal_hold is refused (422 use_legal_hold_endpoint).
    manifest_rebuild (S6; evidence_id): queue a container exhibit's manifest build again when it failed or is stuck
    pending (202, manifest_status pending; poll fenrir_evidence_list view=item); 409 manifest_built /
    manifest_not_indexed.
    disclosure_create (K1; incident lead or admin, else 403 not_incident_lead): the ONE way exhibits leave
    FENRIR — data {purpose: internal | law_enforcement | regulator, recipient_name, item_ids? (omitted = every
    exhibit not destroyed / verify_failed; [] = records only), case_reference, requesting_authority,
    legal_basis (warrant | subpoena | court_order | eio | mla | voluntary | statutory | other; eio needs
    eio_reference + issuing_state + executing_state, mla needs mla_reference), retention_until?,
    include_artifacts?, recipient_role / _organisation / _id_ref / _address?, delivery_channel?,
    delivery_notes?, sender_declaration?, enable_acknowledgment?}. law_enforcement / regulator need
    case_reference, requesting_authority and legal_basis (422 disclosure_field_required); internal defaults
    them. A destroyed / verify_failed item_id → 409 evidence_not_exportable; one of another incident → 404.
    Always signed (Ed25519 over MANIFEST.json + HMAC), custody-logged per exhibit, audited, and the other
    admins are notified. Unsealed drafts are left out unless include_unsealed_drafts=true (audited). Built
    in this one call (up to 30 min); its one-time bundle_password is only in the response — relay it.
    export_create (deprecated: use disclosure_create; incident lead or admin): data {item_ids, recipient,
    purpose, acknowledgments?}; unsealed draft exhibits are left out (listed "excluded: unsealed draft")
    unless include_unsealed_drafts=true (audited). The bundle is built in this one call (up to 30 min; its
    key is only in the response)."""
    base = f"/api/incidents/{incident_id}/evidence"
    body = data or {}
    if action == "custody_log_verify":
        return await request("POST", f"{base}/custody-log/verify", json=body)
    if action in ("export_create", "disclosure_create"):
        if include_unsealed_drafts is not None:
            body = {**body, "include_unsealed_drafts": include_unsealed_drafts}
        path = f"{base}/exports" if action == "export_create" else f"/api/incidents/{incident_id}/disclosures"
        return await request("POST", path, json=body, long_call=True)
    if not evidence_id:
        raise FenrirError(f"evidence_id is required for {action}")
    if action in ("legal_hold_set", "legal_hold_release"):
        if action == "legal_hold_release" and not confirm:
            raise FenrirError(
                "legal_hold_release requires confirm=true — ask the operator to explicitly confirm releasing the "
                "legal hold on this specific evidence item first"
            )
        if not (body.get("reason") or "").strip():
            raise FenrirError(f"{action} needs data={{\"reason\": …}} (audited)")
        return await request("PUT", f"{base}/{evidence_id}/legal-hold",
                             json={"legal_hold": action == "legal_hold_set", "reason": body["reason"]})
    seg = {
        "seal": "seal", "transfer": "transfer", "examine": "examine", "verify": "verify",
        "transfer_accept": "transfer/accept", "transfer_decline": "transfer/decline",
        "examination_session": "examination-session", "working_copy_create": "working-copy",
        "working_copy_record": "working-copy", "working_copy_issue": "working-copies",
        "manifest_rebuild": "manifest/rebuild",
    }[action]
    out = await request("POST", f"{base}/{evidence_id}/{seg}", json=body)
    if action == "working_copy_issue" and isinstance(out, dict) and str(out.get("download_url", "")).startswith("/"):
        out["download_url"] = config.fenrir_url() + out["download_url"]   # for the operator's browser
    return out


@tool("full")
async def fenrir_evidence_dispose(
    incident_id: str, evidence_id: str, confirm: bool = False, data: dict | None = None
) -> dict:
    """Dispose of evidence — a chain-of-custody-TERMINAL act. Requires confirm=true,
    set only after the operator has explicitly approved disposal of THIS evidence
    item. data carries the disposal method/reason per FENRIR's disposal schema
    ({kind: destroy|return|archive, reason}). A legal-hold item also needs witness_id: a
    second user, active and able to see the incident (404 user_not_found, 422
    assignee_no_access)."""
    if not confirm:
        raise FenrirError(
            "disposal requires confirm=true — ask the operator to explicitly confirm "
            "disposing this specific evidence item first"
        )
    return await request("POST", f"/api/incidents/{incident_id}/evidence/{evidence_id}/dispose", json=data or {})
