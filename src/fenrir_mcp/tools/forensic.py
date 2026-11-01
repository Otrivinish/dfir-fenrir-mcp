"""Forensic workspace: email analyzer, PCAP, browser history, timeline imports,
Defender PDF imports, artifacts, collections, OSINT. Uploads go through the FENRIR_MCP_UPLOAD_DIRS
allowlist; analysis calls are serialized (single-worker backend)."""

from __future__ import annotations

from typing import Literal

from .. import config, refcache
from ..client import FenrirError, request, upload_file
from . import params, project, tool


def _upload(file_path: str) -> dict:
    return {"file": config.read_upload(file_path)}


async def _upload_then_analyse(incident_id: str, file_path: str, purpose: str, complete: dict, path_tail: str,
                               json: dict | None = None) -> dict:
    """G3 upload through a chunked upload session (FENRIR G1 stage 3b: streamed, encrypted on arrival,
    registered as a draft exhibit or linked to the one with the same SHA-256), then the analyser's
    from-evidence route on that exhibit. The result carries `upload` = how the file was registered."""
    done = await upload_file(incident_id, file_path, purpose, complete)
    ev = done.get("evidence") or {}
    upload = {"evidence_id": done.get("evidence_id"), "evidence_identifier": ev.get("identifier"),
              "exhibit_link": done.get("exhibit_link")}
    try:
        out = await request("POST", f"/api/incidents/{incident_id}/{path_tail}/from-evidence/{done['evidence_id']}",
                            json=json, expensive=True)
    except FenrirError as e:
        raise FenrirError(f"{e} — the file IS registered as exhibit {upload['evidence_identifier']} (evidence_id "
                          f"{upload['evidence_id']}, {upload['exhibit_link']}); analyse it later with "
                          "action=from_evidence") from e
    return {**out, "upload": upload} if isinstance(out, dict) else out


def _acquired(data: dict | None) -> dict:
    return {"acquired_at": data["acquired_at"]} if (data or {}).get("acquired_at") else {}


@tool("readonly")
async def fenrir_forensic_list(
    incident_id: str,
    view: Literal[
        "email", "email_item", "email_seen_before", "email_hunting_queries", "email_containment_plan",
        "pcap", "pcap_item",
        "webhistory", "webhistory_visits",
        "webhistory_downloads", "webhistory_search_terms", "timeline_imports",
        "timeline_import_item", "artifacts", "artifact_item", "collections",
        "collection_item", "collection_profiles", "osint_sessions",
        "defender_imports", "defender_import_item",
    ],
    item_id: str | None = None,
    limit: int | None = None,
    cursor: str | None = None,
    fields: list | None = None,
    lookback_days: int | None = None,
) -> dict | list:
    """Forensic workspace reads (metadata + analysis results; artifact bytes never
    leave FENRIR). *_item views require item_id. Pass fields to keep list responses small.
    Run records: timeline / Defender imports carry evidence_id, sha256_hash (input),
    parser_version (+ parser_name for Defender), clock_offset_seconds (applied) and
    clock_offset_status (applied | changed | text_only | none); collections carry
    container_sha256 / container_size (as received), output_sha256 (decrypted) and evidence_id.
    G3: email analyses / pcap / webhistory uploads carry evidence_id + evidence_identifier (the
    exhibit; evidence_sealed false = still a draft), the input hash (input_sha256 / sha256_hash),
    analyser_name / analyser_version (parser_* for webhistory) and exhibit_link; pcap_item has
    timeline_candidates; webhistory_visits / _downloads rows have timeline_event_id once promoted.
    email_seen_before (item_id = the analysis): other incidents you can access that already hold the
    email's sender, links, attachment hashes or origin IP as IOCs, each hit with the incident's ref,
    status and triage_state and the IOC's malicious flag; strongest first, plus a summary.
    email_hunting_queries (item_id = the analysis; lookback_days 1-30, default 30): ready-to-run Defender
    XDR Advanced Hunting KQL that scopes the email (delivery, similar mail, link recipients, clicks,
    attachment recipients, devices); FENRIR runs nothing, and the call is audited (query ids only).
    email_containment_plan (item_id = the analysis): what to contain -- the message (quarantine), sender,
    sender domain, Reply-To, each link, each attachment, the origin IP -- each with its Respond template,
    suggested + reason, and existing_ioc_id / existing_action_id; act on it with
    fenrir_email_analyze(action="containment")."""
    base = f"/api/incidents/{incident_id}"
    item = {
        "email_item": f"{base}/email", "pcap_item": f"{base}/pcap",
        "timeline_import_item": f"{base}/forensic/timeline-import/imports",
        "artifact_item": f"{base}/artifacts", "collection_item": f"{base}/collections",
        "defender_import_item": f"{base}/forensic/defender-pdf/imports",
    }
    if view in item:
        if not item_id:
            raise FenrirError(f"item_id is required for view={view}")
        return await request("GET", f"{item[view]}/{item_id}")
    email_sub = {"email_seen_before": "seen-before", "email_hunting_queries": "hunting-queries",
                 "email_containment_plan": "containment-plan"}
    if view in email_sub:
        if not item_id:
            raise FenrirError(f"item_id is required for view={view}")
        q = {"lookback_days": lookback_days} if view == "email_hunting_queries" and lookback_days else None
        return await request("GET", f"{base}/email/{item_id}/{email_sub[view]}", params=q)
    paths = {
        "email": f"{base}/email",
        "pcap": f"{base}/pcap",
        "webhistory": f"{base}/webhistory",
        "webhistory_visits": f"{base}/webhistory/visits",
        "webhistory_downloads": f"{base}/webhistory/downloads",
        "webhistory_search_terms": f"{base}/webhistory/search-terms",
        "timeline_imports": f"{base}/forensic/timeline-import/imports",
        "artifacts": f"{base}/artifacts",
        "collections": f"{base}/collections",
        "collection_profiles": f"{base}/collections/profiles",
        "osint_sessions": f"{base}/osint/sessions",
        "defender_imports": f"{base}/forensic/defender-pdf/imports",
    }
    return project(await request("GET", paths[view], params=params(limit=limit, cursor=cursor)), fields)


@tool("standard")
async def fenrir_email_analyze(
    action: Literal["analyze", "analyze_bulk", "from_evidence", "domain_check", "extract_attachment", "import_hops",
                    "promote_iocs", "mint_evidence", "containment"],
    incident_id: str,
    analysis_id: str | None = None,
    evidence_id: str | None = None,
    file_path: str | None = None,
    file_paths: list | None = None,
    attachment_index: int | None = None,
    data: dict | None = None,
    confirm_outbound: bool = False,
) -> dict:
    """Offline phishing triage. Register-first (G3): the message analysed IS an exhibit.
    - analyze: upload a local .eml/.msg (file_path; streamed in chunks, encrypted as it arrives, never
      read whole). FENRIR first registers it as an UNSEALED DRAFT exhibit (identifier per the naming convention, you as
      collector + custodian, lawful basis pending; hashed, encrypted, custody-logged) — or links the
      one active exhibit with the same SHA-256 — then it is analysed from that exhibit (re-verified).
      data may carry acquired_at (UTC ISO, when the message was acquired). No quarantine copy is made.
      The result's `upload` says how the file was registered (registered | sha256_match). A message
      that can't be parsed stays registered: the error names the exhibit (then use from_evidence).
    - analyze_bulk: file_paths (each inside FENRIR_MCP_UPLOAD_DIRS) = several .eml/.msg, or ONE .zip
      of them (<= 200 messages, <= 250 MB; a multipart upload held whole in memory at both ends, so
      use analyze for a single message). Each message is registered as its own draft exhibit, then
      analysed; the run shares a batch_id; oversized/invalid members come back in skipped / errors.
      data may carry acquired_at. Live SPF/DMARC/DKIM per sender domain (skipped, audited, under
      Dark Operation).
    - domain_check: data={"domain": ..., "selector"?: ...}: live SPF + DMARC DNS check of a domain
      (DKIM only with a selector). Read-only, works on a closed incident. The lookup leaves FENRIR: on
      a TLP:RED or Dark Operation incident it fails with 409 outbound_confirmation_required; ask the
      operator, and only if they agree retry with confirm_outbound=True (audited).
    - from_evidence: analyse a registered exhibit, no upload (evidence_id). It must be active, in
      internal custody, no pending transfer; its hash is re-verified (409 evidence_hash_mismatch
      freezes it); the run is logged in its custody log (evidence_examine).
    On an existing analysis (analysis_id): extract_attachment (attachment_index; re-reads and
    re-verifies the exhibit), import_hops (timeline, idempotent; events carry the exhibit and are
    immutable; data {"link_entities": false} stops linking each hop to the entity its relay host names), promote_iocs (IOCs record the exhibit), mint_evidence (LEGACY: only analyses made
    before G3 — a G3 analysis already is of an exhibit, 409), containment (data = {"items": [{"kind",
    "ref"}, …], "assignee_id"?}: items from fenrir_forensic_list(view="email_containment_plan"), by
    reference only; each becomes an IOC + an open Respond action with its template; idempotent
    (existing ones reported); returns ioc_ids for fenrir_ioc_export(ioc_ids=…) — carry the actions out
    in Defender/Exchange, then mark them done).
    Each analysis is a run record: evidence_id (+ evidence_identifier, evidence_sealed), input_sha256,
    analyser_name / analyser_version, exhibit_link (registered | sha256_match | from_evidence).
    Complete and seal the draft later: fenrir_evidence_register(action="acquisition_record") then
    fenrir_evidence_custody(action="seal"). Analysis is slow and serialized. Closed incident: 409
    (except domain_check)."""
    base = f"/api/incidents/{incident_id}/email"
    if action == "analyze":
        if not file_path:
            raise FenrirError("file_path is required for analyze")
        return await _upload_then_analyse(incident_id, file_path, "email", _acquired(data), "email")
    if action == "analyze_bulk":
        if not file_paths:
            raise FenrirError("file_paths is required for analyze_bulk")
        return await request("POST", f"{base}/analyze-bulk",
                             files=[("files", config.read_upload(p)) for p in file_paths],
                             data=_acquired(data), expensive=True, long_call=True)
    if action == "domain_check":
        if not (data or {}).get("domain"):
            raise FenrirError('domain_check takes data={"domain": "...", "selector"?: "..."}')
        return await request("GET", f"{base}/domain-check", params=params(
            domain=data["domain"], selector=data.get("selector"),
            confirm_outbound="true" if confirm_outbound else None))
    if action == "from_evidence":
        if not evidence_id:
            raise FenrirError("evidence_id is required for from_evidence")
        return await request("POST", f"{base}/from-evidence/{evidence_id}", expensive=True)
    if not analysis_id:
        raise FenrirError(f"analysis_id is required for {action}")
    if action == "extract_attachment":
        if attachment_index is None:
            raise FenrirError("attachment_index is required for extract_attachment")
        return await request("POST", f"{base}/{analysis_id}/attachments/{attachment_index}/extract", expensive=True)
    if action == "import_hops":     # TE: a query parameter; the route takes no body
        link = (data or {}).get("link_entities")
        return await request("POST", f"{base}/{analysis_id}/import-hops", json={}, params=params(link_entities=link))
    seg = {"promote_iocs": "promote-iocs", "mint_evidence": "mint-evidence",
           "containment": "containment"}[action]
    return await request("POST", f"{base}/{analysis_id}/{seg}", json=data or {})


@tool("standard")
async def fenrir_pcap_analyze(
    action: Literal["analyze", "from_evidence", "import_iocs", "promote"],
    incident_id: str,
    result_id: str | None = None,
    evidence_id: str | None = None,
    file_path: str | None = None,
    data: dict | None = None,
) -> dict:
    """Packet-capture analysis in the air-gapped worker. Register-first (G3): the raw capture is kept
    as an exhibit (encrypted, hashed).
    - analyze: upload a local pcap/pcapng (file_path; streamed in chunks, encrypted as it arrives; slow,
      serialized). FENRIR first registers it as an UNSEALED DRAFT exhibit (named by the convention) — or links the one
      active exhibit with the same SHA-256 — then it is analysed from that exhibit (re-verified). data
      may carry acquired_at (UTC ISO). Not pcap/pcapng: 422 not_a_capture, nothing stored. If the
      worker fails the capture stays registered (the error names the exhibit; use from_evidence later).
      The result's `upload` says how the file was registered.
    - from_evidence: analyse a registered exhibit, no upload (evidence_id; same custody/hash rules as
      fenrir_email_analyze; 409 evidence_hash_mismatch freezes it).
    - promote: put timeline candidates on the Timeline (result_id; data {indices: [idx…], ir_phase?}).
      Candidates (in the analysis: timeline_candidates, each with idx, event_time, time_basis,
      recorded_time, promoted) are conversation first/last seen, DNS queries, HTTP requests, TLS SNI and
      the capture window, with pcap times in UTC corrected by the exhibit's clock offset (recorded time
      kept). FENRIR copies them; events carry the exhibit + run and are immutable and internal-only.
      Without a time → skipped_untimestamped; repeat → already_promoted; pre-G3 analysis → 409
      reparse_required.
      data.link_entities (default true) links each new event to the entity its host names (result entities_linked).
    - import_iocs: import discovered IOCs (result_id; data {iocs: [{type: ip|domain|url, value}]});
      they record the exhibit.
    Run record on each analysis: evidence_id, evidence_identifier, input_sha256, analyser_name /
    analyser_version, exhibit_link, clock_offset_seconds + clock_offset_status. Closed incident: 409."""
    base = f"/api/incidents/{incident_id}/pcap"
    if action == "analyze":
        if not file_path:
            raise FenrirError("file_path is required for analyze")
        return await _upload_then_analyse(incident_id, file_path, "pcap", _acquired(data), "pcap")
    if action == "from_evidence":
        if not evidence_id:
            raise FenrirError("evidence_id is required for from_evidence")
        return await request("POST", f"{base}/from-evidence/{evidence_id}", expensive=True)
    if not result_id:
        raise FenrirError(f"result_id is required for {action}")
    if action == "promote":
        body = data or {}
        if not isinstance(body.get("indices"), list) or not body["indices"]:
            raise FenrirError('promote takes data={"indices": [0, 3, …], "ir_phase": …}')
        return await request("POST", f"{base}/{result_id}/promote", json=body)
    return await request("POST", f"{base}/{result_id}/import-iocs", json=data or {})


@tool("standard")
async def fenrir_webhistory_import(
    action: Literal["upload", "from_evidence", "promote", "mint_evidence"],
    incident_id: str,
    upload_id: str | None = None,
    evidence_id: str | None = None,
    file_path: str | None = None,
    data: dict | None = None,
) -> dict:
    """Browser history (Chrome/Edge/Brave History, Firefox places.sqlite). Register-first (G3).
    - upload: a local SQLite file (file_path; data {browser: chrome|edge|brave|firefox, acquired_at?};
      streamed in chunks, encrypted as it arrives). FENRIR first registers it as an UNSEALED DRAFT
      exhibit (named by the convention) — or links the one active exhibit with the same SHA-256 — then it is parsed
      from that exhibit (re-verified). Not SQLite: 422 not_sqlite, nothing stored. Unparseable: the
      error names the exhibit (stays registered; use from_evidence). No quarantine copy. The result's
      `upload` says how the file was registered.
    - from_evidence: parse a registered exhibit, no upload (evidence_id; data {browser,
      form_history_evidence_id? (Firefox formhistory.sqlite exhibit)}). Same custody/hash rules as
      fenrir_email_analyze.
    - promote: put visits / downloads on the Timeline (data {visit_ids: […], download_ids: […],
      ir_phase?}; ids from fenrir_forensic_list views webhistory_visits / webhistory_downloads). FENRIR
      copies each record: events carry the exhibit, upload and record, times are UTC corrected by the
      exhibit's clock offset (recorded time kept), immutable and internal-only. Result lists
      created_ids, already_promoted, skipped_untimestamped, not_found, reparse_required (pre-G3 upload).
    - mint_evidence: LEGACY — register a pre-G3 upload's file as an exhibit (upload_id).
    Each upload is a run record: evidence_id, sha256_hash (input), parser_name / parser_version,
    exhibit_link, clock_offset_seconds + clock_offset_status. Closed incident: 409 incident_closed."""
    base = f"/api/incidents/{incident_id}/webhistory"
    if action == "upload":
        if not file_path:
            raise FenrirError("file_path is required for upload")
        browser = (data or {}).get("browser")
        if not browser:
            raise FenrirError('upload takes data={"browser": "chrome|edge|brave|firefox", "acquired_at"?: …}')
        return await _upload_then_analyse(incident_id, file_path, "webhistory",
                                          {"browser": browser, **_acquired(data)}, "webhistory", json={"browser": browser})
    if action == "from_evidence":
        if not evidence_id:
            raise FenrirError("evidence_id is required for from_evidence")
        body = data or {}
        if not body.get("browser"):
            raise FenrirError('from_evidence takes data={"browser": "chrome|edge|brave|firefox"}')
        return await request("POST", f"{base}/from-evidence/{evidence_id}", json=body, expensive=True)
    if action == "promote":
        body = data or {}
        if not (body.get("visit_ids") or body.get("download_ids")):
            raise FenrirError('promote takes data={"visit_ids": [...], "download_ids": [...], "ir_phase": ...}')
        return await request("POST", f"{base}/promote", json=body)
    if not upload_id:
        raise FenrirError("upload_id is required for mint_evidence")
    return await request("POST", f"{base}/{upload_id}/mint-evidence", json=data or {})


@tool("standard")
async def fenrir_timeline_import(
    action: Literal["parse_upload", "from_artifact", "create_import", "from_evidence", "promote"],
    incident_id: str,
    artifact_id: str | None = None,
    evidence_id: str | None = None,
    import_id: str | None = None,
    file_path: str | None = None,
    data: dict | None = None,
) -> dict:
    """Forensic timeline import. Parsing is slow and serialized.
    - parse_upload: stateless preview of a local file (file_path); nothing stored.
    - create_import: upload a local file (file_path, multipart) and store the parse; data
      {source_tz} = IANA zone of times the file doesn't state (default UTC). A file whose
      SHA-256 equals exactly one exhibit of the incident is linked to it (evidence_id).
    - from_evidence: parse a registered exhibit, no upload (evidence_id; data {source_tz
      (required), parser: auto|evtx|xml|sqlite|csv|tsv|syslog|json}). The exhibit must be active,
      in internal custody, no pending transfer; its hash is re-verified (409 evidence_hash_mismatch
      freezes it) and the run is logged in its custody log (evidence_examine).
    - from_artifact: parse an ingested Velociraptor collection (artifact_id).
    - promote: copy stored events onto the timeline by index (import_id; data {indices: [idx…],
      ir_phase?}). FENRIR copies times from the parse; events without a time are skipped and
      listed, already-promoted indices are skipped. Promoted facts are immutable afterwards
      (timeline edits of time/host/source/type/description/raw_log → 409).
      data.link_entities (default true) links each new event to the entity its host names (result entities_linked).
    Each parsed event has time_basis: explicit | assumed_tz (read in source_tz) | inferred_year
    (BSD syslog, year from the exhibit's acquisition time) | missing. When the import is of an
    exhibit (from_evidence, an upload matching one, or a collection whose container matched one)
    that records system_time_offset_seconds, times are corrected by it: the import has
    clock_offset_seconds, each corrected event keeps recorded_time, promoted events keep
    recorded_event_time. clock_offset_status: applied | changed (the exhibit's offset changed
    after the import — re-import to apply) | text_only (recorded only as text: NOT applied) | none.
    On a closed incident every action except parse_upload is 409 incident_closed."""
    base = f"/api/incidents/{incident_id}/forensic/timeline-import"
    if action in ("parse_upload", "create_import"):
        if not file_path:
            raise FenrirError(f"file_path is required for {action}")
        path = f"{base}/parse" if action == "parse_upload" else f"{base}/imports"
        return await request("POST", path, files=_upload(file_path), data=data or {}, expensive=True)
    if action == "from_artifact":
        if not artifact_id:
            raise FenrirError("artifact_id is required for from_artifact")
        return await request("POST", f"{base}/from-artifact/{artifact_id}", json=data or {}, expensive=True)
    if action == "from_evidence":
        if not evidence_id:
            raise FenrirError("evidence_id is required for from_evidence")
        return await request("POST", f"{base}/from-evidence/{evidence_id}", json=data or {}, expensive=True)
    if not import_id:
        raise FenrirError("import_id is required for promote")
    return await request("POST", f"{base}/imports/{import_id}/promote", json=data or {})


@tool("standard")
async def fenrir_defender_import(
    action: Literal["create_import", "from_evidence", "promote"],
    incident_id: str,
    evidence_id: str | None = None,
    import_id: str | None = None,
    file_path: str | None = None,
    data: dict | None = None,
) -> dict:
    """Microsoft Defender XDR incident PDF import (Examine → Vendor reports). Parsing is serialized.
    - create_import: upload a local PDF (file_path, up to 25 MB). A PDF whose SHA-256 equals
      exactly one active exhibit of the incident is linked to it (evidence_id).
    - from_evidence: parse a registered exhibit, no upload (evidence_id). The exhibit must be an
      active digital file in internal custody with no pending transfer; its hash is re-verified
      (409 evidence_hash_mismatch freezes it) and the run is logged in its custody log
      (evidence_examine).
    - promote: commit candidates by idx (import_id; data {items: [{idx, destination:
      ioc|entity|timeline_event}], ir_phase?}). FENRIR copies the facts from the stored parse;
      IOCs carry the exhibit, timeline events the exhibit + defender_import_id + idx and become
      immutable. Candidates without a time are never placed on the timeline
      (skipped_untimestamped); already_promoted / already_exists are skipped.
      data.link_entities (default true) links each new event to the entity its host names, entities committed in the same call included (result entities_linked).
    Each import is a run record: sha256_hash (input), evidence_id, parser_name / parser_version,
    clock_offset_seconds + clock_offset_status (as fenrir_timeline_import). Read imports with
    fenrir_forensic_list(view=defender_imports | defender_import_item). Closed incident: 409."""
    base = f"/api/incidents/{incident_id}/forensic/defender-pdf"
    if action == "create_import":
        if not file_path:
            raise FenrirError("file_path is required for create_import")
        return await request("POST", f"{base}/imports", files=_upload(file_path), expensive=True)
    if action == "from_evidence":
        if not evidence_id:
            raise FenrirError("evidence_id is required for from_evidence")
        return await request("POST", f"{base}/from-evidence/{evidence_id}", expensive=True)
    if not import_id:
        raise FenrirError("import_id is required for promote")
    body = data or {}
    if not isinstance(body.get("items"), list) or not body["items"]:
        raise FenrirError('promote takes data={"items": [{"idx": 0, "destination": "ioc"}, …]}')
    return await request("POST", f"{base}/imports/{import_id}/promote", json=body)


@tool("standard")
async def fenrir_artifact_write(
    action: Literal["register", "update", "analyze", "promote_iocs"],
    incident_id: str,
    artifact_id: str | None = None,
    analysis_tool: str | None = None,
    file_path: str | None = None,
    data: dict | None = None,
) -> dict:
    """Register (upload) an artifact into FENRIR's store (encrypted at rest), update its description
    (data={"description": "…"} — the only field an artifact update changes; null or ""
    clears it), run a validated analysis tool on it (analysis_tool name; slow,
    serialized), or promote_iocs: create its SHA-256 + MD5 IOCs (existing ones are
    reported, not duplicated). register creates NO IOCs unless data={"create_hash_iocs": true}
    — only for a malicious sample, never for ransom notes, screenshots or context files.
    Artifact bytes never come back — results and metadata do. Closed incident: 409
    incident_closed for all four (stored results stay readable). Delete with fenrir_delete
    (resource_type=artifact, reason required)."""
    base = f"/api/incidents/{incident_id}/artifacts"
    if action == "register":
        if not file_path:
            raise FenrirError("file_path is required for register")
        form = dict(data or {})
        if "create_hash_iocs" in form:
            form["create_hash_iocs"] = "true" if form["create_hash_iocs"] in (True, "true", "1", 1) else "false"
        return await request("POST", base, files=_upload(file_path), data=form, expensive=True)
    if not artifact_id:
        raise FenrirError(f"artifact_id is required for {action}")
    if action == "promote_iocs":
        return await request("POST", f"{base}/{artifact_id}/hash-iocs")
    if action == "update":
        # R65: the PATCH reads one form field, `description`, and stores null when it is absent,
        # so a JSON body wiped the description with a 200. Send exactly that form field.
        body = data or {}
        if set(body) != {"description"}:
            raise FenrirError('update takes data={"description": "…"} only: the description is the one '
                              "field FENRIR lets you change on an artifact")
        return await request("PATCH", f"{base}/{artifact_id}", data={"description": body["description"] or ""})
    if not analysis_tool:
        raise FenrirError("analysis_tool is required for analyze")
    return await request("POST", f"{base}/{artifact_id}/analyze/{analysis_tool}", json=data or {}, expensive=True)


@tool("standard")
async def fenrir_collection_write(
    action: Literal["create", "ingest"],
    incident_id: str,
    collection_id: str | None = None,
    file_path: str | None = None,
    data: dict | None = None,
) -> dict:
    """Create a collection package via the ISO 27037 collection wizard (data per
    the wizard schema), or ingest collected data into one (collection_id +
    file_path; slow, serialized). Ingest records the container's SHA-256 + size as
    received (container_sha256) and links the exhibit whose SHA-256 equals it
    (evidence_id) — register the container as evidence first."""
    base = f"/api/incidents/{incident_id}/collections"
    if action == "create":
        return await request("POST", base, json=data or {})
    if not collection_id:
        raise FenrirError("collection_id is required for ingest")
    files = _upload(file_path) if file_path else None
    return await request("POST", f"{base}/{collection_id}/ingest", files=files, data=data or {}, expensive=True)


@tool("standard")
async def fenrir_osint_enrich(
    action: Literal["sources", "enrich", "session_create", "session_update"],
    incident_id: str | None = None,
    session_id: str | None = None,
    data: dict | None = None,
    confirm_outbound: bool = False,
) -> dict | list:
    """OSINT: list configured sources, run an enrichment (data: indicator, ioc_type,
    sources; uses FENRIR's server-side sources; slow, serialized), and manage
    per-incident OSINT sessions (session_* need incident_id).
    enrich sends the indicator to outside services; pass incident_id when the lookup is
    for an incident. On a TLP:RED or Dark Operation incident (the one given, or one you
    can see holding the indicator as an IOC) it fails with 409
    outbound_confirmation_required (reason tlp_red | dark_operation): ask the operator,
    and only if they agree retry with confirm_outbound=True (audited as
    outbound_manual_lookup). enrich needs the analyst role or higher (a viewer: 403
    insufficient_role)."""
    body = data or {}
    if action == "sources":
        return await request("GET", "/api/osint/sources")
    if action == "enrich":
        body = dict(body)
        if incident_id:
            iid = incident_id
            if refcache.REF_RE.match(iid):   # a ref: request bodies aren't rewritten, so resolve it
                iid = (await request("GET", f"/api/incidents/{iid}"))["id"]
            body["incident_id"] = iid
        if confirm_outbound:
            body["confirm_outbound"] = True
        return await request("POST", "/api/osint/enrich", json=body, expensive=True)
    if not incident_id:
        raise FenrirError(f"incident_id is required for {action}")
    base = f"/api/incidents/{incident_id}/osint/sessions"
    if action == "session_create":
        return await request("POST", base, json=body)
    if not session_id:
        raise FenrirError("session_id is required for session_update")
    return await request("PATCH", f"{base}/{session_id}", json=body)
