"""Forensic workspace: email analyzer, PCAP, browser history, timeline imports,
artifacts, collections, OSINT. Uploads go through the FENRIR_MCP_UPLOAD_DIRS
allowlist; analysis calls are serialized (single-worker backend)."""

from __future__ import annotations

from typing import Literal

from .. import config
from ..client import FenrirError, request
from . import params, project, tool


def _upload(file_path: str) -> dict:
    return {"file": config.read_upload(file_path)}


@tool("readonly")
async def fenrir_forensic_list(
    incident_id: str,
    view: Literal[
        "email", "email_item", "pcap", "pcap_item", "webhistory", "webhistory_visits",
        "webhistory_downloads", "webhistory_search_terms", "timeline_imports",
        "timeline_import_item", "artifacts", "artifact_item", "collections",
        "collection_item", "collection_profiles", "osint_sessions",
    ],
    item_id: str | None = None,
    limit: int | None = None,
    cursor: str | None = None,
    fields: list | None = None,
) -> dict | list:
    """Forensic workspace reads (metadata + analysis results; artifact bytes never
    leave FENRIR). *_item views require item_id. Pass fields to keep list responses small."""
    base = f"/api/incidents/{incident_id}"
    item = {
        "email_item": f"{base}/email", "pcap_item": f"{base}/pcap",
        "timeline_import_item": f"{base}/forensic/timeline-import/imports",
        "artifact_item": f"{base}/artifacts", "collection_item": f"{base}/collections",
    }
    if view in item:
        if not item_id:
            raise FenrirError(f"item_id is required for view={view}")
        return await request("GET", f"{item[view]}/{item_id}")
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
    }
    return project(await request("GET", paths[view], params=params(limit=limit, cursor=cursor)), fields)


@tool("standard")
async def fenrir_email_analyze(
    action: Literal["analyze", "extract_attachment", "import_hops", "promote_iocs", "mint_evidence"],
    incident_id: str,
    analysis_id: str | None = None,
    file_path: str | None = None,
    attachment_index: int | None = None,
    data: dict | None = None,
) -> dict:
    """Offline phishing triage: analyze a local .eml/.msg (file_path), then on an
    existing analysis (analysis_id): extract an attachment server-side
    (attachment_index), import received-hops to the timeline, promote IOCs, or
    mint the email as evidence. Analysis is slow and serialized."""
    base = f"/api/incidents/{incident_id}/email"
    if action == "analyze":
        if not file_path:
            raise FenrirError("file_path is required for analyze")
        return await request("POST", f"{base}/analyze", files=_upload(file_path), data=data or {}, expensive=True)
    if not analysis_id:
        raise FenrirError(f"analysis_id is required for {action}")
    if action == "extract_attachment":
        if attachment_index is None:
            raise FenrirError("attachment_index is required for extract_attachment")
        return await request("POST", f"{base}/{analysis_id}/attachments/{attachment_index}/extract", expensive=True)
    seg = {"import_hops": "import-hops", "promote_iocs": "promote-iocs", "mint_evidence": "mint-evidence"}[action]
    return await request("POST", f"{base}/{analysis_id}/{seg}", json=data or {})


@tool("standard")
async def fenrir_pcap_analyze(
    action: Literal["analyze", "import_iocs"],
    incident_id: str,
    result_id: str | None = None,
    file_path: str | None = None,
    data: dict | None = None,
) -> dict:
    """Analyze a local PCAP (file_path; slow, serialized) or import IOCs discovered
    by an existing analysis (result_id)."""
    base = f"/api/incidents/{incident_id}/pcap"
    if action == "analyze":
        if not file_path:
            raise FenrirError("file_path is required for analyze")
        return await request("POST", base, files=_upload(file_path), data=data or {}, expensive=True)
    if not result_id:
        raise FenrirError("result_id is required for import_iocs")
    return await request("POST", f"{base}/{result_id}/import-iocs", json=data or {})


@tool("standard")
async def fenrir_webhistory_import(
    action: Literal["upload", "mint_evidence"],
    incident_id: str,
    upload_id: str | None = None,
    file_path: str | None = None,
    data: dict | None = None,
) -> dict:
    """Upload a local browser-history artifact for parsing, or mint an existing
    upload (upload_id) as evidence."""
    base = f"/api/incidents/{incident_id}/webhistory"
    if action == "upload":
        if not file_path:
            raise FenrirError("file_path is required for upload")
        return await request("POST", base, files=_upload(file_path), data=data or {}, expensive=True)
    if not upload_id:
        raise FenrirError("upload_id is required for mint_evidence")
    return await request("POST", f"{base}/{upload_id}/mint-evidence", json=data or {})


@tool("standard")
async def fenrir_timeline_import(
    action: Literal["parse_upload", "from_artifact", "create_import"],
    incident_id: str,
    artifact_id: str | None = None,
    file_path: str | None = None,
    data: dict | None = None,
) -> dict:
    """Forensic timeline import: parse a local artifact upload (file_path), parse a
    stored artifact (artifact_id), or create an import from parsed events (data).
    Parsing is slow and serialized."""
    base = f"/api/incidents/{incident_id}/forensic/timeline-import"
    if action == "parse_upload":
        if not file_path:
            raise FenrirError("file_path is required for parse_upload")
        return await request("POST", f"{base}/parse", files=_upload(file_path), data=data or {}, expensive=True)
    if action == "from_artifact":
        if not artifact_id:
            raise FenrirError("artifact_id is required for from_artifact")
        return await request("POST", f"{base}/from-artifact/{artifact_id}", json=data or {}, expensive=True)
    return await request("POST", f"{base}/imports", json=data or {})


@tool("standard")
async def fenrir_artifact_write(
    action: Literal["register", "update", "analyze"],
    incident_id: str,
    artifact_id: str | None = None,
    analysis_tool: str | None = None,
    file_path: str | None = None,
    data: dict | None = None,
) -> dict:
    """Register (upload) an artifact into FENRIR's store, update its description,
    or run a validated analysis tool on it (analysis_tool name; slow, serialized).
    Artifact bytes never come back — results and metadata do."""
    base = f"/api/incidents/{incident_id}/artifacts"
    if action == "register":
        if not file_path:
            raise FenrirError("file_path is required for register")
        return await request("POST", base, files=_upload(file_path), data=data or {}, expensive=True)
    if not artifact_id:
        raise FenrirError(f"artifact_id is required for {action}")
    if action == "update":
        return await request("PATCH", f"{base}/{artifact_id}", json=data or {})
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
    file_path; slow, serialized)."""
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
) -> dict | list:
    """OSINT: list configured sources, run an enrichment (data: target/type; uses
    FENRIR's server-side sources; slow, serialized), and manage per-incident OSINT
    sessions (session_* need incident_id)."""
    body = data or {}
    if action == "sources":
        return await request("GET", "/api/osint/sources")
    if action == "enrich":
        return await request("POST", "/api/osint/enrich", json=body, expensive=True)
    if not incident_id:
        raise FenrirError(f"incident_id is required for {action}")
    base = f"/api/incidents/{incident_id}/osint/sessions"
    if action == "session_create":
        return await request("POST", base, json=body)
    if not session_id:
        raise FenrirError("session_id is required for session_update")
    return await request("PATCH", f"{base}/{session_id}", json=body)
