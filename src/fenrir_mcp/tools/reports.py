"""Reports, post-incident, LE packages. Report/LE generation stays server-side;
saved-report PDF download is denylisted (bytes flow toward FENRIR only)."""

from __future__ import annotations

from typing import Literal

from ..client import FenrirError, request
from . import tool


@tool("readonly")
async def fenrir_report_data(
    incident_id: str,
    view: Literal[
        "data", "history", "analytics", "mitre_summary", "lessons", "lessons_export",
        "checklist", "le_packages", "le_package_item",
    ] = "data",
    item_id: str | None = None,
) -> dict | list | str:
    """Reporting reads: report data (CSF 2.0 / 800-61 aligned), saved-report
    history (retrieval of the PDFs themselves is GUI-only), post-incident
    analytics / MITRE summary / lessons (lessons_export returns text inline),
    the post-incident checklist, LE package status (+item with item_id).
    view=data also carries incident.nciss_severity (critical→emergency,
    high→severe, medium→medium, low→low), report_files[] (figures picked in
    Supporting documents: id, name, mime, size, sha256 of the original, caption,
    integrity "ok"|"failed" (failed = stored bytes missing or tampered: sha256 and
    mime null, don't use the figure); metadata only, no image bytes), oob_log[]
    (out-of-band comms log; never the OOB passphrase, which shows as
    "[passphrase]", or responders' out-of-band contacts), closure {closed,
    closed_at, closed_by, reason = the statement recorded at Close} and
    sign_offs[] (IC, Deputy, Legal Liaison, DPO with their assignees)."""
    base = f"/api/incidents/{incident_id}"
    if view == "le_package_item":
        if not item_id:
            raise FenrirError("item_id is required for view=le_package_item")
        return await request("GET", f"{base}/le-packages/{item_id}")
    paths = {
        "data": f"{base}/reports/data",
        "history": f"{base}/reports/history",
        "analytics": f"{base}/analytics",
        "mitre_summary": f"{base}/post-incident/mitre-summary",
        "lessons": f"{base}/post-incident/lessons",
        "lessons_export": f"{base}/post-incident/lessons/export",
        "checklist": f"{base}/post-incident/checklist",
        "le_packages": f"{base}/le-packages",
    }
    return await request("GET", paths[view])


@tool("standard")
async def fenrir_report_generate(
    action: Literal["report_save", "le_package_prepare"],
    incident_id: str,
    data: dict | None = None,
    include_unsealed_drafts: bool | None = None,
) -> dict:
    """report_save stores a FINISHED report in the incident's report history; FENRIR does not render
    reports server-side (the GUI Reports page renders them from fenrir_report_data). data={report_type
    (≤16 chars), template_id (≤32), classification (≤64), audience?, footer_text?, html (the complete
    rendered HTML document, required)}; JSON bodies are capped at 10 MiB (413). FENRIR records the
    HTML's SHA-256 and size and audits the save (analyst role). Or
    prepare a law-enforcement package (AES-256 encrypted, manifest HMAC-SHA-256 — stays
    on the server; the recipient link/retrieval is handled in the GUI). Slow, serialized.
    le_package_prepare: data {case_reference, requesting_authority, legal_basis, …}; unsealed draft
    exhibits are left out unless include_unsealed_drafts=true (audited). The package is built in this
    one call (up to 30 min); its one-time bundle_password is only in the response — relay it.
    le_package_prepare (and fenrir_report_data le_packages / le_package_item) is
    incident-lead only: an admin, or an analyst assigned as Incident Commander or
    Deputy on this incident (403 not_incident_lead). Every build notifies the other
    admins. Deprecated (K1): prefer fenrir_evidence_custody(action="disclosure_create",
    data={"purpose": "law_enforcement", …}), which also picks the exhibits."""
    if action == "report_save":
        return await request("POST", f"/api/incidents/{incident_id}/reports", json=data or {}, expensive=True)
    body = data or {}
    if include_unsealed_drafts is not None:
        body = {**body, "include_unsealed_drafts": include_unsealed_drafts}
    return await request("POST", f"/api/incidents/{incident_id}/le-package", json=body, expensive=True,
                         long_call=True)


@tool("standard")
async def fenrir_post_incident_write(
    action: Literal["lessons_update", "checklist_add", "checklist_update", "checklist_meta_update"],
    incident_id: str,
    item_id: str | None = None,
    data: dict | None = None,
) -> dict:
    """Post-Incident Activity (800-61 R3) writes: update lessons learned, add a
    checklist item, update one, or update its metadata (item_id required for updates).
    lessons_update data: any LessonsLearnedUpdate fields, e.g. status, conducted_at,
    participants, meeting_minutes (optional review-meeting minutes, plain text; null
    clears), incident_narrative, root_cause_description, report_security_recommendations,
    action_items. Once the incident is closed only action_items (409 incident_closed).
    checklist_update data {checked} or {not_applicable: true, na_reason?} / {not_applicable:
    false}: N/A unchecks the item and counts as done for Gate 2, which warns when na_reason
    is missing; checking clears N/A; incident_closed can't be N/A (422); neither field is
    422 nothing_to_change.
    checklist_meta_update data {notes?, assigned_to_id?}: the assignee must be an active
    user who can see the incident (404 user_not_found, 422 assignee_no_access); null
    clears it."""
    base = f"/api/incidents/{incident_id}/post-incident"
    body = data or {}
    if action == "lessons_update":
        return await request("PATCH", f"{base}/lessons", json=body)
    if action == "checklist_add":
        return await request("POST", f"{base}/checklist", json=body)
    if not item_id:
        raise FenrirError("item_id is required for checklist updates")
    if action == "checklist_update":
        return await request("PATCH", f"{base}/checklist/{item_id}", json=body)
    return await request("PATCH", f"{base}/checklist/{item_id}/meta", json=body)
