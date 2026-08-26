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
    the post-incident checklist, LE package status (+item with item_id)."""
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
) -> dict:
    """Generate and save a report server-side (data: report type/options), or
    prepare a law-enforcement package (AES-256, Ed25519-signed — stays on the
    server; the recipient link/retrieval is handled in the GUI). Slow, serialized."""
    if action == "report_save":
        return await request("POST", f"/api/incidents/{incident_id}/reports", json=data or {}, expensive=True)
    return await request("POST", f"/api/incidents/{incident_id}/le-package", json=data or {}, expensive=True)


@tool("standard")
async def fenrir_post_incident_write(
    action: Literal["lessons_update", "checklist_add", "checklist_update", "checklist_meta_update"],
    incident_id: str,
    item_id: str | None = None,
    data: dict | None = None,
) -> dict:
    """Post-Incident Activity (800-61 R3) writes: update lessons learned, add a
    checklist item, update one, or update its metadata (item_id required for updates)."""
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
