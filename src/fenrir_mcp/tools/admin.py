"""FULL-mode tools: the single consolidated delete tool, user/team admin, and
platform configuration. None of these exist below FENRIR_MCP_MODE=full.

R150/R151: the model never receives a secret and never grants access. Actions that
would (user create / update / password reset, team member add, SIEM key generate,
service-key set, SMTP / syslog / webhook saves) are not in the schemas below — they
stay in the FENRIR GUI — and denylist.py refuses their endpoints on every path."""

from __future__ import annotations

from typing import Literal

from ..client import FenrirError, request
from . import tool

# resource_type → (needs incident_id, path template). {i}=incident, {r}=resource, {s}=sub id.
_DELETABLE: dict[str, tuple[bool, str]] = {
    "timeline_event": (True, "/api/incidents/{i}/timeline/{r}"),
    "ioc": (True, "/api/incidents/{i}/iocs/{r}"),
    "ioc_timeline_link": (True, "/api/incidents/{i}/iocs/{r}/timeline-links/{s}"),
    "entity": (True, "/api/incidents/{i}/entities/{r}"),
    "entity_relation": (True, "/api/incidents/{i}/entity-relations/{r}"),
    "asset_log_event": (True, "/api/incidents/{i}/entities/{r}/asset-log/{s}"),
    "entity_file": (True, "/api/incidents/{i}/entities/{r}/files/{s}"),
    "affected_system": (True, "/api/incidents/{i}/affected-systems/{r}"),
    "comment": (True, "/api/incidents/{i}/comments/{r}"),
    "oob_log_entry": (True, "/api/incidents/{i}/oob/log/{r}"),
    "file": (True, "/api/incidents/{i}/files/{r}"),
    "cost": (True, "/api/incidents/{i}/costs/{r}"),
    "legal_deadline": (True, "/api/incidents/{i}/legal/deadlines/{r}"),
    "stakeholder": (True, "/api/incidents/{i}/stakeholders/{r}"),
    "playbook_task": (True, "/api/incidents/{i}/playbook/tasks/{r}"),
    "respond_action": (True, "/api/incidents/{i}/respond/actions/{r}"),
    "respond_decision": (True, "/api/incidents/{i}/respond/decisions/{r}"),
    "pcap_analysis": (True, "/api/incidents/{i}/pcap/{r}"),
    "webhistory_upload": (True, "/api/incidents/{i}/webhistory/{r}"),
    "artifact": (True, "/api/incidents/{i}/artifacts/{r}"),
    "collection": (True, "/api/incidents/{i}/collections/{r}"),
    "osint_session": (True, "/api/incidents/{i}/osint/sessions/{r}"),
    "checklist_item": (True, "/api/incidents/{i}/post-incident/checklist/{r}"),
    "timeline_import": (True, "/api/incidents/{i}/forensic/timeline-import/imports/{r}"),
    "attribution": (True, "/api/incidents/{i}/attributions/{r}"),
    "on_call_entry": (False, "/api/on-call/{r}"),
    "org_contact": (False, "/api/contacts/{r}"),
    "stakeholder_matrix_rule": (False, "/api/stakeholder-matrix/{r}"),
    "yara_rule": (False, "/api/yara/{r}"),
}


@tool("full")
async def fenrir_delete(
    resource_type: Literal[
        "timeline_event", "ioc", "ioc_timeline_link", "entity", "entity_relation",
        "asset_log_event", "entity_file", "affected_system", "comment", "oob_log_entry",
        "file", "cost", "legal_deadline", "stakeholder", "playbook_task",
        "respond_action", "respond_decision", "pcap_analysis", "webhistory_upload",
        "artifact", "collection", "osint_session", "checklist_item", "timeline_import",
        "attribution", "on_call_entry", "org_contact", "stakeholder_matrix_rule", "yara_rule",
    ],
    resource_id: str,
    incident_id: str | None = None,
    sub_id: str | None = None,
    reason: str | None = None,
) -> dict:
    """THE deletion tool — the only way to hard-delete records via MCP. Deletions
    are audited server-side but destructive: be certain the operator asked for
    this specific removal. sub_id is the nested id (e.g. the timeline event id of
    an ioc_timeline_link, the file id of an entity_file). legal_deadline needs
    reason (10-2000 chars, sent in the JSON body; the audit keeps it and a full
    copy of the deadline; 422 reason_required without it), and so does artifact (the
    audit keeps the reason and the hashes; 409 artifact_referenced, with `references`,
    while an email analysis, browser-history upload, collection, Defender or timeline
    import still uses it), and so do file and entity_file (Supporting documents; the audit
    keeps the reason and the file's hashes; 409 file_referenced, with `references`, while
    it is a report figure, printed in a saved report, cited by a case note, registered as
    an exhibit, linked to an exhibit / timeline event / IOC (type link; fenrir_entity_write
    unlink_file first) or — for file — attached to an entity); a closed incident
    gives 409 incident_closed, as do timeline_event, timeline_import, pcap_analysis
    and artifact. A timeline_event the server recorded itself (server_generated=true)
    can't be deleted: 409 system_event_immutable. affected_system only clears the entity's
    compromised flag (the entity stays; delete it as resource_type=entity)."""
    needs_incident, template = _DELETABLE[resource_type]
    if needs_incident and not incident_id:
        raise FenrirError(f"incident_id is required to delete {resource_type}")
    if "{s}" in template and not sub_id:
        raise FenrirError(f"sub_id is required to delete {resource_type}")
    path = template.replace("{i}", incident_id or "").replace("{r}", resource_id).replace("{s}", sub_id or "")
    if resource_type in ("legal_deadline", "artifact", "file", "entity_file") and reason is not None:
        # In the body, not ?reason= (query strings land in access logs).
        return await request("DELETE", path, json={"reason": reason})
    return await request("DELETE", path)


@tool("full")
async def fenrir_admin_users(
    action: Literal[
        "list", "get", "activity", "sessions", "teams",
        "unlock", "revoke_session", "revoke_all_sessions", "delete",
    ],
    user_id: str | None = None,
    session_id: str | None = None,
    data: dict | None = None,
) -> dict | list:
    """User administration (FENRIR admin role required): list/get users, view a
    user's activity/sessions/teams, unlock, revoke one or all sessions, delete a
    user. Creating users, changing role/active/TOTP and password resets are FENRIR
    GUI only (Admin → Users) — the MCP never grants access or handles a password."""
    body = data or {}
    if action == "list":
        return await request("GET", "/api/users")
    if not user_id:
        raise FenrirError(f"user_id is required for {action}")
    base = f"/api/users/{user_id}"
    if action == "get":
        return await request("GET", base)
    if action == "activity":
        return await request("GET", f"{base}/activity")
    if action == "sessions":
        return await request("GET", f"{base}/sessions")
    if action == "teams":
        return await request("GET", f"{base}/teams")
    if action == "unlock":
        return await request("POST", f"{base}/unlock", json=body)
    if action == "revoke_session":
        if not session_id:
            raise FenrirError("session_id is required for revoke_session")
        return await request("DELETE", f"{base}/sessions/{session_id}")
    if action == "revoke_all_sessions":
        return await request("POST", f"{base}/sessions/revoke-all")
    return await request("DELETE", base)


@tool("full")
async def fenrir_admin_teams(
    action: Literal[
        "team_create", "team_update", "team_delete", "member_remove",
        "role_create", "role_update", "role_delete",
    ],
    team_id: str | None = None,
    user_id: str | None = None,
    role_id: str | None = None,
    data: dict | None = None,
) -> dict:
    """Team + operational-role catalog administration: create/update/delete teams,
    remove members, and manage the operational role catalog (system roles are
    read-only server-side). Adding a member grants incident access: FENRIR GUI only."""
    body = data or {}
    if action == "team_create":
        return await request("POST", "/api/teams", json=body)
    if action == "role_create":
        return await request("POST", "/api/operational-roles", json=body)
    if action in ("role_update", "role_delete"):
        if not role_id:
            raise FenrirError(f"role_id is required for {action}")
        verb = "PATCH" if action == "role_update" else "DELETE"
        return await request(verb, f"/api/operational-roles/{role_id}", json=body if verb == "PATCH" else None)
    if not team_id:
        raise FenrirError(f"team_id is required for {action}")
    if action == "team_update":
        return await request("PATCH", f"/api/teams/{team_id}", json=body)
    if action == "team_delete":
        return await request("DELETE", f"/api/teams/{team_id}")
    if not user_id:
        raise FenrirError(f"user_id is required for {action}")
    return await request("DELETE", f"/api/teams/{team_id}/members/{user_id}")


@tool("full")
async def fenrir_admin_platform(
    action: Literal[
        "api_keys_status", "api_key_delete",
        "integration_get", "smtp_test", "syslog_test", "siem_key_delete",
        "backups_list", "backup_run", "storage_usage",
        "feed_create", "feed_update", "feed_delete", "feed_pull", "feeds_pull_all", "feeds_init",
        "lolbins_sync", "actor_sync",
        "playbook_template_create", "playbook_template_update", "playbook_template_delete",
        "playbook_template_review",
        "validated_tool_create", "validated_tool_update", "validated_tool_delete",
        "tokens_list", "token_revoke",
    ],
    item_id: str | None = None,
    data: dict | None = None,
) -> dict | list:
    """Platform configuration (FENRIR admin): OSINT API key status / delete
    (item_id=service), integrations (integration_get item_id ∈ smtp|syslog|webhooks|siem-key
    — secrets come back redacted; send a test; delete the SIEM key), backups,
    storage usage, threat-feed admin (pulls are slow, serialized),
    LOLBins/MITRE actor sync, playbook-template + validated-tool CRUD
    (playbook_template_review item_id=template_id marks it reviewed now — the date
    Readiness checks; system templates need an admin — and data.incident_types on
    create/update sets the types it is suggested for), and
    API-token oversight (list all users' tokens, revoke by id — issuance is
    never possible through the MCP). Setting a service key, generating the SIEM key
    and saving SMTP / syslog / webhook config are FENRIR GUI only (secrets, outbound
    redirection). The incident-reference prefix (new incidents get PREFIX-YYYY-NNNNN; existing
    refs never change) is read / set with fenrir_api GET / PATCH /api/settings/incident-ref
    {prefix: 2-10 chars, A-Z then A-Z/0-9}; GET also previews the next ref (not reserved)."""
    body = data or {}
    simple = {
        "api_keys_status": ("GET", "/api/settings/api-keys", False),
        "backups_list": ("GET", "/api/admin/backups", False),
        "backup_run": ("POST", "/api/admin/backups/run", False),
        "storage_usage": ("GET", "/api/admin/storage", False),
        "smtp_test": ("POST", "/api/integrations/smtp/test", False),
        "syslog_test": ("POST", "/api/integrations/syslog/test", False),
        "siem_key_delete": ("DELETE", "/api/integrations/siem-key", False),
        "feed_create": ("POST", "/api/threat-intel/feeds", False),
        "feeds_pull_all": ("POST", "/api/threat-intel/feeds/pull-all", True),
        "feeds_init": ("POST", "/api/threat-intel/feeds/init", False),
        "lolbins_sync": ("POST", "/api/lolbins/sync", True),
        "actor_sync": ("POST", "/api/threat-actors/sync", True),
        "playbook_template_create": ("POST", "/api/playbook-templates", False),
        "validated_tool_create": ("POST", "/api/validated-tools", False),
        "tokens_list": ("GET", "/api/admin/tokens", False),
    }
    if action in simple:
        verb, path, expensive = simple[action]
        return await request(verb, path, json=body if verb in ("POST", "PUT") else None, expensive=expensive)
    if not item_id:
        raise FenrirError(f"item_id is required for {action}")
    by_item = {
        "api_key_delete": ("DELETE", f"/api/settings/api-keys/{item_id}"),
        "integration_get": ("GET", f"/api/integrations/{item_id}"),
        "feed_update": ("PATCH", f"/api/threat-intel/feeds/{item_id}"),
        "feed_delete": ("DELETE", f"/api/threat-intel/feeds/{item_id}"),
        "feed_pull": ("POST", f"/api/threat-intel/feeds/{item_id}/pull"),
        "playbook_template_update": ("PATCH", f"/api/playbook-templates/{item_id}"),
        "playbook_template_delete": ("DELETE", f"/api/playbook-templates/{item_id}"),
        "playbook_template_review": ("POST", f"/api/playbook-templates/{item_id}/review"),
        "validated_tool_update": ("PATCH", f"/api/validated-tools/{item_id}"),
        "validated_tool_delete": ("DELETE", f"/api/validated-tools/{item_id}"),
        "token_revoke": ("DELETE", f"/api/admin/tokens/{item_id}"),
    }
    verb, path = by_item[action]
    return await request(
        verb, path, json=body if verb in ("POST", "PUT", "PATCH") else None,
        expensive=(action == "feed_pull"),
    )
