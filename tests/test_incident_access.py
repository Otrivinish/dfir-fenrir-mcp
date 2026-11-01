"""E3: fenrir_people_list view=incident_access reads GET /api/incidents/{id}/access, and a
403 not_incident_lead reaches the model as a coded business rule (no token role-cap hint)."""

import asyncio

import httpx
import pytest

from fenrir_mcp import client
from fenrir_mcp.client import FenrirError, _raise_for
from fenrir_mcp.tools import people

INC = "00000000-0000-4000-8000-000000000003"


def _mock(monkeypatch, handler):
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})


def test_incident_access_view(monkeypatch):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, req.url.path))
        return httpx.Response(200, json={"is_lead": True, "capabilities": ["read_audit_log", "override_gate"]})

    _mock(monkeypatch, handler)
    out = asyncio.run(people.fenrir_people_list("incident_access", incident_id=INC))
    assert seen == [("GET", f"/api/incidents/{INC}/access")]
    assert out["is_lead"] is True and "override_gate" in out["capabilities"]


def test_incident_access_needs_incident_id():
    with pytest.raises(FenrirError, match="incident_id is required"):
        asyncio.run(people.fenrir_people_list("incident_access"))


def test_not_incident_lead_is_coded_without_role_hint():
    with pytest.raises(FenrirError) as exc:
        _raise_for(httpx.Response(403, json={"detail": "Only this incident's lead … can do this.",
                                             "code": "not_incident_lead"}))
    msg = str(exc.value)
    assert msg.startswith("FENRIR returned 403: [not_incident_lead]")
    assert "role cap" not in msg


# ── F2: assignable users limited to who can see an incident ────────────────────────────────────────

def test_assignable_users_incident_filter(monkeypatch):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, req.url.path, dict(req.url.params)))
        return httpx.Response(200, json=[{"id": "u1", "username": "alice", "full_name": None}])

    _mock(monkeypatch, handler)
    out = asyncio.run(people.fenrir_people_list("assignable_users", incident_id=INC))
    assert seen == [("GET", "/api/users/assignable", {"incident_id": INC})]
    assert out[0]["username"] == "alice"
    seen.clear()
    asyncio.run(people.fenrir_people_list("assignable_users"))          # no incident: unchanged call
    assert seen == [("GET", "/api/users/assignable", {})]


def test_assignable_users_resolves_an_incident_ref(monkeypatch):
    seen = []
    ref = "INC-2026-00009"

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.url.path, dict(req.url.params)))
        if req.url.path == "/api/incidents":                             # ref lookup (?ref=)
            return httpx.Response(200, json={"items": [{"id": INC, "ref": ref}], "next_cursor": None})
        if req.url.path == f"/api/incidents/{INC}":
            return httpx.Response(200, json={"id": INC, "ref": ref})
        return httpx.Response(200, json=[])

    _mock(monkeypatch, handler)
    asyncio.run(people.fenrir_people_list("assignable_users", incident_id=ref))
    assert seen[-1] == ("/api/users/assignable", {"incident_id": INC})   # the UUID, never the ref


def test_person_reference_docstrings():
    from fenrir_mcp.tools import tasks_respond
    for fn in (tasks_respond.fenrir_task_write, tasks_respond.fenrir_respond_write, people.fenrir_people_write):
        assert "assignee_no_access" in fn.__doc__ and "user_not_found" in fn.__doc__
    assert '"assignee_id": null unassigns' in tasks_respond.fenrir_task_write.__doc__
    assert "null" in tasks_respond.fenrir_respond_write.__doc__ and "decided_by_id" in tasks_respond.fenrir_respond_write.__doc__
    assert "incident_id" in people.fenrir_people_list.__doc__ and "assignable_users" in people.fenrir_people_list.__doc__
