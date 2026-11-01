"""FENRIR J4 (handoff prefill / IC transfer / promote) and J5 (decision/action/task links): the MCP tools
reach the new API surface with the right method, path and body."""

import asyncio
import json

import httpx

from fenrir_mcp import client
from fenrir_mcp.tools import comms, people, tasks_respond

INC = "11111111-1111-4111-8111-111111111111"


def _mock(monkeypatch, reply=None):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append({"method": req.method, "path": req.url.path, "query": dict(req.url.params),
                     "body": json.loads(req.content) if req.content else None})
        return httpx.Response(200, json=reply if reply is not None else {"ok": True})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    return seen


def test_handoff_prefill_view(monkeypatch):
    seen = _mock(monkeypatch, {"phase": "detection_and_analysis", "open_actions": [], "open_tasks": []})
    asyncio.run(people.fenrir_people_list("handoff_prefill", incident_id=INC))
    assert (seen[-1]["method"], seen[-1]["path"]) == ("GET", f"/api/incidents/{INC}/handoffs/prefill")


def test_assignable_writers_only(monkeypatch):
    seen = _mock(monkeypatch, [])
    asyncio.run(people.fenrir_people_list("assignable_users", incident_id=INC, writers_only=True))
    assert seen[-1]["path"] == "/api/users/assignable"
    assert seen[-1]["query"] == {"incident_id": INC, "writers_only": "true"}
    asyncio.run(people.fenrir_people_list("assignable_users", incident_id=INC))
    assert "writers_only" not in seen[-1]["query"]


def test_handoff_create_passes_transfer_ic_and_create_task(monkeypatch):
    seen = _mock(monkeypatch)
    data = {"incoming_user_id": "22222222-2222-4222-8222-222222222222", "transfer_ic": True,
            "next_steps": [{"action": "Re-image WS-12", "priority": "high", "create_task": True}]}
    asyncio.run(people.fenrir_people_write("handoff_create", incident_id=INC, data=data))
    assert (seen[-1]["method"], seen[-1]["path"], seen[-1]["body"]) == ("POST", f"/api/incidents/{INC}/handoffs", data)
    assert "transfer_ic" in people.fenrir_people_write.__doc__ and "create_task" in people.fenrir_people_write.__doc__


def test_promote(monkeypatch):
    seen = _mock(monkeypatch, {"target": "decision", "id": "x"})
    data = {"source_kind": "warroom", "source_id": "33333333-3333-4333-8333-333333333333", "target": "decision",
            "text": "Isolate the DC", "event_time": "2026-10-06T09:00:00Z", "outcome": "approved"}
    asyncio.run(comms.fenrir_comms_write("promote", incident_id=INC, data=data))
    assert (seen[-1]["method"], seen[-1]["path"], seen[-1]["body"]) == ("POST", f"/api/incidents/{INC}/promote", data)


def test_respond_links_pass_through(monkeypatch):
    seen = _mock(monkeypatch)
    a = {"category": "containment", "title": "Isolate", "decision_id": "d", "task_id": "t"}
    asyncio.run(tasks_respond.fenrir_respond_write("action_add", INC, data=a))
    assert (seen[-1]["path"], seen[-1]["body"]) == (f"/api/incidents/{INC}/respond/actions", a)
    asyncio.run(tasks_respond.fenrir_respond_write("decision_update", INC, item_id="dd", data={"action_ids": []}))
    assert (seen[-1]["method"], seen[-1]["path"], seen[-1]["body"]) == (
        "PATCH", f"/api/incidents/{INC}/respond/decisions/dd", {"action_ids": []})
    doc = tasks_respond.fenrir_respond_write.__doc__
    assert "decision_id" in doc and "action_ids" in doc and "task_id" in doc
