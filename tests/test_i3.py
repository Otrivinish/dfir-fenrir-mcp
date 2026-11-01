"""FENRIR I3: playbook apply mode/reason, task due/skip reason, archived history, templates by
incident type and mark reviewed -- the exact requests the tools send, and the guards."""

import asyncio
import json

import httpx
import pytest

from fenrir_mcp import client
from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import admin, tasks_respond

INC = "11111111-1111-4111-8111-111111111111"
TPL = "22222222-2222-4222-8222-222222222222"
TID = "33333333-3333-4333-8333-333333333333"


def _recorder(monkeypatch, body=None):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append({"method": req.method, "path": req.url.path, "query": dict(req.url.params), "body": req.content})
        return httpx.Response(200, json=body if body is not None else [])
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    return seen


def test_tasks_list_default_and_archived(monkeypatch):
    seen = _recorder(monkeypatch)
    asyncio.run(tasks_respond.fenrir_task_list(INC))
    assert (seen[-1]["path"], seen[-1]["query"]) == (f"/api/incidents/{INC}/playbook/tasks", {})
    asyncio.run(tasks_respond.fenrir_task_list(INC, include_archived=True))
    assert seen[-1]["query"] == {"include_archived": "true"}


def test_templates_by_incident_type(monkeypatch):
    seen = _recorder(monkeypatch)
    asyncio.run(tasks_respond.fenrir_task_list(view="templates", incident_type="ransomware"))
    assert (seen[-1]["path"], seen[-1]["query"]) == ("/api/playbook-templates", {"incident_type": "ransomware"})
    asyncio.run(tasks_respond.fenrir_task_list(view="templates"))
    assert seen[-1]["query"] == {}
    with pytest.raises(FenrirError):
        asyncio.run(tasks_respond.fenrir_task_list(INC, view="tasks", incident_type="ransomware"))


def test_instantiate_passes_mode_and_reason(monkeypatch):
    seen = _recorder(monkeypatch)
    data = {"template_id": TPL, "mode": "replace", "reason": "Reclassified to ransomware"}
    asyncio.run(tasks_respond.fenrir_task_write("instantiate_template", INC, data=data))
    r = seen[-1]
    assert (r["method"], r["path"]) == ("POST", f"/api/incidents/{INC}/playbook/instantiate")
    assert json.loads(r["body"]) == data


def test_task_update_due_and_skip_reason(monkeypatch):
    seen = _recorder(monkeypatch, body={"id": TID})
    data = {"status": "skipped", "skip_reason": "Not applicable", "due_at": None}
    asyncio.run(tasks_respond.fenrir_task_write("update", INC, task_id=TID, data=data))
    r = seen[-1]
    assert (r["method"], r["path"]) == ("PATCH", f"/api/incidents/{INC}/playbook/tasks/{TID}")
    assert json.loads(r["body"]) == data


def test_template_review(monkeypatch):
    seen = _recorder(monkeypatch, body={"id": TPL, "last_reviewed_at": "2026-10-06T10:00:00Z"})
    out = asyncio.run(admin.fenrir_admin_platform("playbook_template_review", item_id=TPL))
    assert (seen[-1]["method"], seen[-1]["path"]) == ("POST", f"/api/playbook-templates/{TPL}/review")
    assert out["last_reviewed_at"].endswith("Z")
    with pytest.raises(FenrirError):
        asyncio.run(admin.fenrir_admin_platform("playbook_template_review"))
