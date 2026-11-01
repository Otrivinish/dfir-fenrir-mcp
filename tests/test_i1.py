"""FENRIR I1: the recovery tracker through fenrir_respond_list(view=recovery) and
fenrir_respond_write(recovery_update) -- the exact requests, and the guards."""

import asyncio
import json

import httpx
import pytest

from fenrir_mcp import client
from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import registered, tasks_respond

INC = "11111111-1111-4111-8111-111111111111"
EID = "33333333-3333-4333-8333-333333333333"


def _recorder(monkeypatch, status=200, body=None):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append({"method": req.method, "path": req.url.path, "query": dict(req.url.params), "body": req.content})
        return httpx.Response(status, json=body if body is not None else {"items": [], "next_cursor": None})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    return seen


def test_recovery_list_with_state_filter(monkeypatch):
    seen = _recorder(monkeypatch)
    asyncio.run(tasks_respond.fenrir_respond_list(INC, view="recovery", state="restored", limit=50))
    r = seen[-1]
    assert (r["method"], r["path"]) == ("GET", f"/api/incidents/{INC}/recovery")
    assert r["query"] == {"state": "restored", "limit": "50"}


def test_recovery_one_system(monkeypatch):
    seen = _recorder(monkeypatch, body={"entity_id": EID})
    asyncio.run(tasks_respond.fenrir_respond_list(INC, view="recovery", entity_id=EID))
    assert (seen[-1]["method"], seen[-1]["path"]) == ("GET", f"/api/incidents/{INC}/recovery/{EID}")


def test_recovery_filter_guards(monkeypatch):
    _recorder(monkeypatch)
    with pytest.raises(FenrirError):
        asyncio.run(tasks_respond.fenrir_respond_list(INC, view="actions", state="validated"))
    with pytest.raises(FenrirError):
        asyncio.run(tasks_respond.fenrir_respond_list(INC, view="recovery", ioc_id=EID))


def test_actions_view_unchanged(monkeypatch):
    seen = _recorder(monkeypatch)
    asyncio.run(tasks_respond.fenrir_respond_list(INC, entity_id=EID))
    assert (seen[-1]["path"], seen[-1]["query"]) == (f"/api/incidents/{INC}/respond/actions", {"entity_id": EID})


def test_recovery_update_patches_the_system(monkeypatch):
    seen = _recorder(monkeypatch, body={"entity_id": EID, "state": "restored"})
    data = {"state": "restored", "restore_point_ref": "veeam #7", "restored_at": "2026-10-06T10:00:00Z"}
    out = asyncio.run(tasks_respond.fenrir_respond_write("recovery_update", INC, item_id=EID, data=data))
    r = seen[-1]
    assert (r["method"], r["path"]) == ("PATCH", f"/api/incidents/{INC}/recovery/{EID}")
    assert json.loads(r["body"]) == data
    assert out["state"] == "restored"


def test_recovery_update_needs_entity_id(monkeypatch):
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError):
        asyncio.run(tasks_respond.fenrir_respond_write("recovery_update", INC, data={"state": "restoring"}))
    assert seen == []


def test_recovery_409_is_relayed(monkeypatch):
    _recorder(monkeypatch, status=409, body={"detail": "A system cannot go from not_started to restored",
                                             "code": "invalid_transition", "allowed": ["restoring", "not_required"]})
    with pytest.raises(FenrirError) as e:
        asyncio.run(tasks_respond.fenrir_respond_write("recovery_update", INC, item_id=EID, data={"state": "restored"}))
    assert "invalid_transition" in str(e.value) or "cannot go" in str(e.value)


def test_tiers_unchanged():
    assert "fenrir_respond_list" in registered("readonly")
    assert "fenrir_respond_write" in registered("standard")
    assert "fenrir_respond_write" not in registered("readonly")
