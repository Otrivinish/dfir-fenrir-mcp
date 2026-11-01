"""E-fix M3: fenrir_people_list roster / on_call / on_call_current strip responders'
oob_contact_methods (personal data) unless the caller names it in fields."""

import asyncio

import httpx
import pytest

from fenrir_mcp import client
from fenrir_mcp.tools import people

OOB = [{"channel": "mobile", "value": "+46 70 111 22 33", "preferred": True}]
ENTRY = {"id": "e1", "user_id": "u1", "username": "alice", "start_date": "2026-10-03",
         "end_date": "2026-10-09", "oob_contact_methods": OOB}
ROSTER = {"items": [{"user_id": "u1", "username": "alice", "availability": "available",
                     "oob_contact_methods": OOB},
                    {"user_id": "u2", "username": "bob", "availability": "busy",
                     "oob_contact_methods": []}]}
ON_CALL = {"items": [ENTRY, {**ENTRY, "id": "e2", "user_id": "u2", "username": "bob"}], "current": ENTRY}
BODIES = {"/api/roster": ROSTER, "/api/on-call": ON_CALL, "/api/on-call/current": ENTRY}


def _mock(monkeypatch):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, req.url.path))
        return httpx.Response(200, json=BODIES[req.url.path])
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    return seen


def _has_oob(obj) -> bool:
    if isinstance(obj, dict):
        return "oob_contact_methods" in obj or any(_has_oob(v) for v in obj.values())
    if isinstance(obj, list):
        return any(_has_oob(v) for v in obj)
    return False


@pytest.mark.parametrize("view,path", [("roster", "/api/roster"), ("on_call", "/api/on-call"),
                                       ("on_call_current", "/api/on-call/current")])
def test_oob_stripped_by_default(monkeypatch, view, path):
    seen = _mock(monkeypatch)
    out = asyncio.run(people.fenrir_people_list(view))
    assert seen == [("GET", path)]
    assert not _has_oob(out)
    assert "+46 70 111 22 33" not in repr(out)


def test_oob_stripped_from_items_and_current_keeps_other_keys(monkeypatch):
    _mock(monkeypatch)
    out = asyncio.run(people.fenrir_people_list("on_call"))
    assert [i["username"] for i in out["items"]] == ["alice", "bob"]
    assert out["current"] == {k: v for k, v in ENTRY.items() if k != "oob_contact_methods"}
    roster = asyncio.run(people.fenrir_people_list("roster"))
    assert roster == {"items": [{"user_id": "u1", "username": "alice", "availability": "available"},
                                {"user_id": "u2", "username": "bob", "availability": "busy"}]}


def test_fields_without_oob_projects_and_strips(monkeypatch):
    _mock(monkeypatch)
    out = asyncio.run(people.fenrir_people_list("roster", fields=["username"]))
    assert out == {"items": [{"username": "alice"}, {"username": "bob"}]}
    cur = asyncio.run(people.fenrir_people_list("on_call", fields=["username", "start_date"]))
    assert not _has_oob(cur)


@pytest.mark.parametrize("view", ["roster", "on_call", "on_call_current"])
def test_oob_returned_only_when_named_in_fields(monkeypatch, view):
    _mock(monkeypatch)
    out = asyncio.run(people.fenrir_people_list(view, fields=["username", "oob_contact_methods"]))
    items = out["items"] if isinstance(out, dict) and "items" in out else [out]
    assert items[0] == {"username": "alice", "oob_contact_methods": OOB}


def test_null_current_on_call(monkeypatch):
    def handler(req):
        return httpx.Response(200, json=None)
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    out = asyncio.run(people.fenrir_people_list("on_call_current"))   # the client maps an empty body
    assert not _has_oob(out)


def test_docstring_says_so():
    doc = people.fenrir_people_list.__doc__
    assert "stripped" in doc and "oob_contact_methods" in doc and "fields" in doc
