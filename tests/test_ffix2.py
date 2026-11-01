"""F-fix 2: R65 fenrir_artifact_write update sends the one form field the PATCH reads
(a JSON body wiped the description with a 200); R69 fenrir_respond_list pages with
limit/cursor, and fenrir_intel_lookup correlations take tag/limit/cursor.
Each test asserts the exact request sent."""

import asyncio
from urllib.parse import parse_qs

import httpx
import pytest

from fenrir_mcp import client
from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import forensic, intel, tasks_respond

INC = "11111111-1111-4111-8111-111111111111"
AID = "55555555-5555-4555-8555-555555555555"
EID = "66666666-6666-4666-8666-666666666666"


def _recorder(monkeypatch, status=200, body=None):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append({"method": req.method, "path": req.url.path, "params": dict(req.url.params),
                     "ctype": req.headers.get("content-type", ""), "body": req.content.decode()})
        return httpx.Response(status, json=body if body is not None else {"items": [], "next_cursor": None})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    return seen


# ── R65: artifact update ────────────────────────────────────────────────────

def test_artifact_update_sends_description_as_form_field(monkeypatch):
    seen = _recorder(monkeypatch, body={"id": AID, "description": "Dropper from INC mail"})
    out = asyncio.run(forensic.fenrir_artifact_write("update", INC, artifact_id=AID,
                                                     data={"description": "Dropper from INC mail"}))
    assert len(seen) == 1
    r = seen[0]
    assert (r["method"], r["path"]) == ("PATCH", f"/api/incidents/{INC}/artifacts/{AID}")
    assert r["ctype"].startswith("application/x-www-form-urlencoded")   # never JSON (R65)
    assert parse_qs(r["body"]) == {"description": ["Dropper from INC mail"]}
    assert out["description"] == "Dropper from INC mail"


def test_artifact_update_null_description_clears(monkeypatch):
    seen = _recorder(monkeypatch, body={"id": AID})
    asyncio.run(forensic.fenrir_artifact_write("update", INC, artifact_id=AID, data={"description": None}))
    assert seen[0]["ctype"].startswith("application/x-www-form-urlencoded")
    assert seen[0]["body"] == "description="


@pytest.mark.parametrize("data", [None, {}, {"name": "x"}, {"description": "d", "tlp": "red"}])
def test_artifact_update_needs_exactly_description(monkeypatch, data):
    """Without the field the API would store null (the R65 wipe); other fields are not
    updatable, so they are refused instead of silently dropped. Nothing is sent."""
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError, match="description"):
        asyncio.run(forensic.fenrir_artifact_write("update", INC, artifact_id=AID, data=data))
    assert seen == []


# ── R69: respond_list paging ────────────────────────────────────────────────

@pytest.mark.parametrize("view", ["actions", "decisions"])
def test_respond_list_passes_limit_and_cursor(monkeypatch, view):
    seen = _recorder(monkeypatch)
    asyncio.run(tasks_respond.fenrir_respond_list(INC, view=view, limit=200, cursor="eyJvIjogMjAwfQ"))
    assert seen[0]["path"] == f"/api/incidents/{INC}/respond/{view}"
    assert seen[0]["params"] == {"limit": "200", "cursor": "eyJvIjogMjAwfQ"}


def test_respond_list_paging_with_entity_filter_and_defaults(monkeypatch):
    seen = _recorder(monkeypatch)
    asyncio.run(tasks_respond.fenrir_respond_list(INC, entity_id=EID, limit=5))
    asyncio.run(tasks_respond.fenrir_respond_list(INC))
    assert seen[0]["params"] == {"entity_id": EID, "limit": "5"}
    assert seen[1]["params"] == {}   # server defaults (limit 100)


# ── R69: correlations tag / limit / cursor ─────────────────────────────────

def test_correlations_iocs_tag_limit_cursor(monkeypatch):
    seen = _recorder(monkeypatch)
    asyncio.run(intel.fenrir_intel_lookup("correlations_iocs", tag="c2", limit=10, cursor="eyJvIjogMTB9"))
    assert seen[0]["path"] == "/api/correlations/iocs"
    assert seen[0]["params"] == {"tag": "c2", "limit": "10", "cursor": "eyJvIjogMTB9"}


def test_correlations_entities_limit_cursor(monkeypatch):
    seen = _recorder(monkeypatch)
    asyncio.run(intel.fenrir_intel_lookup("correlations_entities", limit=3, cursor="eyJvIjogM30"))
    assert seen[0]["path"] == "/api/correlations/entities"
    assert seen[0]["params"] == {"limit": "3", "cursor": "eyJvIjogM30"}


def test_correlations_without_paging_sends_no_params(monkeypatch):
    seen = _recorder(monkeypatch)
    asyncio.run(intel.fenrir_intel_lookup("correlations_iocs"))
    assert seen[0]["params"] == {}


@pytest.mark.parametrize("view,kw,msg", [
    ("correlations_entities", {"tag": "c2"}, "tag"),
    ("threat_actors", {"tag": "c2"}, "tag"),
    ("threat_actors", {"limit": 5}, "limit"),
    ("yara_rules", {"cursor": "x"}, "cursor"),
])
def test_paging_and_tag_refused_where_ignored(monkeypatch, view, kw, msg):
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError, match=msg):
        asyncio.run(intel.fenrir_intel_lookup(view, **kw))
    assert seen == []


def test_invalid_tag_422_surfaces(monkeypatch):
    _recorder(monkeypatch, status=422, body={"detail": "Tag filter '!!!' has no usable characters", "code": "invalid_tag"})
    with pytest.raises(FenrirError, match="invalid_tag"):
        asyncio.run(intel.fenrir_intel_lookup("correlations_iocs", tag="!!!"))
