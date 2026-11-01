"""FENRIR I5 (gates v2): fenrir_incident_write action=sign_off posts {role, statement} to
/api/incidents/{id}/gates/{gate}/sign-off (gate taken out of data and validated locally), and the
gates view still reads GET …/gates."""

import asyncio
import json

import httpx
import pytest

from fenrir_mcp import client
from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import incidents

INC = "11111111-1111-4111-8111-111111111111"


def _recorder(monkeypatch, body=None):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append({"method": req.method, "path": req.url.path, "body": req.content})
        return httpx.Response(200, json=body if body is not None else {})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    return seen


@pytest.mark.parametrize("gate", ["post_incident", "close"])
def test_sign_off_posts_to_gate(monkeypatch, gate):
    seen = _recorder(monkeypatch, body={"id": "x"})
    asyncio.run(incidents.fenrir_incident_write(
        "sign_off", incident_id=INC, data={"gate": gate, "role": "ic", "statement": "Approved for close-out"}))
    r = seen[-1]
    assert (r["method"], r["path"]) == ("POST", f"/api/incidents/{INC}/gates/{gate}/sign-off")
    assert json.loads(r["body"]) == {"role": "ic", "statement": "Approved for close-out"}


@pytest.mark.parametrize("data", [None, {}, {"gate": "preparation", "role": "ic", "statement": "x" * 12}])
def test_sign_off_needs_valid_gate(monkeypatch, data):
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError):
        asyncio.run(incidents.fenrir_incident_write("sign_off", incident_id=INC, data=data))
    assert seen == []


def test_sign_off_needs_incident(monkeypatch):
    _recorder(monkeypatch)
    with pytest.raises(FenrirError):
        asyncio.run(incidents.fenrir_incident_write("sign_off", data={"gate": "close", "role": "ic"}))


def test_gates_view_unchanged(monkeypatch):
    seen = _recorder(monkeypatch, body={"items": []})
    asyncio.run(incidents.fenrir_incident_get(INC, gates=True))
    assert (seen[-1]["method"], seen[-1]["path"]) == ("GET", f"/api/incidents/{INC}/gates")
