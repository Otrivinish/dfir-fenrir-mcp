"""FENRIR J3: lessons_update passes meeting_minutes through unchanged (PATCH …/post-incident/lessons)."""

import asyncio
import json

import httpx

from fenrir_mcp import client
from fenrir_mcp.tools import reports


def test_lessons_update_passes_meeting_minutes(monkeypatch):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append({"method": req.method, "path": req.url.path, "body": req.content})
        return httpx.Response(200, json={"id": "x", "meeting_minutes": "Agenda: …"})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    data = {"meeting_minutes": "Agenda: timeline review.\nDecision: rotate keys.", "conducted_at": "2026-10-06T09:00:00Z"}
    asyncio.run(reports.fenrir_post_incident_write("lessons_update", "11111111-1111-4111-8111-111111111111", data=data))
    r = seen[-1]
    assert (r["method"], r["path"]) == ("PATCH", "/api/incidents/11111111-1111-4111-8111-111111111111/post-incident/lessons")
    assert json.loads(r["body"]) == data
    assert "meeting_minutes" in reports.fenrir_post_incident_write.__doc__
