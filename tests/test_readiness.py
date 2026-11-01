"""E1: fenrir_dashboard view=readiness reads GET /api/readiness and passes the body through;
a viewer token's 403 surfaces as a FenrirError."""

import asyncio

import httpx
import pytest

from fenrir_mcp import client
from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import core

BODY = {
    "generated_at": "2026-10-03T12:00:00Z",
    "summary": {"blockers_failing": 1, "warnings_failing": 0, "unknown": 0},
    "checks": [{"id": "on_call_14d", "title": "Someone on call every day of the next 14", "level": "blocker",
                "status": "fail", "detail": "No one on call on 1 day (UTC dates): 2026-10-06.",
                "csf": ["GV.RR-02"], "fix_route": "/on-call"}],
}


def _mock(monkeypatch, handler):
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})


def test_readiness_view(monkeypatch):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, req.url.path, req.url.query))
        return httpx.Response(200, json=BODY)

    _mock(monkeypatch, handler)
    out = asyncio.run(core.fenrir_dashboard("readiness"))
    assert seen == [("GET", "/api/readiness", b"")]
    assert out["summary"]["blockers_failing"] == 1 and out["checks"][0]["id"] == "on_call_14d"


def test_readiness_viewer_forbidden(monkeypatch):
    _mock(monkeypatch, lambda req: httpx.Response(403, json={"detail": "Requires role: ('admin', 'analyst')"}))
    with pytest.raises(FenrirError, match="403"):
        asyncio.run(core.fenrir_dashboard("readiness"))
