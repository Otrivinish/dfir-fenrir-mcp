"""RD (FENRIR readiness deferrals): fenrir_dashboard view=readiness passes `deferral` and the deferred counts through
unchanged; deferring (POST, standard mode) and undoing (DELETE, full mode) go through fenrir_api, which the denylist
lets through; the tool description names both."""

import asyncio

import httpx
import pytest

from fenrir_mcp import client, denylist, openapi_guard
from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import core

BODY = {
    "generated_at": "2026-11-01T12:00:00Z",
    "summary": {"blockers_failing": 0, "warnings_failing": 0, "unknown": 0,
                "blockers_deferred": 1, "warnings_deferred": 0},
    "checks": [{"id": "on_call_14d", "title": "Someone on call every day of the next 14", "level": "blocker",
                "status": "fail", "detail": "No one on call on 1 day (UTC dates): 2026-11-03.",
                "csf": ["GV.RR-02"], "fix_route": "/on-call",
                "deferral": {"by_name": "Ada Admin", "at": "2026-11-01T11:59:00Z", "reason": None}}],
}
SPEC = {"paths": {"/api/readiness": {"get": {}}, "/api/readiness/deferrals": {"post": {}},
                  "/api/readiness/deferrals/{check_id}": {"delete": {}}}}


def test_readiness_view_passes_deferral_through(monkeypatch):
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json=BODY)), base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    out = asyncio.run(core.fenrir_dashboard("readiness"))
    assert out["summary"]["blockers_deferred"] == 1
    assert out["checks"][0]["status"] == "fail" and out["checks"][0]["deferral"]["by_name"] == "Ada Admin"


@pytest.mark.parametrize("verb,path,mode", [("POST", "/api/readiness/deferrals", "standard"),
                                            ("DELETE", "/api/readiness/deferrals/on_call_14d", "full")])
def test_defer_and_undo_reachable_through_fenrir_api(monkeypatch, verb, path, mode):
    assert denylist.is_denied(verb, path) is None
    monkeypatch.setattr(openapi_guard, "_ops", openapi_guard._compile(SPEC))
    openapi_guard.validate(verb, path, mode)


def test_modes(monkeypatch):
    monkeypatch.setattr(openapi_guard, "_ops", openapi_guard._compile(SPEC))
    with pytest.raises(FenrirError):
        openapi_guard.validate("POST", "/api/readiness/deferrals", "readonly")
    with pytest.raises(FenrirError):
        openapi_guard.validate("DELETE", "/api/readiness/deferrals/on_call_14d", "standard")


def test_description_names_the_deferral_endpoints():
    doc = core.fenrir_dashboard.__doc__ or ""
    assert "POST /api/readiness/deferrals" in doc and "DELETE /api/readiness/deferrals/{check_id}" in doc
