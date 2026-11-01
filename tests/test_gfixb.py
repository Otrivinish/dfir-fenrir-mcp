"""FENRIR G-fix B: M5 (a cancelled upload still DELETEs its session, shielded; also when the token check
would now fail), M6 (export_create / le_package_prepare get the long read timeout and never lose the key
silently), L13 (the session's purpose wins over complete's keys), L20 (legal_hold_release needs
confirm=true), include_unsealed_drafts on the export / LE tools."""

import asyncio
import json

import anyio
import httpx
import pytest

from fenrir_mcp import client, config
from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import evidence, reports

from test_g1b_uploads import EID, INC, UID, FakeFenrir, _file


@pytest.fixture
def wired(monkeypatch, tmp_path):
    monkeypatch.setenv("FENRIR_MCP_UPLOAD_DIRS", str(tmp_path))
    monkeypatch.setattr(client, "_bearer", lambda: {"Authorization": "Bearer t"})

    def make(handler):
        monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                                 base_url="https://fenrir.test"))
    return make


def test_cancelled_upload_still_deletes_its_session_shielded(monkeypatch, tmp_path):
    """M5: the tool call is cancelled while a chunk is in flight; the session is DELETEd anyway — and with
    the token check broken after the session opened, the DELETE still goes out with the headers taken then."""
    monkeypatch.setenv("FENRIR_MCP_UPLOAD_DIRS", str(tmp_path))
    srv = FakeFenrir(chunk_size=1024)
    started = asyncio.Event()
    seen = []

    async def handler(req: httpx.Request):
        seen.append((req.method, req.url.path, req.headers.get("authorization")))
        if req.method == "PUT":
            started.set()
            await asyncio.sleep(30)                  # hangs until the caller is cancelled
        return srv(req)

    class AsyncMock(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            await request.aread()
            return await handler(request)
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=AsyncMock(), base_url="https://fenrir.test"))
    p = _file(tmp_path, "big.bin", 4096)

    def bearer():
        if started.is_set():                         # the token "expires" while the chunk is in flight
            raise FenrirError("no stored FENRIR token")
        return {"Authorization": "Bearer t"}
    monkeypatch.setattr(client, "_bearer", bearer)

    async def run():
        async with anyio.create_task_group() as tg:
            tg.start_soon(client.upload_file, INC, str(p), "evidence", {"name": "n", "identifier": "i"})
            await started.wait()
            tg.cancel_scope.cancel()                 # the operator cancels the tool call
    asyncio.run(run())
    assert ("DELETE", f"/api/incidents/{INC}/uploads/{UID}", "Bearer t") in seen


def test_complete_body_purpose_cannot_be_overridden(wired, tmp_path):
    """L13: data carrying "purpose" never changes the purpose sent to complete."""
    srv = FakeFenrir()
    wired(srv)
    p = tmp_path / "c.pcap"
    p.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 100)
    asyncio.run(client.upload_file(INC, str(p), "pcap", {"purpose": "evidence", "acquired_at": "2026-03-01T10:00:00Z"}))
    assert srv.complete["purpose"] == "pcap" and srv.complete["acquired_at"] == "2026-03-01T10:00:00Z"


def _recorder(monkeypatch, status=201, body=None):
    seen = []

    async def handler(req: httpx.Request):
        seen.append({"method": req.method, "path": req.url.path, "body": req.content.decode() or "{}",
                     "timeout": req.extensions.get("timeout")})
        return httpx.Response(status, json=body if body is not None else {"ok": True})

    class T(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            await request.aread()
            return await handler(request)
    monkeypatch.setattr(client, "_bearer", lambda: {})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=T(), base_url="https://fenrir.test",
                                                             timeout=httpx.Timeout(config.READ_TIMEOUT, connect=5)))
    return seen


def test_export_create_uses_the_long_timeout_and_passes_the_drafts_flag(monkeypatch):
    seen = _recorder(monkeypatch)
    asyncio.run(evidence.fenrir_evidence_custody("export_create", INC, data={"item_ids": [EID], "recipient": "LE",
                                                                              "purpose": "p"},
                                                 include_unsealed_drafts=True))
    assert seen[0]["path"] == f"/api/incidents/{INC}/evidence/exports"
    assert json.loads(seen[0]["body"])["include_unsealed_drafts"] is True
    assert seen[0]["timeout"]["read"] == config.LONG_READ_TIMEOUT == 1800.0


def test_le_package_prepare_uses_the_long_timeout_and_passes_the_drafts_flag(monkeypatch):
    seen = _recorder(monkeypatch, body={"bundle_password": "pw"})
    asyncio.run(reports.fenrir_report_generate("le_package_prepare", INC, data={"case_reference": "C"},
                                               include_unsealed_drafts=False))
    assert seen[0]["path"] == f"/api/incidents/{INC}/le-package"
    assert json.loads(seen[0]["body"]) == {"case_reference": "C", "include_unsealed_drafts": False}
    assert seen[0]["timeout"]["read"] == 1800.0


def test_other_calls_keep_the_normal_timeout(monkeypatch):
    seen = _recorder(monkeypatch)
    asyncio.run(reports.fenrir_report_generate("report_save", INC, data={}))
    assert seen[0]["timeout"]["read"] == config.READ_TIMEOUT


def test_a_long_call_timeout_says_the_secret_is_lost(monkeypatch):
    async def handler(req):
        raise httpx.ReadTimeout("slow", request=req)
    monkeypatch.setattr(client, "_bearer", lambda: {})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    with pytest.raises(FenrirError, match="LOST.*revoke"):
        asyncio.run(evidence.fenrir_evidence_custody("export_create", INC, data={"item_ids": [EID]}))


def test_legal_hold_release_needs_confirm(monkeypatch):
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError, match="confirm=true"):
        asyncio.run(evidence.fenrir_evidence_custody("legal_hold_release", INC, evidence_id=EID,
                                                     data={"reason": "counsel letter"}))
    assert seen == []
    asyncio.run(evidence.fenrir_evidence_custody("legal_hold_set", INC, evidence_id=EID, data={"reason": "r"}))
    assert len(seen) == 1                            # setting a hold needs no confirm
