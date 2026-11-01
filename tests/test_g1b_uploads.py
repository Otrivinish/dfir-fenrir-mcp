"""FENRIR G1 stage 3b: evidence_register(digital), email_analyze / pcap_analyze (analyze) and
webhistory_import (upload) stream the local file through FENRIR's chunked upload session API
(POST …/uploads → PUT …/chunks/{i} raw octet-stream → POST …/complete), then the G3 analysers run
from the registered exhibit. The file is never read whole; a failed chunk resumes from the
session's next_index; any failure cancels the session."""

import asyncio
import hashlib
import json
import os
import tracemalloc

import httpx
import pytest

from fenrir_mcp import client
from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import evidence, forensic

INC = "11111111-1111-4111-8111-111111111111"
EID = "22222222-2222-4222-8222-222222222222"
UID = "44444444-4444-4444-8444-444444444444"
MIB = 1024 * 1024


class FakeFenrir:
    """Just enough of the upload session API to drive the client (and record what it sent)."""

    def __init__(self, chunk_size=MIB, fail=None, link="registered", keep=True):
        self.cs, self.fail, self.link, self.keep = chunk_size, dict(fail or {}), link, keep
        self.calls, self.chunks, self.size, self.next, self.body = [], {}, 0, 0, None
        self.received, self.n, self.h, self.streamed = bytearray(), 0, hashlib.sha256(), None

    def __call__(self, req: httpx.Request) -> httpx.Response:
        p, m = req.url.path, req.method
        self.calls.append((m, p, req.headers.get("content-type", "")))
        base = f"/api/incidents/{INC}/uploads"
        if m == "POST" and p == base:
            self.body = json.loads(req.content)
            self.size = self.body["size"]
            return httpx.Response(201, json={"upload_id": UID, "incident_id": INC, "purpose": self.body["purpose"],
                                             "chunk_size": self.cs, "chunk_count": -(-self.size // self.cs),
                                             "next_index": 0, "received_bytes": 0})
        if m == "PUT" and p.startswith(f"{base}/{UID}/chunks/"):
            i = int(p.rsplit("/", 1)[1])
            act = self.fail.pop((i, len([c for c in self.calls if c[1] == p])), None)
            if act == "network":
                raise httpx.ConnectError("boom", request=req)
            if act == "lost":                     # applied, but the answer is lost
                self._apply(i, req.content)
                raise httpx.ReadError("lost", request=req)
            if isinstance(act, int):
                return httpx.Response(act, json={"detail": "x", "code": "rate_limited" if act == 429 else "e"},
                                      headers={"Retry-After": "0"} if act == 429 else {})
            if act == "gone":
                return httpx.Response(404, json={"detail": "gone", "code": "upload_not_found"})
            if i != self.next:
                return httpx.Response(409, json={"detail": "order", "code": "upload_out_of_order",
                                                 "next_index": self.next})
            self._apply(i, req.content)
            return httpx.Response(200, json={"upload_id": UID, "next_index": self.next, "received_bytes": self.n})
        if m == "GET" and p == f"{base}/{UID}":
            return httpx.Response(200, json={"upload_id": UID, "next_index": self.next, "received_bytes": self.n})
        if m == "POST" and p == f"{base}/{UID}/complete":
            self.complete = json.loads(req.content)
            if self.fail.pop("complete", None):
                return httpx.Response(422, json={"detail": "bad", "code": "hash_mismatch"})
            return httpx.Response(201 if self.link != "sha256_match" else 200, json={
                "upload_id": UID, "purpose": self.complete["purpose"], "exhibit_link": self.link, "evidence_id": EID,
                "evidence": {"id": EID, "identifier": "PCAP-ABC", "sha256": self.h.hexdigest()}})
        if m == "DELETE" and p == f"{base}/{UID}":
            return httpx.Response(204)
        if m == "POST" and "/from-evidence/" in p:
            self.analysed = (p, req.content)
            if self.fail.pop("analyse", None):
                return httpx.Response(503, json={"detail": "worker down", "code": "analysis_worker_unavailable"})
            return httpx.Response(201, json={"result_id": "r1", "evidence_id": EID, "exhibit_link": "from_evidence"})
        return httpx.Response(404, json={"detail": f"unmocked {m} {p}", "code": "mock"})

    def _apply(self, i, content):
        if self.streamed is not None:              # StreamingTransport already hashed and counted it
            content, (length, _) = b"", self.streamed
        else:
            length = len(content)
            self.n += length
            self.h.update(content)
        assert length <= self.cs
        self.chunks[i] = length
        if self.keep:
            self.received += content
        self.next = i + 1


class StreamingTransport(httpx.AsyncBaseTransport):
    """Like a real socket: reads a request body piece by piece and keeps none of it (MockTransport
    reads the whole body into the request first, which a real transport never does)."""

    def __init__(self, fake):
        self.fake, self.pieces = fake, []

    async def handle_async_request(self, request):
        self.fake.streamed = None
        if request.method == "PUT":
            n = 0
            async for piece in request.stream:
                self.fake.h.update(piece)
                self.pieces.append(len(piece))
                n += len(piece)
            assert n == int(request.headers["content-length"])
            self.fake.n += n
            self.fake.streamed = (n, None)
            request = httpx.Request(request.method, request.url, headers={"content-type": "application/octet-stream"})
        else:
            await request.aread()
        return self.fake(request)


@pytest.fixture
def fake(monkeypatch, tmp_path):
    monkeypatch.setenv("FENRIR_MCP_UPLOAD_DIRS", str(tmp_path))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    real_sleep = asyncio.sleep
    monkeypatch.setattr(client.asyncio, "sleep", lambda *_a, **_k: real_sleep(0))

    def make(**kw):
        f = FakeFenrir(**kw)
        monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(f),
                                                                 base_url="https://fenrir.test"))
        return f
    return make


def _file(tmp_path, name, n):
    p = tmp_path / name
    p.write_bytes(os.urandom(n))
    return p


def test_evidence_digital_streams_chunks_then_completes_with_json(fake, tmp_path):
    srv = fake()
    f = _file(tmp_path, "disk.e01", 3 * MIB + 77)
    data = {"name": "disk", "identifier": "EXH-1", "device_types": ["computer"], "write_blocker_used": True,
            "system_time_offset_seconds": -120, "acquisition_hash_target": "ab" * 32}
    out = asyncio.run(evidence.fenrir_evidence_register("digital", INC, file_path=str(f), data=data))
    raw = f.read_bytes()
    assert srv.body == {"purpose": "evidence", "filename": "disk.e01", "size": len(raw),
                        "expected_hash": hashlib.sha256(raw).hexdigest()}
    assert [c for c in srv.calls if c[0] == "PUT"] == [
        ("PUT", f"/api/incidents/{INC}/uploads/{UID}/chunks/{i}", "application/octet-stream") for i in range(4)]
    assert srv.chunks == {0: MIB, 1: MIB, 2: MIB, 3: 77}
    assert bytes(srv.received) == raw
    assert srv.complete == {"purpose": "evidence", **data}           # JSON, native types (no form encoding)
    assert out["id"] == EID                                           # the created evidence, as before
    assert not any("multipart" in c[2] for c in srv.calls)
    assert ("DELETE", f"/api/incidents/{INC}/uploads/{UID}", "") not in srv.calls


def test_evidence_mime_type_guessed_from_the_name(fake, tmp_path):
    srv = fake()
    f = _file(tmp_path, "capture.pcap", 10)
    asyncio.run(evidence.fenrir_evidence_register("digital", INC, file_path=str(f), data={"name": "c", "identifier": "C"}))
    assert srv.body["mime_type"] == "application/vnd.tcpdump.pcap"


def test_the_file_is_never_read_whole(monkeypatch, tmp_path):
    monkeypatch.setenv("FENRIR_MCP_UPLOAD_DIRS", str(tmp_path))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    srv = FakeFenrir(chunk_size=8 * MIB, keep=False)
    tr = StreamingTransport(srv)
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=tr, base_url="https://fenrir.test"))
    f = _file(tmp_path, "big.raw", 40 * MIB + 5)
    want = hashlib.sha256(f.read_bytes()).hexdigest()
    reads = []
    real_pread, real_read = os.pread, os.read

    def spy_pread(fd, n, off):
        reads.append(n)
        return real_pread(fd, n, off)
    monkeypatch.setattr(client.os, "pread", spy_pread)
    monkeypatch.setattr(os, "read", lambda fd, n: pytest.fail("the upload must not read() the file"))
    tracemalloc.start()
    asyncio.run(evidence.fenrir_evidence_register("digital", INC, file_path=str(f), data={"name": "b", "identifier": "B"}))
    _cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    monkeypatch.setattr(os, "read", real_read)
    assert max(reads) == MIB and max(tr.pieces) == MIB, (max(reads), max(tr.pieces))   # 1 MiB pieces only
    assert srv.chunks == {0: 8 * MIB, 1: 8 * MIB, 2: 8 * MIB, 3: 8 * MIB, 4: 8 * MIB, 5: 5}
    assert srv.n == 40 * MIB + 5 and srv.h.hexdigest() == want == srv.body["expected_hash"]
    assert peak < 6 * MIB, f"peak {peak / MIB:.1f} MiB for a 40 MiB file (8 MiB chunks): bounded by the 1 MiB piece"


def test_a_failed_chunk_is_retried_and_resumes_from_next_index(fake, tmp_path):
    srv = fake(fail={(1, 1): "network", (2, 1): 503, (3, 1): "lost", (4, 1): 429})
    f = _file(tmp_path, "x.bin", 5 * MIB + 1)
    asyncio.run(evidence.fenrir_evidence_register("digital", INC, file_path=str(f), data={"name": "x", "identifier": "X"}))
    assert bytes(srv.received) == f.read_bytes()                      # chunk 3 landed once despite the lost answer
    assert sorted(srv.chunks) == list(range(6))
    assert ("GET", f"/api/incidents/{INC}/uploads/{UID}", "") in srv.calls    # resumed from the server's next_index
    assert srv.complete["purpose"] == "evidence"


def test_a_lost_session_says_start_again_and_cancels(fake, tmp_path):
    srv = fake(fail={(1, 1): "gone"})
    f = _file(tmp_path, "x.bin", 2 * MIB)
    with pytest.raises(FenrirError, match="upload_interrupted"):
        asyncio.run(evidence.fenrir_evidence_register("digital", INC, file_path=str(f), data={"name": "x", "identifier": "X"}))
    assert ("DELETE", f"/api/incidents/{INC}/uploads/{UID}", "") in srv.calls


def test_a_refused_complete_cancels_the_session(fake, tmp_path):
    srv = fake(fail={"complete": True})
    f = _file(tmp_path, "x.bin", 10)
    with pytest.raises(FenrirError, match="hash_mismatch"):
        asyncio.run(evidence.fenrir_evidence_register("digital", INC, file_path=str(f), data={"name": "x", "identifier": "X"}))
    assert srv.calls[-1][:2] == ("DELETE", f"/api/incidents/{INC}/uploads/{UID}")


def test_gives_up_after_repeated_failures(fake, tmp_path):
    srv = fake(fail={(0, n): 502 for n in range(1, 10)})
    f = _file(tmp_path, "x.bin", 10)
    with pytest.raises(FenrirError, match="502"):
        asyncio.run(evidence.fenrir_evidence_register("digital", INC, file_path=str(f), data={"name": "x", "identifier": "X"}))
    assert len([c for c in srv.calls if c[0] == "PUT"]) == client.UPLOAD_RETRIES + 1
    assert srv.calls[-1][0] == "DELETE"


def test_upload_respects_the_allowlist(fake, tmp_path, monkeypatch):
    srv = fake()
    outside = tmp_path.parent / "outside.bin"
    outside.write_bytes(b"x")
    with pytest.raises(RuntimeError, match="outside FENRIR_MCP_UPLOAD_DIRS"):
        asyncio.run(evidence.fenrir_evidence_register("digital", INC, file_path=str(outside), data={"name": "x", "identifier": "X"}))
    assert srv.calls == []


@pytest.mark.parametrize("tool, kwargs, purpose, complete, tail, analyse_body", [
    (forensic.fenrir_email_analyze, {"action": "analyze", "data": {"acquired_at": "2026-03-01T09:00:00Z"}}, "email",
     {"purpose": "email", "acquired_at": "2026-03-01T09:00:00Z"}, "email", b""),
    (forensic.fenrir_pcap_analyze, {"action": "analyze"}, "pcap", {"purpose": "pcap"}, "pcap", b""),
    (forensic.fenrir_webhistory_import, {"action": "upload", "data": {"browser": "firefox"}}, "webhistory",
     {"purpose": "webhistory", "browser": "firefox"}, "webhistory", b'{"browser":"firefox"}'),
])
def test_g3_uploads_register_through_a_session_then_analyse_the_exhibit(fake, tmp_path, tool, kwargs, purpose,
                                                                      complete, tail, analyse_body):
    srv = fake(link="sha256_match")
    f = _file(tmp_path, "in.bin", MIB + 3)
    out = asyncio.run(tool(incident_id=INC, file_path=str(f), **kwargs))
    assert srv.body["purpose"] == purpose and "mime_type" not in srv.body
    assert srv.complete == complete
    assert srv.analysed == (f"/api/incidents/{INC}/{tail}/from-evidence/{EID}", analyse_body)
    assert out["upload"] == {"evidence_id": EID, "evidence_identifier": "PCAP-ABC", "exhibit_link": "sha256_match"}
    assert not any("multipart" in c[2] for c in srv.calls)


def test_a_failed_analysis_names_the_registered_exhibit(fake, tmp_path):
    fake(fail={"analyse": True})
    f = _file(tmp_path, "c.pcap", 30)
    with pytest.raises(FenrirError, match=r"analysis_worker_unavailable.*IS registered as exhibit PCAP-ABC.*from_evidence"):
        asyncio.run(forensic.fenrir_pcap_analyze("analyze", INC, file_path=str(f)))


def test_webhistory_upload_needs_a_browser(fake, tmp_path):
    srv = fake()
    f = _file(tmp_path, "History", 30)
    with pytest.raises(FenrirError, match="browser"):
        asyncio.run(forensic.fenrir_webhistory_import("upload", INC, file_path=str(f), data={}))
    assert srv.calls == []
