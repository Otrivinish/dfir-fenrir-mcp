"""E4: fenrir_entity_write file_update — pick a Supporting-documents file as a report figure.
Asserts the exact request sent; a 422 (not an image) / 403 (viewer) / 409 (closed) surfaces as FenrirError."""

import asyncio
import json

import httpx
import pytest

from fenrir_mcp import client
from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import entities

INC = "11111111-1111-4111-8111-111111111111"
FID = "44444444-4444-4444-8444-444444444444"


def _recorder(monkeypatch, status=200, body=None):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, req.url.path, json.loads(req.content) if req.content else None))
        return httpx.Response(status, json=body if body is not None else {})
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})
    return seen


def test_file_update_patches_the_file(monkeypatch):
    seen = _recorder(monkeypatch, body={"id": FID, "include_in_report": True, "report_caption": "Fig"})
    out = asyncio.run(entities.fenrir_entity_write(
        "file_update", INC, file_id=FID, data={"include_in_report": True, "report_caption": "Fig"}))
    assert seen == [("PATCH", f"/api/incidents/{INC}/files/{FID}", {"include_in_report": True, "report_caption": "Fig"})]
    assert out["include_in_report"] is True


def test_file_update_needs_file_id(monkeypatch):
    seen = _recorder(monkeypatch)
    with pytest.raises(FenrirError, match="file_id"):
        asyncio.run(entities.fenrir_entity_write("file_update", INC, data={"include_in_report": True}))
    assert seen == []


@pytest.mark.parametrize("status", [403, 409, 422])
def test_file_update_errors_surface(monkeypatch, status):
    _recorder(monkeypatch, status=status, body={"detail": "no", "code": "unsupported_report_image"})
    with pytest.raises(FenrirError, match=str(status)):
        asyncio.run(entities.fenrir_entity_write("file_update", INC, file_id=FID, data={"include_in_report": True}))
