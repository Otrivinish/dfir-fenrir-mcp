"""L4 (R131/R50/R118/R134): the MCP names itself on every request (User-Agent fenrir-mcp/<version>), and
reads FENRIR's flat error shapes: 422 validation_error with errors[], role-cap 403 insufficient_role, and
the edge proxy's bodiless 413."""

import asyncio

import httpx
import pytest

from fenrir_mcp import __version__, cli, client, config
from fenrir_mcp.client import FenrirError, _raise_for
from fenrir_mcp.tools import incidents


def _message(status, body=None, content=b""):
    resp = httpx.Response(status, json=body) if body is not None else httpx.Response(status, content=content)
    with pytest.raises(FenrirError) as exc:
        _raise_for(resp)
    return str(exc.value)


def test_user_agent_on_every_request(monkeypatch):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req.headers.get("user-agent"))
        return httpx.Response(200, json={"id": "x", "ref": "INC-2026-00001"})

    real = httpx.AsyncClient

    def patched(**kw):                      # the real constructor, with a mock transport
        return real(transport=httpx.MockTransport(handler), **kw)

    monkeypatch.setattr(client, "_client", None)
    monkeypatch.setattr(client.httpx, "AsyncClient", patched)
    monkeypatch.setattr(config, "fenrir_url", lambda: "https://fenrir.test")
    monkeypatch.setattr(client, "ssl_context", lambda: True)
    monkeypatch.setattr(client, "_bearer", lambda: {"Authorization": "Bearer t"})
    asyncio.run(incidents.fenrir_incident_get("INC-2026-00001"))
    asyncio.run(client.request("GET", "/api/users/me"))
    assert seen and all(ua == f"fenrir-mcp/{__version__}" for ua in seen), seen
    monkeypatch.setattr(client, "_client", None)


def test_cli_client_sends_user_agent(monkeypatch):
    monkeypatch.setattr(config, "fenrir_url", lambda: "https://fenrir.test")
    monkeypatch.setattr(cli, "ssl_context", lambda: True)
    with cli._client() as c:
        assert c.headers["User-Agent"] == f"fenrir-mcp/{__version__}"


def test_validation_error_shape():
    msg = _message(422, {"detail": "Invalid request: query.limit: Input should be less than or equal to 200",
                         "code": "validation_error",
                         "errors": [{"loc": ["query", "limit"], "msg": "Input should be less than or equal to 200",
                                     "type": "less_than_equal"}]})
    assert msg.startswith("FENRIR returned 422: [validation_error] Invalid request: query.limit:")
    assert '"loc": ["query", "limit"]' in msg          # field info reaches the model


def test_role_cap_403_keeps_hint():
    msg = _message(403, {"detail": "Requires role: ('admin', 'analyst')", "code": "insufficient_role"})
    assert "role cap" in msg and "[insufficient_role]" in msg
    assert "role cap" in _message(403, {"detail": "Forbidden", "code": "forbidden"})
    assert "role cap" not in _message(403, {"detail": "no", "code": "not_custodian"})


def test_bodiless_413_is_readable():
    msg = _message(413)
    assert msg.startswith("FENRIR returned 413: the request body is larger than FENRIR accepts")


def test_generic_code_on_plain_404():
    assert _message(404, {"detail": "Incident not found", "code": "incident_not_found"}) == \
        "FENRIR returned 404: [incident_not_found] Incident not found"
