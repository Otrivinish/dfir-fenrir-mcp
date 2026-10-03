"""Wave C fix-up (M7): ioc_write add_batch sends the API's {"items": …} body, and FENRIR's flat
error codes ({detail, code, …extra}) reach the model as "[code] detail" plus the extra keys,
without the token/role-cap hint on a coded 403."""

import asyncio
import json

import httpx
import pytest

from fenrir_mcp import client
from fenrir_mcp.client import FenrirError, _raise_for
from fenrir_mcp.tools import iocs


def _mock(monkeypatch, handler):
    monkeypatch.setattr(client, "_client", httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                                             base_url="https://fenrir.test"))
    monkeypatch.setattr(client, "_bearer", lambda: {})


def _message(status, body, headers=None):
    with pytest.raises(FenrirError) as exc:
        _raise_for(httpx.Response(status, json=body, headers=headers))
    return str(exc.value)


def test_add_batch_posts_items(monkeypatch):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, req.url.path, req.content))
        return httpx.Response(201, json={"created": 2, "skipped": 0, "errors": []})

    _mock(monkeypatch, handler)
    batch = [{"type": "ip", "value": "203.0.113.9"}, {"type": "domain", "value": "c2.example"}]
    out = asyncio.run(iocs.fenrir_ioc_write("add_batch", "00000000-0000-4000-8000-000000000001", iocs=batch))
    assert out["created"] == 2          # (the client drops empty fields from responses)
    assert len(seen) == 1
    method, path, content = seen[0]
    assert (method, path) == ("POST", "/api/incidents/00000000-0000-4000-8000-000000000001/iocs/batch")
    assert json.loads(content) == {"items": batch}


def test_add_batch_requires_a_list():
    with pytest.raises(FenrirError, match="iocs list is required"):
        asyncio.run(iocs.fenrir_ioc_write("add_batch", "x", iocs=[]))


def test_coded_error_is_code_then_detail():
    msg = _message(409, {"detail": "Incident is closed", "code": "incident_closed"})
    assert msg == "FENRIR returned 409: [incident_closed] Incident is closed"


def test_extra_keys_are_passed_on():
    msg = _message(409, {"detail": "Gate 2 is not met: Lessons learned not final", "code": "gate_unmet",
                         "gate": "close", "unmet": [{"key": "ll_not_final", "label": "Lessons learned not final"}]})
    assert msg.startswith("FENRIR returned 409: [gate_unmet] Gate 2 is not met")
    assert '"gate": "close"' in msg and '"ll_not_final"' in msg


def test_extra_keys_are_capped():
    unmet = [{"key": f"k{i}", "label": "x" * 100} for i in range(200)]
    msg = _message(409, {"detail": "d", "code": "gate_unmet", "gate": "close", "unmet": unmet})
    assert len(msg) < 2200


def test_coded_403_has_no_role_cap_hint():
    msg = _message(403, {"detail": "Only the custodian or an admin can transfer this item", "code": "not_custodian"})
    assert msg == "FENRIR returned 403: [not_custodian] Only the custodian or an admin can transfer this item"
    assert "role cap" not in msg and "fenrir-mcp status" not in msg


def test_uncoded_403_keeps_role_cap_hint():
    msg = _message(403, {"detail": "Forbidden"})
    assert "role cap" in msg and msg.endswith("Forbidden")


def test_uncoded_and_validation_errors_unchanged():
    assert _message(404, {"detail": "Action not found"}) == "FENRIR returned 404: Action not found"
    msg = _message(422, {"detail": [{"loc": ["body", "items"], "msg": "Field required"}]})
    assert msg.startswith("FENRIR returned 422: [{") and "[code]" not in msg


def test_coded_422_and_429():
    msg = _message(422, {"detail": "isolate_host can't target an IOC of type hash_sha256", "code": "target_type_mismatch"})
    assert msg == "FENRIR returned 422: [target_type_mismatch] isolate_host can't target an IOC of type hash_sha256"
    msg = _message(429, {"detail": "slow down", "code": "rate_limited"}, headers={"Retry-After": "7"})
    assert "Retry-After: 7s" in msg and "[rate_limited] slow down" in msg
