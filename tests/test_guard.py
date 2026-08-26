"""Escape-hatch guard: verb-by-mode gating, spec existence check, denylist
precedence, and fail-closed behaviour with no spec."""

import pytest

from fenrir_mcp import openapi_guard
from fenrir_mcp.client import FenrirError

SPEC = {
    "paths": {
        "/api/incidents": {"get": {}, "post": {}},
        "/api/incidents/{incident_id}": {"get": {}, "patch": {}, "delete": {}},
        "/api/exports/{token}": {"get": {}},
        "/api/tokens": {"get": {}, "post": {}},
    }
}


@pytest.fixture(autouse=True)
def loaded_spec():
    openapi_guard._spec = SPEC
    openapi_guard._ops = openapi_guard._compile(SPEC)
    yield
    openapi_guard._spec = None
    openapi_guard._ops = None


def test_readonly_allows_only_get():
    openapi_guard.validate("GET", "/api/incidents", "readonly")
    with pytest.raises(FenrirError, match="not allowed"):
        openapi_guard.validate("POST", "/api/incidents", "readonly")


def test_standard_allows_writes_but_not_delete():
    openapi_guard.validate("POST", "/api/incidents", "standard")
    openapi_guard.validate("PATCH", "/api/incidents/42", "standard")
    with pytest.raises(FenrirError, match="not allowed"):
        openapi_guard.validate("DELETE", "/api/incidents/42", "standard")


def test_full_allows_delete():
    openapi_guard.validate("DELETE", "/api/incidents/42", "full")


def test_unknown_path_rejected():
    with pytest.raises(FenrirError, match="does not exist"):
        openapi_guard.validate("GET", "/api/nonexistent", "full")


def test_denylist_wins_even_in_full_mode():
    with pytest.raises(FenrirError, match="denied by policy"):
        openapi_guard.validate("GET", "/api/exports/abc", "full")
    with pytest.raises(FenrirError, match="denied by policy"):
        openapi_guard.validate("POST", "/api/tokens", "full")


def test_no_spec_fails_closed():
    openapi_guard._spec = None
    openapi_guard._ops = None
    with pytest.raises(FenrirError, match="fail closed"):
        openapi_guard.validate("GET", "/api/incidents", "readonly")
