"""Regression tests for the three bugs found in the first live session
(2026-08-25): whoami self-blocked by the denylist, SDK error masking, and the
silent viewer-token/standard-mode mismatch."""

import inspect

from mcp.server.mcpserver.exceptions import ToolError

from fenrir_mcp import denylist, server
from fenrir_mcp.client import FenrirError
from fenrir_mcp.tools import core


def test_whoami_calls_no_denylisted_endpoint():
    # Bug 1: whoami used GET /api/auth/policy, which its own denylist blocks.
    src = inspect.getsource(core.fenrir_whoami)
    assert "/api/auth" not in src
    assert denylist.is_denied("GET", "/api/users/me") is None


def test_fenrir_error_reaches_the_model_unmasked():
    # Bug 2: mcp 2.x masks non-ToolError exceptions to "Error executing tool".
    assert issubclass(FenrirError, ToolError)


def test_mode_role_gap_warns_on_mismatch():
    # Bug 3: viewer token + standard mode was a silent all-writes-403.
    assert "403" in (server.mode_role_gap("standard", "viewer") or "")
    assert "403" in (server.mode_role_gap("full", "viewer") or "")
    assert "admin tools" in (server.mode_role_gap("full", "analyst") or "")
    assert server.mode_role_gap("readonly", "viewer") is None
    assert server.mode_role_gap("standard", "analyst") is None
    assert server.mode_role_gap("full", "admin") is None
    assert server.mode_role_gap("standard", None) is None
