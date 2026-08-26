"""MCP server (stdio). Tools are registered per FENRIR_MCP_MODE tier; the
OpenAPI spec loads best-effort at startup (unreachable FENRIR is not fatal)."""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from . import config, denylist, openapi_guard, token_store, tools

_ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}
_MODE_NEEDS = {"readonly": "viewer", "standard": "analyst", "full": "analyst"}


def mode_role_gap(mode: str, token_role: str | None) -> str | None:
    """Human-readable warning when the stored token's role cap is below what the
    mode's registered tools need — the mismatch is otherwise silent 403s."""
    if not token_role or token_role not in _ROLE_RANK:
        return None
    needed = _MODE_NEEDS[mode]
    if _ROLE_RANK[token_role] < _ROLE_RANK[needed]:
        return (
            f"WARNING: token role={token_role} but mode={mode} needs ≥ {needed} — "
            f"every write tool will 403. Re-login as an {needed}-capable user "
            f"(fenrir-mcp login) or set FENRIR_MCP_MODE=readonly."
        )
    if mode == "full" and token_role != "admin":
        return f"note: mode=full with token role={token_role} — admin tools will 403"
    return None


def run() -> None:
    mode = config.mode()
    config.fenrir_url()  # validate early: fail fast on missing/plain-http URL
    config.ca_cert()

    spec = openapi_guard.load_spec()
    if spec:
        # Drift check (threat model T4): a new FENRIR endpoint returning bytes
        # that the denylist does not cover is surfaced loudly at every startup.
        for violation in denylist.scan_spec_for_bytes(spec):
            config.log(f"DENYLIST DRIFT WARNING: {violation}")

    meta = token_store.load_meta()
    if not meta:
        config.log("no token stored — tools will error until `fenrir-mcp login` is run")
    elif not token_store.token_age_ok():
        config.log("stored token exceeds the 8 h client TTL — run `fenrir-mcp login`")
    elif meta.get("url") and meta["url"] != config.fenrir_url():
        config.log(f"warning: token was issued for {meta['url']}, FENRIR_URL is {config.fenrir_url()}")
    if meta:
        gap = mode_role_gap(mode, meta.get("role"))
        if gap:
            config.log(gap)

    mcp = MCPServer(
        "fenrir",
        instructions=(
            "DFIR-FENRIR v2 incident-response platform. All timestamps are UTC ISO 8601 "
            "(YYYY-MM-DDTHH:MM:SSZ) — pass them through unchanged; convert to local time "
            "only when presenting to the operator. Actions are audited server-side as the "
            "operator's user. If a tool errors with 401, tell the operator to run "
            "`fenrir-mcp login` in a terminal. Token efficiency: list tools accept "
            "limit and fields=[…] — always pass fields when you only need a few keys, "
            "and prefer filtered lists over incident_get(snapshot=true). incident_id "
            "params accept either the UUID or the INC-#### ref (resolved and remembered "
            "locally). Responses omit null/empty fields by design."
        ),
    )
    count = tools.register_all(mcp, mode)
    config.log(f"mode={mode}: {count} tools registered; uploads={'on' if config.upload_dirs() else 'off'}")
    mcp.run()
