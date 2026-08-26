"""Escape-hatch guard: the OpenAPI spec (live-fetched, cached 0600) is the contract;
`fenrir_api` calls must name an operation that exists in it, pass the denylist,
and use a verb the configured mode allows. No spec → the escape hatch refuses
(fail closed); curated tools are unaffected."""

from __future__ import annotations

import json
import os
import re

import httpx

from . import config, denylist
from .client import FenrirError, ssl_context

_VERBS_BY_MODE = {
    "readonly": {"GET"},
    "standard": {"GET", "POST", "PATCH", "PUT"},
    "full": {"GET", "POST", "PATCH", "PUT", "DELETE"},
}

_spec: dict | None = None
_ops: list[tuple[str, re.Pattern]] | None = None  # (VERB, compiled path pattern)


def _cache_path():
    return config.config_dir() / "openapi.json"


def _compile(spec: dict) -> list[tuple[str, re.Pattern]]:
    ops = []
    for path, verbs in spec.get("paths", {}).items():
        pattern = re.compile("^" + re.sub(r"\{[^}]+\}", r"[^/]+", path) + "$")
        for verb in verbs:
            if verb.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                ops.append((verb.upper(), pattern))
    return ops


def load_spec() -> dict | None:
    """Fetch the live spec (best effort), fall back to the cache. Never fatal."""
    global _spec, _ops
    try:
        resp = httpx.get(
            config.fenrir_url() + "/api/openapi.json", verify=ssl_context(), timeout=config.CONNECT_TIMEOUT
        )
        resp.raise_for_status()
        _spec = resp.json()
        fd = os.open(_cache_path(), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(_spec, f)
        config.log("OpenAPI spec fetched from FENRIR")
    except Exception as e:
        try:
            _spec = json.loads(_cache_path().read_text())
            config.log(f"live spec fetch failed ({e.__class__.__name__}); using cached copy")
        except Exception:
            _spec = None
            config.log(f"no OpenAPI spec available ({e.__class__.__name__}); fenrir_api will refuse calls")
    _ops = _compile(_spec) if _spec else None
    return _spec


def get_spec() -> dict | None:
    return _spec


def validate(method: str, path: str, mode: str) -> None:
    """Raise FenrirError unless method+path is allowed for the escape hatch."""
    verb = method.upper()
    if verb not in _VERBS_BY_MODE[mode]:
        raise FenrirError(
            f"{verb} is not allowed through fenrir_api in mode={mode} "
            f"(allowed: {sorted(_VERBS_BY_MODE[mode])})"
        )
    p = denylist.normalize(path)
    reason = denylist.is_denied(verb, p)
    if reason:
        raise FenrirError(f"denied by policy: {reason}")
    if _ops is None:
        raise FenrirError(
            "no OpenAPI spec available to validate against — FENRIR unreachable and no cache. "
            "Refusing (fail closed); curated tools still work."
        )
    if not any(v == verb and pat.match(p) for v, pat in _ops):
        raise FenrirError(f"{verb} {p} does not exist in FENRIR's OpenAPI spec")
