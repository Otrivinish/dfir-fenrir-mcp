"""Persistent incident ref→UUID memory (~/.config/fenrir-mcp/refcache.json, 0600).

FENRIR's API takes incident UUIDs; humans and Claude think in `INC-0006` refs.
The cache learns id/ref pairs from every incident response that passes through
the client, so tools accept either form without a wasted incident_list round
trip. Non-secret metadata only."""

from __future__ import annotations

import json
import os
import re

from . import config

REF_RE = re.compile(r"^[A-Z]{2,10}-[A-Za-z0-9]{1,12}$")
# The cached id is substituted into a request path, so it must not carry path
# separators or dot-segments (a poisoned FENRIR response could otherwise inject
# e.g. "x/../../tokens"). FENRIR ids are UUIDs; this charset covers them and
# stays permissive for other opaque id formats while blocking path injection.
ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_REF_KEYS = ("ref", "reference", "incident_ref")

_cache: dict[str, str] | None = None


def _path():
    return config.config_dir() / "refcache.json"


def _load() -> dict[str, str]:
    global _cache
    if _cache is None:
        try:
            _cache = json.loads(_path().read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            _cache = {}
    return _cache


def _save() -> None:
    fd = os.open(_path(), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(_cache, f)


def lookup(ref: str) -> str | None:
    return _load().get(ref)


def learn(obj) -> None:
    """Harvest id/ref pairs from any incident-shaped response (item, list, or
    {items: [...]}). Cheap, silent, and lossless — unknown shapes are ignored."""
    cache = _load()
    before = len(cache)

    def visit(d):
        if not isinstance(d, dict):
            return
        ident = d.get("id")
        if not (isinstance(ident, str) and ID_RE.match(ident)):
            return  # reject path-injecting ids from adversary-authored responses
        for key in _REF_KEYS:
            ref = d.get(key)
            if isinstance(ref, str) and REF_RE.match(ref):
                cache[ref] = ident
                break

    if isinstance(obj, dict):
        visit(obj)
        items = obj.get("items")
        if isinstance(items, list):
            for it in items:
                visit(it)
    elif isinstance(obj, list):
        for it in obj:
            visit(it)
    if len(cache) != before:
        _save()


def rewrite_path(path: str, look=lookup) -> tuple[str, str | None]:
    """Translate the incident-id segment of /api/incidents/<X>/… when <X> is a
    ref. Returns (path, unresolved_ref) — unresolved_ref is set when the ref is
    not in memory yet (caller refreshes and retries). Only the segment directly
    after /api/incidents/ is ever touched."""
    if not path.startswith("/api/incidents/"):
        return path, None
    segs = path.split("/")
    seg = segs[3] if len(segs) > 3 else ""
    if not REF_RE.match(seg):
        return path, None
    uuid = look(seg)
    if uuid:
        segs[3] = uuid
        return "/".join(segs), None
    return path, seg
