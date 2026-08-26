"""Tier-gated tool registry. A tool above the configured mode is never
registered — it does not exist, so it cannot be prompt-injected (threat model T1)."""

from __future__ import annotations

import importlib
from typing import Callable

from .. import config

_REGISTRY: list[tuple[int, Callable]] = []

_MODULES = [
    "core", "incidents", "timeline", "iocs", "entities", "evidence",
    "tasks_respond", "comms", "people", "legal_costs", "forensic",
    "intel", "reports", "admin", "escape",
]


def tool(tier: str) -> Callable:
    level = config.TIER[tier]

    def deco(fn: Callable) -> Callable:
        _REGISTRY.append((level, fn))
        return fn

    return deco


def params(**kw) -> dict:
    """Drop None values — shared query/body builder for tool modules."""
    return {k: v for k, v in kw.items() if v is not None}


def project(result, fields: list | None):
    """Token-efficiency projection: keep only the named keys of each item.
    Understands FENRIR's {items, next_cursor} list shape, plain lists, and
    single objects. fields=None returns the result untouched."""
    if not fields:
        return result

    def pick(d):
        return {k: d[k] for k in fields if k in d} if isinstance(d, dict) else d

    if isinstance(result, dict) and isinstance(result.get("items"), list):
        return {**result, "items": [pick(i) for i in result["items"]]}
    if isinstance(result, list):
        return [pick(i) for i in result]
    return pick(result)


def register_all(mcp, mode: str) -> int:
    for name in _MODULES:
        importlib.import_module(f"{__name__}.{name}")
    level = config.TIER[mode]
    count = 0
    for tier, fn in _REGISTRY:
        if tier <= level:
            mcp.tool()(fn)
            count += 1
    return count


def registered(mode: str) -> list[str]:
    for name in _MODULES:
        importlib.import_module(f"{__name__}.{name}")
    level = config.TIER[mode]
    return sorted(fn.__name__ for tier, fn in _REGISTRY if tier <= level)
