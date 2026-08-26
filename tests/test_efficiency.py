"""Token-efficiency features (v0.1.3): response slimming, field projection, and
the persistent incident ref→UUID memory."""

from fenrir_mcp import refcache
from fenrir_mcp.client import slim
from fenrir_mcp.tools import project


def test_slim_drops_null_and_empty_fields():
    body = {
        "id": "x", "title": "t", "notes": None, "tags": [], "meta": {},
        "nested": {"keep": 1, "drop": None, "zero": 0, "false": False},
        "items": [{"a": None, "b": "y"}],
    }
    assert slim(body) == {
        "id": "x", "title": "t",
        "nested": {"keep": 1, "zero": 0, "false": False},
        "items": [{"b": "y"}],
    }


def test_project_handles_all_result_shapes():
    fields = ["id", "title"]
    item = {"id": 1, "title": "t", "big": "x" * 100}
    assert project({"items": [item], "next_cursor": "c"}, fields) == {
        "items": [{"id": 1, "title": "t"}], "next_cursor": "c",
    }
    assert project([item], fields) == [{"id": 1, "title": "t"}]
    assert project(item, fields) == {"id": 1, "title": "t"}
    assert project(item, None) == item


def test_refcache_learns_and_persists():
    refcache.learn({"items": [{"id": "uuid-1", "ref": "INC-0006", "title": "t"}]})
    assert refcache.lookup("INC-0006") == "uuid-1"
    # survives a fresh in-memory cache (reloaded from the 0600 json file)
    refcache._cache = None
    assert refcache.lookup("INC-0006") == "uuid-1"


def test_rewrite_path_translates_only_the_incident_segment():
    refcache.learn({"id": "uuid-9", "ref": "INC-0009"})
    assert refcache.rewrite_path("/api/incidents/INC-0009/timeline") == (
        "/api/incidents/uuid-9/timeline", None,
    )
    # UUIDs and non-incident paths pass through untouched
    assert refcache.rewrite_path("/api/incidents/abc-123-uuid/iocs")[1] is None
    assert refcache.rewrite_path("/api/threat-actors/INC-0009") == ("/api/threat-actors/INC-0009", None)
    # unknown ref is reported for a refresh-and-retry, not guessed
    assert refcache.rewrite_path("/api/incidents/INC-9999/iocs") == ("/api/incidents/INC-9999/iocs", "INC-9999")


def test_ioc_export_fmt_segment_never_treated_as_ref():
    # /api/incidents/{id}/iocs/export/{fmt} — only segment 3 is rewritten
    path = "/api/incidents/uuid-1/iocs/export/STIX-2"
    assert refcache.rewrite_path(path) == (path, None)


def test_refcache_rejects_path_injecting_ids():
    # Adversary-authored FENRIR response tries to poison the cache with an id
    # that would inject path segments when substituted into a request path.
    refcache.learn({"items": [
        {"id": "x/../../tokens", "ref": "INC-9001"},
        {"id": "a/b", "ref": "INC-9002"},
        {"id": "..", "ref": "INC-9003"},
        {"id": "good-uuid-0001", "ref": "INC-9004"},
    ]})
    assert refcache.lookup("INC-9001") is None
    assert refcache.lookup("INC-9002") is None
    assert refcache.lookup("INC-9003") is None
    assert refcache.lookup("INC-9004") == "good-uuid-0001"  # clean id still cached
