"""The denylist is the byte-ban + credential-ban boundary (threat model T4).
Every entry, the generic download rule, and normalization bypasses are covered."""

from fenrir_mcp import denylist


DENIED = [
    ("GET", "/api/auth/policy"),
    ("POST", "/api/auth/login"),
    ("POST", "/api/auth/totp/verify"),
    ("POST", "/api/tokens"),
    ("POST", "/api/admin/tokens"),
    ("POST", "/api/webhooks/elastic"),
    ("GET", "/api/exports/abc123"),
    ("GET", "/api/audit-exports/abc123"),
    ("GET", "/api/collections/abc123"),
    ("GET", "/api/le-package-ack/abc123"),
    ("POST", "/api/le-package-ack/abc123"),
    ("GET", "/api/incidents/42/evidence/7/photos/1"),
    ("GET", "/api/incidents/42/artifacts/7/download"),
    ("GET", "/api/incidents/42/files/7/download"),
    ("GET", "/api/incidents/42/entities/7/files/9/download"),
    ("POST", "/api/incidents/42/reports/7/download"),
]

ALLOWED = [
    ("GET", "/api/incidents"),
    ("GET", "/api/tokens"),                       # listing own tokens is fine
    ("DELETE", "/api/tokens/xyz"),                # revocation only reduces privilege
    ("DELETE", "/api/admin/tokens/xyz"),
    ("GET", "/api/incidents/42/detections/download"),  # text rules, owner-ruled inline-OK
    ("GET", "/api/incidents/42/evidence/7/provenance"),
    ("GET", "/api/incidents/42/post-incident/lessons/export"),
    ("POST", "/api/incidents/42/evidence/7/photos"),   # upload TO fenrir is fine
]


def test_denied():
    for method, path in DENIED:
        assert denylist.is_denied(method, path), f"{method} {path} must be denied"


def test_allowed():
    for method, path in ALLOWED:
        assert denylist.is_denied(method, path) is None, f"{method} {path} must be allowed"


def test_normalization_bypasses():
    # encoding, doubled slashes, trailing slashes and query strings must not
    # sneak a denied path past the matcher
    assert denylist.is_denied("GET", "/api/exports/%61bc")
    assert denylist.is_denied("GET", "/api%2Fexports/abc")          # double-decode
    assert denylist.is_denied("GET", "//api//exports//abc")
    assert denylist.is_denied("GET", "/api/exports/abc/")
    assert denylist.is_denied("GET", "/api/exports/abc?x=1")
    assert denylist.is_denied("POST", "/api/tokens/")
    assert denylist.is_denied("GET", "/api/incidents/42/artifacts/7/download#frag")


def test_dot_segments_fail_closed():
    # httpx canonicalises "a/../b" before sending, so a path the denylist reads
    # as innocuous can hit a denied endpoint on the wire. Any '.'/'..' segment
    # must be refused (curated tools have no spec-existence backstop).
    for method, path in [
        ("POST", "/api/incidents/x/../../tokens"),          # -> POST /api/tokens
        ("GET", "/api/incidents/x/../../exports/REALID"),   # -> GET /api/exports/REALID
        ("GET", "/api/incidents/42/artifacts/7/download/z/.."),  # -> …/download
        ("GET", "/api/incidents/x/iocs/export/../../../../exports/REALID"),
        ("GET", "/api/incidents/./iocs"),
        ("GET", "/api/incidents/x/%2e%2e/%2e%2e/tokens"),   # encoded dot-segments
    ]:
        assert denylist.is_denied(method, path), f"{method} {path} must be refused"


def test_generic_download_rule_is_fail_closed():
    # a hypothetical future byte endpoint FENRIR ships is denied by default
    assert denylist.is_denied("GET", "/api/incidents/42/some-new-feature/download")
    assert denylist.is_denied("POST", "/api/something/download")


def test_scan_spec_for_bytes_flags_uncovered_binary_ops():
    spec = {
        "paths": {
            "/api/new-thing/{id}/blob": {
                "get": {"responses": {"200": {"content": {"application/octet-stream": {}}}}}
            },
            "/api/exports/{token}": {
                "get": {"responses": {"200": {"content": {"application/zip": {}}}}}
            },
            "/api/incidents/{id}/iocs": {
                "get": {"responses": {"200": {"content": {"application/json": {}}}}}
            },
        }
    }
    violations = denylist.scan_spec_for_bytes(spec)
    assert any("/api/new-thing/{id}/blob" in v for v in violations)
    assert not any("/api/exports" in v for v in violations)          # covered by denylist
    assert not any("/api/incidents/{id}/iocs" in v for v in violations)  # json is fine
