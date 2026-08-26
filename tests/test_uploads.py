"""Upload allowlist (threat model T10): paths outside FENRIR_MCP_UPLOAD_DIRS
fail structurally; unset allowlist means uploads are disabled (secure default)."""

import pytest

from fenrir_mcp import config


def test_uploads_disabled_by_default(monkeypatch, tmp_path):
    monkeypatch.delenv("FENRIR_MCP_UPLOAD_DIRS", raising=False)
    sample = tmp_path / "a.eml"
    sample.write_text("x")
    with pytest.raises(RuntimeError, match="uploads are disabled"):
        config.check_upload_path(str(sample))


def test_path_inside_allowlist_ok(monkeypatch, tmp_path):
    monkeypatch.setenv("FENRIR_MCP_UPLOAD_DIRS", str(tmp_path))
    sample = tmp_path / "cases" / "a.eml"
    sample.parent.mkdir()
    sample.write_text("x")
    assert config.check_upload_path(str(sample)) == sample.resolve()


def test_path_outside_allowlist_denied(monkeypatch, tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside.eml"
    outside.write_text("x")
    monkeypatch.setenv("FENRIR_MCP_UPLOAD_DIRS", str(allowed))
    with pytest.raises(RuntimeError, match="outside FENRIR_MCP_UPLOAD_DIRS"):
        config.check_upload_path(str(outside))


def test_traversal_out_of_allowlist_denied(monkeypatch, tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    secret = tmp_path / "secret.key"
    secret.write_text("x")
    monkeypatch.setenv("FENRIR_MCP_UPLOAD_DIRS", str(allowed))
    sneaky = str(allowed / ".." / "secret.key")
    with pytest.raises(RuntimeError, match="outside FENRIR_MCP_UPLOAD_DIRS"):
        config.check_upload_path(sneaky)


def test_missing_file_denied(monkeypatch, tmp_path):
    monkeypatch.setenv("FENRIR_MCP_UPLOAD_DIRS", str(tmp_path))
    with pytest.raises(RuntimeError, match="not a file"):
        config.check_upload_path(str(tmp_path / "nope.eml"))


def test_read_upload_returns_name_and_bytes(monkeypatch, tmp_path):
    monkeypatch.setenv("FENRIR_MCP_UPLOAD_DIRS", str(tmp_path))
    sample = tmp_path / "a.eml"
    sample.write_bytes(b"hello")
    assert config.read_upload(str(sample)) == ("a.eml", b"hello")


def test_read_upload_enforces_allowlist(monkeypatch, tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside.eml"
    outside.write_bytes(b"x")
    monkeypatch.setenv("FENRIR_MCP_UPLOAD_DIRS", str(allowed))
    with pytest.raises(RuntimeError, match="outside FENRIR_MCP_UPLOAD_DIRS"):
        config.read_upload(str(outside))


def test_read_upload_rejects_directory(monkeypatch, tmp_path):
    monkeypatch.setenv("FENRIR_MCP_UPLOAD_DIRS", str(tmp_path))
    d = tmp_path / "sub"
    d.mkdir()
    with pytest.raises(RuntimeError):  # not a file / not a regular file
        config.read_upload(str(d))
