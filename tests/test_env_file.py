"""~/.config/fenrir-mcp/env loader: fills unset FENRIR_* keys, real environment
wins, unknown keys are ignored, and the token can never come from it."""

import os

from fenrir_mcp import config


def _write_env_file(content: str) -> None:
    (config.config_dir() / "env").write_text(content)


def test_env_file_fills_unset_keys():
    _write_env_file(
        "# deployment facts\n"
        'FENRIR_URL="https://fenrir.test.internal"\n'
        "FENRIR_MCP_MODE=standard\n"
    )
    assert config.fenrir_url() == "https://fenrir.test.internal"
    assert config.mode() == "standard"


def test_real_environment_wins(monkeypatch):
    _write_env_file("FENRIR_URL=https://file.example\n")
    monkeypatch.setenv("FENRIR_URL", "https://env.example")
    assert config.fenrir_url() == "https://env.example"


def test_unknown_and_malformed_keys_ignored():
    _write_env_file(
        "FENRIR_TOKEN=fnr_v1_should_never_load\n"   # not an accepted key
        "PATH=/tmp/evil\n"
        "not a kv line\n"
        "FENRIR_MCP_MODE=readonly\n"
    )
    assert config.mode() == "readonly"
    assert "FENRIR_TOKEN" not in os.environ
    assert os.environ.get("PATH") != "/tmp/evil"


def test_missing_file_is_fine():
    assert config.mode() == "readonly"  # default, no file present
