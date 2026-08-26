import pytest

from fenrir_mcp import config, refcache


@pytest.fixture(autouse=True)
def isolated_config(monkeypatch, tmp_path):
    """Keep tests hermetic: never read the operator's real ~/.config/fenrir-mcp."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(config, "_env_loaded", False)
    monkeypatch.setattr(refcache, "_cache", None)
    for key in config.ENV_FILE_KEYS:
        monkeypatch.delenv(key, raising=False)
