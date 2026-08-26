"""Token at rest: OS keyring primary, 0600 file fallback (fallback requires FDE — README).

Non-secret metadata (url, token id/prefix/role, issue time) always lives in a
0600 JSON file so `status` works without unlocking the keyring.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from . import config

_SERVICE = "fenrir-mcp"
_ACCOUNT = "api-token"


def _meta_path():
    return config.config_dir() / "meta.json"


def _token_path():
    return config.config_dir() / "token"


def _keyring():
    try:
        import keyring
        from keyring.errors import KeyringError  # noqa: F401

        # A fail/null backend advertises priority 0 and silently loses secrets.
        backend = keyring.get_keyring()
        if getattr(backend, "priority", 0) < 1:
            return None
        return keyring
    except Exception:
        return None


def store(token: str, meta: dict) -> str:
    """Persist token + metadata. Returns 'keyring' or 'file' (where the secret went)."""
    meta = dict(meta, issued_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    kr = _keyring()
    if kr is not None:
        kr.set_password(_SERVICE, _ACCOUNT, token)
        _token_path().unlink(missing_ok=True)
        location = "keyring"
    elif config.require_keyring():
        raise RuntimeError("no usable OS keyring and FENRIR_MCP_REQUIRE_KEYRING is set — refusing file fallback")
    else:
        fd = os.open(_token_path(), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(token)
        location = "file"
    meta["storage"] = location
    fd = os.open(_meta_path(), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(meta, f, indent=2)
    return location


def load_meta() -> dict | None:
    try:
        return json.loads(_meta_path().read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def load_token() -> str | None:
    kr = _keyring()
    if kr is not None:
        try:
            token = kr.get_password(_SERVICE, _ACCOUNT)
            if token:
                return token
        except Exception:
            pass
    if config.require_keyring():
        return None
    try:
        return _token_path().read_text().strip() or None
    except FileNotFoundError:
        return None


def token_age_ok() -> bool:
    meta = load_meta()
    if not meta or "issued_at" not in meta:
        return False
    issued = datetime.strptime(meta["issued_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - issued < config.TOKEN_MAX_AGE


def clear() -> None:
    kr = _keyring()
    if kr is not None:
        try:
            kr.delete_password(_SERVICE, _ACCOUNT)
        except Exception:
            pass
    _token_path().unlink(missing_ok=True)
    _meta_path().unlink(missing_ok=True)
