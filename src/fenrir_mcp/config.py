"""Environment-driven configuration. Secure defaults: mode=readonly, uploads disabled."""

from __future__ import annotations

import os
import stat
import sys
from datetime import timedelta
from pathlib import Path

MODES = ("readonly", "standard", "full")
TIER = {"readonly": 0, "standard": 1, "full": 2}

CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 120.0

# Server-side token expiry is days-granular (min 1 day); the 8 h design TTL is
# enforced client-side against the recorded issue time. See docs/DESIGN.md §5.2.
TOKEN_MAX_AGE = timedelta(hours=8)

# Keys that may come from ~/.config/fenrir-mcp/env. The bearer token is NOT
# configurable via env or file — it only ever lives in the token store.
ENV_FILE_KEYS = (
    "FENRIR_URL", "FENRIR_CA_CERT", "FENRIR_MCP_MODE",
    "FENRIR_MCP_UPLOAD_DIRS", "FENRIR_MCP_REQUIRE_KEYRING", "FENRIR_MCP_SLIM",
)

_env_loaded = False


def _load_env_file() -> None:
    """Fill unset FENRIR_* vars from ~/.config/fenrir-mcp/env (KEY=VALUE lines,
    # comments). Real environment always wins; unknown keys are ignored."""
    global _env_loaded
    if _env_loaded:
        return
    _env_loaded = True
    try:
        lines = (config_dir() / "env").read_text().splitlines()
    except FileNotFoundError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip("'\"")
        if key in ENV_FILE_KEYS and key not in os.environ:
            os.environ[key] = value


def fenrir_url() -> str:
    _load_env_file()
    url = os.environ.get("FENRIR_URL", "").rstrip("/")
    if not url:
        raise RuntimeError("FENRIR_URL is not set (e.g. https://fenrir.example.internal)")
    if not url.startswith("https://"):
        raise RuntimeError("FENRIR_URL must be https:// — TLS is not optional")
    return url


def ca_cert() -> str | None:
    _load_env_file()
    path = os.environ.get("FENRIR_CA_CERT")
    if not path:
        return None
    p = Path(path).expanduser()
    if not p.is_file():
        raise RuntimeError(f"FENRIR_CA_CERT points at a missing file: {p}")
    return str(p)


def mode() -> str:
    _load_env_file()
    m = os.environ.get("FENRIR_MCP_MODE", "readonly").lower()
    if m not in MODES:
        raise RuntimeError(f"FENRIR_MCP_MODE must be one of {MODES}, got {m!r}")
    return m


def upload_dirs() -> list[Path]:
    _load_env_file()
    raw = os.environ.get("FENRIR_MCP_UPLOAD_DIRS", "")
    return [Path(p).expanduser().resolve() for p in raw.split(":") if p.strip()]


def require_keyring() -> bool:
    _load_env_file()
    return os.environ.get("FENRIR_MCP_REQUIRE_KEYRING", "").lower() in ("1", "true", "yes")


def slim_enabled() -> bool:
    """Strip null/empty fields from responses before they cost context tokens.
    On by default; FENRIR_MCP_SLIM=0 returns raw API payloads."""
    _load_env_file()
    return os.environ.get("FENRIR_MCP_SLIM", "1").lower() not in ("0", "false", "no")


def config_dir() -> Path:
    d = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "fenrir-mcp"
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    return d


def check_upload_path(file_path: str) -> Path:
    """Resolve and validate a local upload path against the allowlist. Fail closed."""
    dirs = upload_dirs()
    if not dirs:
        raise RuntimeError(
            "uploads are disabled: set FENRIR_MCP_UPLOAD_DIRS to a colon-separated "
            "allowlist of directories (e.g. ~/cases)"
        )
    p = Path(file_path).expanduser().resolve()
    if not p.is_file():
        raise RuntimeError(f"not a file: {p}")
    if not any(p.is_relative_to(d) for d in dirs):
        raise RuntimeError(f"{p} is outside FENRIR_MCP_UPLOAD_DIRS ({':'.join(map(str, dirs))})")
    return p


def read_upload(file_path: str) -> tuple[str, bytes]:
    """Validate against the allowlist and read through a single file descriptor —
    no re-open by name, closing the check-vs-read TOCTOU (a concurrent symlink
    swap between validation and read can't redirect the read to another file).
    Returns (filename, content)."""
    p = check_upload_path(file_path)
    fd = os.open(p, os.O_RDONLY)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RuntimeError(f"not a regular file: {p}")
        chunks = []
        while chunk := os.read(fd, 1 << 20):
            chunks.append(chunk)
    finally:
        os.close(fd)
    return p.name, b"".join(chunks)


def log(msg: str) -> None:
    print(f"fenrir-mcp: {msg}", file=sys.stderr)
