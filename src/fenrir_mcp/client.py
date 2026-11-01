"""HTTP client to FENRIR: TLS 1.3 floor, pinned internal CA, bearer auth,
structured error mapping, expensive-call serialization. Fail closed everywhere."""

from __future__ import annotations

import asyncio
import hashlib
import json
import mimetypes
import os
import ssl
from typing import Any

import anyio
import httpx
from mcp.server.mcpserver.exceptions import ToolError

from . import __version__, config, denylist, refcache, token_store

# R131 (L4): every request names this client, so FENRIR's audit rows (hash v3) show what made them.
USER_AGENT = f"fenrir-mcp/{__version__}"


class FenrirError(ToolError):
    """Subclasses the SDK's ToolError so mcp 2.x delivers the message to the
    model verbatim — anything else is masked to a bare 'Error executing tool'."""


def ssl_context() -> ssl.SSLContext:
    ca = config.ca_cert()
    if ca:
        ctx = ssl.create_default_context(cafile=ca)
        # Python 3.13+ enables VERIFY_X509_STRICT by default, which rejects the
        # generate-certs.sh CA (no keyUsage extension). With a pinned single-CA
        # trust store, chain + hostname verification still fully apply; only the
        # RFC 5280 formalities check is relaxed. Strict stays on for the system
        # trust store below.
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    else:
        ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


_client: httpx.AsyncClient | None = None
# The backend runs --workers 1: expensive synchronous endpoints are serialized
# so the MCP can never freeze FENRIR for other responders (threat model T7).
_expensive_gate = asyncio.Semaphore(1)


def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(
            base_url=config.fenrir_url(),
            verify=ssl_context(),
            timeout=httpx.Timeout(config.READ_TIMEOUT, connect=config.CONNECT_TIMEOUT),
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
        )
    return _client


def _bearer() -> dict[str, str]:
    token = token_store.load_token()
    if not token:
        raise FenrirError("no stored FENRIR token — run `fenrir-mcp login` in a terminal")
    if not token_store.token_age_ok():
        raise FenrirError("stored token is older than 8 h (client-side TTL) — run `fenrir-mcp login` again")
    return {"Authorization": f"Bearer {token}"}


_EXTRA_MAX = 2000   # chars of an error's extra keys (e.g. gate_unmet's unmet list) passed on


# Role-cap / generic 403 codes: the token's role (or incident access) is the cause, not a business rule.
_ROLE_403 = ("insufficient_role", "forbidden")


def _raise_for(resp: httpx.Response) -> None:
    """FENRIR errors are flat {detail, code, …extra}: the message is "[code] detail" plus any
    extra keys (e.g. gate, unmet; a 422 validation_error's errors[{loc, msg, type}]), so the model
    can branch on the code and see what is missing. A list-shaped detail (FENRIR before L4) is
    shown as its field messages."""
    detail = ""
    err_code = None
    try:
        body = resp.json()
        detail = body.get("detail") or body.get("message") or ""
        if isinstance(detail, list):
            detail = "; ".join(f"{'.'.join(str(p) for p in e.get('loc', []))}: {e.get('msg', '')}"
                               if isinstance(e, dict) else str(e) for e in detail)
        elif isinstance(detail, dict):
            detail = str(detail)
        if isinstance(body.get("code"), str) and body["code"]:
            err_code = body["code"]
            extra = {k: v for k, v in body.items() if k not in ("detail", "code", "message")}
            detail = f"[{err_code}] {detail}"
            if extra:
                detail += " " + json.dumps(extra, default=str, ensure_ascii=False)[:_EXTRA_MAX]
    except Exception:
        detail = resp.text[:300]
    code = resp.status_code
    if code == 413 and not detail:
        # The edge proxy's size limit answers with an empty body.
        detail = "the request body is larger than FENRIR accepts (10 MiB for JSON); nothing was stored"
    if code == 401:
        raise FenrirError("FENRIR rejected the token (401) — run `fenrir-mcp login` again. " + detail)
    if code == 403 and err_code and err_code not in _ROLE_403:
        # A coded 403 is a business rule (e.g. not_custodian), not the token's role cap.
        raise FenrirError(f"FENRIR returned 403: {detail}")
    if code == 403:
        raise FenrirError(
            f"forbidden (403): the token's role cap or incident access does not allow this. "
            f"Token role ≤ FENRIR role; check `fenrir-mcp status`. {detail}"
        )
    if code == 429:
        retry = resp.headers.get("Retry-After", "?")
        raise FenrirError(f"rate limited (429), Retry-After: {retry}s. Not retrying automatically. {detail}")
    raise FenrirError(f"FENRIR returned {code}: {detail}")


async def request(
    method: str,
    path: str,
    *,
    params: dict | None = None,
    json: Any = None,
    files: dict | None = None,
    data: dict | None = None,
    expensive: bool = False,
    long_call: bool = False,
) -> Any:
    # Incident ref memory: /api/incidents/INC-2026-00009/… → /api/incidents/<uuid>/….
    # A new ref is resolved with FENRIR's exact ?ref= filter; servers without that
    # filter ignore it, so fall back to learning from the first 200 incidents.
    path, missing = refcache.rewrite_path(path)
    if missing:
        await request("GET", "/api/incidents", params={"ref": missing, "limit": 1})
        path, missing = refcache.rewrite_path(path)
        if missing:
            await request("GET", "/api/incidents", params={"limit": 200})
            path, missing = refcache.rewrite_path(path)
        if missing:
            raise FenrirError(
                f"unknown incident ref {missing!r} — not found by exact lookup or in the first "
                "200 incidents; use the incident UUID (fenrir_incident_list shows both)"
            )
    reason = denylist.is_denied(method, path)
    if reason:
        raise FenrirError(f"denied by policy: {reason}")
    headers = _bearer()
    # M6: a call whose one-time secret is only in its response waits as long as the edge allows.
    timeout = httpx.Timeout(config.LONG_READ_TIMEOUT, connect=config.CONNECT_TIMEOUT) if long_call else httpx.USE_CLIENT_DEFAULT
    try:
        if expensive:
            async with _expensive_gate:
                resp = await _get_client().request(
                    method, path, params=params, json=json, files=files, data=data, headers=headers, timeout=timeout
                )
        else:
            resp = await _get_client().request(
                method, path, params=params, json=json, files=files, data=data, headers=headers, timeout=timeout
            )
    except ssl.SSLError as e:
        raise FenrirError(
            f"TLS verification failed: {e}. Check FENRIR_CA_CERT points at the FENRIR internal CA. "
            "Verification is never disabled."
        ) from e
    except httpx.ConnectError as e:
        raise FenrirError(f"FENRIR unreachable at {config.fenrir_url()}: {e}. VPN up?") from e
    except httpx.TimeoutException as e:
        if long_call:
            raise FenrirError(
                f"FENRIR did not answer {method} {path} within {int(config.LONG_READ_TIMEOUT)} s ({e}). The server may "
                "still finish the bundle, but its one-time key / password was in that response and is LOST: tell the "
                "operator, have them revoke that export in the GUI (Evidence → Exports) and build a smaller one."
            ) from e
        raise FenrirError(f"FENRIR timed out on {method} {path}: {e}") from e

    if resp.status_code >= 400:
        _raise_for(resp)
    if resp.status_code == 204 or not resp.content:
        return {"status": resp.status_code}
    ctype = resp.headers.get("content-type", "")
    if "application/json" in ctype:
        body = resp.json()
        if path.startswith("/api/incidents"):
            refcache.learn(body)
        return slim(body) if config.slim_enabled() else body
    return resp.text


# ── Chunked, resumable upload (FENRIR G1 stage 3b) ───────────────────────────────────────────
# A multipart upload is spooled by FENRIR to its disk in plaintext; an upload session takes raw
# chunks that FENRIR encrypts as they arrive and stores nothing until `complete`. The local file is
# streamed — each chunk's body is read from the file in ≤ 1 MiB pieces while httpx sends it, so
# neither the file nor a whole chunk is ever held in memory — and its SHA-256 is sent as
# expected_hash, so FENRIR refuses anything that changed on the way (or on disk meanwhile).

UPLOAD_RETRIES = 5
_HASH_BLOCK = 1 << 20
_PIECE = 1 << 20


def _sha256_of(fd: int) -> str:
    h = hashlib.sha256()
    off = 0
    while block := os.pread(fd, _HASH_BLOCK, off):
        h.update(block)
        off += len(block)
    return h.hexdigest()


def _interrupted() -> FenrirError:
    return FenrirError("[upload_interrupted] FENRIR no longer has this upload session (it expired after 30 "
                       "minutes without progress, or FENRIR restarted). Nothing was stored — run the tool again.")


async def _file_pieces(fd: int, offset: int, length: int):
    """A chunk's bytes, read from the file in ≤ 1 MiB pieces as they are sent."""
    end = offset + length
    while offset < end:
        piece = await asyncio.to_thread(os.pread, fd, min(_PIECE, end - offset), offset)
        if not piece:
            raise FenrirError("the file got shorter while it was being uploaded; nothing was stored")
        offset += len(piece)
        yield piece


async def _put_chunk(path: str, fd: int, offset: int, length: int) -> httpx.Response | None:
    """One chunk (streamed from the file, explicit Content-Length); None on a network failure (the
    caller resumes from the session's next_index)."""
    reason = denylist.is_denied("PUT", path)
    if reason:
        raise FenrirError(f"denied by policy: {reason}")
    try:
        return await _get_client().request(
            "PUT", path, content=_file_pieces(fd, offset, length),
            headers={**_bearer(), "Content-Type": "application/octet-stream", "Content-Length": str(length)})
    except ssl.SSLError as e:
        raise FenrirError(f"TLS verification failed: {e}. Verification is never disabled.") from e
    except httpx.TransportError:
        return None


def _code(resp: httpx.Response | None) -> str | None:
    try:
        body = resp.json() if resp is not None else None
    except Exception:
        return None
    return body.get("code") if isinstance(body, dict) else None


async def upload_file(incident_id: str, file_path: str, purpose: str, complete: dict | None = None) -> dict:
    """Stream a local file (inside FENRIR_MCP_UPLOAD_DIRS) to FENRIR through an upload session and
    complete it with `complete` (the purpose's metadata). Returns FENRIR's complete response
    {upload_id, purpose, exhibit_link, evidence_id, evidence}. A failed chunk is retried (backoff /
    Retry-After) from the session's next_index; any failure cancels the session (nothing stored)."""
    name, f, size = config.open_upload(file_path)
    try:
        body = {"purpose": purpose, "filename": name, "size": size,
                "expected_hash": await asyncio.to_thread(_sha256_of, f.fileno())}
        if purpose == "evidence" and (mime := mimetypes.guess_type(name)[0]):
            body["mime_type"] = mime
        async with _expensive_gate:            # one upload at a time (single-worker backend, T7)
            s = await request("POST", f"/api/incidents/{incident_id}/uploads", json=body)
            url = f"/api/incidents/{s['incident_id']}/uploads/{s['upload_id']}"
            cancel_headers = _bearer()          # M5: computed now, so the cancel below can't fail on the token
            try:
                nxt, failures = s.get("next_index", 0), 0
                cs, count = s["chunk_size"], s.get("chunk_count", 0)
                while nxt < count:
                    resp = await _put_chunk(f"{url}/chunks/{nxt}", f.fileno(), nxt * cs, min(cs, size - nxt * cs))
                    code = _code(resp)
                    if resp is not None and resp.status_code == 200:
                        nxt, failures = resp.json()["next_index"], 0
                        continue
                    if resp is not None and resp.status_code == 404 and code == "upload_not_found":
                        raise _interrupted()
                    if resp is not None and resp.status_code == 409 and code == "upload_out_of_order":
                        nxt = resp.json()["next_index"]
                        continue
                    if not (resp is None or resp.status_code >= 500 or resp.status_code == 429 or code == "upload_busy"):
                        _raise_for(resp)
                    failures += 1
                    if failures > UPLOAD_RETRIES:
                        if resp is None:
                            raise FenrirError(f"upload failed: the connection to FENRIR keeps failing ({config.fenrir_url()})")
                        _raise_for(resp)
                    try:
                        delay = float(resp.headers.get("Retry-After", "")) if resp is not None else 0.0
                    except ValueError:
                        delay = 0.0
                    await asyncio.sleep(delay if delay > 0 else min(16.0, 2.0 ** (failures - 1)))
                    try:                        # resume from what FENRIR has (a lost answer may have landed)
                        nxt = (await request("GET", url)).get("next_index", nxt)
                    except FenrirError as e:
                        if "upload_not_found" in str(e):
                            raise _interrupted() from e
                try:                            # L13: the session's purpose always wins over complete's keys
                    return await request("POST", f"{url}/complete", json={**(complete or {}), "purpose": purpose})
                except FenrirError as e:
                    if "upload_not_found" in str(e):
                        raise _interrupted() from e
                    raise
            except BaseException:
                # Never leave a session open (its staged file is deleted, the user's 3-session slot freed) — M5:
                # also when the tool call itself was cancelled: the DELETE runs shielded from that cancellation,
                # for at most 5 s.
                with anyio.move_on_after(5, shield=True):
                    try:
                        await _get_client().request("DELETE", url, headers=cancel_headers)
                    except Exception:
                        pass
                raise
    finally:
        f.close()


def slim(obj):
    """Drop null / empty-string / empty-collection fields recursively — FENRIR's
    Pydantic models carry many, and each one costs context tokens on every call."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            s = slim(v)
            if s is None or s == "" or s == [] or s == {}:
                continue
            out[k] = s
        return out
    if isinstance(obj, list):
        return [slim(v) for v in obj]
    return obj
