# fenrir-mcp

MCP server. Wraps DFIR-FENRIR v2 REST API. Talks to Claude Code over stdio.
Python. stdio only. No listening port.

## HOW-TO — first run

Do once. Replace `https://HOST` with your FENRIR browser URL. VPN up.

```sh
# 1. get code + deps
git clone <repo> dfir-fenrir-mcp
cd dfir-fenrir-mcp
uv sync

# 2. get the internal CA onto this machine
scp deploy-host:/path/dfir-fenrir-v2/certs/ca.crt ~/ca.crt

# 3. verify the CA matches the live server (expect: {"needs_setup":false})
curl --cacert ~/ca.crt https://HOST/api/auth/setup-check

# 4. write deployment config
mkdir -p ~/.config/fenrir-mcp && chmod 700 ~/.config/fenrir-mcp
printf 'FENRIR_URL=https://HOST\nFENRIR_CA_CERT=%s/ca.crt\n' "$HOME" > ~/.config/fenrir-mcp/env
chmod 600 ~/.config/fenrir-mcp/env

# 5. mint a token (asks user + pass + TOTP, then role cap: analyst for standard)
.venv/bin/fenrir-mcp login

# 6. register with Claude Code (run from the project dir you want the tools in)
claude mcp add-json fenrir '{"type":"stdio","command":"'"$PWD"'/.venv/bin/fenrir-mcp","env":{"FENRIR_MCP_MODE":"standard","FENRIR_MCP_UPLOAD_DIRS":"'"$HOME"'/cases"}}'
```

Or skip 4–6: run `./install.sh` (prompts for all of it, can fetch+pin the CA).

Verify: start `claude`, run `/mcp` → `fenrir ✔ connected`, ask `run fenrir_whoami`.

## HOW-TO — operate

```sh
# start of day: mint fresh 8 h token
.venv/bin/fenrir-mcp login

# check state any time
.venv/bin/fenrir-mcp status         # user, token role, mode, live server check

# work: in Claude Code, plain language. examples:
#   "triage INC-0006"               (loads the SOC skill)
#   "list open critical incidents"
#   "analyze ~/cases/x.eml into INC-0006 and promote the IOCs"
#   "verify the custody chain on INC-0006"
#   "write up findings and close INC-0006"

# end of day: revoke
.venv/bin/fenrir-mcp logout
```

- 401 from a tool = token expired. Re-run `login`. Nothing in-session fixes it.
- 403 on a write = token cap too low for the mode. Re-`login`, pick a higher cap.
- Change mode/upload dirs = edit the `.mcp.json` registration, restart `claude`.
- New server code (git pull) = restart `claude` (editable install, no reinstall).

## What

- 52 tools over the FENRIR API. Mode-tiered: readonly 22, standard +25, full +5.
- 51 curated tools + 1 escape hatch (`fenrir_api`, OpenAPI-validated).
- Auth = FENRIR bearer token. Minted by CLI after password + TOTP. 8 h TTL.
- Read incidents/timeline/IOCs/entities/evidence. Write findings. Upload
  .eml/pcap/artifacts. Run analyses. Manage CoC. Close incidents.

## Requires

- Python >= 3.12
- uv
- claude CLI
- Network path to FENRIR (VPN)
- FENRIR internal CA file (`certs/ca.crt` on the deployment host)

## Install

```sh
git clone <repo> dfir-fenrir-mcp
cd dfir-fenrir-mcp
./install.sh          # prompts: URL, CA, mode, upload dirs, register, skill
```

Manual:

```sh
uv sync
mkdir -p ~/.config/fenrir-mcp && chmod 700 ~/.config/fenrir-mcp
printf 'FENRIR_URL=https://HOST\nFENRIR_CA_CERT=/abs/ca.crt\n' > ~/.config/fenrir-mcp/env
chmod 600 ~/.config/fenrir-mcp/env
claude mcp add-json fenrir '{"type":"stdio","command":"/abs/dfir-fenrir-mcp/.venv/bin/fenrir-mcp","env":{"FENRIR_MCP_MODE":"standard"}}'
```

Use `add-json`, not flag-form `add` (mis-parses `-e`).

## Auth

```sh
.venv/bin/fenrir-mcp login     # user + pass + TOTP, then pick role cap
.venv/bin/fenrir-mcp status    # token meta + live check
.venv/bin/fenrir-mcp logout    # revoke server-side + wipe local
```

- Token role cap chosen at login. Never above your FENRIR account role.
- Effective role per request = min(account role, token cap). Enforced by FENRIR.
- Token stored in OS keyring, else 0600 file. Never in env, never in repo.
- 8 h client TTL. Re-login daily. 401 = expired.

## Config

Env vars, or `~/.config/fenrir-mcp/env` (KEY=VALUE). Real env wins.

| var | req | meaning |
|---|---|---|
| `FENRIR_URL` | yes | https base URL |
| `FENRIR_CA_CERT` | rec | internal CA path; becomes only trust anchor |
| `FENRIR_MCP_MODE` | no | readonly (default) / standard / full |
| `FENRIR_MCP_UPLOAD_DIRS` | uploads | colon-sep allowlist; unset = uploads off |
| `FENRIR_MCP_REQUIRE_KEYRING` | no | 1 = refuse 0600-file token fallback |
| `FENRIR_MCP_SLIM` | no | 0 = raw responses (default strips null/empty) |

URL + CA = deployment facts, put in env file. Mode + upload dirs = per-project,
put in the `.mcp.json` registration.

## Mode vs role

| mode | tools | needs token cap |
|---|---|---|
| readonly | reads | viewer |
| standard | + writes, uploads | analyst |
| full | + deletes, admin | analyst (admin tools need admin) |

Tools above the mode are not registered. GUI admin != token cap. Writes 403 =
token cap too low; re-login higher.

## Security rules (enforced in code)

- Bytes flow toward FENRIR only. No evidence/export/photo/report bytes to disk.
  Hard denylist, curated + escape hatch, every mode. Text exports inline only.
- MCP never mints tokens. `POST /api/tokens` denylisted. Login CLI only.
- `/api/auth/*` denylisted.
- TLS 1.3 floor. Pinned CA. verify never off. Redirects off.
  (Pinned-CA path relaxes RFC 5280 strict-format check only — generate-certs.sh
  CAs lack keyUsage; chain + hostname still verified. System-store stays strict.)
- Uploads only from `FENRIR_MCP_UPLOAD_DIRS`. Path checked, no traversal out.
- Expensive calls (enrich-all, feed pull, reports, analyses) serialized,
  semaphore 1. FENRIR backend is single-worker.
- Destructive ops in one tool (`fenrir_delete`, full mode). Dispose needs
  `confirm=true`.

## Token efficiency

- Responses slimmed (null/empty dropped). `FENRIR_MCP_SLIM=0` disables.
- List tools take `fields=[...]` and `limit`. Pass them.
- `incident_id` accepts `INC-####` ref or UUID. Ref→UUID map cached at
  `~/.config/fenrir-mcp/refcache.json`.
- readonly mode = 22 schemas loaded, not 52.

## Skill

`.claude/skills/fenrir-soc-analyst/` ships in the repo. SOC triage methodology
+ playbooks + token discipline. Loads only when triage work starts. Installer
symlinks it to `~/.claude/skills/`.

## Layout

```
src/fenrir_mcp/
  __main__.py     entry: serve (default) | login | logout | status
  server.py       MCPServer, tier-gated registration, startup checks
  config.py       env + env-file + upload allowlist
  client.py       httpx: TLS, bearer, errors, slim, ref-rewrite, semaphore
  token_store.py  keyring -> 0600 file
  cli.py          login / logout / status
  denylist.py     single-source hard denylist + byte-drift scan
  openapi_guard.py escape-hatch spec validation
  refcache.py     INC-ref -> UUID memory
  tools/          15 modules, @tool(tier) registry
tests/            40 tests
```

`docs/` (DESIGN, TOOLS, SBD-REVIEW, api-inventory) and `THREAT_MODEL.md` are
gitignored — local-only, they describe deployment posture + full API surface.

## Dev

```sh
uv run pytest     # 35 tests: denylist, tiering, guard, uploads, tls, env, efficiency
```

## Compromise response

`fenrir-mcp logout`. Or revoke elsewhere: GUI Settings > API tokens, admin
`/api/admin/tokens`. Audit filters on token prefix `claude-mcp`. Blast radius =
8 h TTL x role cap x VPN reach.
