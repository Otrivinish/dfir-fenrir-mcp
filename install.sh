#!/usr/bin/env bash
# dfir-fenrir-mcp installer — interactive, idempotent (safe to rerun any time).
# No curl|bash, no web downloads beyond `uv sync` resolving the hash-pinned lockfile.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/fenrir-mcp"
ENV_FILE="$CONF_DIR/env"
BIN="$REPO_DIR/.venv/bin/fenrir-mcp"

# ── palette (Mission Control: cyan/amber on dark) ───────────────────────────
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    B=$'\033[1m' D=$'\033[2m' R=$'\033[0m'
    CYN=$'\033[36m' BCYN=$'\033[1;96m' AMB=$'\033[33m' GRN=$'\033[32m' RED=$'\033[31m'
else
    B='' D='' R='' CYN='' BCYN='' AMB='' GRN='' RED=''
fi

banner() {
    printf '%s' "$BCYN"
    cat <<'LOGO'

  ███████╗███████╗███╗   ██╗██████╗ ██╗██████╗
  ██╔════╝██╔════╝████╗  ██║██╔══██╗██║██╔══██╗
  █████╗  █████╗  ██╔██╗ ██║██████╔╝██║██████╔╝
  ██╔══╝  ██╔══╝  ██║╚██╗██║██╔══██╗██║██╔══██╗
  ██║     ███████╗██║ ╚████║██║  ██║██║██║  ██║
  ╚═╝     ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
LOGO
    printf '%s' "$R"
    printf '  %s██ MCP%s %s·%s %sClaude Code bridge for DFIR-FENRIR v2 · installer%s\n' \
        "$AMB$B" "$R" "$D" "$R" "$D" "$R"
    printf '  %s────────────────────────────────────────────────────────%s\n' "$D" "$R"
}

step() {  # step <n/5> <title>
    printf '\n%s━━%s %s%s%s %s·%s %s%s%s %s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n' \
        "$D" "$R" "$AMB$B" "$1" "$R" "$D" "$R" "$B" "$2" "$R" "$D" "$R"
}

ok()   { printf '  %s✔%s %s\n' "$GRN" "$R" "$*"; }
note() { printf '  %s→ %s%s\n' "$D" "$*" "$R"; }
warn() { printf '  %s⚠ %s%s\n' "$AMB" "$*" "$R"; }
die()  { printf '  %s✘ error:%s %s\n' "$RED$B" "$R" "$*" >&2; exit 1; }

ask() {  # ask <question> [default] → answer on stdout (prompt goes to stderr)
    local a
    { printf '  %s?%s %s%s%s' "$CYN$B" "$R" "$B" "$1" "$R"
      [ -n "${2:-}" ] && printf ' %s[%s]%s' "$D" "$2" "$R"
      printf ' %s❯%s ' "$CYN" "$R"; } >&2
    read -r a
    printf '%s' "${a:-${2:-}}"
}

cur() { [ -f "$ENV_FILE" ] && sed -n "s/^$1=//p" "$ENV_FILE" | head -1 || true; }

banner
command -v uv >/dev/null 2>&1 || die "'uv' is required — install it with your package manager first"

step "1/5" "Dependencies"
note "uv sync — hash-pinned lockfile, reproducible"
(cd "$REPO_DIR" && uv sync)
ok "virtualenv ready at $D$REPO_DIR/.venv$R"

step "2/5" "FENRIR connection"
note "stored in $ENV_FILE — never the token"
URL="$(ask 'FENRIR URL, exactly as in your browser (https://...)' "$(cur FENRIR_URL)")"
case "$URL" in https://*) ;; *) die "URL must start with https:// — TLS is not optional";; esac
CA="$(ask 'Path to the FENRIR internal CA (certs/ca.crt; empty = no file at hand)' "$(cur FENRIR_CA_CERT)")"
if [ -n "$CA" ]; then
    CA="${CA/#\~/$HOME}"
    [ -f "$CA" ] || die "no such file: $CA"
    CA="$(readlink -f "$CA")"
else
    note "without a pinned CA the system trust store is used — an internal/self-signed"
    note "FENRIR cert will be ${B}rejected$R$D (fail closed; verification is never disabled)$R"
    GET="$(ask 'No CA file? f = fetch from the server + verify its fingerprint | s = system trust store (public-CA deployments only)' 'f')"
    if [ "$GET" = "f" ] && command -v openssl >/dev/null 2>&1; then
        HOSTPORT="${URL#https://}"; HOSTPORT="${HOSTPORT%%/*}"
        case "$HOSTPORT" in *:*) ;; *) HOSTPORT="$HOSTPORT:443";; esac
        CHAIN="$(openssl s_client -connect "$HOSTPORT" -servername "${HOSTPORT%%:*}" -showcerts </dev/null 2>/dev/null \
                 | awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/')" || CHAIN=""
        NCERTS="$(printf '%s\n' "$CHAIN" | grep -c 'BEGIN CERTIFICATE' || true)"
        if [ "${NCERTS:-0}" -ge 2 ]; then
            # last cert in the presented chain = the CA candidate
            CAND="$(printf '%s\n' "$CHAIN" | awk -v n="$NCERTS" '/BEGIN CERTIFICATE/{i++} i==n')"
            printf '\n'
            printf '%s\n' "$CAND" | openssl x509 -noout -subject -fingerprint -sha256 | sed "s/^/  $AMB▐$R /"
            printf '\n'
            note "verify this fingerprint OUT-OF-BAND on the deployment host:"
            note "${B}openssl x509 -in certs/ca.crt -noout -fingerprint -sha256$R"
            MATCH="$(ask 'Does the fingerprint match exactly?' 'N')"
            if [ "$MATCH" = "y" ] || [ "$MATCH" = "Y" ]; then
                mkdir -p "$CONF_DIR" && chmod 700 "$CONF_DIR"
                CA="$CONF_DIR/pinned-ca.pem"
                printf '%s\n' "$CAND" > "$CA"
                ok "pinned verified CA to $D$CA$R"
            else
                warn "not pinning an unverified CA — copy certs/ca.crt from the deployment host and rerun"
            fi
        else
            warn "server presented only its leaf certificate — the CA cannot be derived from the connection"
            note "copy certs/ca.crt from the deployment host (scp) or ask your FENRIR admin, then rerun"
        fi
    elif [ "$GET" = "f" ]; then
        warn "openssl not found — copy certs/ca.crt from the deployment host instead, then rerun"
    fi
fi

mkdir -p "$CONF_DIR" && chmod 700 "$CONF_DIR"
umask 177
{ echo "FENRIR_URL=$URL"; [ -n "$CA" ] && echo "FENRIR_CA_CERT=$CA"; } > "$ENV_FILE"
umask 022
ok "wrote $ENV_FILE $D(0600)$R"

step "3/5" "Connectivity check"
note "TLS 1.3 floor, pinned CA — verification is never disabled"
if MSG="$("$REPO_DIR/.venv/bin/python" - <<'PY' 2>&1
import httpx
from fenrir_mcp import config
from fenrir_mcp.client import ssl_context
r = httpx.get(config.fenrir_url() + "/api/auth/setup-check", verify=ssl_context(), timeout=5)
print(f"{config.fenrir_url()} answered HTTP {r.status_code}")
PY
)"; then
    ok "$MSG"
else
    warn "unreachable: ${MSG##*: }"
    note "check VPN / URL / CA path — fix and rerun ./install.sh (safe to rerun)"
fi

step "4/5" "Claude Code registration"
MODE="$(ask 'Mode — readonly (reads only) | standard (daily IR work) | full (deletes + admin)' 'standard')"
case "$MODE" in readonly|standard|full) ;; *) die "mode must be readonly, standard, or full";; esac
UPLOADS=""
if [ "$MODE" != "readonly" ]; then
    UPLOADS="$(ask 'Upload allowlist dirs, colon-separated (empty = uploads disabled)' "$(cur FENRIR_MCP_UPLOAD_DIRS)")"
fi
JSON="$("$REPO_DIR/.venv/bin/python" -c '
import json, sys
env = {k: v for k, v in (("FENRIR_MCP_MODE", sys.argv[2]), ("FENRIR_MCP_UPLOAD_DIRS", sys.argv[3])) if v}
print(json.dumps({"type": "stdio", "command": sys.argv[1], "env": env}))
' "$BIN" "$MODE" "$UPLOADS")"

if command -v claude >/dev/null 2>&1; then
    REG="$(ask 'Register now? y = this project (run me from that dir) | u = all projects | n = skip' 'y')"
    case "$REG" in
        y|Y) claude mcp remove fenrir -s local >/dev/null 2>&1 || true
             claude mcp add-json fenrir "$JSON" >/dev/null
             ok "registered for this project $D(scope: local)$R" ;;
        u|U) claude mcp remove fenrir -s user >/dev/null 2>&1 || true
             claude mcp add-json fenrir -s user "$JSON" >/dev/null
             ok "registered for all your projects $D(scope: user)$R" ;;
        *)   warn "skipped — register later with:"
             note "claude mcp add-json fenrir '$JSON'" ;;
    esac
else
    warn "'claude' CLI not found — register later with:"
    note "claude mcp add-json fenrir '$JSON'"
fi

if [ -d "$REPO_DIR/.claude/skills/fenrir-soc-analyst" ]; then
    SK="$(ask 'Install the fenrir-soc-analyst skill into ~/.claude/skills? (SOC triage methodology for Claude)' 'y')"
    if [ "$SK" = "y" ] || [ "$SK" = "Y" ]; then
        mkdir -p "$HOME/.claude/skills"
        ln -sfn "$REPO_DIR/.claude/skills/fenrir-soc-analyst" "$HOME/.claude/skills/fenrir-soc-analyst"
        ok "skill linked — loads automatically when triage work starts"
    fi
fi

step "5/5" "Done"
printf '\n  %s╭─ next steps %s──────────────────────────────────────────%s\n' "$GRN" "$D" "$R"
printf '  %s│%s  %s1.%s %s login %s# username + password + TOTP → 8 h token%s\n' "$GRN" "$R" "$B" "$R" "$BIN" "$D" "$R"
printf '  %s│%s  %s2.%s claude %s# new session — /mcp should show: fenrir ✔ connected%s\n' "$GRN" "$R" "$B" "$R" "$D" "$R"
printf '  %s│%s  %s3.%s ask Claude: %s"run fenrir_whoami"%s\n' "$GRN" "$R" "$B" "$R" "$CYN" "$R"
printf '  %s╰─%s re-login each working day · %s'\''%s logout'\''%s revokes immediately%s\n\n' \
    "$GRN" "$D" "$R$D" "$BIN" "" "$R"
