#!/usr/bin/env bash
# dfir-fenrir-mcp uninstaller — revokes the token, removes registration + config + venv.
# The repo checkout itself is left in place. Idempotent.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/fenrir-mcp"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    B=$'\033[1m' D=$'\033[2m' R=$'\033[0m'
    CYN=$'\033[36m' AMB=$'\033[33m' GRN=$'\033[32m' RED=$'\033[31m' BRED=$'\033[1;91m'
else
    B='' D='' R='' CYN='' AMB='' GRN='' RED='' BRED=''
fi

ok()   { printf '  %s✔%s %s\n' "$GRN" "$R" "$*"; }
note() { printf '  %s→ %s%s\n' "$D" "$*" "$R"; }

printf '%s' "$BRED"
cat <<'LOGO'

  ███████╗███████╗███╗   ██╗██████╗ ██╗██████╗
  ██╔════╝██╔════╝████╗  ██║██╔══██╗██║██╔══██╗
  █████╗  █████╗  ██╔██╗ ██║██████╔╝██║██████╔╝
  ██╔══╝  ██╔══╝  ██║╚██╗██║██╔══██╗██║██╔══██╗
  ██║     ███████╗██║ ╚████║██║  ██║██║██║  ██║
  ╚═╝     ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
LOGO
printf '%s' "$R"
printf '  %s██ MCP%s %s·%s %suninstaller%s\n' "$AMB$B" "$R" "$D" "$R" "$D" "$R"
printf '  %s────────────────────────────────────────────────────────%s\n\n' "$D" "$R"

printf '  %sThis will:%s\n' "$B" "$R"
printf '   %s·%s revoke the FENRIR token server-side %s(fenrir-mcp logout)%s\n' "$AMB" "$R" "$D" "$R"
printf '   %s·%s remove the Claude Code registration %s(local + user scope)%s\n' "$AMB" "$R" "$D" "$R"
printf '   %s·%s delete %s%s%s and %s%s/.venv%s\n' "$AMB" "$R" "$D" "$CONF_DIR" "$R" "$D" "$REPO_DIR" "$R"
printf '   %s·%s leave the repo checkout itself in place\n\n' "$AMB" "$R"

printf '  %s?%s %sProceed?%s %s[y/N]%s %s❯%s ' "$CYN$B" "$R" "$B" "$R" "$D" "$R" "$CYN" "$R"
read -r a
[ "${a:-n}" = "y" ] || { printf '\n  %s✘ aborted — nothing changed%s\n\n' "$RED" "$R"; exit 0; }
echo

if [ -x "$REPO_DIR/.venv/bin/fenrir-mcp" ]; then
    "$REPO_DIR/.venv/bin/fenrir-mcp" logout >/dev/null 2>&1 && ok "token revoked server-side" \
        || note "no token to revoke (or FENRIR unreachable) — revoke via GUI → Settings → API tokens if needed"
fi
if command -v claude >/dev/null 2>&1; then
    claude mcp remove fenrir -s local >/dev/null 2>&1 || true
    claude mcp remove fenrir -s user  >/dev/null 2>&1 || true
    ok "Claude Code registration removed"
fi
rm -rf "$CONF_DIR" "$REPO_DIR/.venv"
ok "removed $CONF_DIR and .venv"
printf '\n  %s╰─%s done — delete the repo directory to remove it fully%s\n\n' "$GRN" "$D" "$R"
