"""Entrypoint: `fenrir-mcp` serves MCP over stdio; subcommands run the companion CLI."""

from __future__ import annotations

import argparse
import sys


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="fenrir-mcp",
        description="DFIR-FENRIR v2 MCP server for Claude Code (default: serve over stdio)",
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="run the MCP server over stdio (default)")
    p_login = sub.add_parser("login", help="interactive TOTP-verified login; mints and stores an 8 h token")
    p_login.add_argument("--role", choices=["viewer", "analyst", "admin"], default=None,
                         help="token role cap (default: weakest role the mode needs)")
    p_login.add_argument("--name", default=None, help="token label (default: claude-mcp)")
    sub.add_parser("logout", help="revoke the stored token server-side and clear the local store")
    sub.add_parser("status", help="show stored-token metadata and check it against FENRIR")

    args = parser.parse_args()
    if args.command in (None, "serve"):
        from . import server

        server.run()
        return

    from . import cli

    if args.command == "login":
        kwargs = {"role": args.role}
        if args.name:
            kwargs["name"] = args.name
        sys.exit(cli.login(**kwargs))
    elif args.command == "logout":
        sys.exit(cli.logout())
    else:
        sys.exit(cli.status())


if __name__ == "__main__":
    main()
