"""FENRIR J2 deadline-reminder email switch: since R151 it is FENRIR GUI only — saving the
SMTP config (which carries the switch) is refused on every MCP path."""

import typing

from fenrir_mcp import denylist
from fenrir_mcp.tools import admin


def test_smtp_save_is_gone_and_the_put_is_refused():
    actions = typing.get_args(typing.get_type_hints(admin.fenrir_admin_platform)["action"])
    assert "smtp_save" not in actions and "smtp_test" in actions
    assert "deadline_reminders" not in admin.fenrir_admin_platform.__doc__
    assert denylist.is_denied("PUT", "/api/integrations/smtp")
