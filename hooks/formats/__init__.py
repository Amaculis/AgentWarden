"""Per-agent hook output formatters (spec 027).

`<agent>.py` (stdlib only) defines `decision_output(decision, reason, system_message) -> str`
and `scan_output(warning) -> str` for an agent whose hook output schema is not Claude Code's.
No file -> the hooks print the Claude Code schema.
"""
