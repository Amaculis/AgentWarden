"""Cross-cutting check: both hooks must print nothing to stdout, for any input.

Stdout must contain only JSON decisions per the hook-protocol skill, and spec
001 makes no decisions at all — so stdout must always be empty for on_prompt.py
and on_tool.py, valid input or not.
"""

import json

import pytest

from ._support import ON_PROMPT, ON_TOOL, SAMPLE_PRE_TOOL_USE, SAMPLE_USER_PROMPT_SUBMIT, run_hook

SAMPLE_PAYLOAD_FOR = {
    ON_TOOL: json.dumps(SAMPLE_PRE_TOOL_USE),
    ON_PROMPT: json.dumps(SAMPLE_USER_PROMPT_SUBMIT),
}


@pytest.mark.parametrize("script", [ON_TOOL, ON_PROMPT], ids=["on_tool", "on_prompt"])
@pytest.mark.parametrize(
    "stdin_kind",
    ["valid", "invalid"],
)
def test_hooks_print_nothing(tmp_path, script, stdin_kind):
    stdin_text = SAMPLE_PAYLOAD_FOR[script] if stdin_kind == "valid" else "{{{ not json"

    result = run_hook(script, stdin_text, tmp_path)

    assert result.returncode == 0
    assert result.stdout == ""
