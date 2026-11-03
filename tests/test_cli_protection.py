"""The protected agent cannot use the agentwarden CLI or the installed package (spec 037)."""

from __future__ import annotations

import pytest

from agentwarden import resources, rules
from agentwarden.models import ToolEvent
from agentwarden.rules import evaluate


def _event(tool: str, cwd: str = "/work/proj", **tool_input) -> ToolEvent:
    return ToolEvent(
        session_id="s", cwd=cwd, hook_event_name="PreToolUse", tool_name=tool, tool_input=tool_input
    )


def _decision(tool: str, command: str) -> str | None:
    verdict = evaluate(_event(tool, command=command))
    return verdict.decision if verdict else None


@pytest.mark.parametrize("tool", ["Bash", "PowerShell"])
@pytest.mark.parametrize(
    "command",
    [
        "agentwarden uninstall",
        "agentwarden uninstall .",
        "agentwarden init --shared",
        "agentwarden serve",
        "AGENTWARDEN.EXE serve",
        '"C:/Users/me/.local/bin/agentwarden.exe" uninstall',
        "~/.local/bin/agentwarden uninstall /work/proj",
        "python -m agentwarden uninstall",
        "python3 -m agentwarden.cli init",
        "uv run agentwarden serve",
        "uvx agentwarden init",
        "echo ok && agentwarden uninstall",
        "WARDEN_JUDGE=mock agentwarden serve",
        "uvicorn agentwarden.daemon:app --port 8766",
    ],
)
def test_cli_init_uninstall_serve_denied(tool, command):
    assert _decision(tool, command) == "deny"


@pytest.mark.parametrize(
    "command",
    ["agentwarden status", "agentwarden --help", "agentwarden --version", "ls .agentwarden-notes"],
)
def test_cli_status_help_not_denied(command):
    verdict = evaluate(_event("Bash", command=command))
    assert verdict is None or "AgentWarden's hooks or starting" not in verdict.reason


@pytest.mark.parametrize(
    "command",
    [
        "pip uninstall -y agentwarden",
        "pip3 uninstall agentwarden",
        "uv pip uninstall agentwarden",
        "uv tool uninstall agentwarden",
        "pipx uninstall agentwarden",
    ],
)
def test_pip_uninstall_agentwarden_denied(command):
    assert _decision("Bash", command) == "deny"


def test_uninstall_other_package_not_hit():
    verdict = evaluate(_event("Bash", command="pip uninstall -y agentwarden-extras"))
    assert verdict is None or "uninstalling AgentWarden" not in verdict.reason


@pytest.mark.parametrize(
    "command",
    [
        "sed -i s/deny/allow/ ~/.local/share/uv/tools/agentwarden/lib/rules.py",
        "nano /venv/lib/site-packages/agentwarden/rules.py",
        "cp evil.py /usr/lib/python3/dist-packages/agentwarden/hooks/on_tool.py",
        "Remove-Item C:\\Users\\me\\pipx\\venvs\\agentwarden -Recurse",
    ],
)
def test_shell_installed_dir_denied(command):
    assert _decision("Bash", command) == "deny"


@pytest.fixture
def installed(tmp_path, monkeypatch):
    package = tmp_path / "venv" / "lib" / "site-packages" / "agentwarden"
    package.mkdir(parents=True)
    monkeypatch.setattr(resources, "PACKAGE_DIR", package)
    (tmp_path / "proj").mkdir()
    return package, str(tmp_path / "proj")


@pytest.mark.parametrize("tool", ["Edit", "Write", "MultiEdit"])
def test_edit_installed_package_denied(installed, tool):
    package, cwd = installed
    verdict = evaluate(_event(tool, cwd, file_path=str(package / "rules.py")))
    assert verdict is not None and verdict.decision == "deny"
    assert "installed files" in verdict.reason


def test_edit_installed_hooks_denied(installed):
    package, cwd = installed
    verdict = evaluate(_event("Write", cwd, file_path=str(package / "hooks" / "on_tool.py")))
    assert verdict is not None and verdict.decision == "deny"
    assert "installed files" in verdict.reason


def test_developing_agentwarden_itself_not_hit(tmp_path, monkeypatch):
    repo = tmp_path / "AgentWarden"
    package = repo / "src" / "agentwarden"
    package.mkdir(parents=True)
    monkeypatch.setattr(resources, "PACKAGE_DIR", package)
    assert rules._in_installed_package(str(package / "rules.py"), str(repo)) is False


# Reviewer findings on spec 037: indirection bypasses and false positives.


@pytest.mark.parametrize(
    "command",
    [
        "python -c \"from agentwarden.cli import main; main(['init'])\"",
        'python -c "import agentwarden, shutil; shutil.rmtree(agentwarden.__path__[0])"',
        'rm -rf $(python -c "import agentwarden,os;print(os.path.dirname(agentwarden.__file__))")',
        "python -c \"__import__('agentwarden.cli').cli.main(['serve'])\"",
        "alias aw=agentwarden",
        'function aw(){ agentwarden "$@"; }; aw serve',
        "Set-Alias aw agentwarden",
        "X=agentwarden; $X init",
        '$env:AW = "agentwarden.exe"',
        'bash -c "agentwarden uninstall"',
        "pwsh -Command agentwarden init",
        "cmd /c agentwarden serve",
        "echo $(agentwarden uninstall)",
        '& "C:/Program Files/aw/agentwarden.exe" uninstall',
        "python -m uvicorn agentwarden.daemon:app",
    ],
)
def test_cli_indirection_denied(command):
    assert _decision("Bash", command) == "deny"


@pytest.mark.parametrize(
    "command",
    [
        "grep -rn 'agentwarden serve' docs/",
        "echo 'run: agentwarden init'",
        "git log --grep='agentwarden serve'",
        "cat README.md | grep -A2 'agentwarden init'",
        "grep -rn agentwarden.daemon notes.md",
        "ls ~/.agentwarden-backup",
    ],
)
def test_mentions_of_cli_not_hard_denied(command):
    verdict = evaluate(_event("Bash", command=command))
    assert verdict is None or "AgentWarden's hooks or starting" not in verdict.reason
    assert verdict is None or "indirectly" not in verdict.reason


def test_checkout_may_import_agentwarden(tmp_path, monkeypatch):
    repo = tmp_path / "AgentWarden"
    package = repo / "src" / "agentwarden"
    package.mkdir(parents=True)
    monkeypatch.setattr(resources, "PACKAGE_DIR", package)
    command = 'uv run python -c "from agentwarden import rules"'
    verdict = evaluate(_event("Bash", str(repo), command=command))
    assert verdict is None or "indirectly" not in verdict.reason
