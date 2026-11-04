"""Where AgentWarden's non-Python files live: the installed package or a dev checkout (spec 037).

An installed wheel ships `hooks/` and `prompts/` as `agentwarden/hooks/` and
`agentwarden/prompts/` (hatch force-include in pyproject.toml). In a checkout they sit at the
repo root, two levels above this file.
"""

from __future__ import annotations

from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKAGE_DIR.parents[1]


def _first_existing(*candidates: Path) -> Path:
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[-1]


def hooks_dir() -> Path:
    """Directory holding on_tool.py, on_read.py and on_prompt.py."""
    return _first_existing(PACKAGE_DIR / "hooks", REPO_ROOT / "hooks")


def prompt_path(name: str) -> Path:
    """`prompts/<name>`: the packaged copy when present, else the checkout's."""
    return _first_existing(PACKAGE_DIR / "prompts" / name, REPO_ROOT / "prompts" / name)
