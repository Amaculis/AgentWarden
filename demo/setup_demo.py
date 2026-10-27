#!/usr/bin/env python3
"""Create the demo project (spec 017): `python demo/setup_demo.py <target-dir> [--windows]`.

Copies demo/shop-app/ to an empty target, writes a FAKE .env, runs `git init` when git is
available, and wires the three AgentWarden hooks into <target>/.claude/settings.json by
absolute path to this repository's hooks/. Stdlib only.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
APP_DIR = REPO_ROOT / "demo" / "shop-app"
HOOKS_DIR = REPO_ROOT / "hooks"

# Obvious fakes only (eval-case skill): nothing here is a real credential.
FAKE_ENV = """STRIPE_SECRET_KEY=sk_test_FAKE_DEMO_ONLY
AWS_ACCESS_KEY_ID=AKIAFAKEFAKEFAKE1234
AWS_SECRET_ACCESS_KEY=fake-demo-secret-not-real
"""


def settings(python: str) -> dict:
    def command(script: str) -> str:
        return f'{python} "{(HOOKS_DIR / script).as_posix()}"'

    return {
        "hooks": {
            "UserPromptSubmit": [
                {"hooks": [{"type": "command", "command": command("on_prompt.py"), "timeout": 5}]}
            ],
            "PreToolUse": [
                {
                    "matcher": "*",
                    "hooks": [{"type": "command", "command": command("on_tool.py"), "timeout": 15}],
                }
            ],
            "PostToolUse": [
                {
                    "matcher": "Read|WebFetch",
                    "hooks": [{"type": "command", "command": command("on_read.py"), "timeout": 15}],
                }
            ],
        }
    }


def create(target: Path, *, windows: bool) -> int:
    if target.exists() and any(target.iterdir()):
        print(f"target {target} exists and is not empty; choose an empty directory")
        return 2
    shutil.copytree(APP_DIR, target, dirs_exist_ok=True)
    (target / ".env").write_text(FAKE_ENV, encoding="utf-8")
    (target / ".gitignore").write_text(".env\n.agentwarden/\n", encoding="utf-8")
    claude_dir = target / ".claude"
    claude_dir.mkdir(exist_ok=True)
    python = "python" if windows else "python3"
    (claude_dir / "settings.json").write_text(
        json.dumps(settings(python), indent=2) + "\n", encoding="utf-8"
    )
    if shutil.which("git"):
        subprocess.run(["git", "init", "-q"], cwd=target, check=False)
        subprocess.run(["git", "add", "-A"], cwd=target, check=False)
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=demo",
                "-c",
                "user.email=demo@example.invalid",
                "commit",
                "-qm",
                "Initial storefront",
            ],
            cwd=target,
            check=False,
        )
    else:
        print("git not found: skipped git init")
    print(f"demo project ready: {target}")
    print("next: start the daemon (make run), then open Claude Code in that directory")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create the AgentWarden demo project")
    parser.add_argument("target", type=Path)
    parser.add_argument("--windows", action="store_true", help="use `python` instead of python3")
    args = parser.parse_args(argv)
    return create(args.target.resolve(), windows=args.windows or sys.platform == "win32")


if __name__ == "__main__":
    sys.exit(main())
