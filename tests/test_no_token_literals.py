"""Guard: no tracked file holds a contiguous token-shaped fake secret.

GitHub push protection rejects pushes containing strings shaped like real tokens, even fake
ones in tests (a Slack-style fake blocked a push on 2026-10-28). Build such fakes at runtime
with explicit `+` concatenation; ruff merges implicit "a" "b" literals back together.
AWS key ids alone (AKIAFAKE...) are fine: push protection needs the id + secret pair.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PATTERNS = {
    "slack": r"xox[abprs]-[0-9A-Za-z-]{10,}",
    "github": r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}",
    "stripe": r"[rsp]k_(?:live|test)_[0-9A-Za-z]{10,}",
    "google": r"AIza[0-9A-Za-z_-]{35}",
    "npm": r"npm_[A-Za-z0-9]{36}",
    "anthropic": r"sk-ant-[A-Za-z0-9_-]{20,}",
    "private_key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
}


def test_no_contiguous_token_literals():
    files = subprocess.run(
        ["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    ).stdout.split()
    hits = []
    for name in files:
        path = REPO_ROOT / name
        if not path.is_file():
            continue
        text = path.read_bytes().decode("utf-8", "replace")
        for kind, pattern in PATTERNS.items():
            for match in re.finditer(pattern, text):
                hits.append(f"{name}: {kind}: {match.group(0)[:40]}")
    assert hits == [], "token-shaped literals would trip GitHub push protection:\n" + "\n".join(
        hits
    )
