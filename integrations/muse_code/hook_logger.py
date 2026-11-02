#!/usr/bin/env python3
"""One-shot logging hook for the live Muse Code capture (spec 028).

Wire this into Muse Code's hook config (see README.md) for PreToolUse, PostToolUse and
UserPromptSubmit. It appends the raw stdin bytes plus which event name/args it was called
with to `muse_code_capture.jsonl`, next to this file, and ALWAYS exits 0 printing nothing --
it must never itself block or alter a Muse Code session. Stdlib only.

Run this for ONE short Muse Code session (the human's Muse Code budget is limited): a few
`ls`, a file read, a file write/edit, a search, and one `.env` read attempt are enough to
confirm or correct every guess in `agentwarden/agents/muse_code.py`.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

LOG_PATH = Path(__file__).resolve().parent / "muse_code_capture.jsonl"


def main() -> None:
    try:
        raw = sys.stdin.buffer.read()
    except Exception:
        raw = b""
    record: dict = {
        "received_at": datetime.now(UTC).isoformat(),
        "argv": sys.argv[1:],
        "raw_len": len(raw),
    }
    try:
        record["body"] = json.loads(raw.decode("utf-8"))
    except Exception:
        record["body_raw_b64"] = raw[:4000].hex()  # keep it short; never block on a huge body
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=True) + "\n")
    except Exception:
        pass  # never fail the hook: this script must not affect the Muse Code session


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    # Deliberately prints nothing and always exits 0: a logging hook must never deny,
    # ask or otherwise change what Muse Code does during the capture session.
