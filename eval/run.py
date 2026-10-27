"""Eval entry point used by the Makefile (spec 007)."""

import sys

from agentwarden.evalrun import main

if __name__ == "__main__":
    sys.exit(main())
