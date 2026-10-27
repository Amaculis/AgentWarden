"""Red-team loop entry point used by the Makefile (spec 014)."""

import sys

from agentwarden.redteam import main

if __name__ == "__main__":
    sys.exit(main())
