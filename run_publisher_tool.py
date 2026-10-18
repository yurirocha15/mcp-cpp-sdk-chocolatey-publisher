#!/usr/bin/env python3
"""Run one allowlisted publisher module in an isolated Python interpreter."""

from __future__ import annotations

from pathlib import Path
import runpy
import sys


MODULES = frozenset(
    {
        "submission",
        "validate_dispatch",
        "verify_release",
        "verify_source",
    }
)


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in MODULES:
        print("usage: run_publisher_tool.py <allowlisted-module> [args...]", file=sys.stderr)
        return 2
    module = sys.argv.pop(1)
    root = Path(__file__).resolve().parent
    sys.path.insert(0, str(root))
    runpy.run_module(f"publisher.{module}", run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
