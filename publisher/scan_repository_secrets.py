from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys


SENSITIVE_PATTERN = re.compile(
    b"|".join(
        (
            rb"BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE" rb" KEY",
            rb"gh[pousr]_[A-Za-z0-9_]{20,}",
            rb"CHOCOLATEY_" rb"API_KEY=",
        )
    )
)


def tracked_files(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=True,
        stdout=subprocess.PIPE,
    )
    paths: list[Path] = []
    for encoded in result.stdout.split(b"\0"):
        if not encoded:
            continue
        relative = Path(os.fsdecode(encoded))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"unsafe tracked path: {str(relative)!r}")
        paths.append(root / relative)
    return paths


def find_sensitive_paths(root: Path) -> list[Path]:
    matches: list[Path] = []
    for path in tracked_files(root):
        if path.is_symlink():
            content = os.readlink(path).encode("utf-8", errors="surrogateescape")
        elif path.is_file():
            content = path.read_bytes()
        else:
            continue
        if SENSITIVE_PATTERN.search(content):
            matches.append(path.relative_to(root))
    return matches


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args()
    matches = find_sensitive_paths(args.root.resolve())
    if matches:
        for path in matches:
            print(f"sensitive material pattern found in tracked file: {str(path)!r}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
