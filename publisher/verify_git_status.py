#!/usr/bin/env python3
"""Verify one exact tag-signing subkey and primary fingerprint."""

from __future__ import annotations

from pathlib import Path
import re
import sys


FINGERPRINT = re.compile(r"[0-9A-F]{40}|[0-9A-F]{64}")
FATAL = {
    "BADSIG", "ERRSIG", "EXPKEYSIG", "EXPSIG", "KEYEXPIRED",
    "NO_PUBKEY", "REVKEYSIG", "SIGEXPIRED",
}


def verify(text: str, tag_fingerprint: str, primary_fingerprint: str) -> None:
    if FINGERPRINT.fullmatch(tag_fingerprint) is None or FINGERPRINT.fullmatch(primary_fingerprint) is None:
        raise ValueError("configured tag fingerprint is malformed")
    signatures: list[list[str]] = []
    for line in text.splitlines():
        if not line.startswith("[GNUPG:] "):
            if line.strip():
                raise ValueError("tag status contains non-status output")
            continue
        fields = line.removeprefix("[GNUPG:] ").split()
        if fields and fields[0] in FATAL:
            raise ValueError(f"GnuPG reported {fields[0]}")
        if fields and fields[0] == "VALIDSIG":
            signatures.append(fields)
    if len(signatures) != 1 or len(signatures[0]) < 11:
        raise ValueError("tag status must contain one well-formed VALIDSIG")
    if signatures[0][1] != tag_fingerprint or signatures[0][-1] != primary_fingerprint:
        raise ValueError("tag signature identity mismatch")


def main() -> int:
    if len(sys.argv) != 4:
        return 2
    try:
        verify(Path(sys.argv[1]).read_text(encoding="utf-8"), sys.argv[2], sys.argv[3])
    except (OSError, UnicodeError, ValueError) as error:
        print(f"verify-git-status: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
