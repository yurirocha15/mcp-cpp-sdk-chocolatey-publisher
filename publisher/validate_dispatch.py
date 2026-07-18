#!/usr/bin/env python3
"""Validate the exact stable-release dispatch accepted by the publisher."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
from uuid import UUID


FIELDS = (
    "source_tag",
    "source_commit_sha",
    "github_release_id",
    "source_workflow_run_id",
    "release_manifest_sha256",
    "request_uuid",
)
TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
DECIMAL = re.compile(r"[1-9][0-9]*")


def validate(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != set(FIELDS):
        raise ValueError("dispatch must contain exactly the approved fields")
    result: dict[str, str] = {}
    for field in FIELDS:
        item = value[field]
        if not isinstance(item, str) or not item or len(item) > 160:
            raise ValueError(f"{field} is not a bounded non-empty string")
        if any(character.isspace() or ord(character) < 0x20 for character in item):
            raise ValueError(f"{field} contains whitespace or control characters")
        result[field] = item
    if TAG.fullmatch(result["source_tag"]) is None:
        raise ValueError("source_tag is not a canonical stable tag")
    if SHA.fullmatch(result["source_commit_sha"]) is None:
        raise ValueError("source_commit_sha is not canonical")
    if DIGEST.fullmatch(result["release_manifest_sha256"]) is None:
        raise ValueError("release_manifest_sha256 is not canonical")
    for field in ("github_release_id", "source_workflow_run_id"):
        if DECIMAL.fullmatch(result[field]) is None:
            raise ValueError(f"{field} is not a positive canonical decimal")
    try:
        request_id = UUID(result["request_uuid"])
    except ValueError as error:
        raise ValueError("request_uuid is invalid") from error
    if str(request_id) != result["request_uuid"]:
        raise ValueError("request_uuid is not canonical lowercase")
    return result


def main() -> int:
    try:
        value = validate(json.loads(os.environ["DISPATCH_JSON"]))
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            for field in FIELDS:
                output.write(f"{field}={value[field]}\n")
            output.write(f"version={value['source_tag'][1:]}\n")
    except (KeyError, OSError, json.JSONDecodeError, ValueError) as error:
        print(f"validate-dispatch: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
