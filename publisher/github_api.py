"""Small, strict GitHub CLI boundary shared by publisher commands."""

from __future__ import annotations

import json
import re
import subprocess
from typing import Mapping, Protocol


API_VERSION = "2026-03-10"
MINIMUM_GH_VERSION = (2, 96, 0)
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class GitHubApiError(ValueError):
    """Raised when GitHub state or the local CLI is not exactly usable."""


class ApiRequest(Protocol):
    def __call__(
        self, method: str, endpoint: str, payload: Mapping[str, object] | None = None
    ) -> object | None: ...


def strict_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise GitHubApiError(f"GitHub JSON contains duplicate field: {key}")
        value[key] = item
    return value


def parse_json(raw: bytes, label: str) -> object:
    if len(raw) > MAX_RESPONSE_BYTES:
        raise GitHubApiError(f"{label} exceeds the response size limit")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=strict_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GitHubApiError(f"{label} is malformed JSON") from error


def require_gh_version() -> None:
    completed = subprocess.run(
        ["gh", "--version"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    if completed.returncode != 0:
        raise GitHubApiError("GitHub CLI version probe failed")
    try:
        first_line = completed.stdout.decode("ascii").splitlines()[0]
    except (UnicodeDecodeError, IndexError) as error:
        raise GitHubApiError("GitHub CLI version output is malformed") from error
    match = re.fullmatch(r"gh version ([0-9]+\.[0-9]+\.[0-9]+)(?: \([^\r\n]+\))?", first_line)
    if match is None:
        raise GitHubApiError(f"GitHub CLI version output is malformed: {first_line!r}")
    found = tuple(int(part) for part in match.group(1).split("."))
    if found < MINIMUM_GH_VERSION:
        minimum = ".".join(str(part) for part in MINIMUM_GH_VERSION)
        raise GitHubApiError(
            f"GitHub CLI must be at least {minimum}, got {first_line!r}"
        )


class GhApi:
    """Invoke fixed REST requests without exposing ``GH_TOKEN`` as an argument."""

    def __call__(
        self, method: str, endpoint: str, payload: Mapping[str, object] | None = None
    ) -> object | None:
        if method not in {"GET", "POST", "PATCH"} or endpoint.startswith("/"):
            raise GitHubApiError("invalid internal GitHub API request")
        arguments = [
            "gh",
            "api",
            "--method",
            method,
            "-H",
            f"X-GitHub-Api-Version: {API_VERSION}",
            endpoint,
        ]
        stdin = None
        if payload is not None:
            arguments.extend(("--input", "-"))
            stdin = (
                json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode("utf-8")
        completed = subprocess.run(
            arguments,
            input=stdin,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
        )
        if completed.returncode != 0:
            raise GitHubApiError("GitHub API request failed")
        if not completed.stdout.strip():
            return None
        return parse_json(completed.stdout, "GitHub API response")


def paginated_get(endpoint: str) -> list[object]:
    """Return all pages from one fixed list endpoint through ``gh`` pagination."""

    if endpoint.startswith("/"):
        raise GitHubApiError("invalid internal GitHub pagination request")
    completed = subprocess.run(
        [
            "gh",
            "api",
            "--method",
            "GET",
            "-H",
            f"X-GitHub-Api-Version: {API_VERSION}",
            "--paginate",
            "--slurp",
            endpoint,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )
    if completed.returncode != 0:
        raise GitHubApiError("paginated GitHub API request failed")
    pages = parse_json(completed.stdout, "paginated GitHub API response")
    if not isinstance(pages, list) or any(not isinstance(page, list) for page in pages):
        raise GitHubApiError("paginated GitHub response is not a list of pages")
    return [item for page in pages for item in page]
