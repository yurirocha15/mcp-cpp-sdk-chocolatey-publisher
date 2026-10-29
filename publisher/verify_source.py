#!/usr/bin/env python3
"""Verify the publisher execution context and immutable source release."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from typing import Callable, Mapping, Sequence

from publisher.github_api import (
    ApiRequest,
    GhApi,
    GitHubApiError,
    require_gh_version,
    strict_pairs,
)
from publisher.validate_dispatch import SOURCE_REPOSITORY, validate
from publisher.verify_git_status import verify as verify_gpg_status


PUBLISHER_REPOSITORY = "yurirocha15/mcp-cpp-sdk-chocolatey-publisher"
PUBLISHER_WORKFLOW = ".github/workflows/publish.yml"
SOURCE_WORKFLOW = ".github/workflows/release.yml"
PUBLISHER_REF = "refs/heads/main"
POSITIVE_DECIMAL = re.compile(r"[1-9][0-9]*")
# The source run contains approval-gated jobs, so wait up to two hours.
SOURCE_RUN_INTERVAL_SECONDS = 30
SOURCE_RUN_ATTEMPTS = 240
# Statuses GitHub reports while a run is queued or parked at an approval gate.
SOURCE_RUN_PENDING_STATUSES = frozenset(
    {"queued", "in_progress", "waiting", "requested", "pending"}
)
# Consecutive transient API failures tolerated while polling; the next raises.
SOURCE_RUN_MAX_CONSECUTIVE_FAILURES = 4


class SourceVerificationError(ValueError):
    """Raised when live source or execution identity differs from the dispatch."""


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise SourceVerificationError(f"{label} is not a JSON object")
    return value


def _positive_integer(value: str, label: str) -> int:
    if POSITIVE_DECIMAL.fullmatch(value) is None:
        raise SourceVerificationError(f"{label} is not a positive canonical decimal")
    return int(value)


def verify_execution_context(
    dispatch: Mapping[str, str],
    *,
    repository: str,
    repository_id: str,
    expected_repository_id: str,
    sha: str,
    ref: str,
    workflow_ref: str,
) -> None:
    """Bind this run to protected ``main`` at the commit the source dispatched."""

    if repository != PUBLISHER_REPOSITORY:
        raise SourceVerificationError("publisher repository identity is wrong")
    actual_id = _positive_integer(repository_id, "publisher repository ID")
    expected_id = _positive_integer(
        expected_repository_id, "expected publisher repository ID"
    )
    if actual_id != expected_id:
        raise SourceVerificationError("publisher repository numeric identity is wrong")
    if sha != dispatch["provider_control_sha"]:
        raise SourceVerificationError("workflow commit differs from provider control commit")
    if ref != PUBLISHER_REF:
        raise SourceVerificationError("publisher must run from protected main")
    expected_workflow_ref = f"{PUBLISHER_REPOSITORY}/{PUBLISHER_WORKFLOW}@{ref}"
    if workflow_ref != expected_workflow_ref:
        raise SourceVerificationError("publisher workflow ref differs from protected main")


def verify_source_state(
    api: ApiRequest,
    dispatch: Mapping[str, str],
    *,
    source_repository_id: str,
    source_owner_id: str,
    sleep: Callable[[float], None] = time.sleep,
    attempts: int = SOURCE_RUN_ATTEMPTS,
) -> None:
    """Verify repository, immutable release, and completed dispatching workflow."""

    expected_repository_id = _positive_integer(
        source_repository_id, "source repository ID"
    )
    expected_owner_id = _positive_integer(source_owner_id, "source owner ID")
    repository = _mapping(api("GET", f"repos/{SOURCE_REPOSITORY}"), "source repository")
    owner = _mapping(repository.get("owner"), "source repository owner")
    if (
        repository.get("id") != expected_repository_id
        or repository.get("full_name") != SOURCE_REPOSITORY
        or repository.get("default_branch") != "main"
        or repository.get("archived") is not False
        or repository.get("disabled") is not False
        or owner.get("id") != expected_owner_id
    ):
        raise SourceVerificationError("source repository identity is wrong")

    tag = dispatch["source_tag"]
    release = _mapping(
        api("GET", f"repos/{SOURCE_REPOSITORY}/releases/tags/{tag}"),
        "source release",
    )
    if (
        release.get("id") != int(dispatch["github_release_id"])
        or release.get("tag_name") != tag
        or release.get("draft") is not False
        or release.get("prerelease") is not False
        or release.get("immutable") is not True
    ):
        raise SourceVerificationError("source release is not the expected immutable release")

    run_id = dispatch["source_workflow_run_id"]
    run: Mapping[str, object] | None = None
    failures = 0
    for attempt in range(attempts):
        try:
            run = _mapping(
                api("GET", f"repos/{SOURCE_REPOSITORY}/actions/runs/{run_id}"),
                "source workflow run",
            )
        except GitHubApiError:
            failures += 1
            if failures > SOURCE_RUN_MAX_CONSECUTIVE_FAILURES:
                raise
            if attempt + 1 < attempts:
                sleep(SOURCE_RUN_INTERVAL_SECONDS)
            continue
        failures = 0
        status = run.get("status")
        if status == "completed":
            break
        if status not in SOURCE_RUN_PENDING_STATUSES:
            raise SourceVerificationError("source workflow run has an invalid status")
        if attempt + 1 < attempts:
            sleep(SOURCE_RUN_INTERVAL_SECONDS)
    if run is None or run.get("status") != "completed":
        raise SourceVerificationError("source workflow did not complete before the timeout")
    run_repository = _mapping(run.get("repository"), "source workflow repository")
    if (
        run.get("event") != "workflow_dispatch"
        or run.get("conclusion") != "success"
        or run.get("head_sha") != dispatch["source_workflow_head_sha"]
        or run.get("head_branch") != "main"
        or run.get("path") != SOURCE_WORKFLOW
        or run_repository.get("id") != expected_repository_id
        or run_repository.get("full_name") != SOURCE_REPOSITORY
    ):
        raise SourceVerificationError("source workflow run identity is wrong")


def _run(
    arguments: Sequence[str],
    *,
    environment: Mapping[str, str] | None = None,
    timeout: int = 120,
) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        list(arguments),
        env=dict(environment) if environment is not None else None,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    if len(completed.stdout) > 1024 * 1024 or len(completed.stderr) > 1024 * 1024:
        raise SourceVerificationError("verification command output exceeds the limit")
    return completed


def _require_success(
    arguments: Sequence[str],
    *,
    environment: Mapping[str, str] | None = None,
    timeout: int = 120,
) -> subprocess.CompletedProcess[bytes]:
    completed = _run(arguments, environment=environment, timeout=timeout)
    if completed.returncode != 0:
        raise SourceVerificationError(f"verification command failed: {arguments[0]}")
    return completed


def verify_signed_tag(
    *,
    tag: str,
    commit: str,
    public_key: Path,
    primary_fingerprint: str,
    tag_fingerprint: str,
) -> None:
    """Verify the exact annotated tag with an isolated keyring and Git checkout."""

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        repository = root / "source.git"
        key_home = root / "gnupg"
        key_home.mkdir(mode=0o700)
        _require_success(
            ["gpg", "--batch", "--homedir", str(key_home), "--import", str(public_key)]
        )
        _require_success(["git", "init", "--bare", str(repository)])
        source_url = f"https://github.com/{SOURCE_REPOSITORY}.git"
        _require_success(
            [
                "git", "-C", str(repository), "fetch", "--no-tags", "--depth=1",
                source_url, f"refs/tags/{tag}:refs/tags/{tag}",
            ],
            timeout=300,
        )
        _require_success(
            [
                "git", "-C", str(repository), "fetch", "--no-tags",
                source_url, "refs/heads/main:refs/heads/main",
            ],
            timeout=300,
        )
        object_type = _require_success(
            ["git", "-C", str(repository), "cat-file", "-t", tag]
        ).stdout.decode("ascii").strip()
        if object_type != "tag":
            raise SourceVerificationError("source tag is not annotated")
        environment = dict(os.environ)
        environment["GNUPGHOME"] = str(key_home)
        signature = _require_success(
            ["git", "-C", str(repository), "verify-tag", "--raw", tag],
            environment=environment,
        )
        try:
            status = signature.stderr.decode("utf-8")
        except UnicodeDecodeError as error:
            raise SourceVerificationError("source tag signature status is not UTF-8") from error
        verify_gpg_status(status, tag_fingerprint, primary_fingerprint)
        resolved = _require_success(
            ["git", "-C", str(repository), "rev-list", "-n1", tag]
        ).stdout.decode("ascii").strip()
        if resolved != commit:
            raise SourceVerificationError("source tag resolves to the wrong commit")
        _require_success(
            [
                "git", "-C", str(repository), "merge-base", "--is-ancestor",
                commit, "refs/heads/main",
            ]
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-key", type=Path, required=True)
    args = parser.parse_args()
    try:
        dispatch = validate(
            json.loads(os.environ["DISPATCH_JSON"], object_pairs_hook=strict_pairs)
        )
        verify_execution_context(
            dispatch,
            repository=os.environ["GITHUB_REPOSITORY"],
            repository_id=os.environ["GITHUB_REPOSITORY_ID"],
            expected_repository_id=os.environ["PUBLISHER_REPOSITORY_ID"],
            sha=os.environ["GITHUB_SHA"],
            ref=os.environ["GITHUB_REF"],
            workflow_ref=os.environ["GITHUB_WORKFLOW_REF"],
        )
        require_gh_version()
        verify_source_state(
            GhApi(),
            dispatch,
            source_repository_id=os.environ["SOURCE_REPOSITORY_ID"],
            source_owner_id=os.environ["SOURCE_OWNER_ID"],
        )
        verify_signed_tag(
            tag=dispatch["source_tag"],
            commit=dispatch["source_commit_sha"],
            public_key=args.public_key,
            primary_fingerprint=os.environ["SOURCE_SIGNING_PRIMARY_FINGERPRINT"],
            tag_fingerprint=os.environ["SOURCE_TAG_SIGNING_SUBKEY_FINGERPRINT"],
        )
    except (
        GitHubApiError,
        KeyError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        SourceVerificationError,
        ValueError,
    ) as error:
        print(f"verify-source: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
