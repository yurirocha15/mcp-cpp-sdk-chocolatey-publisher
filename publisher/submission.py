#!/usr/bin/env python3
"""Prepare, claim, and record one digest-bound Chocolatey submission."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
from typing import Mapping, Sequence

from publisher.github_api import (
    GhApi,
    GitHubApiError,
    paginated_get,
    require_gh_version,
    strict_pairs,
)
from publisher.validate_dispatch import validate


PUBLISHER_REPOSITORY = "yurirocha15/mcp-cpp-sdk-chocolatey-publisher"
ISSUE_LABEL = "chocolatey-submission"
PACKAGE_ID = "mcp-cpp-sdk"
CLAIM_IDENTITY_FIELDS = frozenset(
    {
        "source_tag",
        "source_commit_sha",
        "provider_control_sha",
        "github_release_id",
        "release_manifest_sha256",
        "request_uuid",
        "package_name",
        "package_sha256",
    }
)


class SubmissionError(ValueError):
    """Raised when a submission handoff or durable claim is ambiguous."""


@dataclass(frozen=True)
class ClaimDecision:
    issue_number: int | None
    already_submitted: bool
    new_body: str | None


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _dispatch() -> dict[str, str]:
    return validate(
        json.loads(os.environ["DISPATCH_JSON"], object_pairs_hook=strict_pairs)
    )


def _positive_decimal(value: str, label: str) -> str:
    if not value.isascii() or not value.isdecimal() or value.startswith("0"):
        raise SubmissionError(f"{label} is not a positive canonical decimal")
    return value


def claim_identity(
    dispatch: Mapping[str, str], *, package_name: str, package_sha256: str
) -> dict[str, str]:
    expected_name = f"{PACKAGE_ID}.{dispatch['source_tag'][1:]}.nupkg"
    if package_name != expected_name:
        raise SubmissionError("Chocolatey package name differs from the source tag")
    if len(package_sha256) != 64 or any(character not in "0123456789abcdef" for character in package_sha256):
        raise SubmissionError("Chocolatey package digest is malformed")
    return {
        "source_tag": dispatch["source_tag"],
        "source_commit_sha": dispatch["source_commit_sha"],
        "provider_control_sha": dispatch["provider_control_sha"],
        "github_release_id": dispatch["github_release_id"],
        "release_manifest_sha256": dispatch["release_manifest_sha256"],
        "request_uuid": dispatch["request_uuid"],
        "package_name": package_name,
        "package_sha256": package_sha256,
    }


def prepare_handoff(
    directory: Path,
    *,
    dispatch: Mapping[str, str],
    package: Path,
    package_sha256: str,
    publisher_script: Path,
    run_id: str,
    run_attempt: str,
) -> None:
    identity = claim_identity(
        dispatch, package_name=package.name, package_sha256=package_sha256
    )
    _positive_decimal(run_id, "publisher run ID")
    _positive_decimal(run_attempt, "publisher run attempt")
    if sha256(package) != package_sha256:
        raise SubmissionError("Chocolatey package differs from its verified digest")
    if publisher_script.name != "publish.ps1" or not publisher_script.is_file():
        raise SubmissionError("publisher script identity is wrong")
    if directory.exists():
        raise SubmissionError("submission handoff directory already exists")
    directory.mkdir()
    shutil.copyfile(package, directory / package.name)
    shutil.copyfile(publisher_script, directory / publisher_script.name)
    handoff = {
        "schema_version": 1,
        **dispatch,
        "package_name": package.name,
        "package_sha256": package_sha256,
        "publisher_script_sha256": sha256(publisher_script),
        "run_id": run_id,
        "run_attempt": run_attempt,
    }
    (directory / "identity.json").write_text(
        json.dumps(handoff, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _marker(identity: Mapping[str, str]) -> str:
    version = identity["source_tag"][1:]
    return f"<!-- chocolatey-submission:v1 package={PACKAGE_ID} version={version} -->"


def claim_body(identity: Mapping[str, str], state: str) -> str:
    if set(identity) != CLAIM_IDENTITY_FIELDS or state not in {"PREPARING", "SUBMITTED"}:
        raise SubmissionError("submission claim identity or state is malformed")
    visible_state = "PREPARING" if state == "PREPARING" else "SUBMITTED_PENDING_MODERATION"
    claim = {"schema_version": 1, "state": state, "identity": dict(identity)}
    return (
        _marker(identity)
        + f"\n\nChocolatey submission state: **{visible_state}**\n\n"
        + "<!-- chocolatey-submission-json\n"
        + json.dumps(claim, sort_keys=True, separators=(",", ":"))
        + "\nchocolatey-submission-json -->\n"
    )


def _parse_claim(body: str, identity: Mapping[str, str]) -> str:
    prefix = "<!-- chocolatey-submission-json\n"
    suffix = "\nchocolatey-submission-json -->"
    if body.count(_marker(identity)) != 1 or body.count(prefix) != 1 or body.count(suffix) != 1:
        raise SubmissionError("existing submission claim is malformed")
    encoded = body.split(prefix, 1)[1].split(suffix, 1)[0]
    value = json.loads(encoded, object_pairs_hook=strict_pairs)
    if not isinstance(value, dict) or set(value) != {"schema_version", "state", "identity"}:
        raise SubmissionError("existing submission claim schema is not exact")
    if value["schema_version"] != 1 or value["identity"] != dict(identity):
        raise SubmissionError("existing submission claim conflicts with this release")
    state = value["state"]
    if state not in {"PREPARING", "SUBMITTED"}:
        raise SubmissionError("existing submission claim state is invalid")
    if body != claim_body(identity, state):
        raise SubmissionError("existing submission claim body is not canonical")
    return state


def decide_claim(
    issues: Sequence[object], identity: Mapping[str, str]
) -> ClaimDecision:
    matches: list[Mapping[str, object]] = []
    marker = _marker(identity)
    for value in issues:
        if not isinstance(value, Mapping) or "pull_request" in value:
            continue
        body = value.get("body")
        if isinstance(body, str) and marker in body:
            matches.append(value)
    if len(matches) > 1:
        raise SubmissionError("submission claim identity is ambiguous")
    if not matches:
        return ClaimDecision(None, False, claim_body(identity, "PREPARING"))
    issue = matches[0]
    number = issue.get("number")
    body = issue.get("body")
    if type(number) is not int or number < 1 or not isinstance(body, str):
        raise SubmissionError("existing submission issue identity is malformed")
    state = _parse_claim(body, identity)
    if state == "PREPARING":
        # _parse_claim proved the identity (including request_uuid) is
        # byte-identical, so this is a retry of the same request: resume its
        # own claim. A different request or package never reaches this point.
        return ClaimDecision(number, False, None)
    return ClaimDecision(number, True, None)


def create_or_find_claim(
    dispatch: Mapping[str, str], *, package_name: str, package_sha256: str
) -> ClaimDecision:
    identity = claim_identity(
        dispatch, package_name=package_name, package_sha256=package_sha256
    )
    issues = paginated_get(
        f"repos/{PUBLISHER_REPOSITORY}/issues?state=all&labels={ISSUE_LABEL}&per_page=100"
    )
    decision = decide_claim(issues, identity)
    if decision.new_body is None:
        return decision
    version = dispatch["source_tag"][1:]
    response = GhApi()(
        "POST",
        f"repos/{PUBLISHER_REPOSITORY}/issues",
        {
            "title": f"[chocolatey] {PACKAGE_ID} {version}",
            "body": decision.new_body,
            "labels": [ISSUE_LABEL],
        },
    )
    if not isinstance(response, Mapping):
        raise SubmissionError("created submission issue response is malformed")
    issue_number = response.get("number")
    if type(issue_number) is not int or issue_number < 1 or response.get("body") != decision.new_body:
        raise SubmissionError("created submission issue identity is wrong")
    return ClaimDecision(issue_number, False, None)


def record_claim(
    dispatch: Mapping[str, str],
    *,
    issue_number: str,
    package_name: str,
    package_sha256: str,
) -> None:
    number = int(_positive_decimal(issue_number, "submission issue number"))
    identity = claim_identity(
        dispatch, package_name=package_name, package_sha256=package_sha256
    )
    api = GhApi()
    endpoint = f"repos/{PUBLISHER_REPOSITORY}/issues/{number}"
    existing = api("GET", endpoint)
    if not isinstance(existing, Mapping) or existing.get("number") != number:
        raise SubmissionError("submission issue readback is malformed")
    body = existing.get("body")
    if not isinstance(body, str) or _parse_claim(body, identity) != "PREPARING":
        raise SubmissionError("submission claim is not in PREPARING state")
    submitted = claim_body(identity, "SUBMITTED")
    updated = api("PATCH", endpoint, {"body": submitted})
    if not isinstance(updated, Mapping) or updated.get("number") != number or updated.get("body") != submitted:
        raise SubmissionError("submitted claim readback is wrong")


def _write_claim_outputs(decision: ClaimDecision) -> None:
    output_path = Path(os.environ["GITHUB_OUTPUT"])
    if decision.issue_number is None:
        raise SubmissionError("submission claim has no issue number")
    with output_path.open("a", encoding="ascii") as output:
        output.write(f"issue_number={decision.issue_number}\n")
        output.write(
            f"already_submitted={'true' if decision.already_submitted else 'false'}\n"
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--directory", type=Path, required=True)
    prepare.add_argument("--package", type=Path, required=True)
    prepare.add_argument("--package-sha256", required=True)
    prepare.add_argument("--publisher-script", type=Path, required=True)
    prepare.add_argument("--run-id", required=True)
    prepare.add_argument("--run-attempt", required=True)
    claim = commands.add_parser("claim")
    claim.add_argument("--package-name", required=True)
    claim.add_argument("--package-sha256", required=True)
    record = commands.add_parser("record")
    record.add_argument("--issue-number", required=True)
    record.add_argument("--package-name", required=True)
    record.add_argument("--package-sha256", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        dispatch = _dispatch()
        if args.command == "prepare":
            prepare_handoff(
                args.directory,
                dispatch=dispatch,
                package=args.package,
                package_sha256=args.package_sha256,
                publisher_script=args.publisher_script,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
            )
        elif args.command == "claim":
            require_gh_version()
            _write_claim_outputs(
                create_or_find_claim(
                    dispatch,
                    package_name=args.package_name,
                    package_sha256=args.package_sha256,
                )
            )
        else:
            require_gh_version()
            record_claim(
                dispatch,
                issue_number=args.issue_number,
                package_name=args.package_name,
                package_sha256=args.package_sha256,
            )
    except (
        GitHubApiError,
        KeyError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        SubmissionError,
        ValueError,
    ) as error:
        print(f"submission: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
