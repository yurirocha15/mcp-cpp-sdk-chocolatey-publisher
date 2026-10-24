from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from uuid import NAMESPACE_URL, uuid5

from publisher.github_api import GitHubApiError, require_gh_version
from publisher.submission import (
    SubmissionError,
    claim_body,
    claim_identity,
    decide_claim,
    prepare_handoff,
    record_claim,
    sha256,
)
from publisher.verify_release import _verify_publication_contract
from publisher.verify_source import (
    SOURCE_RUN_ATTEMPTS,
    SOURCE_RUN_INTERVAL_SECONDS,
    SOURCE_RUN_MAX_CONSECUTIVE_FAILURES,
    SourceVerificationError,
    verify_execution_context,
    verify_source_state,
)


PUBLISHER = "yurirocha15/mcp-cpp-sdk-chocolatey-publisher"
SOURCE = "yurirocha15/mcp-cpp-sdk"
ROOT = Path(__file__).resolve().parents[1]


def dispatch() -> dict[str, str]:
    value = {
        "source_tag": "v0.2.0",
        "source_commit_sha": "0" * 40,
        "source_workflow_head_sha": "1" * 40,
        "provider_control_sha": "2" * 40,
        "github_release_id": "10",
        "source_workflow_run_id": "20",
        "release_manifest_sha256": "3" * 64,
    }
    value["request_uuid"] = str(
        uuid5(
            NAMESPACE_URL,
            f"{SOURCE}:{value['source_tag']}:{value['release_manifest_sha256']}:chocolatey",
        )
    )
    return value


class FakeSourceApi:
    def __init__(self) -> None:
        self.run_head_sha = "1" * 40

    def __call__(self, method: str, endpoint: str, payload=None):
        if endpoint == f"repos/{SOURCE}":
            return {
                "id": 101,
                "full_name": SOURCE,
                "default_branch": "main",
                "archived": False,
                "disabled": False,
                "owner": {"id": 202},
            }
        if endpoint.endswith("/releases/tags/v0.2.0"):
            return {
                "id": 10,
                "tag_name": "v0.2.0",
                "draft": False,
                "prerelease": False,
                "immutable": True,
            }
        if endpoint.endswith("/actions/runs/20"):
            return {
                "status": "completed",
                "event": "workflow_dispatch",
                "conclusion": "success",
                "head_sha": self.run_head_sha,
                "head_branch": "main",
                "path": ".github/workflows/release.yml",
                "repository": {"id": 101, "full_name": SOURCE},
            }
        raise AssertionError(endpoint)


class SourceVerificationTests(unittest.TestCase):
    def test_isolated_runner_executes_dispatch_validator(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            environment = dict(os.environ)
            environment["DISPATCH_JSON"] = json.dumps(dispatch())
            environment["GITHUB_OUTPUT"] = str(output)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "run_publisher_tool.py",
                    "validate_dispatch",
                ],
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("source_workflow_head_sha=" + "1" * 40, output.read_text())

    def test_github_cli_version_is_a_minimum(self) -> None:
        for version in ("2.96.0", "2.102.0", "3.0.0"):
            valid = subprocess.CompletedProcess(
                [], 0, stdout=f"gh version {version} (2026-06-25)\n".encode(), stderr=b""
            )
            with self.subTest(version=version), patch(
                "publisher.github_api.subprocess.run", return_value=valid
            ):
                require_gh_version()
        wrong = subprocess.CompletedProcess(
            [], 0, stdout=b"gh version 2.95.0 (2026-06-01)\n", stderr=b""
        )
        with (
            patch("publisher.github_api.subprocess.run", return_value=wrong),
            self.assertRaises(GitHubApiError),
        ):
            require_gh_version()

    def test_control_tag_context_binds_exact_provider_commit(self) -> None:
        value = dispatch()
        control_tag = verify_execution_context(
            value,
            repository=PUBLISHER,
            repository_id="303",
            expected_repository_id="303",
            sha=value["provider_control_sha"],
            ref="refs/tags/release-control-v2",
            workflow_ref=(
                f"{PUBLISHER}/.github/workflows/publish.yml@"
                "refs/tags/release-control-v2"
            ),
        )
        self.assertEqual(control_tag, "release-control-v2")
        with self.assertRaises(SourceVerificationError):
            verify_execution_context(
                value,
                repository=PUBLISHER,
                repository_id="303",
                expected_repository_id="303",
                sha="4" * 40,
                ref="refs/tags/release-control-v2",
                workflow_ref=(
                    f"{PUBLISHER}/.github/workflows/publish.yml@"
                    "refs/tags/release-control-v2"
                ),
            )

    def test_resumed_release_uses_workflow_head_not_release_commit(self) -> None:
        value = dispatch()
        self.assertNotEqual(
            value["source_commit_sha"], value["source_workflow_head_sha"]
        )
        verify_source_state(
            FakeSourceApi(),
            value,
            source_repository_id="101",
            source_owner_id="202",
            sleep=lambda _: None,
        )

    def test_source_run_polling_waits_two_hours_at_thirty_seconds(self) -> None:
        self.assertEqual(SOURCE_RUN_INTERVAL_SECONDS, 30)
        self.assertEqual(SOURCE_RUN_ATTEMPTS * SOURCE_RUN_INTERVAL_SECONDS, 7200)
        api = FakeSourceApi()
        polls = {"count": 0}
        original = api.__call__

        def slow(method, endpoint, payload=None):
            result = original(method, endpoint, payload)
            if endpoint.endswith("/actions/runs/20"):
                polls["count"] += 1
                if polls["count"] < 200:
                    return {**result, "status": "in_progress", "conclusion": None}
            return result

        sleeps: list[float] = []
        verify_source_state(
            slow,
            dispatch(),
            source_repository_id="101",
            source_owner_id="202",
            sleep=sleeps.append,
        )
        self.assertEqual(len(sleeps), 199)
        self.assertEqual(set(sleeps), {30})

    def test_source_run_that_never_completes_times_out_after_all_attempts(self) -> None:
        api = FakeSourceApi()
        original = api.__call__
        polls = {"count": 0}

        def never(method, endpoint, payload=None):
            result = original(method, endpoint, payload)
            if endpoint.endswith("/actions/runs/20"):
                polls["count"] += 1
                return {**result, "status": "queued", "conclusion": None}
            return result

        with self.assertRaises(SourceVerificationError):
            verify_source_state(
                never,
                dispatch(),
                source_repository_id="101",
                source_owner_id="202",
                sleep=lambda _: None,
            )
        self.assertEqual(polls["count"], SOURCE_RUN_ATTEMPTS)

    def test_approval_gate_statuses_keep_waiting(self) -> None:
        for status in ("waiting", "requested", "pending", "queued", "in_progress"):
            api = FakeSourceApi()
            original = api.__call__
            polls = {"count": 0}

            def gated(method, endpoint, payload=None, original=original, polls=polls, status=status):
                result = original(method, endpoint, payload)
                if endpoint.endswith("/actions/runs/20"):
                    polls["count"] += 1
                    if polls["count"] < 3:
                        return {**result, "status": status, "conclusion": None}
                return result

            with self.subTest(status=status):
                verify_source_state(
                    gated, dispatch(), source_repository_id="101",
                    source_owner_id="202", sleep=lambda _: None,
                )
                self.assertEqual(polls["count"], 3)

    def _flaky(self, failures_in_a_row: int, cycles: int):
        api = FakeSourceApi()
        original = api.__call__
        polls = {"count": 0}

        def flaky(method, endpoint, payload=None):
            if endpoint.endswith("/actions/runs/20"):
                polls["count"] += 1
                position = (polls["count"] - 1) % (failures_in_a_row + 1)
                if polls["count"] <= cycles * (failures_in_a_row + 1) - 1 and position < failures_in_a_row:
                    raise GitHubApiError("GitHub API request failed")
                if polls["count"] <= cycles * (failures_in_a_row + 1) - 1:
                    return {**original(method, endpoint, payload), "status": "waiting", "conclusion": None}
            return original(method, endpoint, payload)

        return flaky

    def test_four_consecutive_transient_failures_are_tolerated(self) -> None:
        self.assertEqual(SOURCE_RUN_MAX_CONSECUTIVE_FAILURES, 4)
        verify_source_state(
            self._flaky(4, 3), dispatch(), source_repository_id="101",
            source_owner_id="202", sleep=lambda _: None,
        )

    def test_fifth_consecutive_transient_failure_is_raised(self) -> None:
        with self.assertRaises(GitHubApiError):
            verify_source_state(
                self._flaky(5, 3), dispatch(), source_repository_id="101",
                source_owner_id="202", sleep=lambda _: None,
            )

    def test_verify_job_timeout_covers_source_polling(self) -> None:
        workflow = (ROOT / ".github/workflows/publish.yml").read_text(encoding="utf-8")
        verify = workflow.split("\n  verify:\n", 1)[1].split("\n  claim:\n", 1)[0]
        match = re.search(r"timeout-minutes: ([0-9]+)", verify)
        self.assertIsNotNone(match)
        self.assertGreater(
            int(match.group(1)) * 60,
            SOURCE_RUN_ATTEMPTS * SOURCE_RUN_INTERVAL_SECONDS,
        )

    def test_wrong_source_workflow_head_fails_closed(self) -> None:
        api = FakeSourceApi()
        api.run_head_sha = "4" * 40
        with self.assertRaises(SourceVerificationError):
            verify_source_state(
                api,
                dispatch(),
                source_repository_id="101",
                source_owner_id="202",
                sleep=lambda _: None,
            )


class PublicationContractTests(unittest.TestCase):
    def contract(self) -> dict[str, object]:
        value = dispatch()
        return {
            "schema_version": 1,
            "native_targets": [],
            "native_builders": [],
            "channel_targets": {
                "aur": {},
                "homebrew": {},
                "chocolatey": {
                    "package_id": "mcp-cpp-sdk",
                    "architecture": "x86_64",
                    "toolset": "v143",
                    "runtime": "MD",
                },
            },
            "destinations": {
                "cloudsmith": {},
                "homebrew": {},
                "chocolatey": {
                    "repository": PUBLISHER,
                    "repository_id": "303",
                },
                "conan_control": {},
            },
            "conan_requirements": [],
            "provider_controls": {
                "homebrew": {},
                "chocolatey": {
                    "repository": PUBLISHER,
                    "control_tag": "release-control-v2",
                    "control_commit": value["provider_control_sha"],
                    "workflow": "publish.yml",
                },
                "conan": {},
            },
        }

    def test_signed_destination_and_control_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            path.write_text(json.dumps(self.contract()), encoding="utf-8")
            _verify_publication_contract(
                path,
                publisher_repository_id="303",
                provider_control_tag="release-control-v2",
                provider_control_sha="2" * 40,
            )

    def test_wrong_signed_control_commit_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            path.write_text(json.dumps(self.contract()), encoding="utf-8")
            with self.assertRaises(ValueError):
                _verify_publication_contract(
                    path,
                    publisher_repository_id="303",
                    provider_control_tag="release-control-v2",
                    provider_control_sha="4" * 40,
                )


class SubmissionStateTests(unittest.TestCase):
    def test_prepare_handoff_binds_package_script_dispatch_and_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "mcp-cpp-sdk.0.2.0.nupkg"
            package.write_bytes(b"package")
            script = root / "publish.ps1"
            script.write_text("publisher", encoding="utf-8")
            output = root / "submission"
            prepare_handoff(
                output,
                dispatch=dispatch(),
                package=package,
                package_sha256=sha256(package),
                publisher_script=script,
                run_id="30",
                run_attempt="1",
            )
            self.assertEqual(
                {path.name for path in output.iterdir()},
                {"identity.json", package.name, "publish.ps1"},
            )
            identity = json.loads((output / "identity.json").read_text())
            self.assertEqual(identity["source_workflow_head_sha"], "1" * 40)
            self.assertEqual(identity["publisher_script_sha256"], sha256(script))

    def test_claim_is_idempotent_across_source_workflow_retries(self) -> None:
        first_dispatch = dispatch()
        identity = claim_identity(
            first_dispatch,
            package_name="mcp-cpp-sdk.0.2.0.nupkg",
            package_sha256="a" * 64,
        )
        retry_dispatch = dict(first_dispatch)
        retry_dispatch["source_workflow_head_sha"] = "4" * 40
        retry_dispatch["source_workflow_run_id"] = "21"
        self.assertEqual(
            identity,
            claim_identity(
                retry_dispatch,
                package_name="mcp-cpp-sdk.0.2.0.nupkg",
                package_sha256="a" * 64,
            ),
        )
        issue = {"number": 7, "body": claim_body(identity, "SUBMITTED")}
        decision = decide_claim([issue], identity)
        self.assertTrue(decision.already_submitted)
        self.assertEqual(decision.issue_number, 7)

    def test_same_request_resumes_its_own_preparing_claim(self) -> None:
        identity = claim_identity(
            dispatch(),
            package_name="mcp-cpp-sdk.0.2.0.nupkg",
            package_sha256="a" * 64,
        )
        decision = decide_claim(
            [{"number": 7, "body": claim_body(identity, "PREPARING")}], identity
        )
        self.assertEqual(decision.issue_number, 7)
        self.assertFalse(decision.already_submitted)
        self.assertIsNone(decision.new_body)

    def test_other_request_does_not_resume_a_preparing_claim(self) -> None:
        identity = claim_identity(
            dispatch(),
            package_name="mcp-cpp-sdk.0.2.0.nupkg",
            package_sha256="a" * 64,
        )
        other = dict(identity)
        other["request_uuid"] = "00000000-0000-4000-8000-000000000002"
        with self.assertRaises(SubmissionError):
            decide_claim(
                [{"number": 7, "body": claim_body(other, "PREPARING")}], identity
            )

    def test_conflicting_claims_fail_closed(self) -> None:
        identity = claim_identity(
            dispatch(),
            package_name="mcp-cpp-sdk.0.2.0.nupkg",
            package_sha256="a" * 64,
        )
        conflicting = dict(identity)
        conflicting["package_sha256"] = "b" * 64
        with self.assertRaises(SubmissionError):
            decide_claim(
                [{"number": 7, "body": claim_body(conflicting, "SUBMITTED")}],
                identity,
            )

    def test_record_reads_preparing_claim_before_mutating(self) -> None:
        identity = claim_identity(
            dispatch(),
            package_name="mcp-cpp-sdk.0.2.0.nupkg",
            package_sha256="a" * 64,
        )

        class FakeIssueApi:
            def __init__(self) -> None:
                self.body = claim_body(identity, "PREPARING")

            def __call__(self, method, endpoint, payload=None):
                if method == "GET":
                    return {"number": 7, "body": self.body}
                self.body = payload["body"]
                return {"number": 7, "body": self.body}

        api = FakeIssueApi()
        with patch("publisher.submission.GhApi", return_value=api):
            record_claim(
                dispatch(),
                issue_number="7",
                package_name="mcp-cpp-sdk.0.2.0.nupkg",
                package_sha256="a" * 64,
            )
        self.assertIn('"state":"SUBMITTED"', api.body)


if __name__ == "__main__":
    unittest.main()
