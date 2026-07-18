from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from uuid import UUID
import zipfile

from publisher.scan_repository_secrets import (
    SENSITIVE_PATTERN,
    find_sensitive_paths,
    tracked_files,
)
from publisher.validate_dispatch import validate
from publisher.verify_release import _verify_nupkg


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
ACTION = re.compile(r"uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([0-9a-f]{40})(?:\s|$)")


class DispatchTests(unittest.TestCase):
    def request(self) -> dict[str, str]:
        return {
            "source_tag": "v0.2.0",
            "source_commit_sha": "0" * 40,
            "github_release_id": "1",
            "source_workflow_run_id": "2",
            "release_manifest_sha256": "1" * 64,
            "request_uuid": str(UUID(int=1)),
        }

    def test_exact_stable_dispatch(self) -> None:
        self.assertEqual(validate(self.request()), self.request())

    def test_rejects_rc_extra_and_noncanonical_values(self) -> None:
        for field, value in (
            ("source_tag", "v0.2.0-rc.1"),
            ("source_commit_sha", "A" * 40),
            ("github_release_id", "01"),
            ("extra", "value"),
        ):
            request = self.request()
            request[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate(request)


class PackageTests(unittest.TestCase):
    def test_nupkg_binds_archive_checksum_and_sdk_root(self) -> None:
        version = "0.2.0"
        tag = f"v{version}"
        archive = f"mcp-cpp-sdk-{version}-windows-x64-v143-md.zip"
        digest = "a" * 64
        nuspec = """<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd">
  <metadata>
    <id>mcp-cpp-sdk</id><version>0.2.0</version>
    <license type="expression">Apache-2.0</license>
  </metadata>
</package>
"""
        install = (
            f"Get-ChocolateyWebFile -Url64bit 'https://github.com/yurirocha15/mcp-cpp-sdk/releases/download/{tag}/{archive}' "
            f"-Checksum64 '{digest}'\nMCP_CPP_SDK_ROOT\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / f"mcp-cpp-sdk.{version}.nupkg"
            with zipfile.ZipFile(package, "w") as output:
                output.writestr("mcp-cpp-sdk.nuspec", nuspec)
                output.writestr("tools/chocolateyinstall.ps1", install)
                output.writestr("tools/chocolateyuninstall.ps1", "uninstall")
                output.writestr("LICENSE.txt", "license")
                output.writestr("VERIFICATION.txt", "verification")
            _verify_nupkg(
                package,
                version=version,
                tag=tag,
                records={archive: {"sha256": digest}},
            )
            with zipfile.ZipFile(package, "a") as output:
                output.writestr("../escape", "bad")
            with self.assertRaises(ValueError):
                _verify_nupkg(
                    package,
                    version=version,
                    tag=tag,
                    records={archive: {"sha256": digest}},
                )


class WorkflowPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = (WORKFLOWS / "publish.yml").read_text(encoding="utf-8")
        self.manifest = json.loads((ROOT / "repository-settings.json").read_text(encoding="utf-8"))

    def test_actions_are_full_sha_allowlisted(self) -> None:
        allowed = self.manifest["actions"]["allowed_actions"]
        for path in WORKFLOWS.glob("*.yml"):
            for line in path.read_text(encoding="utf-8").splitlines():
                if "uses:" not in line:
                    continue
                match = ACTION.search(line)
                self.assertIsNotNone(match, line)
                self.assertEqual(allowed.get(match.group(1)), match.group(2))

    def test_api_key_is_one_final_no_checkout_step(self) -> None:
        publish = self.workflow.split("\n  publish:\n", 1)[1].split("\n  record:\n", 1)[0]
        self.assertNotIn("actions/checkout", publish)
        self.assertNotIn("publisher/", publish)
        self.assertEqual(publish.count("secrets.CHOCOLATEY_API_KEY"), 1)
        self.assertTrue(publish.rstrip().endswith('throw "Chocolatey push failed with exit code $LASTEXITCODE"\n          }'))

    def test_claim_and_record_are_credential_free(self) -> None:
        claim = self.workflow.split("\n  claim:\n", 1)[1].split("\n  publish:\n", 1)[0]
        record = self.workflow.split("\n  record:\n", 1)[1]
        self.assertNotIn("secrets.", claim)
        self.assertNotIn("secrets.", record)
        self.assertIn("existing PREPARING claim requires manual reconciliation", claim)


class SecretScanTests(unittest.TestCase):
    def test_detector_recognizes_each_forbidden_shape(self) -> None:
        samples = (
            b"-----BEGIN PRIVATE" b" KEY-----",
            b"ghp_" + b"a" * 20,
            b"CHOCOLATEY_" b"API_KEY=secret",
        )
        for sample in samples:
            with self.subTest(sample=sample[:16]):
                self.assertIsNotNone(SENSITIVE_PATTERN.search(sample))

    def test_tracked_repository_does_not_match_its_own_scanner(self) -> None:
        self.assertEqual(find_sensitive_paths(ROOT), [])

    def test_tracked_sensitive_file_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "--quiet", str(root)], check=True)
            (root / "leak.txt").write_bytes(b"CHOCOLATEY_" b"API_KEY=secret")
            subprocess.run(["git", "-C", str(root), "add", "leak.txt"], check=True)
            self.assertEqual(find_sensitive_paths(root), [Path("leak.txt")])

    def test_unsafe_path_error_escapes_control_characters(self) -> None:
        result = subprocess.CompletedProcess([], 0, stdout=b"../bad\n\x1b[31m\0")
        with (
            patch("publisher.scan_repository_secrets.subprocess.run", return_value=result),
            self.assertRaises(ValueError) as context,
        ):
            tracked_files(ROOT)
        message = str(context.exception)
        self.assertNotIn("\n", message)
        self.assertNotIn("\x1b", message)
        self.assertIn(r"\n\x1b", message)


if __name__ == "__main__":
    unittest.main()
