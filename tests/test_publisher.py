from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from uuid import NAMESPACE_URL, uuid5
import zipfile

from publisher.scan_repository_secrets import (
    SENSITIVE_PATTERN,
    find_sensitive_paths,
    tracked_files,
)
from publisher.validate_dispatch import validate
from publisher.verify_release import _install_script, _uninstall_script, _verify_nupkg


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
ACTION = re.compile(r"uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([0-9a-f]{40})(?:\s|$)")


class DispatchTests(unittest.TestCase):
    def request(self) -> dict[str, str]:
        request = {
            "source_tag": "v0.2.0",
            "source_commit_sha": "0" * 40,
            "source_workflow_head_sha": "1" * 40,
            "provider_control_sha": "2" * 40,
            "github_release_id": "1",
            "source_workflow_run_id": "2",
            "release_manifest_sha256": "3" * 64,
        }
        request["request_uuid"] = str(
            uuid5(
                NAMESPACE_URL,
                f"yurirocha15/mcp-cpp-sdk:{request['source_tag']}:"
                f"{request['release_manifest_sha256']}:chocolatey",
            )
        )
        return request

    def test_exact_stable_dispatch(self) -> None:
        self.assertEqual(validate(self.request()), self.request())

    def test_rejects_rc_extra_and_noncanonical_values(self) -> None:
        for field, value in (
            ("source_tag", "v0.2.0-rc.1"),
            ("source_commit_sha", "A" * 40),
            ("github_release_id", "01"),
            ("request_uuid", "00000000-0000-0000-0000-000000000001"),
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
        license_url = f"https://github.com/yurirocha15/mcp-cpp-sdk/blob/{tag}/LICENSE"

        def nuspec_for(
            namespace: str = "http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd",
            url: str = license_url,
        ) -> bytes:
            # Shape emitted by ``choco pack`` 2.7.4: UTF-8 BOM, 2013/05
            # namespace, licenseUrl, and no <files> element.
            return (
                '\ufeff<?xml version="1.0" encoding="utf-8"?>\n'
                f'<package xmlns="{namespace}">\n'
                "  <metadata>\n"
                "    <id>mcp-cpp-sdk</id>\n    <version>0.2.0</version>\n"
                f"    <licenseUrl>{url}</licenseUrl>\n"
                "  </metadata>\n</package>\n"
            ).encode("utf-8")

        nuspec = nuspec_for()
        install = _install_script(
            version=version,
            archive_url=(
                f"https://github.com/yurirocha15/mcp-cpp-sdk/"
                f"releases/download/{tag}/{archive}"
            ),
            archive_sha256=digest,
        )
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / f"mcp-cpp-sdk.{version}.nupkg"

            def write_package(install_script: str, spec: bytes = nuspec) -> None:
                with zipfile.ZipFile(package, "w") as output:
                    output.writestr("mcp-cpp-sdk.nuspec", spec)
                    output.writestr("tools/chocolateyinstall.ps1", install_script)
                    output.writestr("tools/chocolateyuninstall.ps1", _uninstall_script())
                    output.writestr("LICENSE.txt", "license")
                    output.writestr(
                        "VERIFICATION.txt",
                        f"The archive SHA-256 is {digest} and is bound by the immutable "
                        "GitHub Release manifest.\n",
                    )

            write_package(install)
            _verify_nupkg(
                package,
                version=version,
                tag=tag,
                records={archive: {"sha256": digest}},
            )
            # The pre-pack 2015/06 namespace is still accepted.
            write_package(
                install,
                nuspec_for("http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd"),
            )
            _verify_nupkg(
                package, version=version, tag=tag, records={archive: {"sha256": digest}}
            )
            bad_specs = (
                nuspec_for("http://example.invalid/nuspec.xsd"),
                nuspec_for(url="https://github.com/yurirocha15/mcp-cpp-sdk/blob/v9.9.9/LICENSE"),
                nuspec_for(url="https://example.invalid/LICENSE"),
            )
            for bad in bad_specs:
                write_package(install, bad)
                with self.assertRaises(ValueError):
                    _verify_nupkg(
                        package,
                        version=version,
                        tag=tag,
                        records={archive: {"sha256": digest}},
                    )
            write_package(install)
            write_package(install + "Invoke-WebRequest 'https://example.invalid'\n")
            with self.assertRaises(ValueError):
                _verify_nupkg(
                    package,
                    version=version,
                    tag=tag,
                    records={archive: {"sha256": digest}},
                )
            write_package(install)
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
        self.assertEqual(publish.count("secrets.CHOCOLATEY_API_KEY"), 1)
        self.assertIn("environment: chocolatey-publish", publish)
        self.assertIn("./submission/publish.ps1", publish)

    def test_claim_and_record_are_credential_free(self) -> None:
        claim = self.workflow.split("\n  claim:\n", 1)[1].split("\n  publish:\n", 1)[0]
        record = self.workflow.split("\n  record:\n", 1)[1]
        self.assertNotIn("secrets.", claim)
        self.assertNotIn("secrets.", record)

    def test_workflow_has_exact_source_dispatch_and_no_embedded_python(self) -> None:
        dispatch = self.workflow.split("  workflow_dispatch:\n", 1)[1].split(
            "\npermissions:", 1
        )[0]
        declared = {
            match.group(1)
            for match in re.finditer(
                r"^      ([a-z][a-z0-9_]+):$", dispatch, re.MULTILINE
            )
        }
        self.assertEqual(
            declared,
            {
                "source_tag",
                "source_commit_sha",
                "source_workflow_head_sha",
                "provider_control_sha",
                "github_release_id",
                "source_workflow_run_id",
                "release_manifest_sha256",
                "request_uuid",
            },
        )
        self.assertNotIn("<<'PY'", self.workflow)
        self.assertNotIn("refs/heads/main", self.workflow)


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
