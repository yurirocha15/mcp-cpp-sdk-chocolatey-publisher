#!/usr/bin/env python3
"""Verify the immutable source release and its Chocolatey package offline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile


CONTROL = {"release-manifest.json", "release-manifest.json.asc", "SHA256SUMS", "SHA256SUMS.asc"}
FINGERPRINT = re.compile(r"[0-9A-F]{40}|[0-9A-F]{64}")
DIGEST = re.compile(r"[0-9a-f]{64}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify(
    directory: Path,
    *,
    tag: str,
    commit: str,
    manifest_sha256: str,
    primary_fingerprint: str,
    artifact_fingerprint: str,
    public_key: Path,
) -> tuple[str, str]:
    release_key = directory / "release-signing-key.asc"
    if release_key.read_bytes() != public_key.read_bytes():
        raise ValueError("release verification key differs from the protected publisher key")
    _verify_key(public_key, primary_fingerprint, artifact_fingerprint)

    manifest_path = directory / "release-manifest.json"
    if sha256(manifest_path) != manifest_sha256:
        raise ValueError("release manifest digest mismatch")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    version = tag.removeprefix("v")
    if manifest.get("tag") != tag or manifest.get("version") != version or manifest.get("commit") != commit:
        raise ValueError("release manifest source identity mismatch")
    signers = manifest.get("signers")
    if not isinstance(signers, dict):
        raise ValueError("release manifest signer map is missing")
    if signers.get("primary_fingerprint") != primary_fingerprint:
        raise ValueError("release manifest primary fingerprint mismatch")
    if signers.get("artifact_subkey_fingerprint") != artifact_fingerprint:
        raise ValueError("release manifest artifact fingerprint mismatch")

    payloads = manifest.get("payloads")
    if not isinstance(payloads, list):
        raise ValueError("release manifest payloads are missing")
    records: dict[str, dict[str, object]] = {}
    for item in payloads:
        if not isinstance(item, dict) or not {"name", "size", "sha256"} <= set(item):
            raise ValueError("release manifest payload record is malformed")
        name = item["name"]
        if not isinstance(name, str) or Path(name).name != name or name in CONTROL or name in records:
            raise ValueError("release manifest payload name is unsafe or duplicated")
        records[name] = item

    detached_signatures = {
        f"{name}.asc" for name in records if name.endswith((".tar.gz", ".zip"))
    }
    downloaded = {path.name for path in directory.iterdir() if path.is_file()}
    if downloaded != set(records) | CONTROL | detached_signatures:
        raise ValueError("release payload and detached-signature sets are not exact")
    for name, item in records.items():
        path = directory / name
        if path.stat().st_size != item["size"] or sha256(path) != item["sha256"]:
            raise ValueError(f"release manifest payload mismatch: {name}")

    checksums = _checksums((directory / "SHA256SUMS").read_text(encoding="utf-8"))
    expected_checksums = downloaded - {"SHA256SUMS", "SHA256SUMS.asc"}
    if set(checksums) != expected_checksums:
        raise ValueError("SHA256SUMS asset set mismatch")
    for name, digest in checksums.items():
        if sha256(directory / name) != digest:
            raise ValueError(f"SHA256SUMS mismatch: {name}")

    signed_assets = [
        (manifest_path, directory / "release-manifest.json.asc"),
        (directory / "SHA256SUMS", directory / "SHA256SUMS.asc"),
    ]
    signed_assets.extend(
        (directory / name, directory / f"{name}.asc")
        for name in sorted(records)
        if name.endswith((".tar.gz", ".zip"))
    )
    for signed, signature in signed_assets:
        _signature(signed, signature, public_key, primary_fingerprint, artifact_fingerprint)

    package_name = f"mcp-cpp-sdk.{version}.nupkg"
    packages = [name for name in records if name.endswith(".nupkg")]
    if packages != [package_name]:
        raise ValueError("release does not contain the one exact Chocolatey package")
    package_digest = str(records[package_name]["sha256"])
    _verify_nupkg(directory / package_name, version=version, tag=tag, records=records)
    return package_name, package_digest


def _verify_nupkg(
    path: Path, *, version: str, tag: str, records: dict[str, dict[str, object]]
) -> None:
    with zipfile.ZipFile(path) as package:
        names = package.namelist()
        if len(names) != len(set(names)):
            raise ValueError("Chocolatey package contains duplicate paths")
        for name in names:
            member = PurePosixPath(name)
            if member.is_absolute() or ".." in member.parts or "\\" in name:
                raise ValueError("Chocolatey package contains an unsafe path")
        required = {
            "tools/chocolateyinstall.ps1",
            "tools/chocolateyuninstall.ps1",
            "LICENSE.txt",
            "VERIFICATION.txt",
        }
        if not required <= set(names):
            raise ValueError("Chocolatey package omits required files")
        nuspecs = [name for name in names if PurePosixPath(name).parent == PurePosixPath(".") and name.endswith(".nuspec")]
        if len(nuspecs) != 1:
            raise ValueError("Chocolatey package must contain one root nuspec")
        root = ET.fromstring(package.read(nuspecs[0]))
        namespace = {"n": "http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd"}
        metadata = root.find("n:metadata", namespace)
        if metadata is None:
            raise ValueError("Chocolatey nuspec metadata is missing")

        def text(name: str) -> str:
            element = metadata.find(f"n:{name}", namespace)
            if element is None or element.text is None:
                raise ValueError(f"Chocolatey nuspec {name} is missing")
            return element.text

        if text("id") != "mcp-cpp-sdk" or text("version") != version:
            raise ValueError("Chocolatey nuspec identity mismatch")
        license_element = metadata.find("n:license", namespace)
        if license_element is None or license_element.get("type") != "expression" or license_element.text != "Apache-2.0":
            raise ValueError("Chocolatey nuspec license is not Apache-2.0")
        install_script = package.read("tools/chocolateyinstall.ps1").decode("utf-8")

    archive_name = f"mcp-cpp-sdk-{version}-windows-x64-v143-md.zip"
    expected_url = f"https://github.com/yurirocha15/mcp-cpp-sdk/releases/download/{tag}/{archive_name}"
    if expected_url not in install_script or "MCP_CPP_SDK_ROOT" not in install_script:
        raise ValueError("Chocolatey install script does not bind the immutable SDK archive")
    checksum = re.search(r"-Checksum64 '([0-9a-f]{64})'", install_script)
    if checksum is None or archive_name not in records or checksum.group(1) != records[archive_name]["sha256"]:
        raise ValueError("Chocolatey install checksum does not match the release manifest")


def _verify_key(path: Path, primary_fingerprint: str, artifact_fingerprint: str) -> None:
    result = subprocess.run(
        ["gpg", "--batch", "--with-colons", "--show-keys", str(path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise ValueError("release public key is unreadable")
    fingerprints = [line.split(":")[9] for line in result.stdout.splitlines() if line.startswith("fpr:")]
    if not fingerprints or fingerprints[0] != primary_fingerprint or artifact_fingerprint not in fingerprints:
        raise ValueError("release public key fingerprint mismatch")


def _checksums(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+-]*)", line)
        if match is None or match.group(2) in result:
            raise ValueError("SHA256SUMS record is malformed or duplicated")
        result[match.group(2)] = match.group(1)
    return result


def _signature(signed: Path, signature: Path, key: Path, primary: str, artifact: str) -> None:
    with tempfile.TemporaryDirectory() as home:
        imported = subprocess.run(
            ["gpg", "--batch", "--homedir", home, "--import", str(key)],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if imported.returncode != 0:
            raise ValueError("release key import failed")
        result = subprocess.run(
            ["gpgv", "--homedir", home, "--status-fd", "1", "--keyring", f"{home}/pubring.kbx", str(signature), str(signed)],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    signatures = [line.split() for line in result.stdout.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
    if result.returncode != 0 or len(signatures) != 1 or len(signatures[0]) < 12:
        raise ValueError(f"signature verification failed: {signed.name}")
    if signatures[0][2] != artifact or signatures[0][-1] != primary:
        raise ValueError(f"signature identity mismatch: {signed.name}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--primary-fingerprint", required=True)
    parser.add_argument("--artifact-fingerprint", required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    args = parser.parse_args()
    try:
        if DIGEST.fullmatch(args.manifest_sha256) is None:
            raise ValueError("manifest SHA-256 is malformed")
        if FINGERPRINT.fullmatch(args.primary_fingerprint) is None or FINGERPRINT.fullmatch(args.artifact_fingerprint) is None:
            raise ValueError("configured release fingerprint is malformed")
        package_name, package_digest = verify(
            args.directory,
            tag=args.tag,
            commit=args.commit,
            manifest_sha256=args.manifest_sha256,
            primary_fingerprint=args.primary_fingerprint,
            artifact_fingerprint=args.artifact_fingerprint,
            public_key=args.public_key,
        )
        output_path = os.environ.get("GITHUB_OUTPUT")
        if output_path:
            with Path(output_path).open("a", encoding="utf-8") as output:
                output.write(f"package_name={package_name}\npackage_sha256={package_digest}\n")
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        ValueError,
        ET.ParseError,
        zipfile.BadZipFile,
    ) as error:
        print(f"verify-release: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
