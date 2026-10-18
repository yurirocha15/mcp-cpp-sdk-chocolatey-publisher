Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Join-Path $env:RUNNER_TEMP 'chocolatey-publisher-offline-test'
if (Test-Path -LiteralPath $root) {
    Remove-Item -LiteralPath $root -Recurse -Force
}
New-Item -ItemType Directory -Path $root | Out-Null

try {
    $submission = Join-Path $root 'submission'
    New-Item -ItemType Directory -Path $submission | Out-Null
    $packageName = 'mcp-cpp-sdk.0.2.0.nupkg'
    $package = Join-Path $submission $packageName
    [IO.File]::WriteAllBytes($package, [byte[]](1, 2, 3, 4))
    $packageSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $package).Hash.ToLowerInvariant()
    $publisher = Join-Path $submission 'publish.ps1'
    Copy-Item -LiteralPath 'publisher/publish.ps1' -Destination $publisher
    $publisherSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $publisher).Hash.ToLowerInvariant()

    $identity = [ordered]@{
        schema_version = 1
        source_tag = 'v0.2.0'
        source_commit_sha = '0000000000000000000000000000000000000000'
        source_workflow_head_sha = '1111111111111111111111111111111111111111'
        provider_control_sha = '2222222222222222222222222222222222222222'
        github_release_id = '10'
        source_workflow_run_id = '20'
        release_manifest_sha256 = ('3' * 64)
        request_uuid = 'd54e5e0c-c66d-5ec0-b043-d4ac0f2bc83d'
        package_name = $packageName
        package_sha256 = $packageSha256
        publisher_script_sha256 = $publisherSha256
        run_id = '30'
        run_attempt = '1'
    }
    [IO.File]::WriteAllText(
        (Join-Path $submission 'identity.json'),
        ($identity | ConvertTo-Json -Compress),
        [Text.UTF8Encoding]::new($false)
    )

    $mock = Join-Path $root 'mock-choco.ps1'
    @'
if ($args.Count -eq 1 -and $args[0] -ceq '--version') {
    if ($env:MOCK_CHOCO_VERSION) { $env:MOCK_CHOCO_VERSION } else { '2.7.3' }
    exit 0
}
if ($env:MOCK_FAIL_PUSH -eq 'true') {
    exit 9
}
if ($args.Count -ne 6 -or $args[0] -cne 'push' -or
    $args[2] -cne '--source' -or $args[3] -cne 'https://push.chocolatey.org/' -or
    $args[4] -cne '--api-key' -or $args[5] -cne $env:EXPECTED_TEST_KEY) {
    exit 4
}
[IO.File]::WriteAllText($env:MOCK_MARKER, 'published')
exit 0
'@ | Set-Content -LiteralPath $mock -Encoding utf8NoBOM

    $env:CHOCOLATEY_API_KEY = 'offline-test-key'
    $env:EXPECTED_TEST_KEY = $env:CHOCOLATEY_API_KEY
    $env:MOCK_MARKER = Join-Path $root 'published.txt'
    $env:MOCK_FAIL_PUSH = 'false'
    $env:MOCK_CHOCO_VERSION = '2.7.3'
    & $publisher -SubmissionDirectory $submission -ExpectedPackage $packageName `
        -ExpectedSha256 $packageSha256 -RunId '30' -RunAttempt '1' `
        -ChocolateyCommand $mock
    if (-not (Test-Path -LiteralPath $env:MOCK_MARKER)) {
        throw 'mock Chocolatey push was not invoked'
    }

    $env:MOCK_CHOCO_VERSION = '2.7.4'
    try {
        & $publisher -SubmissionDirectory $submission -ExpectedPackage $packageName `
            -ExpectedSha256 $packageSha256 -RunId '30' -RunAttempt '1' `
            -ChocolateyCommand $mock
        throw 'wrong Chocolatey version unexpectedly succeeded'
    }
    catch {
        if ($_.Exception.Message -notmatch 'Chocolatey CLI must be exactly 2.7.3') {
            throw
        }
    }

    $env:MOCK_CHOCO_VERSION = '2.7.3'
    $env:MOCK_FAIL_PUSH = 'true'
    try {
        & $publisher -SubmissionDirectory $submission -ExpectedPackage $packageName `
            -ExpectedSha256 $packageSha256 -RunId '30' -RunAttempt '1' `
            -ChocolateyCommand $mock
        throw 'failed Chocolatey push unexpectedly succeeded'
    }
    catch {
        if ($_.Exception.Message -notmatch 'Chocolatey push failed with exit code 9') {
            throw
        }
    }
}
finally {
    Remove-Item Env:CHOCOLATEY_API_KEY -ErrorAction SilentlyContinue
    Remove-Item Env:EXPECTED_TEST_KEY -ErrorAction SilentlyContinue
    Remove-Item Env:MOCK_MARKER -ErrorAction SilentlyContinue
    Remove-Item Env:MOCK_FAIL_PUSH -ErrorAction SilentlyContinue
    Remove-Item Env:MOCK_CHOCO_VERSION -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}

# The expected-failure push above leaves $LASTEXITCODE at 9.
exit 0
