param(
    [Parameter(Mandatory = $true)]
    [string]$SubmissionDirectory,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedPackage,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedSha256,

    [Parameter(Mandatory = $true)]
    [string]$RunId,

    [Parameter(Mandatory = $true)]
    [string]$RunAttempt,

    [string]$ChocolateyCommand = 'choco.exe'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$expectedChocolateyVersion = '2.7.3'

if ([string]::IsNullOrWhiteSpace($env:CHOCOLATEY_API_KEY)) {
    throw 'Chocolatey API key is unavailable'
}
if ((Split-Path -Leaf $ExpectedPackage) -ne $ExpectedPackage) {
    throw 'expected package name is unsafe'
}
if ($ExpectedSha256 -cnotmatch '^[0-9a-f]{64}$') {
    throw 'expected package SHA-256 is malformed'
}

$directory = (Resolve-Path -LiteralPath $SubmissionDirectory).Path
$expectedFiles = @('identity.json', $ExpectedPackage, 'publish.ps1') | Sort-Object
$actualFiles = @(
    Get-ChildItem -LiteralPath $directory -Force | ForEach-Object {
        if ($_.PSIsContainer -or
            ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw 'submission handoff contains a directory or reparse point'
        }
        $_.Name
    }
) | Sort-Object
if (@(Compare-Object $expectedFiles $actualFiles).Count -ne 0) {
    throw 'submission handoff file inventory is not exact'
}

$identityPath = Join-Path $directory 'identity.json'
$identity = Get-Content -Raw -LiteralPath $identityPath | ConvertFrom-Json
$expectedProperties = @(
    'schema_version', 'source_tag', 'source_commit_sha',
    'source_workflow_head_sha', 'provider_control_sha', 'github_release_id',
    'source_workflow_run_id', 'release_manifest_sha256', 'request_uuid',
    'package_name', 'package_sha256', 'publisher_script_sha256',
    'run_id', 'run_attempt'
) | Sort-Object
$actualProperties = @($identity.PSObject.Properties.Name) | Sort-Object
if (@(Compare-Object $expectedProperties $actualProperties).Count -ne 0 -or
    $identity.schema_version -ne 1) {
    throw 'submission identity schema is not exact'
}
if ($identity.run_id -cne $RunId -or $identity.run_attempt -cne $RunAttempt) {
    throw 'submission handoff belongs to a different workflow run'
}
if ($identity.package_name -cne $ExpectedPackage -or
    $identity.package_sha256 -cne $ExpectedSha256) {
    throw 'submission handoff package identity is wrong'
}

$package = Join-Path $directory $ExpectedPackage
$actualPackageSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $package).Hash.ToLowerInvariant()
if ($actualPackageSha256 -cne $ExpectedSha256) {
    throw 'submission package SHA-256 mismatch'
}
$actualScriptSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $PSCommandPath).Hash.ToLowerInvariant()
if ($actualScriptSha256 -cne $identity.publisher_script_sha256) {
    throw 'publisher script SHA-256 mismatch'
}

$chocolateyVersion = (& $ChocolateyCommand --version 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $chocolateyVersion -cne $expectedChocolateyVersion) {
    throw "Chocolatey CLI must be exactly $expectedChocolateyVersion"
}
& $ChocolateyCommand push $package `
    --source 'https://push.chocolatey.org/' `
    --api-key $env:CHOCOLATEY_API_KEY
if ($LASTEXITCODE -ne 0) {
    throw "Chocolatey push failed with exit code $LASTEXITCODE"
}
