[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Debug'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$cargoCommand = Get-Command cargo -ErrorAction SilentlyContinue
if ($null -eq $cargoCommand) {
    $userCargo = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
    if (-not (Test-Path -LiteralPath $userCargo -PathType Leaf)) {
        throw 'cargo was not found. Install the stable Rust toolchain and retry.'
    }

    $cargoPath = $userCargo
}
else {
    $cargoPath = $cargoCommand.Source
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $repositoryRoot 'native\halo-protocol\Cargo.toml'
if ($Configuration -eq 'Release') {
    & $cargoPath build --locked --manifest-path $manifestPath --release
}
else {
    & $cargoPath build --locked --manifest-path $manifestPath
}
if ($LASTEXITCODE -ne 0) {
    throw "cargo build failed with exit code $LASTEXITCODE."
}

$profileName = if ($Configuration -eq 'Release') { 'release' } else { 'debug' }
$sourceDll = Join-Path $repositoryRoot "native\halo-protocol\target\$profileName\halo_protocol.dll"
if (-not (Test-Path -LiteralPath $sourceDll -PathType Leaf)) {
    throw "Expected native library was not produced: $sourceDll"
}

$destinationDirectory = Join-Path $repositoryRoot "artifacts\native\$Configuration\win-x64"
New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
Copy-Item -LiteralPath $sourceDll -Destination (Join-Path $destinationDirectory 'halo_protocol.dll') -Force

Write-Host "Built $Configuration native library at $destinationDirectory"
