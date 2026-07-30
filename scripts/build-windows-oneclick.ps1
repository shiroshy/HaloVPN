[CmdletBinding()]
param(
    [ValidateSet("Release")]
    [string] $Configuration = "Release",

    [string] $WintunDllPath = "C:\Program Files\HaloVPN\wintun.dll"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$publishRoot = Join-Path $repositoryRoot "publish\windows-oneclick"
$workingRoot = Join-Path $publishRoot "work"
$payloadRoot = Join-Path $workingRoot "payload"
$serviceOutput = Join-Path $payloadRoot "Service"
$desktopOutput = Join-Path $payloadRoot "Desktop"
$bootstrapOutput = Join-Path $workingRoot "bootstrap"
$payloadArchive = Join-Path $workingRoot "payload.zip"
$finalExecutable = Join-Path $publishRoot "HaloVPN.exe"
$hashFile = Join-Path $publishRoot "HaloVPN.exe.sha256.txt"

$resolvedPublishRoot = [IO.Path]::GetFullPath($publishRoot)
$expectedPrefix = [IO.Path]::GetFullPath((Join-Path $repositoryRoot "publish")) + [IO.Path]::DirectorySeparatorChar
if (-not $resolvedPublishRoot.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to use an output directory outside the repository publish root."
}

if (Test-Path -LiteralPath $publishRoot) {
    Remove-Item -LiteralPath $publishRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $serviceOutput -Force | Out-Null
New-Item -ItemType Directory -Path $desktopOutput -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $payloadRoot "licenses") -Force | Out-Null

& (Join-Path $PSScriptRoot "build-native.ps1") -Configuration $Configuration
if ($LASTEXITCODE -ne 0) {
    throw "Native protocol build failed."
}

& dotnet publish `
    (Join-Path $repositoryRoot "src\HaloVPN.WindowsService\HaloVPN.WindowsService.csproj") `
    -c $Configuration -r win-x64 --self-contained true -o $serviceOutput
if ($LASTEXITCODE -ne 0) {
    throw "Windows Service publish failed."
}

& dotnet publish `
    (Join-Path $repositoryRoot "src\HaloVPN.Desktop\HaloVPN.Desktop.csproj") `
    -c $Configuration -r win-x64 --self-contained true -o $desktopOutput
if ($LASTEXITCODE -ne 0) {
    throw "Desktop publish failed."
}

Get-ChildItem -LiteralPath $payloadRoot -Recurse -File | Where-Object {
    $_.Name -like "appsettings*.json" -or $_.Extension -eq ".pdb"
} | Remove-Item -Force

$wintun = Get-Item -LiteralPath $WintunDllPath -ErrorAction Stop
if (-not [string]::Equals($wintun.Name, "wintun.dll", [StringComparison]::OrdinalIgnoreCase)) {
    throw "WintunDllPath must point to wintun.dll."
}
$signature = Get-AuthenticodeSignature -LiteralPath $wintun.FullName
if ($signature.Status -ne "Valid" -or
    $null -eq $signature.SignerCertificate -or
    $signature.SignerCertificate.Subject -notlike "*O=WireGuard LLC*") {
    throw "Refusing to package Wintun without a valid WireGuard LLC signature."
}
$expectedWintunHash = "E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE"
$actualWintunHash = (Get-FileHash -LiteralPath $wintun.FullName -Algorithm SHA256).Hash
if (-not [string]::Equals($expectedWintunHash, $actualWintunHash, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Wintun is signed but does not match the reviewed 0.14.1 x64 DLL."
}
Copy-Item -LiteralPath $wintun.FullName -Destination (Join-Path $payloadRoot "wintun.dll")
Copy-Item -LiteralPath (Join-Path $repositoryRoot "deploy\windows\WINTUN-PREBUILT-LICENSE.txt") `
    -Destination (Join-Path $payloadRoot "licenses\WINTUN-PREBUILT-LICENSE.txt")

$forbidden = @(Get-ChildItem -LiteralPath $payloadRoot -Recurse -File | Where-Object {
    $_.Name -match "^(appsettings(\..+)?\.json|device-key\.json|network-plan\.json|refresh-token.*)$" -or
    $_.Extension -in @(".key", ".pem", ".pfx", ".p12", ".pdb")
})
if ($forbidden.Count -ne 0) {
    throw "One-click payload contains forbidden configuration, key, token, journal, or PDB files."
}

Compress-Archive -Path (Join-Path $payloadRoot "*") `
    -DestinationPath $payloadArchive `
    -CompressionLevel Optimal

& dotnet publish `
    (Join-Path $repositoryRoot "src\HaloVPN.Setup\HaloVPN.Setup.csproj") `
    -c $Configuration -r win-x64 -o $bootstrapOutput
if ($LASTEXITCODE -ne 0) {
    throw "Native AOT setup bootstrapper publish failed."
}

$bootstrap = Join-Path $bootstrapOutput "HaloVPN.Setup.exe"
if (-not (Test-Path -LiteralPath $bootstrap -PathType Leaf)) {
    throw "Native setup bootstrapper was not produced."
}

Copy-Item -LiteralPath $bootstrap -Destination $finalExecutable
$payloadLength = (Get-Item -LiteralPath $payloadArchive).Length
$payloadHashHex = (Get-FileHash -LiteralPath $payloadArchive -Algorithm SHA256).Hash
$payloadHashBytes = New-Object byte[] 32
for ($index = 0; $index -lt $payloadHashBytes.Length; $index++) {
    $payloadHashBytes[$index] = [Convert]::ToByte($payloadHashHex.Substring($index * 2, 2), 16)
}
$magic = [Text.Encoding]::ASCII.GetBytes("HALOVPN_PAYLOAD1")
if ($magic.Length -ne 16 -or $payloadHashBytes.Length -ne 32) {
    throw "Invalid one-click footer constants."
}

$output = [IO.File]::Open($finalExecutable, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
    $payload = [IO.File]::OpenRead($payloadArchive)
    try {
        $payload.CopyTo($output)
    }
    finally {
        $payload.Dispose()
    }

    $output.Write($magic, 0, $magic.Length)
    $lengthBytes = [BitConverter]::GetBytes([long]$payloadLength)
    $output.Write($lengthBytes, 0, $lengthBytes.Length)
    $output.Write($payloadHashBytes, 0, $payloadHashBytes.Length)
}
finally {
    $output.Dispose()
}

$verification = Start-Process `
    -FilePath $finalExecutable `
    -ArgumentList "--verify" `
    -WindowStyle Hidden `
    -Wait `
    -PassThru
if ($verification.ExitCode -ne 0) {
    throw "The final HaloVPN.exe failed its embedded payload self-check."
}

$finalHash = (Get-FileHash -LiteralPath $finalExecutable -Algorithm SHA256).Hash
[IO.File]::WriteAllText(
    $hashFile,
    "$finalHash  HaloVPN.exe`r`n",
    [Text.UTF8Encoding]::new($false))

Remove-Item -LiteralPath $workingRoot -Recurse -Force

Write-Host "Created one-click tester release: $finalExecutable"
Write-Host "SHA-256: $finalHash"
Write-Host "The tester only needs to double-click HaloVPN.exe and approve UAC."
