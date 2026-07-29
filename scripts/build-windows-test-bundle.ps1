[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string] $Configuration = "Release",

    [string] $WintunDllPath = "C:\Program Files\HaloVPN\wintun.dll",
    [switch] $FrameworkDependent
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$publishRoot = Join-Path $repositoryRoot "publish\windows-test-bundle"
$stagingRoot = Join-Path $publishRoot "HaloVPN-Windows-x64-Test"
$archivePath = Join-Path $publishRoot "HaloVPN-Windows-x64-Test.zip"
$serviceOutput = Join-Path $stagingRoot "Service"
$desktopOutput = Join-Path $stagingRoot "Desktop"

$resolvedPublishRoot = [IO.Path]::GetFullPath($publishRoot)
$expectedPrefix = [IO.Path]::GetFullPath((Join-Path $repositoryRoot "publish")) + [IO.Path]::DirectorySeparatorChar
if (-not $resolvedPublishRoot.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to use a publish directory outside the repository publish root."
}

if (Test-Path -LiteralPath $publishRoot) {
    Remove-Item -LiteralPath $publishRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $serviceOutput -Force | Out-Null
New-Item -ItemType Directory -Path $desktopOutput -Force | Out-Null

& (Join-Path $PSScriptRoot "build-native.ps1") -Configuration $Configuration
if ($LASTEXITCODE -ne 0) {
    throw "Native Release build failed."
}

$selfContained = -not $FrameworkDependent.IsPresent
$serviceProject = Join-Path $repositoryRoot "src\HaloVPN.WindowsService\HaloVPN.WindowsService.csproj"
$desktopProject = Join-Path $repositoryRoot "src\HaloVPN.Desktop\HaloVPN.Desktop.csproj"
& dotnet publish $serviceProject -c $Configuration -r win-x64 --self-contained $selfContained -o $serviceOutput
if ($LASTEXITCODE -ne 0) {
    throw "Windows Service publish failed."
}
& dotnet publish $desktopProject -c $Configuration -r win-x64 --self-contained $selfContained -o $desktopOutput
if ($LASTEXITCODE -ne 0) {
    throw "Desktop publish failed."
}

Get-ChildItem -LiteralPath $stagingRoot -Recurse -File | Where-Object {
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
    throw "Refusing to package a Wintun DLL without a valid WireGuard LLC Authenticode signature."
}
Copy-Item -LiteralPath $wintun.FullName -Destination (Join-Path $stagingRoot "wintun.dll")

Copy-Item -LiteralPath (Join-Path $repositoryRoot "scripts\install-windows-test-bundle.ps1") `
    -Destination (Join-Path $stagingRoot "Install-HaloVPN.ps1")
Copy-Item -LiteralPath (Join-Path $repositoryRoot "scripts\preflight-windows.ps1") `
    -Destination (Join-Path $stagingRoot "Preflight-HaloVPN.ps1")
Copy-Item -LiteralPath (Join-Path $repositoryRoot "scripts\update-windows-service.ps1") `
    -Destination (Join-Path $stagingRoot "Update-HaloVPN-Service.ps1")
Copy-Item -LiteralPath (Join-Path $repositoryRoot "deploy\windows\README-TESTER.md") `
    -Destination (Join-Path $stagingRoot "README-TESTER.md")
New-Item -ItemType Directory -Path (Join-Path $stagingRoot "licenses") -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $repositoryRoot "deploy\windows\WINTUN-PREBUILT-LICENSE.txt") `
    -Destination (Join-Path $stagingRoot "licenses\WINTUN-PREBUILT-LICENSE.txt")

$forbiddenFiles = @(Get-ChildItem -LiteralPath $stagingRoot -Recurse -File | Where-Object {
    $_.Name -match "^(appsettings(\..+)?\.json|device-key\.json|network-plan\.json|refresh-token.*)$" -or
    $_.Extension -in @(".key", ".pem", ".pfx", ".p12", ".pdb")
})
if ($forbiddenFiles.Count -ne 0) {
    throw "Bundle contains forbidden configuration, key, token, journal, or debug files."
}

$textFiles = @(Get-ChildItem -LiteralPath $stagingRoot -Recurse -File | Where-Object {
    $_.Extension -in @(".ps1", ".md", ".txt", ".json", ".config")
})
foreach ($file in $textFiles) {
    $text = Get-Content -LiteralPath $file.FullName -Raw
    if ($text -match "S-1-5-21-\d+" -or
        $text -match "-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----" -or
        $text -match "176\.12\.73\.4") {
        throw "Bundle text contains machine-specific or production material: $($file.FullName)"
    }
}

$hashLines = Get-ChildItem -LiteralPath $stagingRoot -Recurse -File |
    Where-Object Name -ne "SHA256SUMS.txt" |
    Sort-Object FullName |
    ForEach-Object {
        $relative = $_.FullName.Substring($stagingRoot.Length).TrimStart("\").Replace("\", "/")
        "{0}  {1}" -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $relative
    }
[IO.File]::WriteAllLines(
    (Join-Path $stagingRoot "SHA256SUMS.txt"),
    $hashLines,
    [Text.UTF8Encoding]::new($false))

Compress-Archive -LiteralPath $stagingRoot -DestinationPath $archivePath -CompressionLevel Optimal
$archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash

Write-Host "Created tester bundle: $archivePath"
Write-Host "ZIP SHA-256: $archiveHash"
Write-Host "Wintun SHA-256: $((Get-FileHash -LiteralPath $wintun.FullName -Algorithm SHA256).Hash)"
Write-Host "No production appsettings, device key, token, guard journal, PDB, or private key was included."
