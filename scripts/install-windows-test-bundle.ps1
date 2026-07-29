[CmdletBinding()]
param(
    [string] $BundleDirectory = $PSScriptRoot,
    [string] $InstallRoot = "C:\Program Files\HaloVPN",
    [string] $DataDirectory = "C:\ProgramData\HaloVPN",
    [string] $ServiceName = "HaloVPN",
    [string] $AllowedUserSid
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Resolve-InteractiveUserSid {
    $interactiveUser = (Get-CimInstance Win32_ComputerSystem).UserName
    if ([string]::IsNullOrWhiteSpace($interactiveUser)) {
        throw "No interactive Windows user was detected. Supply -AllowedUserSid explicitly."
    }

    return ([Security.Principal.NTAccount]::new($interactiveUser)).
        Translate([Security.Principal.SecurityIdentifier]).Value
}

function Assert-OfficialWintun {
    param([string] $Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf) -or
        -not [string]::Equals([IO.Path]::GetFileName($Path), "wintun.dll", [StringComparison]::OrdinalIgnoreCase)) {
        throw "The bundle does not contain wintun.dll."
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne "Valid" -or
        $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -notlike "*O=WireGuard LLC*") {
        throw "wintun.dll does not have a valid WireGuard LLC Authenticode signature."
    }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this installer from an elevated PowerShell session."
}

$bundle = (Resolve-Path -LiteralPath $BundleDirectory).Path
$serviceSource = Join-Path $bundle "Service"
$desktopSource = Join-Path $bundle "Desktop"
$wintunSource = Join-Path $bundle "wintun.dll"
if (-not (Test-Path -LiteralPath (Join-Path $serviceSource "HaloVPN.WindowsService.exe") -PathType Leaf)) {
    throw "The Service publish directory is incomplete."
}
if (-not (Test-Path -LiteralPath (Join-Path $desktopSource "HaloVPN.Desktop.exe") -PathType Leaf)) {
    throw "The Desktop publish directory is incomplete."
}
if (-not (Test-Path -LiteralPath (Join-Path $serviceSource "halo_protocol.dll") -PathType Leaf)) {
    throw "The native Halo Protocol DLL is missing from the Service publish directory."
}
Assert-OfficialWintun $wintunSource

if ([string]::IsNullOrWhiteSpace($AllowedUserSid)) {
    $AllowedUserSid = Resolve-InteractiveUserSid
}
try {
    $AllowedUserSid = [Security.Principal.SecurityIdentifier]::new($AllowedUserSid).Value
}
catch {
    throw "AllowedUserSid is not a valid Windows SID."
}

if ($null -ne (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
    throw "Service '$ServiceName' already exists. Use Update-HaloVPN-Service.ps1 for an existing installation."
}
if (Test-Path -LiteralPath $InstallRoot) {
    throw "Install directory already exists: $InstallRoot. Refusing to overwrite an unknown installation."
}

$serviceTarget = Join-Path $InstallRoot "Service"
$desktopTarget = Join-Path $InstallRoot "Desktop"
$wintunTarget = Join-Path $InstallRoot "wintun.dll"
$serviceCreated = $false
$installCreated = $false

try {
    New-Item -ItemType Directory -Path $serviceTarget -Force | Out-Null
    New-Item -ItemType Directory -Path $desktopTarget -Force | Out-Null
    $installCreated = $true
    Get-ChildItem -LiteralPath $serviceSource -Force | Copy-Item -Destination $serviceTarget -Recurse -Force
    Get-ChildItem -LiteralPath $desktopSource -Force | Copy-Item -Destination $desktopTarget -Recurse -Force
    Copy-Item -LiteralPath $wintunSource -Destination $wintunTarget

    New-Item -ItemType Directory -Path $DataDirectory -Force | Out-Null
    & icacls.exe $DataDirectory /inheritance:r /grant:r `
        "*S-1-5-18:(OI)(CI)F" `
        "*S-1-5-32-544:(OI)(CI)F" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to restrict the HaloVPN device-data directory ACL."
    }

    $configuration = [ordered]@{
        HaloVPN = [ordered]@{
            PipeName = "HaloVPN.Service.v1"
            AllowedUserSid = $AllowedUserSid
            DeviceKeyPath = Join-Path $DataDirectory "device-key.json"
            WintunDllPath = $wintunTarget
            NetworkJournalPath = Join-Path $DataDirectory "network-plan.json"
            AdapterName = "HaloVPN"
            HandshakeAttempts = 4
            HandshakeInitialDelay = "00:00:00.500"
            HandshakeMaximumDelay = "00:00:02"
            HandshakeTimeout = "00:00:10"
            KeepAliveInterval = "00:00:20"
            LivenessTimeout = "00:01:05"
        }
        Logging = [ordered]@{
            LogLevel = [ordered]@{
                Default = "Information"
                "Microsoft.Hosting.Lifetime" = "Information"
            }
        }
    }
    $configurationPath = Join-Path $serviceTarget "appsettings.json"
    $json = $configuration | ConvertTo-Json -Depth 8
    [IO.File]::WriteAllText($configurationPath, $json, [Text.UTF8Encoding]::new($false))

    $serviceExecutable = Join-Path $serviceTarget "HaloVPN.WindowsService.exe"
    New-Service -Name $ServiceName `
        -BinaryPathName ('"{0}"' -f $serviceExecutable) `
        -DisplayName "HaloVPN" `
        -Description "HaloVPN protected Windows tunnel service" `
        -StartupType Automatic | Out-Null
    $serviceCreated = $true

    Start-Service -Name $ServiceName
    $service = Get-Service -Name $ServiceName
    $service.WaitForStatus(
        [ServiceProcess.ServiceControllerStatus]::Running,
        [TimeSpan]::FromSeconds(30))

    Write-Host "HaloVPN installed successfully."
    Write-Host "Allowed Desktop user SID: $AllowedUserSid"
    Write-Host "Desktop: $(Join-Path $desktopTarget 'HaloVPN.Desktop.exe')"
    Write-Host "Device private key will be generated locally by the service and is not part of this bundle."
}
catch {
    if ($serviceCreated) {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        & sc.exe delete $ServiceName | Out-Null
    }
    if ($installCreated) {
        $resolvedInstall = [IO.Path]::GetFullPath($InstallRoot).TrimEnd("\")
        $programFilesRoot = [IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd("\") + "\"
        if ($resolvedInstall.StartsWith($programFilesRoot, [StringComparison]::OrdinalIgnoreCase) -and
            [string]::Equals([IO.Path]::GetFileName($resolvedInstall), "HaloVPN", [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $resolvedInstall -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    throw
}
