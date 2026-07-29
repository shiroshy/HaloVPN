[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string] $PublishDirectory,

    [string] $InstallDirectory = "C:\Program Files\HaloVPN\Service",
    [string] $ServiceName = "HaloVPN",
    [string] $ConfigurationFileName = "appsettings.json",
    [int] $ServiceTimeoutSeconds = 30
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -and -not $WhatIfPreference) {
    throw "Run this update script from an elevated PowerShell session."
}

$source = (Resolve-Path -LiteralPath $PublishDirectory).Path
$target = [IO.Path]::GetFullPath($InstallDirectory)
$sourceExecutable = Join-Path $source "HaloVPN.WindowsService.exe"
$productionConfig = Join-Path $target $ConfigurationFileName
if (-not (Test-Path -LiteralPath $sourceExecutable -PathType Leaf)) {
    throw "The publish directory does not contain HaloVPN.WindowsService.exe."
}
if (-not (Test-Path -LiteralPath $productionConfig -PathType Leaf)) {
    throw "The production appsettings.json does not exist; refusing an update without preserved configuration."
}

$configHash = (Get-FileHash -LiteralPath $productionConfig -Algorithm SHA256).Hash
$config = Get-Content -LiteralPath $productionConfig -Raw | ConvertFrom-Json
foreach ($required in @("AllowedUserSid", "DeviceKeyPath", "NetworkJournalPath", "WintunDllPath")) {
    if ([string]::IsNullOrWhiteSpace($config.HaloVPN.$required)) {
        throw "Production configuration is missing HaloVPN:$required."
    }
}

$service = Get-Service -Name $ServiceName -ErrorAction Stop
$backupRoot = Join-Path ([IO.Path]::GetTempPath()) ("halovpn-service-backup-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $backupRoot | Out-Null
$wasRunning = $service.Status -eq [ServiceProcess.ServiceControllerStatus]::Running

try {
    Get-ChildItem -LiteralPath $target -Force | Copy-Item -Destination $backupRoot -Recurse -Force -ErrorAction Stop
    if ($PSCmdlet.ShouldProcess($ServiceName, "Stop, update binaries while preserving production configuration, and restart")) {
        if ($wasRunning) {
            Stop-Service -Name $ServiceName -Force
            (Get-Service -Name $ServiceName).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds($ServiceTimeoutSeconds))
        }

        Get-ChildItem -LiteralPath $source -File -Recurse | Where-Object {
            $_.Name -notlike "appsettings*.json" -and
            -not $_.Name.EndsWith(".pdb", [StringComparison]::OrdinalIgnoreCase)
        } | ForEach-Object {
            $relative = $_.FullName.Substring($source.Length).TrimStart([IO.Path]::DirectorySeparatorChar)
            $destination = Join-Path $target $relative
            [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination)) | Out-Null
            Copy-Item -LiteralPath $_.FullName -Destination $destination -Force
        }

        $updatedHash = (Get-FileHash -LiteralPath $productionConfig -Algorithm SHA256).Hash
        if (-not [string]::Equals($configHash, $updatedHash, [StringComparison]::Ordinal)) {
            throw "Production configuration changed during update; rolling back."
        }

        Start-Service -Name $ServiceName
        (Get-Service -Name $ServiceName).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds($ServiceTimeoutSeconds))
    }
}
catch {
    try {
        if ((Get-Service -Name $ServiceName).Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) {
            Stop-Service -Name $ServiceName -Force
            (Get-Service -Name $ServiceName).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds($ServiceTimeoutSeconds))
        }
        Get-ChildItem -LiteralPath $backupRoot -Force | Copy-Item -Destination $target -Recurse -Force
        if ($wasRunning) {
            Start-Service -Name $ServiceName
        }
    }
    catch {
        Write-Error "Automatic service rollback was incomplete; inspect the service before reconnecting."
    }
    throw
}
finally {
    Remove-Item -LiteralPath $backupRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if ($WhatIfPreference) {
    Write-Host "HaloVPN service update validation completed in WhatIf mode; no service or installed file was changed."
} else {
    Write-Host "HaloVPN service update completed; production appsettings.json SHA-256 remained $configHash."
}
