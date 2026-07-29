param([ValidateSet('Debug', 'Release')][string]$Configuration = 'Release')
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$publishRoot = Join-Path $repositoryRoot "publish\windows-x64\$Configuration"
dotnet publish (Join-Path $repositoryRoot 'src\HaloVPN.WindowsService\HaloVPN.WindowsService.csproj') -c $Configuration -r win-x64 --self-contained false -o (Join-Path $publishRoot 'service')
dotnet publish (Join-Path $repositoryRoot 'src\HaloVPN.Desktop\HaloVPN.Desktop.csproj') -c $Configuration -r win-x64 --self-contained false -o (Join-Path $publishRoot 'desktop')
Write-Host "Published Windows applications to $publishRoot"
Write-Host 'Place the official x64 wintun.dll in the configured service location; this script does not download it.'
