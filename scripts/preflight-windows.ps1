[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$logPath = 'D:\Csharp\HaloVPN\local\service-fix-log.txt'
Set-Content -LiteralPath $logPath -Value ("start {0:o} pid={1}" -f (Get-Date), $PID) -Encoding UTF8

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $child = Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath -Wait -PassThru
        Add-Content -LiteralPath $logPath -Value ("child_exit={0}" -f $child.ExitCode)
        exit $child.ExitCode
    }

    $configPath = 'C:\Program Files\HaloVPN\Service\appsettings.json'
    $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    $config.HaloVPN.AllowedUserSid = 'S-1-5-21-1837161404-603832921-3392811069-1001'
    $config.HaloVPN.DeviceKeyPath = 'C:\ProgramData\HaloVPN\device-key.json'
    $config.HaloVPN.NetworkJournalPath = 'C:\ProgramData\HaloVPN\network-plan.json'
    $config.HaloVPN.WintunDllPath = 'C:\Program Files\HaloVPN\wintun.dll'
    $config | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $configPath -Encoding UTF8

    Start-Service -Name HaloVPN
    $service = Get-Service -Name HaloVPN
    $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(20))
    Add-Content -LiteralPath $logPath -Value ("service_status={0}" -f $service.Status)
    exit 0
}
catch {
    Add-Content -LiteralPath $logPath -Value ($_ | Out-String)
    exit 1
}
