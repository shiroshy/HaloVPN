[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $AllowedUserSid,

    [Parameter(Mandatory)]
    [Uri] $ControlPlaneUrl,

    [Parameter(Mandatory)]
    [string] $NodeHost,

    [string] $WintunDllPath = "C:\Program Files\HaloVPN\wintun.dll",
    [string] $DeviceKeyDirectory = "C:\ProgramData\HaloVPN",
    [string] $TunnelSubnet = "10.77.0.0/24",
    [string] $SpkiPinBase64,
    [string] $ExpectedWintunSha256
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$failures = [Collections.Generic.List[string]]::new()
$warnings = [Collections.Generic.List[string]]::new()

function Write-Check {
    param([string] $Name, [bool] $Passed, [string] $Detail)

    $status = if ($Passed) { "PASS" } else { "FAIL" }
    Write-Host ("[{0}] {1}: {2}" -f $status, $Name, $Detail)
    if (-not $Passed) {
        $script:failures.Add($Name)
    }
}

function Write-WarningCheck {
    param([string] $Name, [string] $Detail)

    Write-Host ("[WARN] {0}: {1}" -f $Name, $Detail)
    $script:warnings.Add($Name)
}

function ConvertTo-Ipv4UInt32 {
    param([Net.IPAddress] $Address)

    $bytes = $Address.GetAddressBytes()
    if ($bytes.Length -ne 4) {
        throw "Only IPv4 addresses are supported."
    }

    [Array]::Reverse($bytes)
    return [BitConverter]::ToUInt32($bytes, 0)
}

function Test-AddressInCidr {
    param([Net.IPAddress] $Address, [string] $Cidr)

    $parts = $Cidr.Split("/")
    if ($parts.Length -ne 2) {
        throw "TunnelSubnet must use CIDR notation."
    }

    $network = [Net.IPAddress]::Parse($parts[0])
    $prefix = 0
    if (-not [int]::TryParse($parts[1], [ref]$prefix) -or $prefix -lt 0 -or $prefix -gt 32) {
        throw "TunnelSubnet contains an invalid IPv4 prefix."
    }

    $mask = if ($prefix -eq 0) { [uint32]0 } else { [uint32]::MaxValue -shl (32 - $prefix) }
    return ((ConvertTo-Ipv4UInt32 $Address) -band $mask) -eq ((ConvertTo-Ipv4UInt32 $network) -band $mask)
}

try {
    $os = Get-CimInstance Win32_OperatingSystem
    $supportedVersion = [Version]$os.Version -ge [Version]"10.0.19041"
    Write-Check "Windows version" $supportedVersion ("{0} build {1}" -f $os.Caption, $os.BuildNumber)
    Write-Check "x64 operating system" ([Environment]::Is64BitOperatingSystem) $env:PROCESSOR_ARCHITECTURE

    $requiredCommands = @("sc.exe", "netsh.exe", "route.exe", "powershell.exe")
    $missingCommands = @($requiredCommands | Where-Object { $null -eq (Get-Command $_ -ErrorAction SilentlyContinue) })
    $commandDetail = if ($missingCommands.Count -eq 0) { "available" } else { "missing: " + ($missingCommands -join ", ") }
    Write-Check "Service/network prerequisites" ($missingCommands.Count -eq 0) $commandDetail

    try {
        $sid = [Security.Principal.SecurityIdentifier]::new($AllowedUserSid)
        Write-Check "AllowedUserSid" $true $sid.Value
    }
    catch {
        Write-Check "AllowedUserSid" $false "invalid SID"
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Host ("[INFO] Current shell elevation: {0}; elevation is required only for install/update operations." -f $isAdministrator)

    $wintunExists = Test-Path -LiteralPath $WintunDllPath -PathType Leaf
    Write-Check "Wintun DLL exists" $wintunExists $WintunDllPath
    if ($wintunExists) {
        $signature = Get-AuthenticodeSignature -LiteralPath $WintunDllPath
        $wireGuardSigner = $null -ne $signature.SignerCertificate -and
            $signature.SignerCertificate.Subject -like "*O=WireGuard LLC*"
        $signatureDetail = if ($null -ne $signature.SignerCertificate) {
            $signature.SignerCertificate.Subject
        }
        else {
            $signature.StatusMessage
        }
        Write-Check "Wintun signature" ($signature.Status -eq "Valid" -and $wireGuardSigner) $signatureDetail

        $actualHash = (Get-FileHash -LiteralPath $WintunDllPath -Algorithm SHA256).Hash
        if ([string]::IsNullOrWhiteSpace($ExpectedWintunSha256)) {
            Write-Host "[INFO] Wintun SHA-256: $actualHash"
        }
        else {
            Write-Check "Wintun SHA-256" (
                [string]::Equals($actualHash, $ExpectedWintunSha256, [StringComparison]::OrdinalIgnoreCase)
            ) $actualHash
        }

        if ($null -eq ("HaloVpnPreflight.NativeMethods" -as [type])) {
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace HaloVpnPreflight {
    public static class NativeMethods {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr LoadLibraryEx(string path, IntPtr file, uint flags);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr GetProcAddress(IntPtr module, string name);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FreeLibrary(IntPtr module);
    }
}
"@
        }

        $module = [HaloVpnPreflight.NativeMethods]::LoadLibraryEx(
            [IO.Path]::GetFullPath($WintunDllPath),
            [IntPtr]::Zero,
            0x00000001)
        if ($module -eq [IntPtr]::Zero) {
            Write-Check "Wintun exports" $false "DLL could not be inspected"
        }
        else {
            try {
                $expectedExports = @(
                    "WintunCreateAdapter",
                    "WintunOpenAdapter",
                    "WintunCloseAdapter",
                    "WintunGetAdapterLUID",
                    "WintunStartSession",
                    "WintunEndSession",
                    "WintunGetReadWaitEvent",
                    "WintunReceivePacket",
                    "WintunReleaseReceivePacket",
                    "WintunAllocateSendPacket",
                    "WintunSendPacket"
                )
                $missingExports = @($expectedExports | Where-Object {
                    [HaloVpnPreflight.NativeMethods]::GetProcAddress($module, $_) -eq [IntPtr]::Zero
                })
                $exportDetail = if ($missingExports.Count -eq 0) {
                    "all expected exports found"
                }
                else {
                    "missing: " + ($missingExports -join ", ")
                }
                Write-Check "Wintun exports" ($missingExports.Count -eq 0) $exportDetail
            }
            finally {
                [void][HaloVpnPreflight.NativeMethods]::FreeLibrary($module)
            }
        }
    }

    if (Test-Path -LiteralPath $DeviceKeyDirectory -PathType Container) {
        try {
            $acl = Get-Acl -LiteralPath $DeviceKeyDirectory
            $broadSids = @("S-1-1-0", "S-1-5-11", "S-1-5-32-545")
            $unsafeRules = @($acl.Access | Where-Object {
                $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                $broadSids -contains $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -and
                ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadAndExecute)
            })
            $aclDetail = if ($unsafeRules.Count -eq 0) { "no broad read grant detected" } else { "broad read access is present" }
            Write-Check "Device-key directory ACL" ($unsafeRules.Count -eq 0) $aclDetail
        }
        catch [UnauthorizedAccessException] {
            Write-WarningCheck "Device-key directory ACL" "current non-elevated user cannot read the protected ACL; rerun preflight elevated to inspect it"
        }
    }
    else {
        Write-WarningCheck "Device-key directory" "not present yet; the installer will create it with restricted ACLs"
    }

    Write-Check "ControlPlane HTTPS" ($ControlPlaneUrl.Scheme -eq [Uri]::UriSchemeHttps) $ControlPlaneUrl.AbsoluteUri
    if (-not [string]::IsNullOrWhiteSpace($SpkiPinBase64)) {
        try {
            $pin = [Convert]::FromBase64String($SpkiPinBase64)
            Write-Check "SPKI pin" ($pin.Length -eq 32) "Base64 SHA-256 value supplied out-of-band"
        }
        catch {
            Write-Check "SPKI pin" $false "not valid Base64"
        }
    }
    else {
        Write-Host "[INFO] SPKI pin is not configured; the ControlPlane certificate must chain to a trusted CA."
    }

    $controlAddresses = @([Net.Dns]::GetHostAddresses($ControlPlaneUrl.DnsSafeHost) |
        Where-Object AddressFamily -eq ([Net.Sockets.AddressFamily]::InterNetwork) |
        Select-Object -Unique)
    $controlDetail = if ($controlAddresses.Count -gt 0) { $controlAddresses.IPAddressToString -join ", " } else { "no IPv4 address" }
    Write-Check "ControlPlane IPv4 bootstrap" ($controlAddresses.Count -gt 0 -and $controlAddresses.Count -le 16) $controlDetail

    $nodeAddresses = @([Net.Dns]::GetHostAddresses($NodeHost) |
        Where-Object AddressFamily -eq ([Net.Sockets.AddressFamily]::InterNetwork) |
        Select-Object -Unique)
    $nodeDetail = if ($nodeAddresses.Count -gt 0) { $nodeAddresses.IPAddressToString -join ", " } else { "no IPv4 address" }
    Write-Check "Node IPv4 resolution" ($nodeAddresses.Count -gt 0) $nodeDetail

    $conflictingAddresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object {
        $_.InterfaceAlias -ne "HaloVPN" -and (Test-AddressInCidr $_.IPAddress $TunnelSubnet)
    })
    $subnetDetail = if ($conflictingAddresses.Count -eq 0) { "$TunnelSubnet is unused locally" } else { "overlaps an existing local IPv4 address" }
    Write-Check "Tunnel subnet conflict" ($conflictingAddresses.Count -eq 0) $subnetDetail

    $service = Get-Service -Name "HaloVPN" -ErrorAction SilentlyContinue
    $serviceStatus = if ($null -eq $service) { "not installed" } else { $service.Status }
    Write-Host ("[INFO] HaloVPN service: {0}" -f $serviceStatus)
}
catch {
    Write-Check "Preflight execution" $false $_.Exception.Message
}

Write-Host ("Preflight completed: {0} failure(s), {1} warning(s). No system state was changed." -f $failures.Count, $warnings.Count)
if ($failures.Count -ne 0) {
    exit 1
}

exit 0
