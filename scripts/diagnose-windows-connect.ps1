[CmdletBinding()]
param(
    [string]$OutputPath = "$env:TEMP\halovpn-connect-diagnostic.txt",
    [int]$RouteWaitSeconds = 180,
    [int]$DisconnectRetrySeconds = 45
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

function Send-HaloRequest {
    param([Parameter(Mandatory)][ValidateSet(3, 4)][int]$Type)

    $pipe = [System.IO.Pipes.NamedPipeClientStream]::new(
        '.',
        'HaloVPN.Service.v1',
        [System.IO.Pipes.PipeDirection]::InOut,
        [System.IO.Pipes.PipeOptions]::Asynchronous)
    try {
        $pipe.Connect(5000)
        $payload = [System.Text.Encoding]::UTF8.GetBytes(
            "{`"Version`":1,`"Type`":$Type,`"Profile`":null,`"BootstrapIpv4Addresses`":null}")
        $header = [System.BitConverter]::GetBytes([int]$payload.Length)
        [Array]::Reverse($header)
        $pipe.Write($header, 0, $header.Length)
        $pipe.Write($payload, 0, $payload.Length)
        $pipe.Flush()

        $responseHeader = [byte[]]::new(4)
        $offset = 0
        while ($offset -lt $responseHeader.Length) {
            $read = $pipe.Read($responseHeader, $offset, $responseHeader.Length - $offset)
            if ($read -eq 0) {
                throw 'HaloVPN Service returned a truncated IPC response header.'
            }
            $offset += $read
        }

        [Array]::Reverse($responseHeader)
        $responseLength = [System.BitConverter]::ToInt32($responseHeader, 0)
        if ($responseLength -le 0 -or $responseLength -gt 65536) {
            throw 'HaloVPN Service returned an invalid IPC response length.'
        }

        $responsePayload = [byte[]]::new($responseLength)
        $offset = 0
        while ($offset -lt $responsePayload.Length) {
            $read = $pipe.Read($responsePayload, $offset, $responsePayload.Length - $offset)
            if ($read -eq 0) {
                throw 'HaloVPN Service returned a truncated IPC response.'
            }
            $offset += $read
        }

        return [System.Text.Encoding]::UTF8.GetString($responsePayload) | ConvertFrom-Json
    }
    finally {
        $pipe.Dispose()
    }
}

$guardObserved = $false
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
try {
    "StartedUtc=$([DateTimeOffset]::UtcNow.ToString('O'))" | Set-Content -LiteralPath $OutputPath -Encoding utf8
    while ($stopwatch.Elapsed.TotalSeconds -lt $RouteWaitSeconds) {
        $route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/1' -ErrorAction SilentlyContinue |
            Where-Object InterfaceAlias -EQ 'HaloVPN' |
            Select-Object -First 1
        if ($null -ne $route) {
            $guardObserved = $true
            break
        }

        Start-Sleep -Milliseconds 100
    }

    if (-not $guardObserved) {
        'GuardRouteObserved=False' | Add-Content -LiteralPath $OutputPath -Encoding utf8
        return
    }

    'GuardRouteObserved=True' | Add-Content -LiteralPath $OutputPath -Encoding utf8
    "ObservedAfterMs=$($stopwatch.ElapsedMilliseconds)" | Add-Content -LiteralPath $OutputPath -Encoding utf8

    $connected = $false
    $statusDeadline = [DateTimeOffset]::UtcNow.AddSeconds(15)
    while ([DateTimeOffset]::UtcNow -lt $statusDeadline) {
        try {
            $status = Send-HaloRequest -Type 4
            if ($status.Success -and $status.Status.State -eq 'Connected') {
                $connected = $true
                break
            }
        }
        catch {
            # The single-instance pipe may briefly be occupied by the Connect request.
        }
        Start-Sleep -Milliseconds 100
    }

    "ConnectedObserved=$connected" | Add-Content -LiteralPath $OutputPath -Encoding utf8
    if (-not $connected) {
        return
    }

    '=== ROUTES ===' | Add-Content -LiteralPath $OutputPath -Encoding utf8
    Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceAlias -eq 'HaloVPN' -or $_.DestinationPrefix -eq '176.12.73.4/32' } |
        Sort-Object DestinationPrefix |
        Format-Table DestinationPrefix, NextHop, InterfaceAlias, InterfaceIndex, RouteMetric, State -Auto |
        Out-String | Add-Content -LiteralPath $OutputPath -Encoding utf8

    '=== IP_CONFIGURATION ===' | Add-Content -LiteralPath $OutputPath -Encoding utf8
    Get-NetIPConfiguration -InterfaceAlias 'HaloVPN' -ErrorAction SilentlyContinue |
        Format-List InterfaceAlias, InterfaceIndex, IPv4Address, IPv4DefaultGateway, DnsServer |
        Out-String | Add-Content -LiteralPath $OutputPath -Encoding utf8
    Get-NetIPAddress -InterfaceAlias 'HaloVPN' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Format-List IPAddress, PrefixLength, AddressState, PrefixOrigin, SuffixOrigin, SkipAsSource |
        Out-String | Add-Content -LiteralPath $OutputPath -Encoding utf8

    '=== INTERFACE ===' | Add-Content -LiteralPath $OutputPath -Encoding utf8
    Get-NetIPInterface -InterfaceAlias 'HaloVPN' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Format-List InterfaceAlias, InterfaceIndex, ConnectionState, Dhcp, NlMtu, InterfaceMetric, AutomaticMetric, RouterDiscovery, DadTransmits, NeighborDiscoverySupported, WeakHostSend, WeakHostReceive |
        Out-String | Add-Content -LiteralPath $OutputPath -Encoding utf8

    '=== NEIGHBORS_BEFORE ===' | Add-Content -LiteralPath $OutputPath -Encoding utf8
    Get-NetNeighbor -InterfaceAlias 'HaloVPN' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Format-Table IPAddress, LinkLayerAddress, State -Auto |
        Out-String | Add-Content -LiteralPath $OutputPath -Encoding utf8

    '=== ADAPTER_STATS_BEFORE ===' | Add-Content -LiteralPath $OutputPath -Encoding utf8
    Get-NetAdapterStatistics -Name 'HaloVPN' -ErrorAction SilentlyContinue |
        Format-List ReceivedBytes, ReceivedUnicastPackets, SentBytes, SentUnicastPackets |
        Out-String | Add-Content -LiteralPath $OutputPath -Encoding utf8

    '=== PING_1_1_1_1 ===' | Add-Content -LiteralPath $OutputPath -Encoding utf8
    (& ping.exe -n 2 -w 1500 1.1.1.1 2>&1 | Out-String) |
        Add-Content -LiteralPath $OutputPath -Encoding utf8

    '=== HTTPS_IPIFY ===' | Add-Content -LiteralPath $OutputPath -Encoding utf8
    (& curl.exe --silent --show-error --max-time 4 https://api.ipify.org 2>&1 | Out-String) |
        Add-Content -LiteralPath $OutputPath -Encoding utf8

    '=== ADAPTER_STATS_AFTER ===' | Add-Content -LiteralPath $OutputPath -Encoding utf8
    Get-NetAdapterStatistics -Name 'HaloVPN' -ErrorAction SilentlyContinue |
        Format-List ReceivedBytes, ReceivedUnicastPackets, SentBytes, SentUnicastPackets |
        Out-String | Add-Content -LiteralPath $OutputPath -Encoding utf8
}
finally {
    $disconnectSucceeded = $false
    $disconnectErrorType = 'None'
    $disconnectDeadline = [DateTimeOffset]::UtcNow.AddSeconds($DisconnectRetrySeconds)
    do {
        try {
            $response = Send-HaloRequest -Type 3
            if ($response.Success) {
                $disconnectSucceeded = $true
                break
            }
            $disconnectErrorType = 'ServiceRejected'
        }
        catch {
            $disconnectErrorType = $_.Exception.GetType().Name
        }

        Start-Sleep -Milliseconds 500
    } while ([DateTimeOffset]::UtcNow -lt $disconnectDeadline)

    if ($disconnectSucceeded) {
        'FailSafeDisconnect=True' | Add-Content -LiteralPath $OutputPath -Encoding utf8
    }
    else {
        "FailSafeDisconnect=False Type=$disconnectErrorType" |
            Add-Content -LiteralPath $OutputPath -Encoding utf8
    }

    "FinishedUtc=$([DateTimeOffset]::UtcNow.ToString('O'))" | Add-Content -LiteralPath $OutputPath -Encoding utf8
}
