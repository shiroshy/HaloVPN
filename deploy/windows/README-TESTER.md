# HaloVPN Windows x64 private test

This is a private, pre-release IPv4 full-tunnel build. It is not an independently
reviewed VPN product. While connected or reconnecting, HaloVPN deliberately keeps
the protected `/1` routes and IPv6 guard active. Always use **Disconnect** before
uninstalling or intentionally returning to the normal direct connection.

## What the owner must send separately

- a unique username and password created for this tester;
- the HTTPS ControlPlane URL;
- the expected SPKI SHA-256 pin when the server certificate is private/self-signed.

Never send a device private key, refresh token, PostgreSQL credential, or node
private key. The Windows Service creates the device key locally with LocalMachine
DPAPI protection.

## Verify and install

1. Compare the ZIP SHA-256 with the value sent by the owner:

   ```powershell
   Get-FileHash .\HaloVPN-Windows-x64-Test.zip -Algorithm SHA256
   ```

2. Extract the ZIP to a local directory. Do not run it directly from the archive.
3. Open a normal PowerShell window and determine the intended Desktop user's SID:

   ```powershell
   whoami /user
   ```

4. Run the read-only preflight. Replace the sample values:

   ```powershell
   .\Preflight-HaloVPN.ps1 `
     -AllowedUserSid 'S-1-5-21-REPLACE' `
     -ControlPlaneUrl 'https://vpn-control.example:8443' `
     -NodeHost 'vpn-node.example' `
     -WintunDllPath .\wintun.dll `
     -TunnelSubnet '10.77.0.0/24'
   ```

   Add `-SpkiPinBase64 '<pin>'` when the owner provided a pin. Preflight reports
   prerequisites and conflicts but does not install, route, change DNS, create an
   adapter, or alter firewall rules.

5. Open PowerShell **as Administrator**, change to the extracted bundle directory,
   and install:

   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   .\Install-HaloVPN.ps1
   ```

   The installer detects the currently interactive user. If elevation used a
   different administrator account, pass the SID explicitly:

   ```powershell
   .\Install-HaloVPN.ps1 -AllowedUserSid 'S-1-5-21-REPLACE'
   ```

6. If the owner supplied a private-deployment SPKI pin, set it for the intended
   non-administrator Desktop user and then sign out/in (or start Desktop from a new
   process):

   ```powershell
   [Environment]::SetEnvironmentVariable(
     'HALOVPN_CONTROLPLANE_SPKI_PIN',
     '<Base64 SHA-256 SPKI pin from the owner>',
     'User')
   ```

7. Start:

   ```text
   C:\Program Files\HaloVPN\Desktop\HaloVPN.Desktop.exe
   ```

Enter the HTTPS URL, username, and password, then press **Login** and **Connect**.
The password is not saved. Device registration consumes one device slot.

## Test checklist

Before Connect, record the public IPv4:

```powershell
(Invoke-RestMethod https://api.ipify.org).Trim()
```

After Connect:

```powershell
Get-NetAdapter -Name HaloVPN
Get-NetIPAddress -InterfaceAlias HaloVPN -AddressFamily IPv4
Get-NetRoute -AddressFamily IPv4 |
  Where-Object DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')
Resolve-DnsName example.com
(Invoke-RestMethod https://api.ipify.org).Trim()
```

Confirm normal HTTP/HTTPS and DNS work. Test **Disconnect**, confirm the two `/1`
routes disappear and the original public IPv4 returns, then test Connect once more.
Do not share `C:\ProgramData\HaloVPN`, raw application logs, or screenshots that
contain credentials/tokens.

If Connect fails, press Disconnect before closing the app. Send the owner:

```powershell
Get-Service HaloVPN
Get-NetAdapter -Name HaloVPN -ErrorAction SilentlyContinue
Get-NetRoute -AddressFamily IPv4 |
  Where-Object DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')
```

Also send the visible diagnostic code, Windows version, and failure time. Do not
send the device-key file.

## Updating an existing test install

The supplied updater changes only Service binaries and verifies that the installed
production `appsettings.json` hash is unchanged:

```powershell
.\Update-HaloVPN-Service.ps1 -PublishDirectory .\Service
```

Close Desktop before replacing its files. A fresh install must use
`Install-HaloVPN.ps1`; the installer refuses to overwrite an existing installation.

## Third-party component

The included x64 `wintun.dll` is the unmodified, Authenticode-signed Wintun prebuilt
binary. Its license is in `licenses\WINTUN-PREBUILT-LICENSE.txt`. The installer
rejects a DLL without a valid WireGuard LLC signature.
