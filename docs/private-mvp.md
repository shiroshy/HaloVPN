# Private MVP architecture and operation

This stage preserves the Stage 1 wire format and exactly `Noise_IK_25519_ChaChaPoly_SHA256`. Login/password authenticate only HTTPS ControlPlane requests. The UDP tunnel accepts a device only when its static Noise public key is in the bounded active-device allowlist; passwords and tokens never enter the Noise handshake.

## Components

- `HaloVPN.ControlPlane`: ASP.NET Core API, HTTPS enforcement outside Development, per-source login/refresh rate limiting, JWT access tokens (15 minutes by default), transactionally rotating hashed refresh tokens, device enrollment and profiles. PostgreSQL locks the presented token row; the parent revocation, replacement insert and `replaced_by_token_id` update commit together. Concurrent reuse deterministically revokes the family, including the newly issued child, so at most one request receives a replacement and it cannot remain usable after the race.
- `HaloVPN.Infrastructure`: EF Core/Npgsql PostgreSQL model, Argon2id password hashing, transactional address allocation, auth/device/admin services and the node read-only authorization repository.
- `HaloVPN.AdminCli`: owner-only user/device/token administration and `database migrate`. Passwords are read without echo or from two redirected stdin lines, never from arguments.
- `HaloVPN.Node` + `HaloVPN.Platform.Linux`: bounded multi-client Noise sessions, `/dev/net/tun`, source-address anti-spoofing, client-to-client blocking, outbound destination policy and fail-closed authorization for new sessions. A recent bounded allowlist snapshot lets existing sessions survive a brief PostgreSQL/ControlPlane outage. Default special/private destinations, the tunnel subnet and local VPS addresses are rejected before TUN; the owned nftables table repeats the critical restrictions.
- `HaloVPN.WindowsService` + `HaloVPN.Platform.Windows`: LocalMachine-DPAPI device key, official Wintun ABI wrapper, Noise/UDP packet pumps, reversible route/DNS/IPv6 plans and user/admin ACL-protected named-pipe IPC. The persistent guard (Wintun, `/1` routes, exact node/bootstrap `/32` routes, DNS and IPv6 block) survives transport reconnect and service restart. Its bounded journal stores only a versioned validated descriptor, never executable paths or arguments; only explicit Disconnect/Logout rolls it back.
- `HaloVPN.Desktop`: non-elevated WPF login/connect UI. The access token stays in memory and the refresh token is CurrentUser-DPAPI protected. The Desktop never receives the device private key.

PostgreSQL uses UTC timestamps, snake_case names and unique indexes for normalized usernames, device keys, leases and token hashes. Raw refresh tokens are never stored. The default `10.77.0.0/24`, gateway `10.77.0.1`, MTU 1200, session limit 16 and single `Astana-1` node are configuration values, not location-specific behavior. The node seed is skipped until a public host and a 32-byte public key are supplied.

## ControlPlane and Admin CLI

Set secrets through the process environment or an external secret store:

```text
HALOVPN_DATABASE=Host=...;Database=halovpn;Username=...;Password=...
Tokens__SigningKeyBase64=<at-least-32-random-bytes>
VpnNode__PublicHost=<operator-provided-host>
VpnNode__PublicKeyBase64=<node-public-key>
```

Apply the checked-in initial migration and create users:

```powershell
dotnet run --project src/HaloVPN.AdminCli -c Release -- database migrate
dotnet run --project src/HaloVPN.AdminCli -c Release -- user create alice 1
dotnet run --project src/HaloVPN.AdminCli -c Release -- user disable alice
```

Production ControlPlane rejects plain HTTP. A normal CA certificate is preferred. For a private deployment, set `HALOVPN_CONTROLPLANE_SPKI_PIN` on the Desktop to the Base64 SHA-256 of a pre-distributed certificate SPKI. The pin is never learned from the connection it authenticates. HTTP loopback is permitted only when the explicit development environment variable is `1`.

## Windows prerequisites

Obtain the official Wintun x64 package from the Wintun project, review its license/redistribution terms, and put only the expected `wintun.dll` at `HaloVPN:WintunDllPath` (default `C:\Program Files\HaloVPN\wintun.dll`). No build or runtime path downloads it. Configure `HaloVPN:AllowedUserSid` to the intended Desktop user's SID before installing the service.

The service creates a `HaloVPN` Layer-3 adapter, gives the public node/bootstrap IPv4 addresses exact host routes through the original selected gateway, adds two IPv4 `/1` routes through Wintun, applies adapter DNS, and temporarily blocks IPv6 with two explicitly named Windows Firewall rules. It journals only the typed inputs needed to reconstruct the allowlisted rollback plan and removes only those mutations. Unit tests do not modify the host network; real Wintun tests require an explicit administrator-run environment.

Before enabling the guard, Desktop resolves the HTTPS ControlPlane hostname and passes at most 16 exact IPv4 bootstrap addresses to the service. HTTP connections use those fixed socket destinations while the original hostname remains the request host/TLS SNI and normal certificate validation plus the optional preconfigured SPKI pin remains active. The client sends the exact same serialized `HandshakeInit` up to four times (500 ms initial backoff, ten-second total default). After authentication it sends an encrypted `KeepAlive` after 20 seconds without outbound traffic; the node returns one bounded authenticated keepalive and the client reconnects protected after 65 seconds without authenticated inbound traffic.

## Linux VPS

Use `deploy/linux/build-publish.sh Release`, then follow `deploy/linux/README.md`. The nftables installer requires the external interface as an argument, accepts `HALOVPN_TUNNEL_SUBNET`/`HALOVPN_TUN_INTERFACE`, and owns only the `halovpn_filter` and `halovpn_nat` tables. It never flushes the host firewall. ControlPlane and Node run as separate systemd services; the Node needs `/dev/net/tun` and `CAP_NET_ADMIN` but not a custom kernel driver.

Both preflights are read-only: `deploy/linux/preflight.sh` uses explicit `HALOVPN_*` environment values, and `scripts/preflight-windows.ps1` requires the expected Wintun/key/SID/URL/node/subnet arguments. They report prerequisites and conflicts without installing, routing or firewall changes.

## Verification and explicit limits

Local automated tests cover auth lifecycle, token rotation/reuse, device limits and leases, two concurrent native Noise clients, packet spoofing/client isolation, authorization-cache outage behavior, session/handshake bounds, Windows route/DNS/firewall planning, IPC parsing and DPAPI token storage. Stage 1 tamper/replay/10,000-message loopback tests remain unchanged.

The repository does not prove a real VPS route, nftables NAT to the Internet, service installation, CA provisioning or Wintun operation because no VPS configuration or official DLL was supplied. IPv4 full tunnel only is implemented; split tunnel, IPv6 transport, public registration, payments, web administration, traffic masking and DPI evasion are deliberately absent. Destination addresses, DNS queries and packet contents are not audit-log data.
