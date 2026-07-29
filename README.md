# HaloVPN

HaloVPN contains the completed Stage 1 laboratory UDP channel and an in-progress Private MVP for one Linux node and two Windows users. The Private MVP adds a PostgreSQL ControlPlane, Admin CLI, multi-client Linux TUN node, Windows Service/Wintun integration and a minimal WPF client. It is not a finished or independently reviewed VPN product, and the real Windows → VPS → Internet path still requires operator-provided infrastructure and verification.

The implementation keeps UDP and the 24-byte outer envelope in .NET 10. Rust owns the complete Noise state machine, X25519 static/ephemeral secrets, ChaCha20-Poly1305 traffic states, packet counters, and the 2048-packet replay window. The fixed protocol is exactly `Noise_IK_25519_ChaChaPoly_SHA256`; there is no cipher-suite negotiation.

## Prerequisites

- .NET SDK 10
- stable Rust toolchain with Cargo
- Windows x64 for the supplied native build script (the Rust crate itself is portable)

## Build and test

```powershell
./scripts/build-native.ps1 -Configuration Release
dotnet build HaloVPN.sln -c Release
dotnet test HaloVPN.sln -c Release --no-build
cargo test --manifest-path native/halo-protocol/Cargo.toml
```

The native script uses `Cargo.lock`, builds only the requested profile, and copies only `halo_protocol.dll` to `artifacts/native/<Configuration>/win-x64`. MSBuild copies the matching profile into application and test output directories. `target`, `bin`, `obj`, `artifacts`, and key files are ignored.

## Generate laboratory keys

Build first, then create each private key at a new explicit path:

```powershell
dotnet run --project src/HaloVPN.KeyGen -c Release --no-build -- --private-key C:\secure-lab\server.key
dotnet run --project src/HaloVPN.KeyGen -c Release --no-build -- --private-key C:\secure-lab\client.key
```

The tool refuses to overwrite a file, writes exactly 32 raw private-key bytes, requests owner-only mode on Unix, and prints the Base64 public key. On Windows the new file inherits the parent directory ACL; use a directory restricted to the intended account. Private keys are never accepted on the command line or written to source/configuration.

## Run the loopback lab

In one terminal:

```powershell
dotnet run --project src/HaloVPN.ServerLab -c Release --no-build -- --listen 127.0.0.1 --port 45000 --private-key C:\secure-lab\server.key --client-public <client-public-base64> --verbose
```

In another terminal:

```powershell
dotnet run --project src/HaloVPN.ClientLab -c Release --no-build -- --server 127.0.0.1:45000 --private-key C:\secure-lab\client.key --server-public <server-public-base64> --count 10000 --timeout 5
```

Diagnostics contain only endpoint, connection ID, phase, safe reject code, and message count. They never include private/session keys, plaintext, decrypted payloads, authentication tags, or raw datagrams.

## Fuzz scaffolding

`native/halo-protocol/fuzz` contains targets for handshake input, decrypt input, and ABI length handling. `cargo-fuzz` is not installed automatically. With it already installed:

```powershell
cargo fuzz run handshake_input --fuzz-dir native/halo-protocol/fuzz
cargo fuzz run decrypt_input --fuzz-dir native/halo-protocol/fuzz
cargo fuzz run abi_length_handling --fuzz-dir native/halo-protocol/fuzz
```

See `docs/` for the threat model, wire format, key lifecycle, protocol limits, ABI ownership rules, and test plan.

## Private MVP

The new architecture and operator steps are in [docs/private-mvp.md](docs/private-mvp.md). Linux systemd/nftables templates live in `deploy/linux`. The Windows publish script deliberately does not download Wintun: an operator must obtain the official x64 DLL, review its redistribution license, and put it at the configured service path.

Pre-deployment checks are read-only: run `deploy/linux/preflight.sh` with the explicit environment described in `deploy/linux/README.md`, and run `scripts/preflight-windows.ps1 -?` for the required Windows paths, SID, HTTPS URL, node host and tunnel subnet. These checks do not replace the still-unperformed Windows → VPS → Internet acceptance test.
