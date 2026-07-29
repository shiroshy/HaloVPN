# HaloVPN Stage 1 Test Plan

Stage 1 validates a bounded laboratory channel, not a production VPN or a security audit.

## Automated .NET tests

- encode/parse all five envelope types and exact big-endian fields;
- round trip, invalid magic/version, short header, inconsistent/excess length, and trailing data;
- 10,000 deterministic random parser inputs without an unhandled exception;
- C#-driven native IK handshake and encrypted bidirectional ping/pong;
- ciphertext and outer-header tamper rejection without replay-window consumption;
- duplicate rejection, in-window reordering, stale packet rejection, and `2^32` boundary;
- wrong client static key and use after dispose;
- UDP loopback, cancellation/handshake timeout, and pending-attempt bounds;
- assertion that the encrypted ping datagram does not contain the ping byte sequence.

Run:

```powershell
./scripts/build-native.ps1 -Configuration Release
dotnet build HaloVPN.sln -c Release
dotnet test HaloVPN.sln -c Release --no-build
```

## Rust tests

- successful IK handshake and compatible stateless transport directions;
- encrypt/decrypt, tamper, replay, wrong static key, and wrong handshake order;
- replay-window reorder/stale behavior;
- null arguments, undersized output, destroy/double-destroy, invalid handles;
- deliberate panic converted to `HALO_INTERNAL_ERROR` inside the FFI boundary.

Run:

```powershell
cargo test --manifest-path native/halo-protocol/Cargo.toml
cargo build --release --locked --manifest-path native/halo-protocol/Cargo.toml
```

## Process-level acceptance

Generate ephemeral keys outside the repository, run ServerLab, then ClientLab with `--count 10000`. Record both exit codes, established/closed phases, duration, and verify no secrets/plaintext/raw datagrams appear in output. Separately run ServerLab with no client to verify its handshake timeout exits without hanging.

## Fuzzing

Prepared targets are `handshake_input`, `decrypt_input`, and `abi_length_handling` under `native/halo-protocol/fuzz`. Install and run cargo-fuzz explicitly as documented in README; the build does not install tools or download arbitrary runtime binaries. Future campaigns must record toolchain, duration, corpus, and crash artifacts.

## Remaining future coverage

- repeatable Linux x64 native/application runs;
- packet-loss/retransmission behavior after a retransmission design exists;
- long-duration fuzz and sanitizer campaigns;
- resource flood and log-rate testing;
- automatic rekey/overlap tests after that protocol is designed;
- secure keystore, routing, DNS, kill-switch, and TUN testing in later stages.
