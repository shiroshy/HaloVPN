# Halo Protocol v0 — Stage 1

Status: experimental laboratory protocol; not suitable for real VPN traffic.

## Scope and layering

Stage 1 exchanges opaque ping/pong messages over UDP. .NET owns envelope parsing, socket lifetime, cancellation, endpoints, timeouts, and diagnostics. The Rust core owns `Noise_IK_25519_ChaChaPoly_SHA256`, static/ephemeral/traffic secret state, stateless transport cipher states, outbound counter enforcement, and replay protection. No TUN/TAP, routing, DNS, UI, ASP.NET, database, Docker, traffic masking, padding, DPI evasion, negotiation, or multi-user node exists.

## Identity and handshake

- server: one static X25519 private key;
- client: one static X25519 private key;
- client is provisioned with the server static public key;
- the one-client lab server is provisioned with the allowed client static public key;
- Noise IK supplies a fresh ephemeral key from both peers and independent traffic directions;
- a session becomes established only after Noise completes and the server constant-time matches the authenticated initiator static key.

The fixed prologue binds Stage 1, wire version zero, and the exact Noise name. There is no downgrade or suite negotiation. A nonzero client-generated connection ID correlates the two handshake messages and identifies established datagrams; it is neither an identity nor an authorization token.

## State and messages

Client: `Created -> Handshaking -> Established -> Closing -> Closed`.

Server: `Created -> Handshaking -> Established -> Closed`.

Invalid transitions return a stable safe error and do not advance transport state. Messages are `HandshakeInit`, `HandshakeResponse`, `Data`, `KeepAlive`, and authenticated advisory `Close`. Stage 1 labs remain minimal; the Private MVP Windows transport retransmits the exact serialized `HandshakeInit` with bounded backoff, while the node keeps a short bounded cache of the exact response keyed by source endpoint, connection ID and SHA-256 digest of the initiation.

## UDP laboratory policy

- fixed 1400-byte receive bound and no user-space receive queue;
- asynchronous send/receive with `CancellationToken`;
- ten-second handshake timeout and 180-second library idle default (ServerLab uses 30 seconds);
- one pending/active client in ServerLab;
- at most one pending session and eight attempts per ten-second window;
- no endpoint is considered authenticated until the IK message verifies;
- datagrams from a different endpoint are ignored after establishment;
- unknown/malformed inputs receive no protocol error response.

This is minimal allocation/rate protection, not a production anti-DoS cookie design.

## Replay, usage, and close

The details are in `wire-format.md`. Each direction has a 2048-packet replay window and a `2^32` message limit. Modified packets do not advance the window. There is no automatic rekey or overlap state: `KeyLimitReached` requires close plus a new handshake. Idle timeout or authenticated Close destroys the native session handle and drops Noise state.

## Native ABI

The synchronized header is `native/halo-protocol/include/halo_protocol.h`. Exports are:

- `halo_abi_version`
- `halo_session_create_client`
- `halo_session_create_server`
- `halo_session_write_handshake`
- `halo_session_read_handshake`
- `halo_session_encrypt`
- `halo_session_decrypt`
- `halo_session_is_established`
- `halo_session_destroy`
- `halo_generate_keypair`
- `halo_error_message`

All functions are `extern "C"`, catch Rust unwinding, return stable integer error codes, validate nulls/lengths, and use caller-owned buffers. Output length is caller-owned and reports the actual or required size. A handle is a nonzero integer lookup key, never a C# pointer to a Rust object. Destroy removes it from a bounded synchronized registry; subsequent use/destroy returns `InvalidHandle`. The registry serializes calls, and the C# wrapper additionally locks each session. Rust never returns a pointer to temporary storage.

The decrypt ABI receives the expected 24-byte outer prefix so Rust verifies it before replay commit. Error text is fixed and contains no key, plaintext, raw packet, or internal crypto state.

## Current limitations

- one active laboratory client;
- Stage 1 lab applications still omit retransmission and NAT keepalive; the Private MVP supplies bounded handshake retransmission and authenticated keepalive/liveness outside the Rust state machine;
- no automatic rekey;
- no secure OS keystore integration (the lab uses explicit raw key files);
- Windows ACL strength depends on the user-selected parent directory;
- Linux runtime/build integration is not yet automated;
- fuzz targets are prepared but no fuzz-duration result is claimed;
- no independent security audit or production hardening.
