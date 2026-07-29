# Halo Protocol v0 Wire Format

Status: Stage 1 experimental laboratory format. All multibyte integers are unsigned and encoded in network byte order (big-endian).

## Common envelope

Every UDP datagram is exactly one envelope. The fixed header is 24 bytes:

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 2 | `magic` | `0x48 0x56` (`HV`) |
| 2 | 1 | `version` | `0x00` only |
| 3 | 1 | `message_type` | table below |
| 4 | 2 | `flags` | zero in v0 |
| 6 | 8 | `connection_id` | nonzero opaque identifier |
| 14 | 8 | `packet_number` | zero for handshake; per-direction counter for transport |
| 22 | 2 | `payload_length` | exact bytes after the header |

The total datagram length must equal `24 + payload_length`; trailing bytes are invalid. The parser rejects inputs below 24 bytes, above 1400 bytes, bad magic, unknown version/type, nonzero flags, inconsistent length, and type-specific excess before allocation based on network data.

| Value | Type | Maximum body | Emitted Stage 1 body |
|---:|---|---:|---:|
| `0x01` | `HandshakeInit` | 488 | 96 for empty IK payload |
| `0x02` | `HandshakeResponse` | 488 | 48 for empty IK payload |
| `0x10` | `Data` | 1244 | `44 + application_length` |
| `0x11` | `KeepAlive` | 40 | 40 |
| `0x12` | `Close` | 48 | 48 |

The unauthenticated handshake datagram limit is 512 bytes. The UDP carrier buffer limit is 1400 bytes. A Stage 1 sender emits at most 1268 bytes because application plaintext is limited to 1200 bytes.

## Handshake

`HandshakeInit` and `HandshakeResponse` bodies are the first and second Noise IK messages with empty Noise payloads. The client generates a random nonzero connection ID and the response echoes it. The identifier is not secret and grants no authority. The server binds an endpoint only after the first IK message authenticates the allow-listed client static key; the client accepts only a response from its configured endpoint and authenticated server static key.

The fixed Noise prologue is the ASCII byte string:

```text
HaloVPN Stage 1|wire=0|Noise_IK_25519_ChaChaPoly_SHA256
```

## Transport protection

`snow::StatelessTransportState` receives the outer `packet_number` as its Noise transport nonce. The packet number on the wire remains big-endian; nonce formatting inside ChaChaPoly follows the Noise/snow implementation.

Because snow's stateless API does not accept caller-supplied associated data, Stage 1 authenticates the outer header by placing an exact 24-byte copy at the start of the encrypted plaintext:

```text
NoiseEncrypt(packet_number, outer_header || protected_message)
```

Rust decrypts and constant-time compares that prefix with the received outer header before committing the replay-window update. Changing connection ID, type, flags, length, or packet number therefore cannot make the packet valid or consume the replay slot. The 16-byte ChaCha20-Poly1305 tag is included in `payload_length`.

### Data protected message

After the encrypted header copy:

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 1 | `payload_type` | zero (`OpaqueTestData`) |
| 1 | 1 | `payload_flags` | zero |
| 2 | 2 | `payload_length` | 0 through 1200, big-endian |
| 4 | N | payload | exactly N bytes |

Compression, padding, batching, and fragmentation are absent.

### KeepAlive and Close

KeepAlive has no protected bytes after the encrypted header copy. Close has 8 bytes: big-endian `reason:u16`, zero `reserved:u16`, and `detail:u32`. Both consume packet numbers and replay-window positions.

## Replay and limits

Each direction starts at packet number zero. Rust requires outbound numbers to be exactly sequential, rejects duplicates, accepts unseen reordering within a fixed 2048-packet window, and rejects older packets. The window is 2048 to tolerate bounded UDP reordering while keeping per-session state fixed (2048 booleans in the current lab implementation). Authentication failure does not update it.

Packet number `2^32` and above returns `KeyLimitReached`; automatic rekey is not implemented. The session must close and perform a fresh handshake. This engineering limit is below primitive exhaustion and prevents wrap/reuse.
