# HaloVPN Key Lifecycle v0

Status: Stage 1 laboratory implementation

## Key classes

### Device static key

- X25519 key pair generated locally during enrollment.
- Private key never leaves the device.
- Public key is registered with the control plane and distributed to authorized nodes.
- One key pair represents one independently revocable installation.

### Node static key

- X25519 key pair generated on the VPN node.
- Private key never enters the control-plane database.
- Public key is delivered through signed bootstrap configuration.
- Rotation is performed per node with a bounded overlap period.

### Ephemeral and traffic keys

- Every handshake creates fresh ephemeral keys.
- Noise transport split derives independent client-to-node and node-to-client traffic keys.
- Ephemeral and traffic keys are memory-only, never logged, and discarded on close or rekey.

### Configuration-signing key

- Separate from device and node keys.
- Signs bootstrap configuration, node identities, protocol policy, and revocation metadata.
- The private signing key must not exist on ordinary VPN nodes.

## Device enrollment

1. The device generates a static key pair using the operating-system CSPRNG.
2. The private key is stored using platform-protected storage.
3. The public key is sent through an authenticated control-plane session.
4. The control plane records owner, device identifier, public key, creation time, and status.
5. Authorized nodes receive the active public key through authenticated synchronization.

The system must never accept an uploaded client private key as an enrollment shortcut.

## Platform storage

### Windows

DPAPI/service storage remains future work. The Stage 1 KeyGen writes 32 raw bytes only to an explicit new path and refuses overwrite. On Windows it inherits the selected parent directory ACL, so the operator must use a restricted directory. This is a laboratory limitation, not production key storage.

### Linux node

The node private key is stored outside source control and container images, owned by a dedicated service account, with owner-only permissions. It is excluded from logs, environment dumps, crash reports, and unencrypted backups.

## Session establishment

The client authenticates the configured node static public key. The node authenticates the device static public key against its active authorization set. A session becomes established only after the cryptographic identity maps to an active, non-revoked device record.

## Key usage limits

Stage 1 fixes these engineering limits:

- maximum packets per direction: `2^32`;
- packet number must never wrap or be reused;
- automatic rekey is absent, so the caller closes and performs a new IK handshake at the first `KeyLimitReached` result.

These are product limits, not claims about the theoretical maximum of the primitive.

## Rotation

### Device rotation

The device generates a new pair, enrolls the new public key while authenticated, proves possession through a fresh session, then revokes and erases the old key.

### Node rotation

The node generates a replacement key locally. Signed configuration may advertise old and new public keys during a bounded overlap. Clients prefer the new key and reject unadvertised keys.

### Signing-key rotation

Signing-key rotation requires an offline root or explicitly documented cross-signing procedure. A compromised signing key requires emergency revocation and a recovery path that does not blindly trust that key.

## Revocation

Revocation records contain the device or key identifier, monotonic generation, reason category, audit timestamp, and signature metadata. Nodes reject new handshakes from revoked keys and terminate matching established sessions when the update arrives.

During control-plane outage, the laboratory policy permits previously authorized keys but rejects unknown identities and new enrollment.

## Compromise response

### Device compromise

Revoke the device, terminate sessions, generate a new pair, and inspect account sessions. The old private key cannot be restored from the server because it is never stored there.

### Node compromise

Remove the node from discovery, revoke its public key, terminate sessions, rebuild from trusted media, and create a new key. Exit traffic observed at the compromised node is considered exposed.

### Signing-key compromise

Freeze remote configuration, distribute emergency trust material through a separately authenticated release, revoke the old signer, and rotate all affected metadata.

## Logging prohibition

Never log private keys, traffic keys, ephemeral secrets, raw handshake state, decrypted packets, complete authenticated datagrams, or recovery material.

## In-memory ownership and erasure

Private-key input buffers are zeroed by the lab applications after Rust session creation. C# protected-message temporaries are zeroed with `CryptographicOperations.ZeroMemory`; Rust-generated private-key temporaries use `zeroize::Zeroizing`. Handshake and traffic keys remain entirely inside snow and its crypto backend and are dropped when the registry removes a session. Snow does not expose those session keys or a public method to prove immediate overwriting of every internal allocation, so Stage 1 documents that limitation instead of adding custom cryptography. Crash dumps, paging, and a compromised process remain outside this laboratory guarantee.

## Release gate

Production release requires tests for generation, storage permissions, restart recovery, rotation overlap, revocation propagation, counter exhaustion, failed rekey, and secret-free diagnostic output.
