# HaloVPN Threat Model v0

Status: Draft 0.1  
Scope: Stage 1 laboratory secure datagram channel and future IP tunnel

## 1. Security objectives

HaloVPN must provide:

- confidentiality and integrity for tunneled payloads;
- mutual authentication between an enrolled device and a VPN node;
- forward secrecy for established sessions;
- replay protection for handshake and transport packets;
- downgrade resistance for negotiated protocol versions and capabilities;
- strict validation of packet lengths, counters, identifiers, and state transitions;
- fail-closed behavior when authentication or key state is uncertain.

## 2. Protected assets

- device static private keys;
- node static private keys;
- ephemeral handshake secrets;
- active traffic keys and packet counters;
- signed bootstrap and transport-profile configuration;
- tunneled IP packets and DNS traffic;
- device enrollment and revocation state.

## 3. Adversaries

### Passive network observer

Can record packet sizes, timing, direction, endpoints, and all unencrypted bytes. Cannot initially break standard cryptographic primitives.

### Active network attacker

Can drop, delay, duplicate, reorder, replay, modify, and inject packets. Can redirect DNS and attempt downgrade or path-manipulation attacks.

### Active scanner

Can send arbitrary packets to a node and observe whether, when, and how it responds.

### Compromised control plane

Can read or alter control-plane database contents. It must not gain device or node private keys from the database alone.

### Compromised VPN node

Can observe traffic exiting that node and impersonate that node while its key remains trusted. Compromise of one node must not expose private keys of other nodes or devices.

### Malicious enrolled client

Possesses valid credentials for one device and may send malformed, excessive, or adversarial protocol input.

## 4. Assumptions

- X25519, ChaCha20-Poly1305, and SHA-256 remain secure for this use.
- Random-number generation is supplied by the operating system.
- Endpoint devices and nodes are not already fully compromised.
- Private keys are generated locally and are never transmitted to the control plane.
- Time may be inaccurate; security must not depend solely on wall-clock correctness.

## 5. Non-goals for v0

- anonymity against a global observer;
- hiding the fact that an encrypted tunnel exists;
- guaranteed resistance to all statistical traffic classification;
- protection from malware running with administrator or root privileges;
- multi-hop routing;
- post-quantum security;
- production-grade censorship circumvention.

## 6. Required mitigations

### Cryptographic state

- Use one reviewed Noise handshake pattern and one fixed cipher suite per protocol version.
- Derive independent keys for each traffic direction.
- Never reuse a nonce with the same key.
- Enforce hard packet and byte limits per traffic key.
- Erase superseded key material where the platform permits.

### Replay and ordering

- Every transport packet carries an authenticated monotonically increasing packet number.
- Receivers maintain a bounded sliding replay window.
- Duplicate and stale packets are dropped without changing session state.

### Denial of service

- Parsing is bounded and allocation-aware before authentication.
- Unknown clients do not cause large responses or persistent session allocation.
- Handshake attempts are rate-limited by source and globally.
- Queues, packet sizes, fragment counts, and concurrent sessions have explicit limits.

### Versioning

- Version and negotiated capabilities are authenticated by the handshake transcript.
- Unsupported versions fail without silently falling back.
- Remote configuration is accepted only when signature verification succeeds.

### Platform integration

- Kill-switch and routing changes are transactional where possible.
- Failure to establish protected DNS or required routes prevents connected state.
- Crash recovery must remove stale routes or keep the fail-closed firewall policy.

## 7. Privacy boundaries

The node necessarily sees decrypted destination IP traffic before forwarding it. The control plane must not receive tunneled payloads, destination addresses, or DNS queries. Diagnostic logging must exclude private keys, traffic keys, plaintext packets, authentication tags, and full configuration secrets.

## 8. Deferred questions after Stage 1

- Enrollment/control-plane flow beyond the fixed Stage 1 allow-list.
- Stateless anti-DoS cookie design.
- Rekey thresholds and overlap window.
- Connection-ID rotation beyond the random client-generated Stage 1 identifier.
- Padding and carrier-profile responsibilities.
- Secure key storage choices on Windows and Linux.
- Behavior during control-plane outage and revocation propagation.

## 9. Release gate

No production claim is allowed until protocol tests, fuzzing, dependency review, key-lifecycle review, and an independent security audit have been completed.
