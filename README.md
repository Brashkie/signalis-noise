<div align="center">

# @brashkie/signalis-noise

**The [Noise Protocol Framework](https://noiseprotocol.org/) built on [`@brashkie/signalis-core`](https://github.com/Brashkie/signalis-core).**

[![CI](https://github.com/Brashkie/signalis-noise/actions/workflows/ci.yml/badge.svg)](https://github.com/Brashkie/signalis-noise/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@brashkie/signalis-noise.svg)](https://www.npmjs.com/package/@brashkie/signalis-noise)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
[![types](https://img.shields.io/badge/types-TypeScript-3178c6.svg)](https://www.typescriptlang.org/)
[![vectors](https://img.shields.io/badge/official%20vectors-32%2F32-brightgreen.svg)](#correctness)

</div>

---

The XX, IK, and NK handshake patterns over **Curve25519 + SHA-256**, with a
selectable AEAD — **ChaCha20-Poly1305** or **AES-GCM**. Every handshake is
verified **byte-for-byte against the official Noise test vectors**.

All cryptography is delegated to `@brashkie/signalis-core`; this package is pure
protocol orchestration (`CipherState` / `SymmetricState` / `HandshakeState`).
Noise powers the transport layer of WhatsApp, WireGuard, and Tailscale.

```
  @brashkie/signalis-core (Rust primitives)
        ▲
        │ peerDependency (DH, HKDF, AEAD, SHA-256)
        │
  @brashkie/signalis-noise (this package — TS orchestration)
```

---

## Install

```bash
npm install @brashkie/signalis-noise @brashkie/signalis-core
```

`@brashkie/signalis-core` is a **peer dependency** — install it alongside so a
single copy of the crypto core is shared across the Signalis ecosystem.

## Quick start

A full XX handshake (mutual authentication) between two parties:

```ts
import { HandshakeState } from '@brashkie/signalis-noise';
import { Curve25519 } from '@brashkie/signalis-core';

const aliceStatic = Curve25519.generateKeyPair();
const bobStatic = Curve25519.generateKeyPair();

const alice = new HandshakeState({
  pattern: 'XX',
  initiator: true,
  staticKeyPair: aliceStatic,
});
const bob = new HandshakeState({
  pattern: 'XX',
  initiator: false,
  staticKeyPair: bobStatic,
});

// -> e
const m1 = alice.writeMessage();
bob.readMessage(m1);

// <- e, ee, s, es
const m2 = bob.writeMessage();
alice.readMessage(m2);

// -> s, se
const m3 = alice.writeMessage();
bob.readMessage(m3);

// Both sides now derive matching transport keys.
const aliceTx = alice.split();
const bobTx = bob.split();

// Encrypted transport, both directions:
const ct = aliceTx.send.encryptWithAd(Buffer.alloc(0), Buffer.from('hello bob'));
const pt = bobTx.receive.decryptWithAd(Buffer.alloc(0), ct); // "hello bob"
```

You can piggyback an encrypted payload on any handshake message:

```ts
const m1 = alice.writeMessage(Buffer.from('early data'));
const payload = bob.readMessage(m1); // decrypted once a key exists
```

## Patterns

| Pattern | Authentication | Use case |
|---------|----------------|----------|
| **XX** | Mutual, identities exchanged during the handshake | The workhorse — WhatsApp's transport uses XX |
| **IK** | Mutual, initiator knows responder's static up front | Pinned server key; enables early encrypted data |
| **NK** | Responder only (initiator anonymous) | TLS-like: anonymous client, known server |
| **KK** | Mutual, both statics known in advance | Two servers with pre-exchanged, pinned identities |

IK and NK require the responder's static public key in advance:

```ts
const alice = new HandshakeState({
  pattern: 'IK',
  initiator: true,
  staticKeyPair: aliceStatic,
  remoteStaticPublicKey: bobStatic.publicKey, // known ahead of time
});
```

Additional patterns (XK, NX, KK, …) are pure data additions in `patterns.ts` and
can be contributed without touching the core state machine.

## Choosing the cipher

```ts
new HandshakeState({ pattern: 'XX', initiator: true, staticKeyPair, cipher: 'AESGCM' });
// cipher?: 'ChaChaPoly' (default) | 'AESGCM'
```

The full protocol name is derived automatically, e.g.
`Noise_XX_25519_ChaChaPoly_SHA256` or `Noise_IK_25519_AESGCM_SHA256`.

> **Note on nonces.** Per the Noise spec, ChaChaPoly encodes the message counter
> **little-endian** and AES-GCM **big-endian**. This package handles that
> internally — a subtle detail the official vectors exist to enforce.

## API

| Export | Description |
|--------|-------------|
| `HandshakeState` | Drives a pattern to completion; `writeMessage` / `readMessage` / `split` |
| `CipherState` | AEAD keyed with a 64-bit nonce counter (transport + handshake) |
| `SymmetricState` | Chaining-key + transcript-hash mixing (HKDF + SHA-256) |
| `getPattern`, `XX`, `IK`, `NK`, `PATTERNS` | Pattern definitions |
| `getAead`, `encodeNonce` | Low-level cipher helpers |
| `NoiseError`, `HandshakeError`, `DecryptError`, `NoiseValidationError` | Errors |

`HandshakeState.split()` returns `{ send, receive, handshakeHash }` — two
independent transport `CipherState`s plus the channel-binding hash.

## Correctness

Cryptographic code demands more than "it round-trips." This package replays the
**canonical Noise test vectors** and asserts every handshake and transport
message matches **byte-for-byte**:

- **32 official vectors** — XX / IK / NK × ChaChaPoly / AESGCM, with and without
  a prologue.
- Plus live randomized handshakes for every pattern/cipher combination, nonce
  encoding checks, and error-path coverage.

If the vectors pass, the protocol is correct by construction — not by assertion.

```bash
npm test            # 65 tests, including the 32 official vectors
npm run test:coverage
```

## Security notes

- **This is a handshake framework, not a full transport.** You are responsible
  for framing (length-prefixing) messages on the wire and for terminating the
  connection if a `DecryptError` occurs — a failed tag means tampering.
- **Nonce exhaustion is fatal by design.** After 2^64 messages a `CipherState`
  throws rather than wrapping the nonce. Re-handshake long-lived connections.
- **`_testEphemeral` is for test vectors only.** Never inject ephemeral keys in
  production — ephemeral randomness is essential to forward secrecy.
- Report vulnerabilities per [SECURITY.md](./SECURITY.md).

## Ecosystem

| Package | Role |
|---------|------|
| [`@brashkie/signalis-core`](https://github.com/Brashkie/signalis-core) | Native Rust cryptographic primitives |
| [`@brashkie/signalis`](https://github.com/Brashkie/signalis) | The Signal Protocol: X3DH, Double Ratchet, sessions |
| [`@brashkie/signalis-storage`](https://github.com/Brashkie/signalis-storage) | Decoupled storage layer |
| **`@brashkie/signalis-noise`** | **This package — the Noise Protocol Framework** |

See [ROADMAP.md](./ROADMAP.md).

## License

Apache-2.0 © Brashkie (Hepein Oficial)
