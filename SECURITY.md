# Security Policy

## Scope

`@brashkie/signalis-noise` implements cryptographic handshakes. A flaw here can
compromise the confidentiality, integrity, or forward secrecy of every session
built on it. Reports are taken seriously.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ |
| < 0.1   | ❌ |

Pre-1.0, only the latest minor receives security fixes.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately via GitHub Security Advisories on the
[repository](https://github.com/Brashkie/signalis-noise/security/advisories/new),
or contact the maintainer through the GitHub profile
[@Brashkie](https://github.com/Brashkie).

Please include a description, reproduction steps (a PoC is ideal), affected
versions, and any suggested remediation.

## Hardening guidance for integrators

- **Terminate on `DecryptError`.** A failed AEAD tag means tampering or a
  desynchronised nonce — close the connection; do not retry blindly.
- **Never reuse ephemeral keys.** The `_testEphemeral` option exists solely to
  reproduce official test vectors. Injecting ephemerals in production destroys
  forward secrecy.
- **Re-handshake before nonce exhaustion.** A `CipherState` refuses to encrypt
  past 2^64 messages (it throws rather than wrapping the nonce). Long-lived
  connections must re-key.
- **Frame your messages.** Noise operates on discrete messages; you must
  length-prefix them on the wire yourself. Truncation/concatenation attacks are
  the integrator's responsibility.
- **Validate the remote static key.** In XX you learn the peer's static key
  during the handshake (`getRemoteStaticPublicKey()`); authenticate it against
  your trust model before treating the channel as authenticated.

## Cryptographic delegation

This package performs **no primitive cryptography** of its own — all DH, HKDF,
AEAD, and hashing is delegated to
[`@brashkie/signalis-core`](https://github.com/Brashkie/signalis-core). Primitive
vulnerabilities should be reported there.
