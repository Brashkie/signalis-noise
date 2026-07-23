# Changelog

All notable changes to `@brashkie/signalis-noise` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_Nothing yet._

## [0.1.0] — 2026-07-23

Initial release. The Noise Protocol Framework built on `@brashkie/signalis-core`.

### Added

- **Handshake patterns**: XX, IK, NK, KK — over Curve25519 + SHA-256.
- **Selectable AEAD**: ChaCha20-Poly1305 (default) or AES-GCM, chosen per
  handshake via `cipher`.
- **State machines**: `HandshakeState`, `SymmetricState`, `CipherState` — pure
  protocol orchestration over the core primitives.
- **Pattern definitions** as data (`XX`, `IK`, `NK`, `PATTERNS`, `getPattern`),
  so new patterns can be added without touching the state machine.
- **Errors**: `NoiseError`, `HandshakeError`, `DecryptError`,
  `NoiseValidationError`.
- Dual **CommonJS + ESM** build with full TypeScript declarations.

### Verified

- **32/32 official Noise test vectors** pass byte-for-byte (XX/IK/NK/KK ×
  ChaChaPoly/AESGCM, with and without prologue).
- 65 tests total; 100% statement / line / function coverage.

### Notes

- Correctly encodes the AEAD nonce per spec — **little-endian for ChaChaPoly,
  big-endian for AES-GCM** — a divergence that only manifests once the message
  counter exceeds zero, caught by the official vectors during development.

[Unreleased]: https://github.com/Brashkie/signalis-noise/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Brashkie/signalis-noise/releases/tag/v0.1.0
