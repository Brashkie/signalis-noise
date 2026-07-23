# 🗺️ Roadmap — @brashkie/signalis-noise

Mission: a **correct, verifiable** Noise Protocol implementation for the Signalis
ecosystem — proven against the official vectors, with cryptography delegated to
`@brashkie/signalis-core`, never reimplemented.

**Legend:** ✅ done · 🟡 in progress · 🔴 planned · 💭 under consideration

## ✅ Phase 1 — Foundation (v0.1.0)

- [x] CipherState / SymmetricState / HandshakeState
- [x] Patterns XX, IK, NK, KK
- [x] ChaCha20-Poly1305 + AES-GCM (selectable)
- [x] 32/32 official test vectors, byte-for-byte
- [x] Dual CJS + ESM, TS 6.0, CI across 3 OS × 3 Node

## 🔴 Phase 2 — More patterns (demand-driven)

- [ ] One-way patterns: N, K, X
- [ ] XK, NX, IX, K, N, X (the rest of the fundamental patterns)
- [ ] Deferred patterns (e.g. XX1, IK1)

## 🔴 Phase 3 — PSK & advanced

- [ ] Pre-shared-key modifiers (`psk0`–`psk2`) — `mixKeyAndHash` already exists
- [ ] Rekey support for long-lived sessions
- [ ] Fallback patterns (Noise Pipes: XXfallback)

## 🔴 Phase 4 — Ergonomics

- [ ] `NoiseSocket`-style framing helper (length-prefixed transport)
- [ ] Stream/Duplex adapter for Node
- [ ] Cipher suite: add 448 / BLAKE2 variants if core exposes them

## 💭 Under consideration

- Post-quantum hybrid handshakes (once `signalis-core` ships ML-KEM)
- Formal-model cross-check (e.g. against Noise Explorer output)

## Non-goals

- ❌ Reimplementing crypto primitives — always delegate to `signalis-core`.
- ❌ Wire transport / networking — that belongs in `signalis-net`.

---

🔐 + ❤️ Hepein Oficial
