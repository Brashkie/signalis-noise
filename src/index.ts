/**
 * `@brashkie/signalis-noise`
 *
 * The Noise Protocol Framework built on `@brashkie/signalis-core`'s primitives.
 * Ships the XX, IK, and NK handshake patterns over Curve25519 + SHA-256, with a
 * selectable AEAD (ChaCha20-Poly1305 or AES-GCM).
 *
 * All cryptography is delegated to `@brashkie/signalis-core`; this package is
 * pure protocol orchestration (CipherState / SymmetricState / HandshakeState).
 *
 * @packageDocumentation
 */

// Errors
export {
  NoiseError,
  HandshakeError,
  DecryptError,
  NoiseValidationError,
} from './errors';

// Cipher abstraction
export type { CipherAlgorithm, Aead } from './cipher';
export { getAead, encodeNonce } from './cipher';

// State machines
export { CipherState } from './cipher-state';
export { SymmetricState } from './symmetric-state';
export {
  HandshakeState,
  type HandshakeConfig,
  type TransportPair,
  type KeyPair,
} from './handshake-state';

// Patterns
export {
  XX,
  IK,
  NK,
  KK,
  PATTERNS,
  getPattern,
  type HandshakePattern,
  type PatternName,
  type Token,
  type PreMessage,
} from './patterns';
