/**
 * AEAD cipher abstraction.
 *
 * Noise needs a single AEAD with a 32-byte key, a 12-byte nonce, and a 16-byte
 * tag. Both `ChaCha20Poly1305` and `AES-GCM` from `@brashkie/signalis-core`
 * expose an identical `encryptWithAad` / `decryptWithAad` shape, so we adapt
 * them behind one interface and let the caller pick.
 *
 * @module cipher
 */

import { AES_GCM, ChaCha20Poly1305 } from '@brashkie/signalis-core';
import { DecryptError } from './errors';

/** Supported AEAD ciphers for the Noise `CipherState`. */
export type CipherAlgorithm = 'ChaChaPoly' | 'AESGCM';

/**
 * Minimal AEAD contract used by the Noise cipher state. Both concrete ciphers
 * conform to this shape.
 */
export interface Aead {
  /** Algorithm name as it appears in a Noise protocol name. */
  readonly name: CipherAlgorithm;
  /** Encrypt `plaintext` with 12-byte `nonce` and additional data `ad`. */
  encrypt(key: Buffer, nonce: Buffer, plaintext: Buffer, ad: Buffer): Buffer;
  /** Decrypt `ciphertext`; throws {@link DecryptError} on tag failure. */
  decrypt(key: Buffer, nonce: Buffer, ciphertext: Buffer, ad: Buffer): Buffer;
}

const chacha: Aead = {
  name: 'ChaChaPoly',
  encrypt: (key, nonce, plaintext, ad) =>
    ChaCha20Poly1305.encryptWithAad(key, nonce, plaintext, ad),
  decrypt: (key, nonce, ciphertext, ad) => {
    try {
      return ChaCha20Poly1305.decryptWithAad(key, nonce, ciphertext, ad);
    } catch (err) {
      throw new DecryptError('ChaChaPoly: AEAD decryption failed', {
        cause: (err as Error)?.message,
      });
    }
  },
};

const aesgcm: Aead = {
  name: 'AESGCM',
  encrypt: (key, nonce, plaintext, ad) =>
    AES_GCM.encryptWithAad(key, nonce, plaintext, ad),
  decrypt: (key, nonce, ciphertext, ad) => {
    try {
      return AES_GCM.decryptWithAad(key, nonce, ciphertext, ad);
    } catch (err) {
      throw new DecryptError('AESGCM: AEAD decryption failed', {
        cause: (err as Error)?.message,
      });
    }
  },
};

/** Resolve an {@link Aead} implementation by algorithm name. */
export function getAead(algorithm: CipherAlgorithm): Aead {
  return algorithm === 'AESGCM' ? aesgcm : chacha;
}

/**
 * Build the 12-byte Noise nonce from a 64-bit counter.
 *
 * Per the Noise spec §12, the 96-bit nonce is 4 bytes of zeros followed by the
 * counter as a 64-bit integer — **little-endian for ChaChaPoly, big-endian for
 * AESGCM**. Getting this wrong only shows up once the counter exceeds 0 (nonce
 * 0 is all-zeros in both encodings), which is exactly the kind of bug the
 * official test vectors exist to catch.
 */
export function encodeNonce(counter: bigint, algorithm: CipherAlgorithm): Buffer {
  const nonce = Buffer.alloc(12);
  if (algorithm === 'AESGCM') {
    nonce.writeBigUInt64BE(counter, 4);
  } else {
    nonce.writeBigUInt64LE(counter, 4);
  }
  return nonce;
}
