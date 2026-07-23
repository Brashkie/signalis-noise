/**
 * CipherState (Noise spec §5.1).
 *
 * Wraps an AEAD key with a monotonic 64-bit nonce counter. Used both during the
 * handshake (once a key is established) and for transport messages afterwards.
 *
 * @module cipher-state
 */

import type { Aead } from './cipher';
import { encodeNonce } from './cipher';
import { HandshakeError } from './errors';

/**
 * The maximum nonce value. Per the spec, reaching 2^64 - 1 is a hard error:
 * the connection MUST terminate rather than wrap the nonce (which would reuse a
 * key/nonce pair and catastrophically break confidentiality).
 */
const MAX_NONCE = 2n ** 64n - 1n;

export class CipherState {
  private key: Buffer | null = null;
  private nonce = 0n;

  constructor(private readonly aead: Aead) {}

  /** Set (or clear) the key and reset the nonce counter. */
  public initializeKey(key: Buffer | null): void {
    this.key = key;
    this.nonce = 0n;
  }

  /** Whether a key has been set. */
  public hasKey(): boolean {
    return this.key !== null;
  }

  /**
   * Set the nonce explicitly (used by rekey / out-of-band sync). Rarely needed.
   */
  public setNonce(nonce: bigint): void {
    this.nonce = nonce;
  }

  /**
   * Encrypt with the current key and associated data. If no key is set (an
   * un-keyed handshake stage), returns the plaintext unchanged, per spec.
   */
  public encryptWithAd(ad: Buffer, plaintext: Buffer): Buffer {
    if (this.key === null) return plaintext;
    if (this.nonce > MAX_NONCE) {
      throw new HandshakeError('CipherState: nonce exhausted (2^64 messages)');
    }
    const ct = this.aead.encrypt(
      this.key,
      encodeNonce(this.nonce, this.aead.name),
      plaintext,
      ad,
    );
    this.nonce += 1n;
    return ct;
  }

  /**
   * Decrypt with the current key and associated data. If no key is set, returns
   * the ciphertext unchanged, per spec. Throws {@link DecryptError} on tag
   * failure — and does NOT advance the nonce, so the caller can retry/resync.
   */
  public decryptWithAd(ad: Buffer, ciphertext: Buffer): Buffer {
    if (this.key === null) return ciphertext;
    if (this.nonce > MAX_NONCE) {
      throw new HandshakeError('CipherState: nonce exhausted (2^64 messages)');
    }
    const pt = this.aead.decrypt(
      this.key,
      encodeNonce(this.nonce, this.aead.name),
      ciphertext,
      ad,
    );
    this.nonce += 1n;
    return pt;
  }

  /** Current nonce counter (diagnostics / tests). */
  public getNonce(): bigint {
    return this.nonce;
  }
}
