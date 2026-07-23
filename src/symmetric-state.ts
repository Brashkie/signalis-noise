/**
 * SymmetricState (Noise spec §5.2).
 *
 * Tracks the chaining key `ck` and handshake hash `h` as the handshake mixes in
 * DH outputs and transcript bytes. Built on `HKDF` + `SHA256` from
 * `@brashkie/signalis-core`.
 *
 * @module symmetric-state
 */

import { HKDF, SHA256 } from '@brashkie/signalis-core';
import type { Aead } from './cipher';
import { CipherState } from './cipher-state';

const HASHLEN = 32; // SHA-256

/**
 * HKDF as Noise uses it: one PRK from (ck, ikm), then 2 or 3 outputs of
 * HASHLEN bytes via sequential expand. Returns exactly `numOutputs` buffers.
 */
function hkdfN(ck: Buffer, ikm: Buffer, numOutputs: 2 | 3): Buffer[] {
  const prk = HKDF.extract(ck, ikm);
  const full = HKDF.expand(prk, Buffer.alloc(0), HASHLEN * numOutputs);
  const outputs: Buffer[] = [];
  for (let i = 0; i < numOutputs; i++) {
    outputs.push(full.subarray(i * HASHLEN, (i + 1) * HASHLEN));
  }
  return outputs;
}

export class SymmetricState {
  private ck: Buffer;
  private h: Buffer;
  public readonly cipherState: CipherState;

  constructor(
    protocolName: string,
    private readonly aead: Aead,
  ) {
    // h = protocolName if it fits in HASHLEN, else HASH(protocolName)
    const nameBytes = Buffer.from(protocolName, 'utf8');
    if (nameBytes.length <= HASHLEN) {
      this.h = Buffer.alloc(HASHLEN);
      nameBytes.copy(this.h);
    } else {
      this.h = SHA256.hash(nameBytes);
    }
    this.ck = Buffer.from(this.h);
    this.cipherState = new CipherState(aead);
  }

  /** MixKey (spec §5.2): fold `ikm` into ck and re-key the cipher state. */
  public mixKey(ikm: Buffer): void {
    const [newCk, tempK] = hkdfN(this.ck, ikm, 2) as [Buffer, Buffer];
    this.ck = newCk;
    this.cipherState.initializeKey(tempK.subarray(0, 32));
  }

  /** MixHash (spec §5.2): h = HASH(h || data). */
  public mixHash(data: Buffer): void {
    this.h = SHA256.hash(Buffer.concat([this.h, data]));
  }

  /**
   * MixKeyAndHash (spec §5.2): used for pre-shared keys (psk patterns). Folds
   * `ikm` into ck, mixes a temp value into h, and re-keys. Included for
   * completeness / future psk patterns.
   */
  public mixKeyAndHash(ikm: Buffer): void {
    const [newCk, tempH, tempK] = hkdfN(this.ck, ikm, 3) as [Buffer, Buffer, Buffer];
    this.ck = newCk;
    this.mixHash(tempH);
    this.cipherState.initializeKey(tempK.subarray(0, 32));
  }

  /** Current handshake hash (bound as AAD into every encrypted field). */
  public getHandshakeHash(): Buffer {
    return Buffer.from(this.h);
  }

  /** EncryptAndHash (spec §5.2): encrypt with h as AD, then mix ct into h. */
  public encryptAndHash(plaintext: Buffer): Buffer {
    const ct = this.cipherState.encryptWithAd(this.h, plaintext);
    this.mixHash(ct);
    return ct;
  }

  /** DecryptAndHash (spec §5.2): decrypt with h as AD, then mix ct into h. */
  public decryptAndHash(ciphertext: Buffer): Buffer {
    const pt = this.cipherState.decryptWithAd(this.h, ciphertext);
    this.mixHash(ciphertext);
    return pt;
  }

  /**
   * Split (spec §5.2): derive the two transport CipherStates from ck. Returns
   * `{ c1, c2 }` — the initiator uses c1 to send / c2 to receive, and the
   * responder the mirror.
   */
  public split(): { c1: CipherState; c2: CipherState } {
    const [tempK1, tempK2] = hkdfN(this.ck, Buffer.alloc(0), 2) as [Buffer, Buffer];
    const c1 = new CipherState(this.aead);
    const c2 = new CipherState(this.aead);
    c1.initializeKey(tempK1.subarray(0, 32));
    c2.initializeKey(tempK2.subarray(0, 32));
    return { c1, c2 };
  }
}
