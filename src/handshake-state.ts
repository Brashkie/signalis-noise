/**
 * HandshakeState (Noise spec §5.3).
 *
 * Drives a handshake pattern to completion, producing two transport
 * `CipherState`s via `split()`. This is the orchestration layer — all crypto is
 * delegated to `@brashkie/signalis-core` through the symmetric/cipher states.
 *
 * @module handshake-state
 */

import { Curve25519 } from '@brashkie/signalis-core';
import { type CipherAlgorithm, getAead } from './cipher';
import type { CipherState } from './cipher-state';
import { HandshakeError, NoiseValidationError } from './errors';
import {
  type HandshakePattern,
  type PatternName,
  type Token,
  getPattern,
} from './patterns';
import { SymmetricState } from './symmetric-state';

const DHLEN = 32;

/** A Curve25519 key pair (matches `@brashkie/signalis-core`'s shape). */
export interface KeyPair {
  privateKey: Buffer;
  publicKey: Buffer;
}

export interface HandshakeConfig {
  /** Handshake pattern: 'XX' | 'IK' | 'NK'. */
  pattern: PatternName;
  /** AEAD cipher: 'ChaChaPoly' (default) | 'AESGCM'. */
  cipher?: CipherAlgorithm;
  /** True for the initiator, false for the responder. */
  initiator: boolean;
  /** Optional prologue mixed into the transcript before the first message. */
  prologue?: Buffer;
  /** This party's static key pair (required by XX and IK; unused by NK init). */
  staticKeyPair?: KeyPair;
  /**
   * The remote party's static public key. Required as a pre-message for the
   * initiator in IK and NK (the responder's key is known in advance).
   */
  remoteStaticPublicKey?: Buffer;
  /**
   * Inject an ephemeral key pair (TESTING ONLY — to reproduce official test
   * vectors deterministically). Never set this in production.
   */
  _testEphemeral?: KeyPair;
}

/** Result of a completed handshake: the two transport cipher states. */
export interface TransportPair {
  /** Cipher state for messages THIS party sends. */
  send: CipherState;
  /** Cipher state for messages THIS party receives. */
  receive: CipherState;
  /** Final handshake hash (unique channel binding). */
  handshakeHash: Buffer;
}

export class HandshakeState {
  private readonly symmetric: SymmetricState;
  private readonly pattern: HandshakePattern;
  private readonly initiator: boolean;

  private s: KeyPair | null; // local static
  private e: KeyPair | null = null; // local ephemeral
  private rs: Buffer | null; // remote static (public)
  private re: Buffer | null = null; // remote ephemeral (public)

  private messageIndex = 0;
  private readonly testEphemeral?: KeyPair;

  constructor(config: HandshakeConfig) {
    this.pattern = getPattern(config.pattern);
    this.initiator = config.initiator;
    this.s = config.staticKeyPair ?? null;
    this.rs = config.remoteStaticPublicKey ?? null;
    this.testEphemeral = config._testEphemeral;

    const cipher = config.cipher ?? 'ChaChaPoly';
    const protocolName = `Noise_${this.pattern.name}_25519_${
      cipher === 'AESGCM' ? 'AESGCM' : 'ChaChaPoly'
    }_SHA256`;

    this.symmetric = new SymmetricState(protocolName, getAead(cipher));
    this.symmetric.mixHash(config.prologue ?? Buffer.alloc(0));

    this.validateRequiredKeys();
    this.absorbPreMessages();
  }

  private validateRequiredKeys(): void {
    // Does this role transmit its static key in a message?
    const sendsStatic = this.pattern.messages.some((msg, i) => {
      const isOurTurn = this.initiator ? i % 2 === 0 : i % 2 === 1;
      return isOurTurn && msg.includes('s');
    });
    // Does this role's own static appear as a pre-message (e.g. K*, *K, KK)?
    const ownStaticPreMessage = this.initiator
      ? this.pattern.initiatorPreMessages.includes('s')
      : this.pattern.responderPreMessages.includes('s');

    if ((sendsStatic || ownStaticPreMessage) && this.s === null) {
      throw new NoiseValidationError(
        `${this.pattern.name}: this role requires a staticKeyPair`,
      );
    }

    // Does this role need the REMOTE static up front (as a pre-message)?
    // For the initiator that's the responder's pre-message 's' (IK, NK, KK);
    // for the responder it's the initiator's pre-message 's' (KK).
    const needsRemoteStatic = this.initiator
      ? this.pattern.responderPreMessages.includes('s')
      : this.pattern.initiatorPreMessages.includes('s');

    if (needsRemoteStatic && this.rs === null) {
      throw new NoiseValidationError(
        `${this.pattern.name}: this role requires remoteStaticPublicKey`,
      );
    }
  }

  /** Mix any pre-message public keys into h, in spec order. */
  private absorbPreMessages(): void {
    // Initiator pre-messages first, then responder's.
    for (const token of this.pattern.initiatorPreMessages) {
      const key = this.initiator ? this.publicOf(token) : this.remotePublicOf(token);
      if (key) this.symmetric.mixHash(key);
    }
    for (const token of this.pattern.responderPreMessages) {
      const key = this.initiator ? this.remotePublicOf(token) : this.publicOf(token);
      if (key) this.symmetric.mixHash(key);
    }
  }

  private publicOf(token: 'e' | 's'): Buffer | null {
    if (token === 's') return this.s?.publicKey ?? null;
    return this.e?.publicKey ?? null;
  }

  private remotePublicOf(token: 'e' | 's'): Buffer | null {
    return token === 's' ? this.rs : this.re;
  }

  /** Whether it is this party's turn to call {@link writeMessage}. */
  public isMyTurn(): boolean {
    const isInitiatorTurn = this.messageIndex % 2 === 0;
    return this.initiator === isInitiatorTurn;
  }

  /** Whether the handshake has consumed all its message patterns. */
  public isComplete(): boolean {
    return this.messageIndex >= this.pattern.messages.length;
  }

  private generateEphemeral(): KeyPair {
    if (this.testEphemeral) return this.testEphemeral;
    return Curve25519.generateKeyPair();
  }

  private dh(local: KeyPair, remotePublic: Buffer): Buffer {
    return Curve25519.diffieHellman(local.privateKey, remotePublic);
  }

  /**
   * Write the next handshake message. `payload` is optional application data to
   * piggyback (encrypted once a key exists). Returns the wire bytes to send.
   */
  public writeMessage(payload: Buffer = Buffer.alloc(0)): Buffer {
    if (this.isComplete()) {
      throw new HandshakeError('writeMessage: handshake already complete');
    }
    if (!this.isMyTurn()) {
      throw new HandshakeError("writeMessage: not this party's turn");
    }

    const tokens = this.pattern.messages[this.messageIndex] as readonly Token[];
    const parts: Buffer[] = [];

    for (const token of tokens) {
      switch (token) {
        case 'e': {
          this.e = this.generateEphemeral();
          this.symmetric.mixHash(this.e.publicKey);
          parts.push(this.e.publicKey);
          break;
        }
        case 's': {
          if (this.s === null) throw new HandshakeError('missing static key for s');
          const ct = this.symmetric.encryptAndHash(this.s.publicKey);
          parts.push(ct);
          break;
        }
        default:
          this.mixDh(token);
      }
    }

    const encryptedPayload = this.symmetric.encryptAndHash(payload);
    parts.push(encryptedPayload);
    this.messageIndex += 1;
    return Buffer.concat(parts);
  }

  /**
   * Read the next handshake message. Returns any decrypted application payload
   * (empty buffer if none).
   */
  public readMessage(message: Buffer): Buffer {
    if (this.isComplete()) {
      throw new HandshakeError('readMessage: handshake already complete');
    }
    if (this.isMyTurn()) {
      throw new HandshakeError("readMessage: it is this party's turn to write");
    }

    const tokens = this.pattern.messages[this.messageIndex] as readonly Token[];
    let offset = 0;

    for (const token of tokens) {
      switch (token) {
        case 'e': {
          if (message.length - offset < DHLEN) {
            throw new HandshakeError('readMessage: truncated ephemeral key');
          }
          this.re = message.subarray(offset, offset + DHLEN);
          offset += DHLEN;
          this.symmetric.mixHash(this.re);
          break;
        }
        case 's': {
          // Static key is encrypted iff a key is already established (+16 tag).
          const len = this.symmetric.cipherState.hasKey() ? DHLEN + 16 : DHLEN;
          if (message.length - offset < len) {
            throw new HandshakeError('readMessage: truncated static key');
          }
          const field = message.subarray(offset, offset + len);
          offset += len;
          this.rs = this.symmetric.decryptAndHash(field);
          break;
        }
        default:
          this.mixDh(token);
      }
    }

    const payloadField = message.subarray(offset);
    const payload = this.symmetric.decryptAndHash(payloadField);
    this.messageIndex += 1;
    return payload;
  }

  /** Perform the DH for a token and mix it into the chaining key. */
  private mixDh(token: Token): void {
    let dh: Buffer;
    switch (token) {
      case 'ee':
        dh = this.dh(this.requireLocalE(), this.requireRemoteE());
        break;
      case 'ss':
        dh = this.dh(this.requireLocalS(), this.requireRemoteS());
        break;
      case 'es':
        // initiator: e(local) · s(remote); responder: s(local) · e(remote)
        dh = this.initiator
          ? this.dh(this.requireLocalE(), this.requireRemoteS())
          : this.dh(this.requireLocalS(), this.requireRemoteE());
        break;
      case 'se':
        // initiator: s(local) · e(remote); responder: e(local) · s(remote)
        dh = this.initiator
          ? this.dh(this.requireLocalS(), this.requireRemoteE())
          : this.dh(this.requireLocalE(), this.requireRemoteS());
        break;
      /* c8 ignore next 2 -- defensive: Token is a closed union; unreachable */
      default:
        throw new HandshakeError(`unknown DH token: ${token}`);
    }
    this.symmetric.mixKey(dh);
  }

  private requireLocalE(): KeyPair {
    if (this.e === null) throw new HandshakeError('DH requires local ephemeral');
    return this.e;
  }
  private requireLocalS(): KeyPair {
    if (this.s === null) throw new HandshakeError('DH requires local static');
    return this.s;
  }
  private requireRemoteE(): Buffer {
    if (this.re === null) throw new HandshakeError('DH requires remote ephemeral');
    return this.re;
  }
  private requireRemoteS(): Buffer {
    if (this.rs === null) throw new HandshakeError('DH requires remote static');
    return this.rs;
  }

  /**
   * Finalize the handshake into transport cipher states. Must be called only
   * after {@link isComplete} returns true.
   */
  public split(): TransportPair {
    if (!this.isComplete()) {
      throw new HandshakeError('split: handshake not complete');
    }
    const { c1, c2 } = this.symmetric.split();
    const handshakeHash = this.symmetric.getHandshakeHash();
    // c1 is the initiator's send / responder's receive, and vice-versa.
    return this.initiator
      ? { send: c1, receive: c2, handshakeHash }
      : { send: c2, receive: c1, handshakeHash };
  }

  /** The remote party's static public key, once learned (XX learns it mid-run). */
  public getRemoteStaticPublicKey(): Buffer | null {
    return this.rs;
  }
}
