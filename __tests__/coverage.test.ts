/**
 * Coverage closer — exercises diagnostics, error paths, and the PSK primitive
 * (mixKeyAndHash) that XX/IK/NK don't reach.
 */

import { Curve25519 } from '@brashkie/signalis-core';
import { describe, expect, it } from 'vitest';

import {
  CipherState,
  DecryptError,
  HandshakeError,
  HandshakeState,
  SymmetricState,
  encodeNonce,
  getAead,
} from '../src';

describe('CipherState diagnostics & limits', () => {
  it('setNonce / getNonce', () => {
    const cs = new CipherState(getAead('ChaChaPoly'));
    cs.initializeKey(Buffer.alloc(32, 1));
    cs.setNonce(5n);
    expect(cs.getNonce()).toBe(5n);
  });

  it('throws when the nonce is exhausted', () => {
    const cs = new CipherState(getAead('ChaChaPoly'));
    cs.initializeKey(Buffer.alloc(32, 1));
    cs.setNonce(2n ** 64n); // one past max
    expect(() => cs.encryptWithAd(Buffer.alloc(0), Buffer.from('x'))).toThrow(
      HandshakeError,
    );
    cs.setNonce(2n ** 64n);
    expect(() =>
      cs.decryptWithAd(Buffer.alloc(0), Buffer.from('xxxxxxxxxxxxxxxxx')),
    ).toThrow(HandshakeError);
  });

  it('initializeKey(null) clears the key', () => {
    const cs = new CipherState(getAead('AESGCM'));
    cs.initializeKey(Buffer.alloc(32, 1));
    expect(cs.hasKey()).toBe(true);
    cs.initializeKey(null);
    expect(cs.hasKey()).toBe(false);
  });
});

describe('getAead', () => {
  it('resolves both algorithms and reports the name', () => {
    expect(getAead('ChaChaPoly').name).toBe('ChaChaPoly');
    expect(getAead('AESGCM').name).toBe('AESGCM');
  });
});

describe('SymmetricState.mixKeyAndHash (PSK primitive)', () => {
  it('folds ikm into ck and h, keying the cipher state', () => {
    const ss = new SymmetricState(
      'Noise_TEST_25519_ChaChaPoly_SHA256',
      getAead('ChaChaPoly'),
    );
    const before = ss.getHandshakeHash();
    ss.mixKeyAndHash(Buffer.alloc(32, 7));
    const after = ss.getHandshakeHash();
    expect(after.equals(before)).toBe(false); // h changed
    expect(ss.cipherState.hasKey()).toBe(true); // cipher re-keyed
  });

  it('a long protocol name is hashed into h (>32 bytes path)', () => {
    const longName = `Noise_${'X'.repeat(60)}_25519_ChaChaPoly_SHA256`;
    const ss = new SymmetricState(longName, getAead('ChaChaPoly'));
    expect(ss.getHandshakeHash().length).toBe(32);
  });
});

describe('HandshakeState error paths', () => {
  it('readMessage out of turn throws', () => {
    const s = Curve25519.generateKeyPair();
    const alice = new HandshakeState({
      pattern: 'XX',
      initiator: true,
      staticKeyPair: s,
    });
    // It's alice's turn to WRITE, so reading should fail.
    expect(() => alice.readMessage(Buffer.alloc(48))).toThrow(HandshakeError);
  });

  it('writeMessage after completion throws', () => {
    const aliceS = Curve25519.generateKeyPair();
    const bobS = Curve25519.generateKeyPair();
    const alice = new HandshakeState({
      pattern: 'NK',
      initiator: true,
      staticKeyPair: aliceS,
      remoteStaticPublicKey: bobS.publicKey,
    });
    const bob = new HandshakeState({
      pattern: 'NK',
      initiator: false,
      staticKeyPair: bobS,
    });
    bob.readMessage(alice.writeMessage());
    alice.readMessage(bob.writeMessage());
    expect(alice.isComplete()).toBe(true);
    expect(() => alice.writeMessage()).toThrow(HandshakeError);
  });

  it('truncated ephemeral is rejected', () => {
    const aliceS = Curve25519.generateKeyPair();
    const bobS = Curve25519.generateKeyPair();
    const alice = new HandshakeState({
      pattern: 'XX',
      initiator: true,
      staticKeyPair: aliceS,
    });
    const bob = new HandshakeState({
      pattern: 'XX',
      initiator: false,
      staticKeyPair: bobS,
    });
    alice.writeMessage(); // alice writes msg0
    // Feed bob a too-short message (needs 32-byte ephemeral).
    expect(() => bob.readMessage(Buffer.alloc(10))).toThrow(HandshakeError);
  });

  it('readMessage after completion throws', () => {
    const aliceS = Curve25519.generateKeyPair();
    const bobS = Curve25519.generateKeyPair();
    const alice = new HandshakeState({
      pattern: 'NK',
      initiator: true,
      staticKeyPair: aliceS,
      remoteStaticPublicKey: bobS.publicKey,
    });
    const bob = new HandshakeState({
      pattern: 'NK',
      initiator: false,
      staticKeyPair: bobS,
    });
    bob.readMessage(alice.writeMessage());
    alice.readMessage(bob.writeMessage());
    expect(bob.isComplete()).toBe(true);
    // Bob has consumed every message; another read must fail.
    expect(() => bob.readMessage(Buffer.alloc(48))).toThrow(HandshakeError);
  });

  it('a truncated static-key field is rejected', () => {
    const aliceS = Curve25519.generateKeyPair();
    const bobS = Curve25519.generateKeyPair();
    const alice = new HandshakeState({
      pattern: 'XX',
      initiator: true,
      staticKeyPair: aliceS,
    });
    const bob = new HandshakeState({
      pattern: 'XX',
      initiator: false,
      staticKeyPair: bobS,
    });
    bob.readMessage(alice.writeMessage()); // msg0: -> e
    const m1 = bob.writeMessage(); // msg1: <- e, ee, s, es (96 bytes)
    // Keep the 32-byte ephemeral + a few bytes, cutting the encrypted static short.
    const truncated = m1.subarray(0, 40);
    expect(() => alice.readMessage(truncated)).toThrow(HandshakeError);
  });

  it('a ChaChaPoly tag failure throws DecryptError', () => {
    const cs = new CipherState(getAead('ChaChaPoly'));
    cs.initializeKey(Buffer.alloc(32, 3));
    const ct = cs.encryptWithAd(Buffer.alloc(0), Buffer.from('secret'));
    const tampered = Buffer.from(ct);
    tampered[tampered.length - 1]! ^= 0xff; // corrupt the tag
    const cs2 = new CipherState(getAead('ChaChaPoly'));
    cs2.initializeKey(Buffer.alloc(32, 3));
    expect(() => cs2.decryptWithAd(Buffer.alloc(0), tampered)).toThrow(DecryptError);
  });

  it('getRemoteStaticPublicKey is null before it is learned', () => {
    const s = Curve25519.generateKeyPair();
    const alice = new HandshakeState({
      pattern: 'XX',
      initiator: true,
      staticKeyPair: s,
    });
    expect(alice.getRemoteStaticPublicKey()).toBeNull();
  });
});

describe('encodeNonce edge', () => {
  it('encodes large counters correctly per endianness', () => {
    expect(encodeNonce(255n, 'ChaChaPoly').toString('hex')).toBe(
      '00000000ff00000000000000',
    );
    expect(encodeNonce(255n, 'AESGCM').toString('hex')).toBe('0000000000000000000000ff');
  });
});
