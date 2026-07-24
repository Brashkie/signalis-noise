/**
 * Tests for @brashkie/signalis-noise.
 *
 * The centrepiece is `official vectors` — every XX/IK/NK × ChaChaPoly/AESGCM
 * handshake is replayed against the canonical Noise test vectors and checked
 * byte-for-byte. If those pass, the protocol implementation is correct by
 * construction. The rest cover ergonomics and error paths.
 */

import { readFileSync } from 'node:fs';
import * as path from 'node:path';
import { Curve25519 } from '@brashkie/signalis-core';
import { describe, expect, it } from 'vitest';

import {
  type CipherAlgorithm,
  CipherState,
  DecryptError,
  HandshakeError,
  HandshakeState,
  NoiseValidationError,
  type PatternName,
  encodeNonce,
  getAead,
  getPattern,
} from '../src';

// ─── Official Noise test vectors ───────────────────────────────────────────

interface Vector {
  handshake: string;
  init_static?: string;
  resp_static?: string;
  gen_init_ephemeral: string;
  gen_resp_ephemeral: string;
  prologue?: string;
  [key: string]: string | undefined;
}

const vectors: Vector[] = JSON.parse(
  readFileSync(path.join(__dirname, 'noise-vectors.json'), 'utf8'),
);

const HANDSHAKE_MSGS: Record<string, number> = { XX: 3, IK: 2, NK: 2, KK: 2 };

function kpFromPriv(hex: string) {
  const privateKey = Buffer.from(hex, 'hex');
  return { privateKey, publicKey: Curve25519.publicFromPrivate(privateKey) };
}

describe('official Noise test vectors (byte-for-byte)', () => {
  for (const v of vectors) {
    it(v.handshake + (v.prologue ? ' [prologue]' : ''), () => {
      const m = v.handshake.match(
        /^Noise_(XX|IK|NK|KK)_25519_(ChaChaPoly|AESGCM)_SHA256$/,
      )!;
      const pattern = m[1] as PatternName;
      const cipher = m[2] as CipherAlgorithm;

      const initStatic = v.init_static ? kpFromPriv(v.init_static) : undefined;
      const respStatic = v.resp_static ? kpFromPriv(v.resp_static) : undefined;
      const prologue = v.prologue ? Buffer.from(v.prologue, 'hex') : Buffer.alloc(0);

      // Which role knows the other's static up front:
      //   IK / NK  → only the initiator knows the responder's static
      //   KK       → both parties know each other's static
      const initiatorKnowsRemote =
        pattern === 'IK' || pattern === 'NK' || pattern === 'KK';
      const responderKnowsRemote = pattern === 'KK';

      const initiator = new HandshakeState({
        pattern,
        initiator: true,
        cipher,
        prologue,
        staticKeyPair: initStatic,
        remoteStaticPublicKey: initiatorKnowsRemote ? respStatic!.publicKey : undefined,
        _testEphemeral: kpFromPriv(v.gen_init_ephemeral),
      });
      const responder = new HandshakeState({
        pattern,
        initiator: false,
        cipher,
        prologue,
        staticKeyPair: respStatic,
        remoteStaticPublicKey: responderKnowsRemote ? initStatic!.publicKey : undefined,
        _testEphemeral: kpFromPriv(v.gen_resp_ephemeral),
      });

      const nHs = HANDSHAKE_MSGS[pattern]!;
      let writer = initiator;
      let reader = responder;
      let i = 0;

      for (; i < nHs; i++) {
        const payload = Buffer.from(v[`msg_${i}_payload`] || '', 'hex');
        const msg = writer.writeMessage(payload);
        expect(msg.toString('hex')).toBe(v[`msg_${i}_ciphertext`]);
        const got = reader.readMessage(msg);
        expect(got.toString('hex')).toBe(v[`msg_${i}_payload`] || '');
        [writer, reader] = [reader, writer];
      }

      const initT = initiator.split();
      const respT = responder.split();
      expect(initT.handshakeHash.equals(respT.handshakeHash)).toBe(true);

      // Transport phase: alternates starting with the initiator.
      while (v[`msg_${i}_ciphertext`] !== undefined) {
        const j = i - nHs;
        const senderIsInit = j % 2 === 0;
        const sender = senderIsInit ? initT : respT;
        const recv = senderIsInit ? respT : initT;
        const payload = Buffer.from(v[`msg_${i}_payload`] || '', 'hex');
        const ct = sender.send.encryptWithAd(Buffer.alloc(0), payload);
        expect(ct.toString('hex')).toBe(v[`msg_${i}_ciphertext`]);
        const pt = recv.receive.decryptWithAd(Buffer.alloc(0), ct);
        expect(pt.equals(payload)).toBe(true);
        i++;
      }
    });
  }
});

// ─── Live handshakes (random keys, both ciphers) ────────────────────────────

describe('live handshakes', () => {
  const ciphers: CipherAlgorithm[] = ['ChaChaPoly', 'AESGCM'];
  const patterns: PatternName[] = ['XX', 'IK', 'NK', 'KK'];

  for (const cipher of ciphers) {
    for (const pattern of patterns) {
      it(`${pattern} / ${cipher}: full handshake + bidirectional transport`, () => {
        const aliceS = Curve25519.generateKeyPair();
        const bobS = Curve25519.generateKeyPair();

        const initiatorKnowsRemote =
          pattern === 'IK' || pattern === 'NK' || pattern === 'KK';
        const responderKnowsRemote = pattern === 'KK';

        const alice = new HandshakeState({
          pattern,
          initiator: true,
          cipher,
          staticKeyPair: aliceS,
          remoteStaticPublicKey: initiatorKnowsRemote ? bobS.publicKey : undefined,
        });
        const bob = new HandshakeState({
          pattern,
          initiator: false,
          cipher,
          staticKeyPair: bobS,
          remoteStaticPublicKey: responderKnowsRemote ? aliceS.publicKey : undefined,
        });

        let turn = 0;
        while (!alice.isComplete() || !bob.isComplete()) {
          if (alice.isMyTurn()) {
            const msg = alice.writeMessage(Buffer.from(`a${turn}`));
            expect(bob.readMessage(msg).toString()).toBe(`a${turn}`);
          } else {
            const msg = bob.writeMessage(Buffer.from(`b${turn}`));
            expect(alice.readMessage(msg).toString()).toBe(`b${turn}`);
          }
          turn++;
          expect(turn).toBeLessThan(10);
        }

        const at = alice.split();
        const bt = bob.split();
        expect(at.handshakeHash.equals(bt.handshakeHash)).toBe(true);

        // Round-trip both directions.
        const c1 = at.send.encryptWithAd(Buffer.alloc(0), Buffer.from('hello'));
        expect(bt.receive.decryptWithAd(Buffer.alloc(0), c1).toString()).toBe('hello');
        const c2 = bt.send.encryptWithAd(Buffer.alloc(0), Buffer.from('world'));
        expect(at.receive.decryptWithAd(Buffer.alloc(0), c2).toString()).toBe('world');
      });
    }
  }

  it('XX: both parties learn each other static keys', () => {
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

    while (!alice.isComplete() || !bob.isComplete()) {
      if (alice.isMyTurn()) bob.readMessage(alice.writeMessage());
      else alice.readMessage(bob.writeMessage());
    }
    expect(alice.getRemoteStaticPublicKey()!.equals(bobS.publicKey)).toBe(true);
    expect(bob.getRemoteStaticPublicKey()!.equals(aliceS.publicKey)).toBe(true);
  });
});

// ─── CipherState ────────────────────────────────────────────────────────────

describe('CipherState', () => {
  it('encrypt/decrypt round-trips and advances the nonce', () => {
    const cs = new CipherState(getAead('ChaChaPoly'));
    cs.initializeKey(Buffer.alloc(32, 9));
    expect(cs.hasKey()).toBe(true);
    expect(cs.getNonce()).toBe(0n);
    const ct = cs.encryptWithAd(Buffer.alloc(0), Buffer.from('hi'));
    expect(cs.getNonce()).toBe(1n);

    const cs2 = new CipherState(getAead('ChaChaPoly'));
    cs2.initializeKey(Buffer.alloc(32, 9));
    expect(cs2.decryptWithAd(Buffer.alloc(0), ct).toString()).toBe('hi');
  });

  it('passes through plaintext when no key is set', () => {
    const cs = new CipherState(getAead('ChaChaPoly'));
    expect(cs.hasKey()).toBe(false);
    const pt = Buffer.from('plain');
    expect(cs.encryptWithAd(Buffer.alloc(0), pt).equals(pt)).toBe(true);
    expect(cs.decryptWithAd(Buffer.alloc(0), pt).equals(pt)).toBe(true);
  });

  it('bad ciphertext throws DecryptError', () => {
    const cs = new CipherState(getAead('AESGCM'));
    cs.initializeKey(Buffer.alloc(32, 1));
    const ct = cs.encryptWithAd(Buffer.alloc(0), Buffer.from('secret'));
    const tampered = Buffer.from(ct);
    tampered[0]! ^= 0xff;
    const cs2 = new CipherState(getAead('AESGCM'));
    cs2.initializeKey(Buffer.alloc(32, 1));
    expect(() => cs2.decryptWithAd(Buffer.alloc(0), tampered)).toThrow(DecryptError);
  });
});

// ─── Nonce encoding (the endianness that the vectors caught) ────────────────

describe('encodeNonce', () => {
  it('nonce 0 is all zeros for both ciphers', () => {
    expect(encodeNonce(0n, 'ChaChaPoly').toString('hex')).toBe(
      '000000000000000000000000',
    );
    expect(encodeNonce(0n, 'AESGCM').toString('hex')).toBe('000000000000000000000000');
  });

  it('ChaChaPoly is little-endian, AESGCM is big-endian', () => {
    expect(encodeNonce(1n, 'ChaChaPoly').toString('hex')).toBe(
      '000000000100000000000000',
    );
    expect(encodeNonce(1n, 'AESGCM').toString('hex')).toBe('000000000000000000000001');
  });
});

// ─── Errors / validation ────────────────────────────────────────────────────

describe('validation & errors', () => {
  it('XX requires a static key pair', () => {
    expect(() => new HandshakeState({ pattern: 'XX', initiator: true })).toThrow(
      NoiseValidationError,
    );
  });

  it('IK initiator requires the remote static key', () => {
    const s = Curve25519.generateKeyPair();
    expect(
      () => new HandshakeState({ pattern: 'IK', initiator: true, staticKeyPair: s }),
    ).toThrow(NoiseValidationError);
  });

  it('writeMessage out of turn throws', () => {
    const s = Curve25519.generateKeyPair();
    const responder = new HandshakeState({
      pattern: 'XX',
      initiator: false,
      staticKeyPair: s,
    });
    expect(() => responder.writeMessage()).toThrow(HandshakeError);
  });

  it('split before completion throws', () => {
    const s = Curve25519.generateKeyPair();
    const alice = new HandshakeState({
      pattern: 'XX',
      initiator: true,
      staticKeyPair: s,
    });
    expect(() => alice.split()).toThrow(HandshakeError);
  });

  it('getPattern returns the right token sequences', () => {
    expect(getPattern('XX').messages.length).toBe(3);
    expect(getPattern('IK').messages.length).toBe(2);
    expect(getPattern('NK').messages.length).toBe(2);
  });
});
