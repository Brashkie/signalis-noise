/**
 * Handshake pattern definitions (Noise spec §7 & §8).
 *
 * A pattern is a sequence of message patterns, each a list of tokens. Tokens
 * drive the `HandshakeState`:
 *   - `e`  : ephemeral public key
 *   - `s`  : static public key (encrypted once a key is established)
 *   - `ee` `es` `se` `ss` : DH operations mixed into the chaining key
 *
 * Pre-messages (keys known before the handshake starts) are listed separately.
 *
 * v0.1.0 ships XX, IK, and NK — the three that cover the overwhelming majority
 * of real deployments. Others (XK, NX, KK, …) can be added as data with no core
 * changes.
 *
 * @module patterns
 */

export type Token = 'e' | 's' | 'ee' | 'es' | 'se' | 'ss';

/** Which pre-shared static keys a role knows before the handshake. */
export type PreMessage = 'e' | 's';

export interface HandshakePattern {
  readonly name: string;
  /** Initiator's pre-message tokens (keys the responder already knows). */
  readonly initiatorPreMessages: readonly PreMessage[];
  /** Responder's pre-message tokens (keys the initiator already knows). */
  readonly responderPreMessages: readonly PreMessage[];
  /** The message patterns, alternating initiator → responder → … */
  readonly messages: readonly (readonly Token[])[];
}

/**
 * XX — mutual authentication, no prior knowledge. The workhorse pattern
 * (WhatsApp's transport uses XX). Both sides transmit their static key,
 * encrypted, during the handshake.
 *
 * ```
 * XX:
 *   -> e
 *   <- e, ee, s, es
 *   -> s, se
 * ```
 */
export const XX: HandshakePattern = {
  name: 'XX',
  initiatorPreMessages: [],
  responderPreMessages: [],
  messages: [['e'], ['e', 'ee', 's', 'es'], ['s', 'se']],
};

/**
 * IK — the initiator knows the responder's static key ahead of time (e.g. a
 * server whose key is pinned). Enables sending encrypted data in the first
 * message.
 *
 * ```
 * IK:
 *   <- s               (pre-message: initiator already knows responder's s)
 *   ...
 *   -> e, es, s, ss
 *   <- e, ee, se
 * ```
 */
export const IK: HandshakePattern = {
  name: 'IK',
  initiatorPreMessages: [],
  responderPreMessages: ['s'],
  messages: [
    ['e', 'es', 's', 'ss'],
    ['e', 'ee', 'se'],
  ],
};

/**
 * NK — anonymous initiator, known responder (TLS-like: client stays anonymous,
 * server identity is known/pinned).
 *
 * ```
 * NK:
 *   <- s               (pre-message: initiator already knows responder's s)
 *   ...
 *   -> e, es
 *   <- e, ee
 * ```
 */
export const NK: HandshakePattern = {
  name: 'NK',
  initiatorPreMessages: [],
  responderPreMessages: ['s'],
  messages: [
    ['e', 'es'],
    ['e', 'ee'],
  ],
};

/**
 * KK — both parties know each other's static key in advance (mutual pinning,
 * e.g. two servers with pre-exchanged identities). Both statics are
 * pre-messages, so neither is transmitted during the handshake.
 *
 * ```
 * KK:
 *   -> s               (pre-message: responder already knows initiator's s)
 *   <- s               (pre-message: initiator already knows responder's s)
 *   ...
 *   -> e, es, ss
 *   <- e, ee, se
 * ```
 */
export const KK: HandshakePattern = {
  name: 'KK',
  initiatorPreMessages: ['s'],
  responderPreMessages: ['s'],
  messages: [
    ['e', 'es', 'ss'],
    ['e', 'ee', 'se'],
  ],
};

export const PATTERNS = { XX, IK, NK, KK } as const;

export type PatternName = keyof typeof PATTERNS;

/** Resolve a pattern by name. */
export function getPattern(name: PatternName): HandshakePattern {
  return PATTERNS[name];
}
