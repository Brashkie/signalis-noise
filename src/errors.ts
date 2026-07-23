/**
 * Error types for `@brashkie/signalis-noise`.
 *
 * @module errors
 */

/** Base class for all Noise errors. */
export class NoiseError extends Error {
  public readonly context?: Readonly<Record<string, unknown>>;

  constructor(message: string, context?: Record<string, unknown>) {
    super(message);
    this.name = 'NoiseError';
    this.context = context;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when a handshake step is used incorrectly — wrong turn, exhausted
 * pattern, split() before completion, etc.
 */
export class HandshakeError extends NoiseError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, context);
    this.name = 'HandshakeError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when AEAD decryption fails (bad tag) during a handshake or transport
 * message — i.e. tampering, wrong key, or desynchronised nonce.
 */
export class DecryptError extends NoiseError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, context);
    this.name = 'DecryptError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Thrown when an argument fails validation (bad key length, etc.). */
export class NoiseValidationError extends NoiseError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, context);
    this.name = 'NoiseValidationError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
