# Contributing to @brashkie/signalis-noise

Thanks for your interest! This is cryptographic code, so correctness comes first.

## Ground rules

- **The official test vectors are law.** Any change to the handshake, cipher, or
  symmetric state MUST keep all 24 vectors passing byte-for-byte. New patterns
  should add their vectors to `__tests__/noise-vectors.json`.
- **Never reimplement crypto.** All primitives come from
  `@brashkie/signalis-core`. If you need a primitive it doesn't expose, add it
  there, not here.
- **Correctness over cleverness.** Constant-time concerns and nonce handling are
  security-critical; keep them explicit and well-tested.

## Development setup

```bash
git clone https://github.com/Brashkie/signalis-noise.git
cd signalis-noise
npm install
```

## Workflow

```bash
npm run typecheck     # tsc --noEmit, strict
npm run lint          # biome check
npm run lint:fix      # biome check --write
npm test              # vitest run (includes official vectors)
npm run test:coverage
npm run build         # tsup → dist/ (CJS + ESM + d.ts)
```

Before opening a PR, all of the following must pass:

- [ ] `npm run typecheck`
- [ ] `npm run lint`
- [ ] `npm test` (all official vectors green)
- [ ] `npm run build`

## Adding a handshake pattern

1. Add the token sequence to `src/patterns.ts` (pre-messages + messages).
2. Export it from `PATTERNS` and the barrel.
3. Add its official vectors to the fixture and confirm they pass.
4. Document it in the README pattern table.

Patterns are pure data — you should not need to modify `HandshakeState`.

## Commit style

Conventional Commits are appreciated:

```
feat(patterns): add XK handshake pattern
fix(cipher): correct AES-GCM nonce endianness
test(vectors): add psk0 test vectors
```

## Code of Conduct

See [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md).

## License

By contributing, you agree your contributions are licensed under Apache-2.0.
