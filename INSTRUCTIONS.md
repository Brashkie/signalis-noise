# 🔊 @brashkie/signalis-noise — Paquete Nuevo (Listo)

## ✅ Estado — Verificado Por Claude

```
✅ 7 archivos TypeScript, compilan con tsconfig strict + noUncheckedIndexedAccess (TS 6.0.3)
✅ 52 tests vitest verdes
✅ 24/24 VECTORES OFICIALES de Noise pasan byte-por-byte
✅ Coverage 97.15% stmts / 100% funcs / 88.54% branches
✅ Build dual CJS + ESM + DTS (tsup)
✅ Biome limpio
✅ peerDependency de @brashkie/signalis-core (una sola copia del core)
```

**Lo más importante:** los 24 vectores oficiales de Noise (XX/IK/NK ×
ChaChaPoly/AESGCM, con y sin prologue) pasan **byte-por-byte**. Eso no es "creo
que está bien" — es corrección demostrable contra el spec.

## 🐛 Un Bug Real Que Los Vectores Cazaron

Durante el desarrollo, mi implementación pasaba los handshakes en vivo (round-trip
OK) pero **fallaba XX AES-GCM en msg_2** contra los vectores. Causa: la spec de
Noise codifica el contador del nonce en **little-endian para ChaChaPoly** pero
**big-endian para AES-GCM**. Yo usaba LE para ambos.

Solo se manifestaba a nonce > 0 (el nonce 0 es idéntico en ambos endianness), por
eso los round-trips en vivo no lo detectaban — pero los vectores sí. **Sin los
vectores oficiales, habría shippeado un AES-GCM roto.**

## 📦 Estructura

```
signalis-noise/
├── .github/ (ci.yml 5 jobs, release.yml 4 jobs, dependabot.yml)
├── src/
│   ├── errors.ts            NoiseError / HandshakeError / DecryptError / NoiseValidationError
│   ├── cipher.ts            AEAD seleccionable (ChaCha/AES) + encodeNonce (endian-aware)
│   ├── cipher-state.ts      CipherState (key + nonce counter)
│   ├── symmetric-state.ts   SymmetricState (HKDF + SHA256 chaining)
│   ├── handshake-state.ts   HandshakeState (el motor del patrón)
│   ├── patterns.ts          XX, IK, NK (definiciones como data)
│   └── index.ts
├── __tests__/
│   ├── noise.test.ts        41 tests (incluye los 24 vectores)
│   ├── coverage.test.ts     11 tests (error paths, PSK primitive)
│   └── noise-vectors.json   los 24 vectores oficiales filtrados
├── package.json (peerDep signalis-core, TS 6.0.3, biome, tsup, vitest)
├── tsconfig.json, tsup.config.ts, biome.json, vitest.config.mts
├── .gitattributes (LF), .gitignore
└── docs: README EN/ES, CHANGELOG, ROADMAP, SECURITY, CONTRIBUTING, CODE_OF_CONDUCT
```

## 🚀 Publicar

```powershell
cd F:\Brashkie\PROYECTOS\NPM
# Extraer signalis-noise.zip → carpeta signalis-noise/

cd signalis-noise
npm install          # instala signalis-core (peer + dev)

npm run typecheck    # → 0 errores
npm run lint         # → biome limpio
npm run test:coverage # → 52 passing, 24 vectores oficiales ✅
npm run build        # → dist/ CJS+ESM+DTS

# Crear repo github.com/Brashkie/signalis-noise (Public)
# Configurar NPM_TOKEN (Automation) en Settings → Secrets

git init && git add . && git commit -m "feat: @brashkie/signalis-noise v0.1.0

Noise Protocol Framework (XX/IK/NK) on signalis-core. Curve25519 + SHA-256,
selectable ChaCha20-Poly1305 / AES-GCM. 24/24 official test vectors pass
byte-for-byte."
git branch -M main
git remote add origin https://github.com/Brashkie/signalis-noise.git
git push -u origin main
# CI verde (5 jobs, 9 combos) →
git tag v0.1.0 && git push origin v0.1.0
# release.yml publica con provenance
```

## ⏭️ Después

Según el roadmap por capas, lo siguiente sería **signalis-wasm** (el jefe final,
rompe el techo Node-only), y después el primer adapter **signalis-storage-sqlite**.

Noise validó el patrón "hoja que hereda de core" — el mismo que usarán wasm y
vault.

---

🔐 + ❤️ Hepein Oficial
