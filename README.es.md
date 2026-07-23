<div align="center">

# @brashkie/signalis-noise

**El [Noise Protocol Framework](https://noiseprotocol.org/) construido sobre [`@brashkie/signalis-core`](https://github.com/Brashkie/signalis-core).**

[English](./README.md) · [Español](./README.es.md)

</div>

---

Los patrones de handshake XX, IK y NK sobre **Curve25519 + SHA-256**, con AEAD
seleccionable — **ChaCha20-Poly1305** o **AES-GCM**. Cada handshake está
verificado **byte-por-byte contra los vectores oficiales de Noise**.

Toda la criptografía se delega a `@brashkie/signalis-core`; este paquete es pura
orquestación de protocolo. Noise potencia el transporte de WhatsApp, WireGuard y
Tailscale.

## Instalación

```bash
npm install @brashkie/signalis-noise @brashkie/signalis-core
```

`@brashkie/signalis-core` es **peer dependency** — instalalo al lado para
compartir una sola copia del núcleo cripto en todo el ecosistema.

## Inicio rápido

```ts
import { HandshakeState } from '@brashkie/signalis-noise';
import { Curve25519 } from '@brashkie/signalis-core';

const aliceStatic = Curve25519.generateKeyPair();
const bobStatic = Curve25519.generateKeyPair();

const alice = new HandshakeState({ pattern: 'XX', initiator: true, staticKeyPair: aliceStatic });
const bob = new HandshakeState({ pattern: 'XX', initiator: false, staticKeyPair: bobStatic });

bob.readMessage(alice.writeMessage());   // -> e
alice.readMessage(bob.writeMessage());   // <- e, ee, s, es
bob.readMessage(alice.writeMessage());   // -> s, se

const aliceTx = alice.split();
const bobTx = bob.split();

const ct = aliceTx.send.encryptWithAd(Buffer.alloc(0), Buffer.from('hola bob'));
const pt = bobTx.receive.decryptWithAd(Buffer.alloc(0), ct); // "hola bob"
```

## Patrones

| Patrón | Autenticación | Caso de uso |
|--------|---------------|-------------|
| **XX** | Mutua, identidades intercambiadas en el handshake | El workhorse — WhatsApp usa XX |
| **IK** | Mutua, initiator conoce la static del responder | Server con clave fijada; datos cifrados tempranos |
| **NK** | Solo responder (initiator anónimo) | Tipo TLS: cliente anónimo, server conocido |
| **KK** | Mutua, ambas statics conocidas de antemano | Dos servers con identidades fijadas de antemano |

IK y NK requieren la clave pública static del responder de antemano
(`remoteStaticPublicKey`).

## Elegir el cipher

```ts
new HandshakeState({ pattern: 'XX', initiator: true, staticKeyPair, cipher: 'AESGCM' });
// cipher?: 'ChaChaPoly' (default) | 'AESGCM'
```

> **Nota sobre nonces.** Según la spec de Noise, ChaChaPoly codifica el contador
> en **little-endian** y AES-GCM en **big-endian**. El paquete lo maneja
> internamente — un detalle sutil que los vectores oficiales existen para hacer
> cumplir.

## Corrección

El código criptográfico exige más que "hace round-trip". Este paquete reproduce
los **vectores oficiales de Noise** y verifica cada mensaje **byte-por-byte**:

- **32 vectores oficiales** — XX / IK / NK × ChaChaPoly / AESGCM, con y sin
  prologue.
- Más handshakes aleatorios en vivo, checks de codificación de nonce, y cobertura
  de rutas de error.

```bash
npm test            # 65 tests, incluyendo los 32 vectores oficiales
```

## Licencia

Apache-2.0 © Brashkie (Hepein Oficial)
