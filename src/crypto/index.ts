import crypto from 'node:crypto'
import { Uint8ArrayList } from 'uint8arraylist'
import { pureJsCrypto } from './js.js'
import type { ICryptoInterface } from '../crypto.js'
import type { KeyPair } from '../types.js'

const CHACHA_POLY1305 = 'chacha20-poly1305'
const PKCS8_PREFIX = Buffer.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20])
const X25519_PREFIX = Buffer.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00])
const nodeCrypto: Pick<ICryptoInterface, 'hashSHA256' | 'chaCha20Poly1305Encrypt' | 'chaCha20Poly1305Decrypt'> = {
  hashSHA256 (data) {
    const hash = crypto.createHash('sha256')

    if (data instanceof Uint8Array) {
      return hash.update(data).digest()
    }

    for (const buf of data) {
      hash.update(buf)
    }

    return hash.digest()
  },

  chaCha20Poly1305Encrypt (plaintext, nonce, ad, k) {
    const cipher = crypto.createCipheriv(CHACHA_POLY1305, k, nonce, {
      authTagLength: 16
    })
    cipher.setAAD(ad, { plaintextLength: plaintext.byteLength })

    if (plaintext instanceof Uint8Array) {
      const updated = cipher.update(plaintext)
      const final = cipher.final()
      const tag = cipher.getAuthTag()

      return Buffer.concat([updated, final, tag], updated.byteLength + final.byteLength + tag.byteLength)
    }

    const output = new Uint8ArrayList()

    for (const buf of plaintext) {
      output.append(cipher.update(buf))
    }

    const final = cipher.final()

    if (final.byteLength > 0) {
      output.append(final)
    }

    output.append(cipher.getAuthTag())

    return output
  },

  chaCha20Poly1305Decrypt (ciphertext, nonce, ad, k, _dst) {
    const authTag = ciphertext.subarray(ciphertext.length - 16)
    const decipher = crypto.createDecipheriv(CHACHA_POLY1305, k, nonce, {
      authTagLength: 16
    })

    let text: Uint8Array | Uint8ArrayList

    if (ciphertext instanceof Uint8Array) {
      text = ciphertext.subarray(0, ciphertext.length - 16)
    } else {
      text = ciphertext.sublist(0, ciphertext.length - 16)
    }

    decipher.setAAD(ad, {
      plaintextLength: text.byteLength
    })
    decipher.setAuthTag(authTag)

    if (text instanceof Uint8Array) {
      const output = decipher.update(text)
      const final = decipher.final()

      if (final.byteLength > 0) {
        return Buffer.concat([output, final], output.byteLength + final.byteLength)
      }

      return output
    }

    const output = new Uint8ArrayList()

    for (const buf of text) {
      output.append(decipher.update(buf))
    }

    const final = decipher.final()

    if (final.byteLength > 0) {
      output.append(final)
    }

    return output
  }
}

// We don't use the WASM form of chacha20-poly1305 encryption because it breaks mobile
export const defaultCrypto: ICryptoInterface = {
  ...pureJsCrypto,
  hashSHA256 (data) {
    return nodeCrypto.hashSHA256(data)
  },
  chaCha20Poly1305Encrypt (plaintext, nonce, ad, k) {
    return nodeCrypto.chaCha20Poly1305Encrypt(plaintext, nonce, ad, k)
  },
  chaCha20Poly1305Decrypt (ciphertext, nonce, ad, k, dst) {
    return nodeCrypto.chaCha20Poly1305Decrypt(ciphertext, nonce, ad, k, dst)
  },
  generateX25519KeyPair (): KeyPair {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519', {
      publicKeyEncoding: {
        type: 'spki',
        format: 'der'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'der'
      }
    })

    return {
      publicKey: publicKey.subarray(X25519_PREFIX.length),
      privateKey: privateKey.subarray(PKCS8_PREFIX.length)
    }
  },
  generateX25519KeyPairFromSeed (seed: Uint8Array): KeyPair {
    const privateKey = crypto.createPrivateKey({
      key: Buffer.concat([
        PKCS8_PREFIX,
        seed
      ], PKCS8_PREFIX.byteLength + seed.byteLength),
      type: 'pkcs8',
      format: 'der'
    })

    const publicKey = crypto.createPublicKey(privateKey)
      .export({
        type: 'spki',
        format: 'der'
      }).subarray(X25519_PREFIX.length)

    return {
      publicKey,
      privateKey: seed
    }
  },
  generateX25519SharedKey (privateKey: Uint8Array | Uint8ArrayList, publicKey: Uint8Array | Uint8ArrayList): Uint8Array {
    if (publicKey instanceof Uint8Array) {
      publicKey = Buffer.concat([
        X25519_PREFIX,
        publicKey
      ], X25519_PREFIX.byteLength + publicKey.byteLength)
    } else {
      publicKey = new Uint8ArrayList(X25519_PREFIX, publicKey).subarray()
    }

    if (privateKey instanceof Uint8Array) {
      privateKey = Buffer.concat([
        PKCS8_PREFIX,
        privateKey
      ], PKCS8_PREFIX.byteLength + privateKey.byteLength)
    } else {
      privateKey = new Uint8ArrayList(PKCS8_PREFIX, privateKey).subarray()
    }

    return crypto.diffieHellman({
      publicKey: crypto.createPublicKey({
        key: Buffer.from(publicKey, publicKey.byteOffset, publicKey.byteLength),
        type: 'spki',
        format: 'der'
      }),
      privateKey: crypto.createPrivateKey({
        key: Buffer.from(privateKey, privateKey.byteOffset, privateKey.byteLength),
        type: 'pkcs8',
        format: 'der'
      })
    })
  }
}
