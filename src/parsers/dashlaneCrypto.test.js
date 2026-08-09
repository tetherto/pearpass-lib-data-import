import {
  createCipheriv,
  createHash,
  createHmac,
  randomBytes
} from 'node:crypto'
import { deflateRawSync } from 'node:zlib'

import { argon2d } from '@noble/hashes/argon2'

import {
  decryptDashlaneExport,
  extractDashDataSection,
  parseDashHeader
} from './dashlaneCrypto'

const PASSWORD = 'correct horse battery staple'
const XML =
  '<root><KWAuthentifiant><KWDataItem key="Login">alice</KWDataItem></KWAuthentifiant></root>'

// Dashlane's real cost is t=3, m=32 MiB, p=2, which takes seconds per call in
// pure JS — and every test derives twice, once to build and once to decrypt.
// The construction is identical at any cost, so tests use a cheap one; the real
// parameters are covered by the parseDashHeader cases instead.
const TEST_COST = { t: 1, m: 256, p: 1 }

/**
 * Builds a valid .dash container so the decryptor is exercised against the real
 * construction rather than a fixture that could drift from it.
 */
const buildExport = ({
  password = PASSWORD,
  xml = XML,
  mode = 'cbchmac',
  compress = true,
  header = null,
  corruptMac = false,
  cost = TEST_COST
} = {}) => {
  const salt = randomBytes(16)
  const iv = randomBytes(16)

  const inflated = mode === 'cbchmac64'
  const derived = argon2d(new TextEncoder().encode(password), salt, {
    ...cost,
    dkLen: inflated ? 64 : 32
  })
  const combined = inflated
    ? Buffer.from(derived)
    : createHash('sha512').update(Buffer.from(derived)).digest()

  const encKey = combined.subarray(0, 32)
  const macKey = combined.subarray(32, 64)

  const payload = compress
    ? Buffer.concat([Buffer.alloc(6), deflateRawSync(Buffer.from(xml))])
    : Buffer.from(xml)

  const cipher = createCipheriv('aes-256-cbc', encKey, iv)
  const ciphertext = Buffer.concat([cipher.update(payload), cipher.final()])

  const mac = createHmac('sha256', macKey)
    .update(Buffer.concat([iv, ciphertext]))
    .digest()
  if (corruptMac) mac[0] ^= 0xff

  const headerText =
    header ?? `$1$argon2d$16$${cost.t}$${cost.m}$${cost.p}$aes256$${mode}$16$`
  const base64 = Buffer.concat([
    Buffer.from(headerText, 'ascii'),
    salt,
    iv,
    mac,
    ciphertext
  ]).toString('base64')

  return [
    '-------------------- Dashlane Secured Export ----------------------',
    '--------------------        Id BEGIN         ----------------------',
    'aWQ=',
    '--------------------         Id END          ----------------------',
    '--------------------       Data BEGIN        ----------------------',
    base64,
    '--------------------        Data END         ----------------------'
  ].join('\n')
}

describe('extractDashDataSection', () => {
  it('pulls the base64 payload out of the Data section', () => {
    const file = buildExport()
    expect(extractDashDataSection(file)).toMatch(/^JDEkYXJnb24yZCQ/)
  })

  it('throws when there is no Data section', () => {
    expect(() => extractDashDataSection('not a dash file')).toThrow(
      'no Data section found'
    )
  })

  it('throws when the Data section is empty', () => {
    const file = ['-- Data BEGIN --', '-- Data END --'].join('\n')
    expect(() => extractDashDataSection(file)).toThrow('empty Data section')
  })

  it('tolerates CRLF line endings', () => {
    const file = buildExport().replace(/\n/g, '\r\n')
    expect(extractDashDataSection(file)).toMatch(/^JDEkYXJnb24yZCQ/)
  })
})

describe('parseDashHeader', () => {
  const toBytes = (text) => new Uint8Array(Buffer.from(text, 'ascii'))

  it('parses the argon2d parameter header', () => {
    const { params, headerLength } = parseDashHeader(
      toBytes('$1$argon2d$16$3$32768$2$aes256$cbchmac$16$')
    )

    expect(params).toEqual({
      kdf: 'argon2d',
      saltLength: 16,
      iterations: 3,
      memory: 32768,
      parallelism: 2,
      cipher: 'aes256',
      mode: 'cbchmac',
      ivLength: 16
    })
    expect(headerLength).toBe(42)
  })

  it('parses a pbkdf2 parameter header', () => {
    const { params } = parseDashHeader(
      toBytes('$1$pbkdf2$16$200000$sha256$aes256$cbchmac$16$')
    )

    expect(params.kdf).toBe('pbkdf2')
    expect(params.iterations).toBe(200000)
    expect(params.hashMethod).toBe('sha256')
  })

  it('rejects an unsupported version', () => {
    expect(() =>
      parseDashHeader(toBytes('$2$argon2d$16$3$32768$2$aes256$cbchmac$16$'))
    ).toThrow('Unsupported Dashlane export version: 2')
  })

  it('rejects an unknown derivation algorithm', () => {
    expect(() =>
      parseDashHeader(toBytes('$1$scrypt$16$3$32768$2$aes256$cbchmac$16$'))
    ).toThrow('Unsupported Dashlane key derivation: scrypt')
  })

  it('rejects an unknown cipher mode', () => {
    expect(() =>
      parseDashHeader(toBytes('$1$argon2d$16$3$32768$2$aes256$gcm$16$'))
    ).toThrow('Unsupported Dashlane cipher mode: gcm')
  })

  it('rejects an incomplete header', () => {
    expect(() => parseDashHeader(toBytes('$1$argon2d$16$'))).toThrow(
      'incomplete parameter header'
    )
  })

  // A hostile file could otherwise request an unbounded Argon2 allocation.
  it('rejects an absurd memory cost', () => {
    expect(() =>
      parseDashHeader(toBytes('$1$argon2d$16$3$99999999$2$aes256$cbchmac$16$'))
    ).toThrow('unreasonable Argon2 parameters')
  })

  it('rejects an absurd iteration count', () => {
    expect(() =>
      parseDashHeader(toBytes('$1$argon2d$16$9999$32768$2$aes256$cbchmac$16$'))
    ).toThrow('unreasonable Argon2 parameters')
  })

  it('rejects a zero salt length', () => {
    expect(() =>
      parseDashHeader(toBytes('$1$argon2d$0$3$32768$2$aes256$cbchmac$16$'))
    ).toThrow('invalid salt or IV lengths')
  })
})

describe('decryptDashlaneExport', () => {
  it('round-trips a compressed export', async () => {
    await expect(decryptDashlaneExport(buildExport(), PASSWORD)).resolves.toBe(
      XML
    )
  })

  it('round-trips an uncompressed export', async () => {
    const file = buildExport({ compress: false })
    await expect(decryptDashlaneExport(file, PASSWORD)).resolves.toBe(XML)
  })

  it('round-trips a cbchmac64 export, which skips the sha512 inflation', async () => {
    const file = buildExport({ mode: 'cbchmac64' })
    await expect(decryptDashlaneExport(file, PASSWORD)).resolves.toBe(XML)
  })

  // The signature is checked before decryption, so a wrong password reports
  // itself rather than yielding garbage plaintext.
  // Mirrors how the desktop app hands the memory-hard KDF to the vault worklet
  // so a 32 MiB Argon2 does not block the UI thread.
  it('derives via a worklet when one is supplied', async () => {
    const { argon2d } = await import('@noble/hashes/argon2')
    const file = buildExport()

    const argon2ViaWorklet = jest.fn(async (params) => {
      const derived = argon2d(
        Buffer.from(params.password, 'base64'),
        Buffer.from(params.salt, 'base64'),
        {
          t: params.iterations,
          m: params.memory,
          p: params.parallelism,
          dkLen: params.length,
          version: params.version
        }
      )
      return Buffer.from(derived).toString('base64')
    })

    await expect(
      decryptDashlaneExport(file, PASSWORD, { argon2ViaWorklet })
    ).resolves.toBe(XML)

    expect(argon2ViaWorklet).toHaveBeenCalledTimes(1)
    expect(argon2ViaWorklet.mock.calls[0][0]).toMatchObject({
      type: 'argon2d',
      length: 32,
      version: 0x13,
      iterations: TEST_COST.t,
      memory: TEST_COST.m,
      parallelism: TEST_COST.p
    })
  })

  // Chromium's DecompressionStream rejects bytes after the end of a deflate
  // stream, which a real Dashlane payload carries; Node's ignores them. This
  // stubs the strict behaviour, including the part that makes it dangerous:
  // erroring a stream discards whatever output is still queued, so a naive
  // reader keeps only the fraction it had already drained.
  describe('trailing bytes after the deflate stream', () => {
    const RealDecompressionStream = globalThis.DecompressionStream

    /**
     * @param {Object} options
     * @param {number} options.trailing - junk bytes sitting after the stream
     * @param {Uint8Array} options.output - what a correct decompression yields
     * @param {number} [options.drainedChunks] - chunks read before the error
     */
    const stubChromium = ({ trailing, output, drainedChunks = 1 }) => {
      // The genuine stream length is derived from the first (full) attempt, so
      // the stub does not need to know the compressed size up front.
      let streamLength = null

      globalThis.DecompressionStream = class {
        constructor() {
          const written = []
          // A transform stream only produces output once it has input, so the
          // readable side waits for the writable to close before deciding.
          let markClosed
          const closed = new Promise((resolve) => {
            markClosed = resolve
          })

          this.writable = new WritableStream({
            write(chunk) {
              written.push(chunk)
            },
            close: () => markClosed(),
            abort: () => markClosed()
          })

          let emitted = 0
          this.readable = new ReadableStream({
            async pull(controller) {
              await closed
              const length = written.reduce((n, c) => n + c.length, 0)
              if (streamLength === null) streamLength = length - trailing

              if (length < streamLength) {
                controller.error(new Error('Unexpected end of file'))
                return
              }

              if (length > streamLength) {
                // Deliver only what a reader could drain, then discard the rest
                // exactly as erroring a stream does.
                if (emitted < drainedChunks) {
                  emitted++
                  controller.enqueue(output.slice(0, 8))
                  return
                }
                controller.error(
                  new Error('Junk found after end of compressed data.')
                )
                return
              }

              if (emitted === 0) {
                emitted++
                controller.enqueue(output)
                return
              }
              controller.close()
            }
          })
        }
      }
    }

    afterEach(() => {
      globalThis.DecompressionStream = RealDecompressionStream
    })

    it('recovers the whole payload by locating the stream end', async () => {
      const payload = new TextEncoder().encode(XML)
      // The compressed body sits at a known offset; the search must find it
      // rather than keep the partial output handed over before the error.
      stubChromium({ trailing: 5, output: payload })

      await expect(
        decryptDashlaneExport(buildExport(), PASSWORD)
      ).resolves.toBe(XML)
    })

    // The regression that shipped a 55-record vault out of 1453.
    it('never returns the partial output delivered before the error', async () => {
      const payload = new TextEncoder().encode(XML)
      stubChromium({ trailing: 5, output: payload, drainedChunks: 3 })

      const result = await decryptDashlaneExport(buildExport(), PASSWORD)
      expect(result).toBe(XML)
      expect(result.length).toBeGreaterThan(8)
    })

    it('rethrows a genuine decompression failure', async () => {
      globalThis.DecompressionStream = class {
        constructor() {
          this.writable = new WritableStream()
          this.readable = new ReadableStream({
            pull(controller) {
              controller.error(new Error('invalid distance too far back'))
            }
          })
        }
      }

      await expect(
        decryptDashlaneExport(buildExport(), PASSWORD)
      ).rejects.toThrow('invalid distance too far back')
    })
  })

  it('rejects a wrong password without attempting decryption', async () => {
    await expect(
      decryptDashlaneExport(buildExport(), 'wrong password')
    ).rejects.toThrow('Incorrect password for this Dashlane export')
  })

  it('rejects a tampered signature', async () => {
    await expect(
      decryptDashlaneExport(buildExport({ corruptMac: true }), PASSWORD)
    ).rejects.toThrow('Incorrect password for this Dashlane export')
  })

  it('requires a password', async () => {
    await expect(decryptDashlaneExport(buildExport(), '')).rejects.toThrow(
      'A password is required'
    )
  })

  it('rejects a truncated container', async () => {
    const header = Buffer.from(
      '$1$argon2d$16$3$32768$2$aes256$cbchmac$16$',
      'ascii'
    )
    const short = Buffer.concat([header, randomBytes(20)]).toString('base64')
    const file = ['-- Data BEGIN --', short, '-- Data END --'].join('\n')

    await expect(decryptDashlaneExport(file, PASSWORD)).rejects.toThrow(
      'truncated'
    )
  })

  it('preserves unicode in the decrypted xml', async () => {
    const xml =
      '<root><KWDataItem key="Title">Café — 日本語</KWDataItem></root>'
    const file = buildExport({ xml })
    await expect(decryptDashlaneExport(file, PASSWORD)).resolves.toBe(xml)
  })
})
