import { cbc } from '@noble/ciphers/aes'
import { argon2d } from '@noble/hashes/argon2'
import { hmac } from '@noble/hashes/hmac'
import { pbkdf2 } from '@noble/hashes/pbkdf2'
import { sha256 } from '@noble/hashes/sha256'
import { sha512 } from '@noble/hashes/sha512'

// A `.dash` secure export is an ASCII envelope with three delimited sections.
// Only the Data section carries the vault; Id identifies the account and Files
// holds attachments, neither of which are needed to import records.
const DATA_BEGIN = 'Data BEGIN'
const DATA_END = 'Data END'

const MAC_LENGTH = 32

// The container declares its own KDF cost, so a hostile file could otherwise ask
// for an unbounded Argon2 allocation. These ceilings are far above Dashlane's
// real parameters (t=3, m=32 MiB, p=2) while keeping a malformed import from
// exhausting memory — the same class of issue the 2025 audit raised against the
// import path.
const MAX_MEMORY_KIB = 1024 * 1024
const MAX_ITERATIONS = 16
const MAX_PARALLELISM = 16
const MAX_PBKDF2_ITERATIONS = 10_000_000

/**
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
const timingSafeEqual = (a, b) => {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

/**
 * @param {string} base64
 * @returns {Uint8Array}
 */
const fromBase64 = (base64) => {
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(base64, 'base64'))
  }
  return Uint8Array.from(atob(base64), (char) => char.charCodeAt(0))
}

/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
const toBase64 = (bytes) => {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64')
  }
  return btoa(String.fromCharCode(...bytes))
}

/**
 * Pulls the base64 payload out of the `Data BEGIN` / `Data END` section.
 * @param {string} text
 * @returns {string}
 * @throws {Error}
 */
export const extractDashDataSection = (text) => {
  const lines = text.split(/\r?\n/)
  const begin = lines.findIndex((line) => line.includes(DATA_BEGIN))
  if (begin === -1) {
    throw new Error('Not a Dashlane secure export: no Data section found')
  }

  const end = lines.findIndex(
    (line, index) => index > begin && line.includes(DATA_END)
  )

  const payload = lines
    .slice(begin + 1, end === -1 ? undefined : end)
    .join('')
    .trim()

  if (!payload) {
    throw new Error('Dashlane export contains an empty Data section')
  }

  return payload
}

/**
 * Reads the `$`-delimited parameter header that prefixes the payload. Dashlane
 * writes its own crypto parameters here, so they are parsed rather than assumed.
 * @param {Uint8Array} raw
 * @returns {{params: Object, headerLength: number}}
 * @throws {Error}
 */
export const parseDashHeader = (raw) => {
  // The field count depends on the KDF — argon2d carries four cost parameters
  // where pbkdf2 carries three — so the header is read one field at a time
  // rather than by scanning for a fixed separator count. Reading incrementally
  // also stops the binary body from being interpreted as ASCII.
  let offset = 0

  const nextField = () => {
    const start = offset
    while (offset < raw.length && raw[offset] !== 0x24) offset++
    if (offset >= raw.length) {
      throw new Error('Malformed Dashlane export: incomplete parameter header')
    }
    const field = String.fromCharCode(...raw.subarray(start, offset))
    offset++
    return field
  }

  const leading = nextField()
  if (leading !== '') {
    throw new Error('Malformed Dashlane export: missing initial marker')
  }

  const version = nextField()
  if (version !== '1') {
    throw new Error(`Unsupported Dashlane export version: ${version}`)
  }

  const kdf = nextField()

  let params
  if (kdf === 'argon2d') {
    params = {
      kdf,
      saltLength: Number(nextField()),
      iterations: Number(nextField()),
      memory: Number(nextField()),
      parallelism: Number(nextField())
    }
  } else if (kdf === 'pbkdf2') {
    params = {
      kdf,
      saltLength: Number(nextField()),
      iterations: Number(nextField()),
      hashMethod: nextField()
    }
  } else {
    throw new Error(`Unsupported Dashlane key derivation: ${kdf}`)
  }

  params.cipher = nextField()
  params.mode = nextField()
  params.ivLength = Number(nextField())

  if (params.cipher !== 'aes256') {
    throw new Error(`Unsupported Dashlane cipher: ${params.cipher}`)
  }

  if (params.mode !== 'cbchmac' && params.mode !== 'cbchmac64') {
    throw new Error(`Unsupported Dashlane cipher mode: ${params.mode}`)
  }

  if (params.kdf === 'argon2d') {
    if (
      !(params.memory > 0 && params.memory <= MAX_MEMORY_KIB) ||
      !(params.iterations > 0 && params.iterations <= MAX_ITERATIONS) ||
      !(params.parallelism > 0 && params.parallelism <= MAX_PARALLELISM)
    ) {
      throw new Error('Dashlane export declares unreasonable Argon2 parameters')
    }
  } else if (
    !(params.iterations > 0 && params.iterations <= MAX_PBKDF2_ITERATIONS)
  ) {
    throw new Error('Dashlane export declares unreasonable PBKDF2 parameters')
  }

  if (!(params.saltLength > 0) || !(params.ivLength > 0)) {
    throw new Error('Dashlane export declares invalid salt or IV lengths')
  }

  return { params, headerLength: offset }
}

/**
 * @param {Uint8Array} raw
 * @param {Object} params
 * @param {number} headerLength
 * @returns {{salt: Uint8Array, iv: Uint8Array, mac: Uint8Array, ciphertext: Uint8Array}}
 * @throws {Error}
 */
const splitBody = (raw, params, headerLength) => {
  const body = raw.subarray(headerLength)
  const ivOffset = params.saltLength
  const macOffset = ivOffset + params.ivLength
  const ctOffset = macOffset + MAC_LENGTH

  if (body.length <= ctOffset) {
    throw new Error('Dashlane export is truncated')
  }

  return {
    salt: body.subarray(0, ivOffset),
    iv: body.subarray(ivOffset, macOffset),
    mac: body.subarray(macOffset, ctOffset),
    ciphertext: body.subarray(ctOffset)
  }
}

/**
 * Derives the 64-byte combined key.
 *
 * Dashlane derives 32 bytes from the master password and inflates them to 64
 * with SHA-512 before splitting into ciphering and MAC keys — the inflation is
 * not optional, and skipping it yields a MAC key that never verifies. The
 * `cbchmac64` mode is the exception: it derives the full 64 bytes directly.
 * @param {string} password
 * @param {Uint8Array} salt
 * @param {Object} params
 * @returns {Uint8Array}
 */
const deriveCombinedKey = async (password, salt, params, argon2ViaWorklet) => {
  const inflated = params.mode === 'cbchmac64'
  const dkLen = inflated ? 64 : 32
  const secret = new TextEncoder().encode(password)

  let derived
  if (params.kdf === 'argon2d') {
    // Dashlane's Argon2d is memory-hard by design (32 MiB, 3 passes). Running
    // it inline would block the UI thread for seconds, so callers can hand it
    // to a worklet — the same offload the KeePass KDBX and Bitwarden encrypted
    // imports use.
    derived = argon2ViaWorklet
      ? await argon2ViaWorklet({
          password: toBase64(secret),
          salt: toBase64(salt),
          type: 'argon2d',
          memory: params.memory,
          iterations: params.iterations,
          parallelism: params.parallelism,
          length: dkLen,
          version: 0x13
        }).then(fromBase64)
      : argon2d(secret, salt, {
          t: params.iterations,
          m: params.memory,
          p: params.parallelism,
          dkLen
        })
  } else {
    // PBKDF2 is comparatively cheap, so it stays inline.
    const hash = params.hashMethod === 'sha512' ? sha512 : sha256
    derived = pbkdf2(hash, secret, salt, { c: params.iterations, dkLen })
  }

  return inflated ? derived : sha512(derived)
}

/**
 * @param {Error|unknown} err
 * @returns {boolean}
 */
const isTrailingDataError = (err) =>
  /junk found/i.test(err instanceof Error ? err.message : String(err))

/**
 * Decompresses exactly `data`, rejecting if it is not precisely one deflate
 * stream.
 * @param {Uint8Array} data
 * @returns {Promise<Uint8Array>}
 */
const inflateExact = async (data) => {
  const stream = new DecompressionStream('deflate-raw')
  const writer = stream.writable.getWriter()
  // Both writer promises reject once the stream errors. That failure is
  // surfaced through the reader below, so they are settled here to avoid an
  // unhandled rejection.
  writer.write(data).catch(() => {})
  writer.close().catch(() => {})

  const chunks = []
  const reader = stream.readable.getReader()
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    chunks.push(value)
  }

  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    out.set(chunk, offset)
    offset += chunk.length
  }
  return out
}

/**
 * Decompresses the deflate stream at the start of `data`, ignoring anything
 * after it.
 *
 * A Dashlane payload carries bytes past the end of its deflate stream. Node's
 * decompressor ignores them, but Chromium's raises "Junk found after end of
 * compressed data" — and because erroring a stream discards whatever is still
 * queued, the output collected up to that point is only the fraction the reader
 * had drained. Keeping it would import a silently truncated vault: measured on
 * a 3.7 MB payload, 2 chunks of 58 survived.
 *
 * So the stream's exact length is located instead. The three outcomes order the
 * search: too short fails as a truncated stream, too long fails as trailing
 * data, and only the exact length succeeds — which a bisection is guaranteed to
 * land on. Roughly log2(payload) probes, once per import, and Node never enters
 * the search because its first attempt already succeeds.
 * @param {Uint8Array} data
 * @returns {Promise<Uint8Array>}
 */
const inflateRaw = async (data) => {
  try {
    return await inflateExact(data)
  } catch (err) {
    if (!isTrailingDataError(err)) throw err
  }

  let low = 0
  let high = data.length

  while (low + 1 < high) {
    const mid = (low + high) >>> 1
    try {
      return await inflateExact(data.subarray(0, mid))
    } catch (err) {
      if (isTrailingDataError(err)) {
        high = mid
      } else {
        low = mid
      }
    }
  }

  throw new Error('Could not locate the end of the compressed vault data')
}

/**
 * Decrypts a Dashlane `.dash` secure export and returns its vault XML.
 *
 * The container is AES-256-CBC with an HMAC-SHA256 signature over `iv ‖
 * ciphertext`; the signature is verified before any decryption is attempted, so
 * a wrong password fails cleanly rather than producing garbage plaintext.
 * @function decryptDashlaneExport
 * @param {string} fileText - Contents of the .dash file
 * @param {string} password - The password set during export
 * @param {Object} [options]
 * @param {Function} [options.argon2ViaWorklet] - Runs the Argon2 KDF off-thread
 * @returns {Promise<string>} The decrypted vault XML
 * @throws {Error}
 */
export const decryptDashlaneExport = async (
  fileText,
  password,
  { argon2ViaWorklet } = {}
) => {
  if (!password) {
    throw new Error('A password is required to open a Dashlane secure export')
  }

  const raw = fromBase64(extractDashDataSection(fileText))
  const { params, headerLength } = parseDashHeader(raw)
  const { salt, iv, mac, ciphertext } = splitBody(raw, params, headerLength)

  if (ciphertext.length % 16 !== 0) {
    throw new Error('Dashlane export ciphertext is not block aligned')
  }

  const combinedKey = await deriveCombinedKey(
    password,
    salt,
    params,
    argon2ViaWorklet
  )
  const cipheringKey = combinedKey.subarray(0, 32)
  const macKey = combinedKey.subarray(32, 64)

  const signed = new Uint8Array(iv.length + ciphertext.length)
  signed.set(iv, 0)
  signed.set(ciphertext, iv.length)

  if (!timingSafeEqual(hmac(sha256, macKey, signed), mac)) {
    throw new Error('Incorrect password for this Dashlane export')
  }

  const plaintext = cbc(cipheringKey, iv).decrypt(ciphertext)

  // Dashlane deflates the XML and prefixes it with six bytes before encrypting.
  // Older exports store the XML uncompressed, so the prefix is only stripped
  // when the payload does not already look like markup.
  if (plaintext[0] === 0x3c) {
    return new TextDecoder().decode(plaintext)
  }

  return new TextDecoder().decode(await inflateRaw(plaintext.subarray(6)))
}
