/**
 * Determines the exact key-derivation and HMAC construction used by a Dashlane
 * `.dash` secure export.
 *
 * The container advertises its own parameters (Argon2d / AES-256-CBC / HMAC),
 * but not how the encryption and MAC keys are split out of the Argon2 output,
 * nor which bytes the HMAC covers. Both are recovered here by trying the
 * plausible constructions and using HMAC verification as the oracle — a match
 * is conclusive, so no decryption is needed to confirm the format.
 *
 * PRIVACY: the master password is read without echo and never leaves this
 * process. Output is limited to the structure of the format; no decrypted
 * secret is ever printed.
 *
 * Usage: node scripts/probe-dash-format.mjs "Dashlane Export.dash"
 */
import { createDecipheriv, createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createInterface } from 'node:readline'
import { inflateRawSync, inflateSync } from 'node:zlib'

import { argon2d } from '@noble/hashes/argon2'
import { hmac } from '@noble/hashes/hmac'
import { sha256 } from '@noble/hashes/sha256'

const DATA_BEGIN = 'Data BEGIN'

/**
 * @param {string} text
 * @returns {{header: string, params: Object, salt: Uint8Array, iv: Uint8Array, mac: Uint8Array, ct: Uint8Array}}
 */
const parseContainer = (text) => {
  const lines = text.split('\n')
  const start = lines.findIndex((l) => l.includes(DATA_BEGIN))
  if (start === -1) throw new Error('No "Data BEGIN" section found')

  const payload = lines[start + 1]
  const raw = Buffer.from(payload, 'base64')

  // Header is ten '$'-delimited ASCII fields at the front of the payload.
  let offset = 0
  let seen = 0
  while (seen < 10 && offset < raw.length) {
    if (raw[offset] === 0x24) seen++
    offset++
  }

  const header = raw.subarray(0, offset).toString('ascii')
  const [
    version,
    kdf,
    saltLen,
    iterations,
    memory,
    parallelism,
    cipher,
    mode,
    ivLen
  ] = header.replace(/^\$|\$$/g, '').split('$')

  const params = {
    version,
    kdf,
    saltLen: Number(saltLen),
    iterations: Number(iterations),
    memory: Number(memory),
    parallelism: Number(parallelism),
    cipher,
    mode,
    ivLen: Number(ivLen)
  }

  const body = raw.subarray(offset)
  const salt = body.subarray(0, params.saltLen)
  const iv = body.subarray(params.saltLen, params.saltLen + params.ivLen)
  const macOffset = params.saltLen + params.ivLen
  const mac = body.subarray(macOffset, macOffset + 32)
  const ct = body.subarray(macOffset + 32)

  return { header, params, salt, iv, mac, ct }
}

/**
 * @param {string} prompt
 * @returns {Promise<string>}
 */
const askSecret = (prompt) =>
  new Promise((resolve, reject) => {
    // Requires a real TTY. Piping the password in — heredoc, argv, env var —
    // risks persisting it to shell history or a tool transcript, so those routes
    // are deliberately not offered; --password-file is the escape hatch.
    if (!process.stdin.isTTY) {
      reject(
        new Error(
          'stdin is not a terminal, so the password cannot be read without echo.\n' +
            '  Run this in a normal terminal window (not via a tool or a pipe), or\n' +
            '  write the password to a file and pass: --password-file <path>'
        )
      )
      return
    }

    const rl = createInterface({ input: process.stdin, output: process.stdout })
    const onData = (char) => {
      // Re-write the prompt without the typed characters so nothing is echoed
      // to the terminal or captured in scrollback.
      if (!['\n', '\r', ''].includes(char.toString())) {
        process.stdout.write(`\r\x1b[2K${prompt}`)
      }
    }
    process.stdin.on('data', onData)
    rl.question(prompt, (answer) => {
      process.stdin.removeListener('data', onData)
      rl.close()
      process.stdout.write('\n')
      resolve(answer)
    })
  })

/**
 * Identifies the plaintext without revealing it — reports only the container
 * type and, for a zip, the member filenames.
 * @param {Buffer} plain
 * @returns {string}
 */
const describePlaintext = (plain) => {
  const magic = plain.subarray(0, 4)
  if (magic[0] === 0x50 && magic[1] === 0x4b) {
    const names = []
    for (let i = 0; i < plain.length - 30; i++) {
      if (plain.readUInt32LE(i) === 0x04034b50) {
        const nameLen = plain.readUInt16LE(i + 26)
        names.push(plain.subarray(i + 30, i + 30 + nameLen).toString('utf8'))
      }
    }
    return `ZIP archive, members: ${names.join(', ') || '(none parsed)'}`
  }
  const head = plain.subarray(0, 1).toString('utf8')
  if (head === '{')
    return 'JSON object (top-level keys withheld until you approve)'
  if (head === '[') return 'JSON array'
  if (head === '<') return 'XML document'

  // Dashlane compresses transaction payloads: a 6-byte prefix followed by a raw
  // deflate stream wrapping XML. The export may use the same wrapper, so both
  // that and a plain zlib stream are probed before giving up.
  const candidates = [
    {
      name: 'raw deflate after a 6-byte prefix',
      fn: () => inflateRawSync(plain.subarray(6))
    },
    { name: 'raw deflate', fn: () => inflateRawSync(plain) },
    { name: 'zlib stream', fn: () => inflateSync(plain) }
  ]
  for (const candidate of candidates) {
    try {
      const out = candidate.fn()
      const first = out.subarray(0, 1).toString('utf8')
      const kind =
        first === '<'
          ? 'XML'
          : first === '{'
            ? 'JSON'
            : `unknown (${out.subarray(0, 4).toString('hex')})`
      return `${candidate.name} -> ${kind}, ${out.length} bytes inflated`
    } catch {
      // Not this wrapper; try the next.
    }
  }

  return `unknown, first bytes: ${magic.toString('hex')}`
}

const main = async () => {
  const args = process.argv.slice(2)
  const pwFileIndex = args.indexOf('--password-file')
  const passwordFile = pwFileIndex === -1 ? null : args[pwFileIndex + 1]
  const file = args.find((arg, i) => {
    if (arg.startsWith('--')) return false
    // Skip the value belonging to --password-file, but only when that flag is
    // actually present — otherwise pwFileIndex + 1 would exclude argument 0.
    return pwFileIndex === -1 || i !== pwFileIndex + 1
  })

  if (!file) {
    console.error(
      'Usage: node scripts/probe-dash-format.mjs <file.dash> [--password-file <path>]'
    )
    process.exit(1)
  }

  const { header, params, salt, iv, mac, ct } = parseContainer(
    readFileSync(file, 'utf8')
  )

  console.log('Container header :', header)
  console.log('Parameters       :', JSON.stringify(params))
  console.log(
    `Lengths          : salt=${salt.length} iv=${iv.length} mac=${mac.length} ct=${ct.length}`
  )
  console.log()

  // A trailing newline from an editor or `echo` would silently break the KDF,
  // so it is stripped rather than being passed through as part of the password.
  const password = passwordFile
    ? readFileSync(passwordFile, 'utf8').replace(/\r?\n$/, '')
    : await askSecret('Dashlane master password (not echoed, not stored): ')

  if (!password) {
    console.error('No password provided — aborting.')
    process.exit(1)
  }

  if (passwordFile) {
    console.log(`Password read from ${passwordFile} — shred it when done:`)
    console.log(`   shred -u ${JSON.stringify(passwordFile)}`)
    console.log()
  }

  const pw = new TextEncoder().encode(password)

  // Derive 64 bytes so both the 32/32 split and the single-key case are covered
  // by one Argon2 run — the KDF is the slow part, so it is done only once.
  console.log(
    'Deriving Argon2d key (t=%d, m=%d KiB, p=%d)...',
    params.iterations,
    params.memory,
    params.parallelism
  )
  // Argon2d emits 32 bytes, which Dashlane then inflates to 64 with SHA-512
  // before splitting into the ciphering key and the MAC key. Skipping that
  // inflation is what made the first pass fail to verify.
  const derived = argon2d(pw, salt, {
    t: params.iterations,
    m: params.memory,
    p: params.parallelism,
    dkLen: 32
  })
  const inflated = createHash('sha512').update(Buffer.from(derived)).digest()

  const keySplits = [
    {
      name: 'argon2d(32) -> sha512 -> enc=[0:32], mac=[32:64]',
      enc: inflated.subarray(0, 32),
      mac: inflated.subarray(32, 64)
    },
    // cbchmac64 skips the inflation because the key is already 64 bytes; kept as
    // a fallback in case an export declares that mode.
    {
      name: 'argon2d(64) direct -> enc=[0:32], mac=[32:64] (cbchmac64)',
      enc: null,
      mac: null,
      lazy: () => {
        const d64 = argon2d(pw, salt, {
          t: params.iterations,
          m: params.memory,
          p: params.parallelism,
          dkLen: 64
        })
        return {
          enc: Buffer.from(d64).subarray(0, 32),
          mac: Buffer.from(d64).subarray(32, 64)
        }
      }
    }
  ]

  const macInputs = [
    { name: 'iv || ciphertext', bytes: Buffer.concat([iv, ct]) },
    { name: 'salt || iv || ciphertext', bytes: Buffer.concat([salt, iv, ct]) },
    { name: 'ciphertext only', bytes: Buffer.from(ct) },
    {
      name: 'header || salt || iv || ciphertext',
      bytes: Buffer.concat([Buffer.from(header, 'ascii'), salt, iv, ct])
    }
  ]

  let found = null
  for (const split of keySplits) {
    const keys = split.lazy ? split.lazy() : split
    for (const input of macInputs) {
      const computed = hmac(sha256, keys.mac, input.bytes)
      if (Buffer.from(computed).equals(Buffer.from(mac))) {
        found = { split: { ...split, ...keys }, input }
        break
      }
    }
    if (found) break
  }

  if (!found) {
    console.log()
    console.log(
      '✗ No HMAC match. Either the password is wrong, or the construction'
    )
    console.log(
      '  is outside the candidate set. Re-run to retry the password first.'
    )
    process.exit(2)
  }

  console.log()
  console.log('✓ HMAC VERIFIED — construction identified')
  console.log('    key split :', found.split.name)
  console.log('    mac covers:', found.input.name)

  // HMAC has already proven the key; decrypt only to identify the payload type.
  try {
    const decipher = createDecipheriv(
      'aes-256-cbc',
      Buffer.from(found.split.enc),
      Buffer.from(iv)
    )
    const plain = Buffer.concat([
      decipher.update(Buffer.from(ct)),
      decipher.final()
    ])
    console.log('    plaintext :', describePlaintext(plain))
    console.log(`    plaintext size: ${plain.length} bytes`)
  } catch (err) {
    console.log('    decryption failed despite HMAC match:', err.message)
    console.log('    (payload may be compressed before encryption)')
  }

  console.log()
  console.log('Report the four lines above — they contain no secret material.')
}

main().catch((err) => {
  console.error('Error:', err.message)
  process.exit(1)
})
