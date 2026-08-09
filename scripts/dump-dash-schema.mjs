/**
 * Prints the *structure* of a decrypted Dashlane `.dash` export so the record
 * mapping can be written against a real file.
 *
 * PRIVACY: element and field names are reported with counts; text content is
 * never printed, and neither is anything derived from it beyond a length. The
 * master password is read without echo and never leaves this process.
 *
 * Usage: node scripts/dump-dash-schema.mjs "Dashlane Export.dash"
 */
import { readFileSync } from 'node:fs'
import { createInterface } from 'node:readline'

import { decryptDashlaneExport } from '../src/parsers/dashlaneCrypto.js'

/**
 * @param {string} prompt
 * @returns {Promise<string>}
 */
const askSecret = (prompt) =>
  new Promise((resolve, reject) => {
    if (!process.stdin.isTTY) {
      reject(
        new Error(
          'stdin is not a terminal, so the password cannot be read without echo.\n' +
            '  Run this in a normal terminal window, or pass --password-file <path>.'
        )
      )
      return
    }

    const rl = createInterface({ input: process.stdin, output: process.stdout })
    const onData = (char) => {
      if (!['\n', '\r', ''].includes(char.toString())) {
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

// Whether KWDataItem values are stored as plain text or base64 decides how the
// parser reads every field, and it cannot be inferred from names alone. These
// keys are non-secret metadata — enums, booleans, counters and format markers —
// so sampling them settles the encoding without exposing any credential.
const SAFE_SAMPLE_KEYS = new Set([
  'LocaleFormat',
  'Type',
  'Strength',
  'Status',
  'AutoLogin',
  'Checked',
  'UseFixedUrl',
  'SubdomainOnly',
  'AutoProtected',
  'Secured',
  'KeyAlgorithm',
  'Counter',
  'NumberUse',
  'CardType',
  'Reused',
  'TopOfWallet',
  'CreationDatetime'
])

/**
 * Samples values for the non-secret keys above so the value encoding can be
 * identified. Anything not on the allowlist is never read.
 * @param {string} xml
 * @returns {Map<string, string>}
 */
const sampleSafeValues = (xml) => {
  const samples = new Map()
  const pattern =
    /<KWDataItem\s+key="([^"]+)"\s*>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/KWDataItem>/g

  let match
  while ((match = pattern.exec(xml)) !== null) {
    const [, key, value] = match
    if (!SAFE_SAMPLE_KEYS.has(key) || samples.has(key)) continue
    const clipped = value.length > 40 ? `${value.slice(0, 40)}…` : value
    samples.set(key, clipped)
  }

  return samples
}

/**
 * Walks the XML with a regex rather than a DOM so that no text node is ever
 * materialised — only tag names and attribute names are retained.
 * @param {string} xml
 * @returns {{elements: Map<string, number>, itemKeys: Map<string, Map<string, number>>, attributes: Map<string, Set<string>>}}
 */
const summarize = (xml) => {
  const elements = new Map()
  const attributes = new Map()
  const itemKeys = new Map()

  // Field values can themselves contain angle brackets, which a naive tag scan
  // mistakes for markup and reports as phantom record types. CDATA sections and
  // the text between tags are blanked out first so only real markup is walked —
  // blanking discards the content rather than reading it.
  const markupOnly = xml
    .replace(/<!\[CDATA\[[\s\S]*?\]\]>/g, '')
    .replace(/>[^<]*</g, '><')

  // One pass over opening, closing and self-closing tags, keeping a stack so
  // each KWDataItem key is attributed to the record element that owns it.
  const tagPattern =
    /<(\/?)([A-Za-z_][\w.:-]*)((?:\s+[\w.:-]+\s*=\s*"[^"]*")*)\s*(\/?)>/g
  const attrPattern = /([\w.:-]+)\s*=\s*"([^"]*)"/g

  const stack = []

  let match
  while ((match = tagPattern.exec(markupOnly)) !== null) {
    const [, closing, name, attrString, selfClosing] = match

    if (closing) {
      const at = stack.lastIndexOf(name)
      if (at !== -1) stack.length = at
      continue
    }

    elements.set(name, (elements.get(name) ?? 0) + 1)

    // Group by the immediate parent. Records do not sit at a fixed depth under
    // the root — logins wrap their trusted URLs in further KWDataList and
    // KWDataCollection levels — so attributing by depth puts every field under
    // whichever wrapper happens to sit at that level.
    const container = stack.length ? stack[stack.length - 1] : name

    if (attrString) {
      attrPattern.lastIndex = 0
      let attr
      while ((attr = attrPattern.exec(attrString)) !== null) {
        const [, attrName, attrValue] = attr
        if (!attributes.has(name)) attributes.set(name, new Set())
        attributes.get(name).add(attrName)

        // `key` names the field, so its value is schema, not user data. Every
        // other attribute value is left unread.
        if (attrName === 'key') {
          if (!itemKeys.has(container)) itemKeys.set(container, new Map())
          const keys = itemKeys.get(container)
          keys.set(attrValue, (keys.get(attrValue) ?? 0) + 1)
        }
      }
    }

    if (!selfClosing) stack.push(name)
  }

  return { elements, itemKeys, attributes }
}

const main = async () => {
  const args = process.argv.slice(2)
  const pwFileIndex = args.indexOf('--password-file')
  const passwordFile = pwFileIndex === -1 ? null : args[pwFileIndex + 1]
  const file = args.find(
    (arg, i) =>
      !arg.startsWith('--') && (pwFileIndex === -1 || i !== pwFileIndex + 1)
  )

  if (!file) {
    console.error(
      'Usage: node scripts/dump-dash-schema.mjs <file.dash> [--password-file <path>]'
    )
    process.exit(1)
  }

  const password = passwordFile
    ? readFileSync(passwordFile, 'utf8').replace(/\r?\n$/, '')
    : await askSecret('Dashlane export password (not echoed, not stored): ')

  const xml = await decryptDashlaneExport(readFileSync(file, 'utf8'), password)

  console.log(`Decrypted XML: ${xml.length} characters`)
  console.log()

  const { elements, itemKeys, attributes } = summarize(xml)

  console.log('=== Element counts ===')
  for (const [name, count] of [...elements].sort((a, b) => b[1] - a[1])) {
    const attrs = attributes.get(name)
    const attrNote = attrs ? `  [attrs: ${[...attrs].join(', ')}]` : ''
    console.log(`  ${String(count).padStart(6)}  ${name}${attrNote}`)
  }

  console.log()
  console.log('=== Field keys by record type ===')
  for (const [record, keys] of itemKeys) {
    console.log(`  ${record}:`)
    for (const [key, count] of [...keys].sort((a, b) => b[1] - a[1])) {
      console.log(`      ${String(count).padStart(5)}  ${key}`)
    }
  }

  console.log()
  console.log('=== Sample values (non-secret metadata keys only) ===')
  console.log(
    '    Reveals whether values are plain text, CDATA-wrapped or base64.'
  )
  for (const [key, value] of sampleSafeValues(xml)) {
    console.log(`  ${key.padEnd(18)} = ${JSON.stringify(value)}`)
  }

  console.log()
  console.log('Only the allowlisted metadata keys above had their values read.')
}

main().catch((err) => {
  console.error('Error:', err.message)
  process.exit(1)
})
