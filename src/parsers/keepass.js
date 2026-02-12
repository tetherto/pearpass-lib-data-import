import { argon2id, argon2d } from 'hash-wasm'
import * as kdbxweb from 'kdbxweb'

import { addHttps } from '../utils/addHttps'
import { getRowsFromCsv } from '../utils/getRowsFromCsv'

// Wire Argon2 into kdbxweb for KDBX4 support
kdbxweb.CryptoEngine.setArgon2Impl(
  (password, salt, memory, iterations, length, parallelism, type) => {
    const hashFn = type === kdbxweb.Consts.KdfId.Argon2id ? argon2id : argon2d
    return hashFn({
      password,
      salt,
      memorySize: memory,
      iterations,
      hashLength: length,
      parallelism,
      outputType: 'binary'
    })
  }
)

const STANDARD_FIELDS = new Set([
  'Title',
  'UserName',
  'Password',
  'URL',
  'Notes'
])

const TOTP_FIELDS = new Set([
  'otp',
  'TOTP Settings',
  'TOTP Seed',
  'TimeOtp-Secret-Base32'
])

/**
 * @param {string} value
 * @returns {string}
 */
const getFieldText = (value) => {
  if (!value) return ''
  if (value instanceof kdbxweb.ProtectedValue) return value.getText()
  return String(value)
}

/**
 * Recursively walks KDBX groups and extracts entries
 * @param {object} group
 * @param {string} parentPath
 * @returns {Array<object>}
 */
const walkGroup = (group, parentPath = '') => {
  const results = []
  const groupName = group.name || ''
  const currentPath = parentPath ? `${parentPath}/${groupName}` : groupName

  for (const entry of group.entries || []) {
    const fields = entry.fields || new Map()

    const title = getFieldText(fields.get('Title'))
    const username = getFieldText(fields.get('UserName'))
    const password = getFieldText(fields.get('Password'))
    const url = getFieldText(fields.get('URL'))
    const notes = getFieldText(fields.get('Notes'))

    const customFields = []

    for (const [key, value] of fields) {
      if (STANDARD_FIELDS.has(key)) continue

      const text = getFieldText(value)
      if (!text) continue

      if (TOTP_FIELDS.has(key)) {
        customFields.push({ type: 'note', note: `TOTP: ${text}` })
      } else {
        customFields.push({ type: 'note', note: `${key}: ${text}` })
      }
    }

    results.push({
      type: 'login',
      folder: currentPath || null,
      isFavorite: false,
      data: {
        title,
        username,
        password,
        note: notes,
        websites: url ? [addHttps(url)] : [],
        customFields
      }
    })
  }

  for (const subGroup of group.groups || []) {
    results.push(...walkGroup(subGroup, currentPath))
  }

  return results
}

/**
 * @param {ArrayBuffer} arrayBuffer
 * @param {string} password
 * @returns {Promise<Array<object>>}
 */
export const parseKeePassKdbx = async (arrayBuffer, password) => {
  try {
    const credentials = new kdbxweb.Credentials(
      kdbxweb.ProtectedValue.fromString(password)
    )
    const db = await kdbxweb.Kdbx.load(
      new Uint8Array(arrayBuffer).buffer,
      credentials
    )

    const results = []
    const rootGroup = db.groups[0]
    if (!rootGroup) return results

    // Walk from root, but don't use root group name as folder prefix
    for (const entry of rootGroup.entries || []) {
      const fields = entry.fields || new Map()

      const title = getFieldText(fields.get('Title'))
      const username = getFieldText(fields.get('UserName'))
      const password = getFieldText(fields.get('Password'))
      const url = getFieldText(fields.get('URL'))
      const notes = getFieldText(fields.get('Notes'))

      const customFields = []
      for (const [key, value] of fields) {
        if (STANDARD_FIELDS.has(key)) continue
        const text = getFieldText(value)
        if (!text) continue
        if (TOTP_FIELDS.has(key)) {
          customFields.push({ type: 'note', note: `TOTP: ${text}` })
        } else {
          customFields.push({ type: 'note', note: `${key}: ${text}` })
        }
      }

      results.push({
        type: 'login',
        folder: null,
        isFavorite: false,
        data: {
          title,
          username,
          password,
          note: notes,
          websites: url ? [addHttps(url)] : [],
          customFields
        }
      })
    }

    for (const subGroup of rootGroup.groups || []) {
      results.push(...walkGroup(subGroup, ''))
    }

    return results
  } catch (error) {
    if (
      error?.code === kdbxweb.Consts.ErrorCodes.InvalidKey ||
      error?.message?.includes('Invalid key') ||
      error?.message?.includes('invalid key') ||
      error?.code === 'InvalidKey'
    ) {
      throw new Error('Incorrect password')
    }
    throw new Error('Unsupported or corrupted file')
  }
}

/**
 * Parses KeePass 1.x CSV format
 * Columns: "Account","Login Name","Password","Web Site","Comments"
 * @param {string[][]} headerRow
 * @param {string[][]} dataRows
 * @returns {Array<object>}
 */
const parseKeePass1xCsv = (headerRow, dataRows) => {
  const get = (row, name) =>
    row[headerRow.indexOf(name)]?.replace(/^"|"$/g, '').trim() || ''

  return dataRows.map((row) => {
    const url = get(row, 'Web Site')

    return {
      type: 'login',
      folder: null,
      isFavorite: false,
      data: {
        title: get(row, 'Account'),
        username: get(row, 'Login Name'),
        password: get(row, 'Password'),
        note: get(row, 'Comments'),
        websites: url ? [addHttps(url)] : [],
        customFields: []
      }
    }
  })
}

/**
 * Parses KeePassXC CSV format
 * Columns: "Group","Title","Username","Password","URL","Notes","TOTP",...
 * @param {string[][]} headerRow
 * @param {string[][]} dataRows
 * @returns {Array<object>}
 */
const parseKeePassXCCsv = (headerRow, dataRows) => {
  const headers = headerRow.map((h) => h.trim().toLowerCase())

  return dataRows.map((row) => {
    const item = Object.fromEntries(
      headers.map((key, i) => [key, row[i]?.trim() ?? ''])
    )

    const url = item.url || ''
    const totp = item.totp || ''

    const customFields = totp ? [{ type: 'note', note: `TOTP: ${totp}` }] : []

    return {
      type: 'login',
      folder: item.group || null,
      isFavorite: false,
      data: {
        title: item.title || '',
        username: item.username || '',
        password: item.password || '',
        note: item.notes || '',
        websites: url ? [addHttps(url)] : [],
        customFields
      }
    }
  })
}

/**
 * Auto-detects KeePass vs KeePassXC CSV format from header row and parses
 * @param {string} text
 * @returns {Array<object>}
 */
export const parseKeePassCsv = (text) => {
  const rows = getRowsFromCsv(text)
  const [headerRow, ...dataRows] = rows

  if (!headerRow || dataRows.length === 0) return []

  const normalizedHeaders = headerRow.map((h) => h.trim().toLowerCase())

  if (
    normalizedHeaders.includes('title') &&
    normalizedHeaders.includes('username')
  ) {
    return parseKeePassXCCsv(headerRow, dataRows)
  }

  if (
    normalizedHeaders.includes('account') &&
    normalizedHeaders.includes('login name')
  ) {
    return parseKeePass1xCsv(headerRow, dataRows)
  }

  // Fallback: try KeePassXC format (more columns = more likely to match something)
  return parseKeePassXCCsv(headerRow, dataRows)
}

/**
 * Recursively walks XML Group elements to extract entries with folder paths
 * @param {Element} groupElement
 * @param {string} parentPath
 * @returns {Array<object>}
 */
const walkXmlGroup = (groupElement, parentPath = '') => {
  const results = []

  const nameEl = Array.from(groupElement.children).find(
    (child) => child.tagName === 'Name'
  )
  const groupName = nameEl?.textContent || ''
  const currentPath = parentPath ? `${parentPath}/${groupName}` : groupName

  const entries = Array.from(groupElement.children).filter(
    (child) => child.tagName === 'Entry'
  )

  for (const entry of entries) {
    const strings = Array.from(entry.children).filter(
      (child) => child.tagName === 'String'
    )

    const fields = {}
    for (const str of strings) {
      const keyEl = Array.from(str.children).find((c) => c.tagName === 'Key')
      const valueEl = Array.from(str.children).find(
        (c) => c.tagName === 'Value'
      )
      if (keyEl) {
        fields[keyEl.textContent] = valueEl?.textContent || ''
      }
    }

    const url = fields.URL || ''
    const customFields = []

    for (const [key, value] of Object.entries(fields)) {
      if (STANDARD_FIELDS.has(key)) continue
      if (!value) continue
      if (TOTP_FIELDS.has(key)) {
        customFields.push({ type: 'note', note: `TOTP: ${value}` })
      } else {
        customFields.push({ type: 'note', note: `${key}: ${value}` })
      }
    }

    results.push({
      type: 'login',
      folder: currentPath || null,
      isFavorite: false,
      data: {
        title: fields.Title || '',
        username: fields.UserName || '',
        password: fields.Password || '',
        note: fields.Notes || '',
        websites: url ? [addHttps(url)] : [],
        customFields
      }
    })
  }

  const subGroups = Array.from(groupElement.children).filter(
    (child) => child.tagName === 'Group'
  )

  for (const subGroup of subGroups) {
    results.push(...walkXmlGroup(subGroup, currentPath))
  }

  return results
}

/**
 * @param {string} text
 * @returns {Array<object>}
 */
export const parseKeePassXml = (text) => {
  const parser = new DOMParser()
  const doc = parser.parseFromString(text, 'text/xml')

  const parserError = doc.querySelector('parsererror')
  if (parserError) {
    throw new Error('Invalid KeePass XML file')
  }

  const root = doc.querySelector('KeePassFile > Root')
  if (!root) {
    throw new Error('Invalid KeePass XML file')
  }

  const rootGroup = root.querySelector('Group')
  if (!rootGroup) return []

  const results = []

  // Process entries directly in root group (no folder prefix)
  const rootEntries = Array.from(rootGroup.children).filter(
    (child) => child.tagName === 'Entry'
  )

  for (const entry of rootEntries) {
    const strings = Array.from(entry.children).filter(
      (child) => child.tagName === 'String'
    )

    const fields = {}
    for (const str of strings) {
      const keyEl = Array.from(str.children).find((c) => c.tagName === 'Key')
      const valueEl = Array.from(str.children).find(
        (c) => c.tagName === 'Value'
      )
      if (keyEl) {
        fields[keyEl.textContent] = valueEl?.textContent || ''
      }
    }

    const url = fields.URL || ''
    const customFields = []

    for (const [key, value] of Object.entries(fields)) {
      if (STANDARD_FIELDS.has(key)) continue
      if (!value) continue
      if (TOTP_FIELDS.has(key)) {
        customFields.push({ type: 'note', note: `TOTP: ${value}` })
      } else {
        customFields.push({ type: 'note', note: `${key}: ${value}` })
      }
    }

    results.push({
      type: 'login',
      folder: null,
      isFavorite: false,
      data: {
        title: fields.Title || '',
        username: fields.UserName || '',
        password: fields.Password || '',
        note: fields.Notes || '',
        websites: url ? [addHttps(url)] : [],
        customFields
      }
    })
  }

  // Process sub-groups
  const subGroups = Array.from(rootGroup.children).filter(
    (child) => child.tagName === 'Group'
  )

  for (const subGroup of subGroups) {
    results.push(...walkXmlGroup(subGroup, ''))
  }

  return results
}

/**
 * @param {string|ArrayBuffer} data
 * @param {string} fileType
 * @param {string} [password]
 * @returns {Promise<Array<object>>}
 */
export const parseKeePassData = async (data, fileType, password) => {
  if (fileType === 'kdbx') {
    if (!password) {
      throw new Error('Password is required for KDBX files')
    }
    return parseKeePassKdbx(data, password)
  }

  if (fileType === 'csv') {
    return parseKeePassCsv(data)
  }

  if (fileType === 'xml') {
    return parseKeePassXml(data)
  }

  throw new Error('Unsupported file type, please use KDBX, CSV, or XML')
}
