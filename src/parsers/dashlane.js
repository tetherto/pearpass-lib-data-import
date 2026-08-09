import { decryptDashlaneExport } from './dashlaneCrypto'
import { parseDashlaneXml } from './dashlaneXml'
import { addHttps } from '../utils/addHttps'
import { getRowsFromCsv } from '../utils/getRowsFromCsv'

// Dashlane's CSV export is a zip containing up to five files — credentials,
// securenotes, payments, ids and personalinfo — and none of them carry a column
// that names the file they came from. `type` exists in three of them but means
// something different in each. Detection therefore has to key off which columns
// are present, so each parser is paired with a predicate over the header set.
const isCredentials = (h) =>
  h.has('username') && h.has('password') && h.has('title')

const isPayments = (h) =>
  h.has('type') && h.has('account_name') && h.has('account_holder')

const isIds = (h) => h.has('type') && h.has('number') && h.has('issue_date')

const isPersonalInfo = (h) =>
  h.has('type') && h.has('title') && h.has('first_name')

// securenotes.csv is only `title,note`, which is a subset of several other
// files' headers — so it is only matched once everything else has been ruled out.
const isSecureNotes = (h) => h.has('title') && h.has('note') && h.size <= 3

/**
 * @param {Set<string>} headers
 * @returns {string|null}
 */
const detectRecordFile = (headers) => {
  if (isCredentials(headers)) return 'credentials'
  if (isPayments(headers)) return 'payments'
  if (isIds(headers)) return 'ids'
  if (isPersonalInfo(headers)) return 'personalinfo'
  if (isSecureNotes(headers)) return 'securenotes'
  return null
}

/**
 * The vault only accepts custom fields of type `note`, so every value that has
 * no dedicated schema field is flattened into a `Label: value` note.
 * @param {Array<[string, string]>} pairs
 * @returns {Array<{type: string, note: string}>}
 */
const toCustomFields = (pairs) =>
  pairs
    .filter(([, value]) => Boolean(value))
    .map(([label, value]) => ({ type: 'note', note: `${label}: ${value}` }))

/**
 * @param {string} month
 * @param {string} year
 * @returns {string}
 */
const toExpiryDate = (month, year) => {
  if (!month && !year) return ''
  const mm = month.padStart(2, '0')
  // Dashlane writes a four-digit year; the vault stores MM/YY.
  const yy = year.length > 2 ? year.slice(-2) : year.padStart(2, '0')
  return `${mm}/${yy}`
}

/**
 * @param {string} value
 * @returns {string}
 */
const normalizePhone = (value) => {
  if (!value) return ''
  const trimmed = value.trim()
  // Preserve an already-formatted international number rather than mangling it.
  if (trimmed.startsWith('+')) return trimmed
  const digits = trimmed.replace(/\D/g, '')
  return digits ? `+${digits}` : ''
}

/**
 * @param {string[]} values
 * @returns {string}
 */
const joinName = (values) => values.filter(Boolean).join(' ').trim()

/**
 * credentials.csv → login records.
 * @param {Array<Object>} rows
 * @returns {Array<Object>}
 */
const parseCredentials = (rows) =>
  rows.map((row) => {
    const {
      title,
      username,
      username2,
      username3,
      password,
      note,
      url,
      category,
      otpSecret,
      otpUrl
    } = row

    // Dashlane allows a credential with no title; fall back to the host so the
    // record is still identifiable, since the vault requires a title.
    let fallbackTitle = username || ''
    if (url) {
      try {
        fallbackTitle = new URL(addHttps(url)).hostname
      } catch {
        fallbackTitle = url
      }
    }

    // otpUrl is Dashlane's newer full otpauth:// URI and supersedes otpSecret,
    // which is a bare base32 seed. parseOtpInput in the vault accepts either.
    const otpInput = otpUrl || otpSecret || ''

    return {
      type: 'login',
      folder: category || null,
      isFavorite: false,
      data: {
        title: title || fallbackTitle,
        username: username || '',
        password: password || '',
        note: note || '',
        websites: url ? [addHttps(url)] : [],
        customFields: toCustomFields([
          ['Alternate username', username2],
          ['Alternate username', username3]
        ]),
        ...(otpInput ? { otpInput } : {})
      }
    }
  })

/**
 * securenotes.csv → note records.
 * @param {Array<Object>} rows
 * @returns {Array<Object>}
 */
const parseSecureNotes = (rows) =>
  rows.map((row) => ({
    type: 'note',
    folder: null,
    isFavorite: false,
    data: {
      title: row.title || 'Secure note',
      note: row.note || '',
      customFields: []
    }
  }))

/**
 * payments.csv → creditCard records for cards, custom records for bank accounts.
 * @param {Array<Object>} rows
 * @returns {Array<Object>}
 */
const parsePayments = (rows) =>
  rows.map((row) => {
    const {
      type,
      account_name: accountName,
      account_holder: accountHolder,
      cc_number: ccNumber,
      code,
      expiration_month: expirationMonth,
      expiration_year: expirationYear,
      routing_number: routingNumber,
      account_number: accountNumber,
      country,
      issuing_bank: issuingBank
    } = row

    const base = { folder: null, isFavorite: false }

    // A bank account has no card number or expiry, so it cannot round-trip
    // through the creditCard schema; it becomes a custom record instead.
    if (type === 'bank') {
      return {
        type: 'custom',
        ...base,
        data: {
          title: accountName || issuingBank || 'Bank account',
          customFields: toCustomFields([
            ['Account holder', accountHolder],
            ['Account number', accountNumber],
            ['Routing number', routingNumber],
            ['Issuing bank', issuingBank],
            ['Country', country]
          ])
        }
      }
    }

    return {
      type: 'creditCard',
      ...base,
      data: {
        title: accountName || issuingBank || 'Credit card',
        name: accountHolder || '',
        number: ccNumber || '',
        expireDate: toExpiryDate(expirationMonth || '', expirationYear || ''),
        securityCode: code || '',
        pinCode: '',
        note: '',
        customFields: toCustomFields([
          ['Issuing bank', issuingBank],
          ['Country', country]
        ])
      }
    }
  })

// Dashlane's ids.csv holds one document per row. The vault's identity schema has
// dedicated fields for passports, ID cards and driving licences, so each maps
// onto its own group of columns rather than being flattened into notes.
const ID_FIELD_MAP = {
  passport: {
    label: 'Passport',
    number: 'passportNumber',
    fullName: 'passportFullName',
    issue: 'passportDateOfIssue',
    expiry: 'passportExpiryDate',
    country: 'passportIssuingCountry'
  },
  license: {
    label: 'Driving licence',
    number: 'drivingLicenseNumber',
    issue: 'drivingLicenseDateOfIssue',
    expiry: 'drivingLicenseExpiryDate',
    country: 'drivingLicenseIssuingCountry'
  },
  id_card: {
    label: 'ID card',
    number: 'idCardNumber',
    issue: 'idCardDateOfIssue',
    expiry: 'idCardExpiryDate',
    country: 'idCardIssuingCountry'
  }
}

/**
 * ids.csv → identity records.
 * @param {Array<Object>} rows
 * @returns {Array<Object>}
 */
const parseIds = (rows) =>
  rows.map((row) => {
    const {
      type,
      number,
      name,
      issue_date: issueDate,
      expiration_date: expirationDate,
      place_of_issue: placeOfIssue,
      state
    } = row

    const mapping = ID_FIELD_MAP[type]

    // social_security and tax_number have no dedicated schema fields, so they
    // are preserved as notes rather than silently dropped.
    if (!mapping) {
      const label =
        type === 'social_security' ? 'Social security' : 'Tax number'
      return {
        type: 'identity',
        folder: null,
        isFavorite: false,
        data: {
          title: name || label,
          fullName: name || '',
          customFields: toCustomFields([
            [`${label} number`, number],
            ['Issue date', issueDate],
            ['Expiration date', expirationDate],
            ['Place of issue', placeOfIssue],
            ['State', state]
          ])
        }
      }
    }

    const data = {
      title: name ? `${mapping.label} — ${name}` : mapping.label,
      customFields: toCustomFields([['State', state]])
    }

    if (number) data[mapping.number] = number
    if (issueDate) data[mapping.issue] = issueDate
    if (expirationDate) data[mapping.expiry] = expirationDate
    if (placeOfIssue) data[mapping.country] = placeOfIssue
    // Only a passport carries its own name field in the vault schema; for the
    // other document types the name is kept as the identity's fullName.
    if (name) {
      if (mapping.fullName) data[mapping.fullName] = name
      else data.fullName = name
    }

    return { type: 'identity', folder: null, isFavorite: false, data }
  })

/**
 * personalinfo.csv → identity records.
 *
 * Dashlane splits one person across several typed rows (name, email, phone,
 * address, company…). When there is exactly one `name` row they all describe the
 * same person, so they are merged into a single identity — matching how other
 * importers treat this file. Multiple `name` rows mean multiple people, and each
 * row becomes its own record.
 * @param {Array<Object>} rows
 * @returns {Array<Object>}
 */
const parsePersonalInfo = (rows) => {
  const nameRows = rows.filter((row) => row.type === 'name')

  if (nameRows.length === 1) {
    return [mergePersonalInfo(rows, nameRows[0])]
  }

  return rows.map((row) => mergePersonalInfo([row], row))
}

/**
 * @param {Array<Object>} rows
 * @param {Object} primary
 * @returns {Object}
 */
const mergePersonalInfo = (rows, primary) => {
  const fullName = joinName([
    primary.first_name,
    primary.middle_name,
    primary.last_name
  ])

  const pick = (field) => rows.map((row) => row[field]).find(Boolean) || ''

  const address = rows.find((row) => row.address) || {}

  const extras = []
  for (const row of rows) {
    extras.push(
      ['Date of birth', row.date_of_birth],
      ['Place of birth', row.place_of_birth],
      ['Job title', row.job_title],
      ['Login', row.login],
      ['Website', row.url],
      ['Address recipient', row.address_recipient],
      ['Building', row.address_building],
      ['Apartment', row.address_apartment],
      ['Floor', row.address_floor],
      ['Door code', row.address_door_code]
    )
  }

  return {
    type: 'identity',
    folder: null,
    isFavorite: false,
    data: {
      title: primary.item_name || fullName || primary.title || 'Personal info',
      fullName,
      email: pick('email'),
      phoneNumber: normalizePhone(pick('phone_number')),
      address: address.address || '',
      zip: address.zip || pick('zip'),
      city: address.city || pick('city'),
      region: address.state || pick('state'),
      country: address.country || pick('country'),
      note: '',
      customFields: toCustomFields(extras)
    }
  }
}

const FILE_PARSERS = {
  credentials: parseCredentials,
  securenotes: parseSecureNotes,
  payments: parsePayments,
  ids: parseIds,
  personalinfo: parsePersonalInfo
}

/**
 * Parses a single Dashlane CSV file. The file it came from is inferred from its
 * header row, so the caller does not need to preserve Dashlane's filenames.
 * @function parseDashlaneCSV
 * @param {string} csvText
 * @returns {Array<Object>}
 * @throws {Error}
 */
export const parseDashlaneCSV = (csvText) => {
  const rows = getRowsFromCsv(csvText)
  const [headerRow, ...dataRows] = rows

  // getRowsFromCsv returns [['']] for empty input rather than [], so an empty
  // file has to be detected by its cells being blank, not by row count.
  if (!headerRow || !headerRow.some((cell) => cell?.trim())) {
    return []
  }

  const headers = headerRow.map((header) => header.trim())
  const recordFile = detectRecordFile(new Set(headers))

  if (!recordFile) {
    throw new Error('Unrecognized Dashlane CSV file')
  }

  const items = dataRows
    // Trailing newlines produce a single empty cell; skip those rather than
    // importing a blank record.
    .filter((row) => row.some((cell) => cell?.trim()))
    .map((row) =>
      Object.fromEntries(
        headers.map((key, index) => [key, row[index]?.trim() ?? ''])
      )
    )

  return FILE_PARSERS[recordFile](items)
}

/**
 * @function parseDashlaneData
 * @param {string|string[]} data - One CSV file, or every CSV from the export zip
 * @param {string} fileType
 * @returns {Array<Object>}
 * @throws {Error}
 */
export const parseDashlaneData = (data, fileType) => {
  // A .dash export is encrypted, so it needs a password and an async path;
  // parseDashlaneExport handles it rather than overloading this signature.
  if (fileType === 'dash') {
    throw new Error(
      'Dashlane secure exports are encrypted, use parseDashlaneExport with the export password'
    )
  }

  if (fileType !== 'csv') {
    throw new Error('Unsupported file type, please use CSV')
  }

  // A Dashlane export is a zip of several CSVs. Accepting an array lets the
  // caller unzip and hand over every file in one import.
  const files = Array.isArray(data) ? data : [data]

  return files.filter(Boolean).flatMap((file) => parseDashlaneCSV(file))
}

/**
 * Opens an encrypted Dashlane `.dash` secure export and converts it to records.
 *
 * This carries strictly more than the CSV export: favourites, TOTP seeds,
 * secondary logins and categories all survive, where the CSV path loses them.
 * @function parseDashlaneExport
 * @param {string} fileText - Contents of the .dash file
 * @param {string} password - The password set during export
 * @param {Object} [options] - Forwarded to decryptDashlaneExport
 * @returns {Promise<Array<Object>>}
 * @throws {Error}
 */
export const parseDashlaneExport = async (fileText, password, options) =>
  parseDashlaneXml(await decryptDashlaneExport(fileText, password, options))
