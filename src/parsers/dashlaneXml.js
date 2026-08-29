import { DOMParser } from '@xmldom/xmldom'

import { addHttps } from '../utils/addHttps'

// Dashlane's vault XML stores every field as <KWDataItem key="Name">value</…>
// nested inside a record element named for its type.
const ITEM_TAG = 'KWDataItem'
const LIST_TAG = 'KWDataList'
const COLLECTION_TAG = 'KWDataCollection'

/**
 * Direct children of `element` with the given tag name.
 *
 * A record's own fields are always direct children. Descendant search would
 * also reach the nested KWDataItem elements that trusted-URL groups, collection
 * membership lists and passkey JWK components hang beneath a record, where the
 * same key names recur with unrelated values.
 * @param {Element} element
 * @param {string} tagName
 * @returns {Element[]}
 */
const directChildren = (element, tagName) => {
  const found = []
  const children = element.childNodes ?? []

  for (let i = 0; i < children.length; i++) {
    const child = children[i]
    if (child.nodeName === tagName) found.push(child)
  }

  return found
}

/**
 * @param {Element} record
 * @returns {Object}
 */
const readFields = (record) => {
  const fields = {}

  const collect = (items) => {
    for (let i = 0; i < items.length; i++) {
      const item = items[i]
      const key = item.getAttribute('key')
      // First value wins, so a record's own field is never overwritten by a
      // same-named one from a nested list.
      if (key && fields[key] === undefined) {
        fields[key] = (item.textContent ?? '').trim()
      }
    }
  }

  collect(directChildren(record, ITEM_TAG))

  // Direct children are the observed shape, but falling back to a descendant
  // search means an unexpected extra level of nesting yields a partly-mapped
  // record rather than a silently empty one.
  if (Object.keys(fields).length === 0) {
    collect(record.getElementsByTagName(ITEM_TAG))
  }

  return fields
}

/**
 * @param {Array<[string, string]>} pairs
 * @returns {Array<{type: string, note: string}>}
 */
const toCustomFields = (pairs) =>
  pairs
    .filter(([, value]) => Boolean(value))
    .map(([label, value]) => ({ type: 'note', note: `${label}: ${value}` }))

/**
 * @param {string} value
 * @returns {boolean}
 */
const isTrue = (value) => value === 'true' || value === '1'

/**
 * Maps each record's Dashlane id to the names of the collections holding it.
 *
 * Collections are Dashlane's newer grouping feature and are stored the other way
 * round from categories: rather than each record naming its folder, a
 * KWCollection lists the ids of its members under a `VaultItems` list.
 * @param {Document} doc
 * @returns {Map<string, string[]>}
 */
const readCollections = (doc) => {
  const membership = new Map()
  const collections = doc.getElementsByTagName('KWCollection')

  for (let i = 0; i < collections.length; i++) {
    const collection = collections[i]
    const name = readFields(collection).Name
    if (!name) continue

    for (const list of directChildren(collection, LIST_TAG)) {
      if (list.getAttribute('key') !== 'VaultItems') continue

      for (const entry of directChildren(list, COLLECTION_TAG)) {
        const { Id: id } = readFields(entry)
        if (!id) continue

        const names = membership.get(id) ?? []
        // A record can belong to several collections, and Dashlane may list the
        // same one twice; both are handled by keeping distinct names in order.
        if (!names.includes(name)) names.push(name)
        membership.set(id, names)
      }
    }
  }

  return membership
}

/**
 * Resolves a record's folder and any surplus collection memberships.
 *
 * A record can sit in several collections, but the vault stores a single
 * folder, so the first collection becomes the folder and the rest are kept as
 * notes rather than dropped. Collections take precedence over the older
 * Category field because they are the grouping the user maintains today.
 * @param {Object} fields
 * @param {Map<string, string[]>} collections
 * @returns {{folder: string|null, extra: string[]}}
 */
const resolveFolder = (fields, collections) => {
  const names = collections.get(fields.Id) ?? []

  return {
    folder: names[0] ?? (fields.Category || null),
    extra: names.slice(1)
  }
}

/**
 * @param {string[]} extra
 * @returns {Array<{type: string, note: string}>}
 */
const extraCollectionFields = (extra) =>
  extra.map((name) => ({ type: 'note', note: `Also in collection: ${name}` }))

/**
 * @param {string[]} parts
 * @returns {string}
 */
const joinName = (parts) => parts.filter(Boolean).join(' ').trim()

/**
 * @param {string} url
 * @returns {string}
 */
const hostOf = (url) => {
  try {
    return new URL(addHttps(url)).hostname
  } catch {
    return url
  }
}

/**
 * KWAuthentifiant → login.
 * @param {Object} f
 * @returns {Object}
 */
const toLogin = (f, collections) => {
  // Dashlane stores Login and Email independently; either can be the account
  // name, so Email is only promoted when there is no Login.
  const username = f.Login || f.Email || ''
  const url = f.Url || f.UserSelectedUrl || ''

  const otpInput = f.OtpUrl || f.OtpSecret || ''
  const { folder, extra } = resolveFolder(f, collections)

  return {
    type: 'login',
    folder,
    isFavorite: isTrue(f.IsFavorite),
    data: {
      title: f.Title || (url ? hostOf(url) : username) || 'Login',
      username,
      password: f.Password || '',
      note: f.Note || '',
      websites: url ? [addHttps(url)] : [],
      customFields: toCustomFields([
        ['Alternate username', f.SecondaryLogin],
        // Only surface Email separately when it is not already the username.
        ['Email', f.Email && f.Email !== username ? f.Email : ''],
        ['Extra', f.Extra]
      ]).concat(extraCollectionFields(extra)),
      ...(otpInput ? { otpInput } : {})
    }
  }
}

/**
 * KWSecureNote → note.
 * @param {Object} f
 * @returns {Object}
 */
const toNote = (f, collections) => {
  const { folder, extra } = resolveFolder(f, collections)

  return {
    type: 'note',
    folder,
    isFavorite: false,
    data: {
      title: f.Title || 'Secure note',
      note: f.Content || '',
      customFields: extraCollectionFields(extra)
    }
  }
}

/**
 * KWPaymentMean_creditCard → creditCard.
 * @param {Object} f
 * @returns {Object}
 */
const toCreditCard = (f, collections) => {
  const { folder, extra } = resolveFolder(f, collections)
  const month = (f.ExpireMonth || '').padStart(2, '0')
  const year = f.ExpireYear || ''
  const expireDate =
    month && year ? `${month}/${year.length > 2 ? year.slice(-2) : year}` : ''

  return {
    type: 'creditCard',
    folder,
    isFavorite: false,
    data: {
      title: f.Name || f.Bank || 'Credit card',
      name: f.OwnerName || '',
      number: f.CardNumber || '',
      expireDate,
      securityCode: f.SecurityCode || '',
      pinCode: '',
      note: f.CCNote || '',
      customFields: toCustomFields([
        ['Bank', f.Bank],
        ['Card type', f.CardType],
        ['Issue number', f.IssueNumber]
      ]).concat(extraCollectionFields(extra))
    }
  }
}

/**
 * KWPasskey → login.
 *
 * The vault's credential schema is a full WebAuthn credential and requires an
 * attestation object, authenticator data and client data JSON. Dashlane stores
 * none of those, so a usable passkey cannot be reconstructed from this export.
 * The entry is imported as a login carrying the passkey's metadata rather than
 * as a credential that would fail at authentication time.
 * @param {Object} f
 * @returns {Object}
 */
const toPasskeyRecord = (f, collections) => ({
  type: 'login',
  folder: resolveFolder(f, collections).folder,
  isFavorite: false,
  data: {
    title: f.ItemName || f.RpName || f.RpId || 'Passkey',
    username: f.UserDisplayName || f.UserHandle || '',
    password: '',
    note:
      'Imported from Dashlane as a passkey. Dashlane exports do not include ' +
      'the WebAuthn attestation data needed to rebuild a working passkey, so ' +
      'this entry keeps the details for reference only — re-register the ' +
      'passkey with the site to use it.',
    websites: f.RpId ? [addHttps(f.RpId)] : [],
    customFields: toCustomFields([
      ['Relying party', f.RpName || f.RpId],
      ['Credential ID', f.CredentialId],
      ['Key algorithm', f.KeyAlgorithm],
      ['Counter', f.Counter]
    ])
  }
})

/**
 * @param {Object} f
 * @returns {Object}
 */
const toStandaloneIdentity = (f, title, extras) => ({
  type: 'identity',
  folder: null,
  isFavorite: false,
  data: {
    title,
    customFields: toCustomFields(extras)
  }
})

// A real export carries nodes the DOM will not accept at document level — a
// CDATA section outside the root makes xmldom throw "Unexpected node type 4 for
// parent node type 9", which aborts the whole import. Wrapping the payload in a
// synthetic element makes those nodes ordinary children, so the records around
// them still parse. Records are located with getElementsByTagName, which is
// unaffected by the extra level.
const WRAPPER_TAG = 'pearpassDashlaneImport'

/**
 * @param {string} xml
 * @returns {Document}
 */
const parseVaultDocument = (xml) => {
  const body = xml
    // A byte order mark, XML declaration or doctype is only legal at the top of
    // a document, so each is removed before the payload is nested.
    .replace(/^﻿/, '')
    .replace(/^\s*<\?xml[^>]*\?>/i, '')
    .replace(/^\s*<!DOCTYPE[^>]*>/i, '')

  // xmldom reports recoverable issues through this handler rather than throwing;
  // they are ignored so a stray node cannot fail an otherwise readable vault.
  const errorHandler = { warning: () => {}, error: () => {} }

  return new DOMParser({ errorHandler }).parseFromString(
    `<${WRAPPER_TAG}>${body}</${WRAPPER_TAG}>`,
    'text/xml'
  )
}

const RECORD_TAGS = [
  'KWAuthentifiant',
  'KWSecureNote',
  'KWPaymentMean_creditCard',
  'KWPasskey',
  'KWIdentity',
  'KWAddress',
  'KWEmail',
  'KWPhone',
  'KWPersonalWebsite'
]

/**
 * Builds a single identity from Dashlane's separate personal-detail records.
 *
 * Dashlane keeps name, address, email and phone as independent records. When
 * there is exactly one of the name record they describe the same person, so
 * they are combined — mirroring how the CSV importer treats personalinfo.csv.
 * Any surplus records are emitted on their own so nothing is discarded.
 * @param {Object} groups
 * @param {Map<string, string[]>} collections
 * @returns {Array<Object>}
 */
const buildIdentities = (groups, collections) => {
  const identities = groups.KWIdentity ?? []
  const addresses = groups.KWAddress ?? []
  const emails = groups.KWEmail ?? []
  const phones = groups.KWPhone ?? []
  const websites = groups.KWPersonalWebsite ?? []

  const records = []

  if (identities.length === 1) {
    const f = identities[0]
    const address = addresses[0] ?? {}
    const email = emails[0] ?? {}
    const phone = phones[0] ?? {}

    records.push({
      type: 'identity',
      folder: resolveFolder(f, collections).folder,
      isFavorite: false,
      data: {
        title: f.Title || joinName([f.FirstName, f.LastName]) || 'Identity',
        fullName: joinName([
          f.FirstName,
          f.MiddleName,
          f.LastName,
          f.LastName2
        ]),
        email: email.Email || '',
        phoneNumber: phone.Number || '',
        address: address.AddressFull || '',
        zip: address.ZipCode || '',
        city: address.City || '',
        region: address.State || '',
        country: address.Country || '',
        note: '',
        customFields: toCustomFields([
          ['Date of birth', f.BirthDate],
          ['Place of birth', f.BirthPlace],
          ['Pseudonym', f.Pseudo],
          ['Address name', address.AddressName],
          ['Building', address.Building],
          ['Floor', address.Floor],
          ['Door', address.Door],
          ['Digit code', address.DigitCode],
          ['Receiver', address.Receiver],
          ['Personal note', address.PersonalNote]
        ])
      }
    })
  } else {
    for (const f of identities) {
      records.push(
        toStandaloneIdentity(
          f,
          f.Title || joinName([f.FirstName, f.LastName]) || 'Identity',
          [
            ['Full name', joinName([f.FirstName, f.MiddleName, f.LastName])],
            ['Date of birth', f.BirthDate],
            ['Place of birth', f.BirthPlace]
          ]
        )
      )
    }
  }

  // Anything not folded into the single identity above is kept as its own
  // record rather than dropped.
  const surplus = identities.length === 1 ? 1 : 0
  for (const f of addresses.slice(surplus)) {
    records.push(
      toStandaloneIdentity(f, f.AddressName || 'Address', [
        ['Address', f.AddressFull],
        ['City', f.City],
        ['State', f.State],
        ['Zip', f.ZipCode],
        ['Country', f.Country]
      ])
    )
  }
  for (const f of emails.slice(surplus)) {
    records.push(
      toStandaloneIdentity(f, f.EmailName || f.Email || 'Email', [
        ['Email', f.Email],
        ['Type', f.Type]
      ])
    )
  }
  for (const f of phones.slice(surplus)) {
    records.push(
      toStandaloneIdentity(f, f.PhoneName || 'Phone', [
        ['Number', f.Number],
        ['Type', f.Type]
      ])
    )
  }
  for (const f of websites) {
    records.push(
      toStandaloneIdentity(f, f.Name || 'Website', [['Website', f.Website]])
    )
  }

  return records
}

/**
 * Converts the vault XML from a decrypted `.dash` export into vault records.
 * @function parseDashlaneXml
 * @param {string} xml
 * @returns {Array<Object>}
 * @throws {Error}
 */
export const parseDashlaneXml = (xml) => {
  const doc = parseVaultDocument(xml)

  const groups = {}
  for (const tag of RECORD_TAGS) {
    const nodes = doc.getElementsByTagName(tag)
    groups[tag] = []
    for (let i = 0; i < nodes.length; i++) {
      groups[tag].push(readFields(nodes[i]))
    }
  }

  const total = RECORD_TAGS.reduce((sum, tag) => sum + groups[tag].length, 0)
  if (total === 0) {
    throw new Error('No Dashlane records found in export')
  }

  const collections = readCollections(doc)

  // Each mapper is wrapped rather than passed to map directly, so the array
  // index is not handed over as the collections argument.
  return [
    ...groups.KWAuthentifiant.map((f) => toLogin(f, collections)),
    ...groups.KWSecureNote.map((f) => toNote(f, collections)),
    ...groups.KWPaymentMean_creditCard.map((f) => toCreditCard(f, collections)),
    ...groups.KWPasskey.map((f) => toPasskeyRecord(f, collections)),
    ...buildIdentities(groups, collections)
  ]
}
