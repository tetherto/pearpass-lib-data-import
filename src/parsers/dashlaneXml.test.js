import { parseDashlaneXml } from './dashlaneXml'

/**
 * @param {string} tag
 * @param {Object} fields
 * @returns {string}
 */
const record = (tag, fields) =>
  `<${tag}>${Object.entries(fields)
    .map(
      ([key, value]) =>
        `<KWDataItem key="${key}"><![CDATA[${value}]]></KWDataItem>`
    )
    .join('')}</${tag}>`

const wrap = (...records) => `<root>${records.join('')}</root>`

describe('parseDashlaneXml', () => {
  describe('KWAuthentifiant', () => {
    it('maps a credential to a login record', () => {
      const xml = wrap(
        record('KWAuthentifiant', {
          Title: 'My Site',
          Login: 'alice',
          Password: 'secret',
          Url: 'https://example.com',
          Note: 'a note',
          Category: 'Work'
        })
      )

      expect(parseDashlaneXml(xml)).toEqual([
        {
          type: 'login',
          folder: 'Work',
          isFavorite: false,
          data: {
            title: 'My Site',
            username: 'alice',
            password: 'secret',
            note: 'a note',
            websites: ['https://example.com'],
            customFields: []
          }
        }
      ])
    })

    // The CSV export drops favourites entirely; the XML keeps them.
    it('preserves the favourite flag', () => {
      const xml = wrap(
        record('KWAuthentifiant', {
          Title: 'S',
          Login: 'a',
          IsFavorite: 'true'
        })
      )
      expect(parseDashlaneXml(xml)[0].isFavorite).toBe(true)
    })

    it('prefers OtpUrl over OtpSecret', () => {
      const xml = wrap(
        record('KWAuthentifiant', {
          Title: 'S',
          OtpSecret: 'JBSWY3DPEHPK3PXP',
          OtpUrl: 'otpauth://totp/S?secret=JBSWY3DPEHPK3PXP'
        })
      )
      expect(parseDashlaneXml(xml)[0].data.otpInput).toBe(
        'otpauth://totp/S?secret=JBSWY3DPEHPK3PXP'
      )
    })

    it('falls back to OtpSecret', () => {
      const xml = wrap(
        record('KWAuthentifiant', { Title: 'S', OtpSecret: 'JBSWY3DPEHPK3PXP' })
      )
      expect(parseDashlaneXml(xml)[0].data.otpInput).toBe('JBSWY3DPEHPK3PXP')
    })

    it('omits otpInput when there is no OTP', () => {
      const xml = wrap(record('KWAuthentifiant', { Title: 'S' }))
      expect(parseDashlaneXml(xml)[0].data).not.toHaveProperty('otpInput')
    })

    it('uses Email as the username only when there is no Login', () => {
      const xml = wrap(
        record('KWAuthentifiant', { Title: 'S', Email: 'a@example.com' })
      )
      const login = parseDashlaneXml(xml)[0]

      expect(login.data.username).toBe('a@example.com')
      // Already the username, so it is not duplicated into a custom field.
      expect(login.data.customFields).toEqual([])
    })

    it('keeps Email as a custom field when it differs from Login', () => {
      const xml = wrap(
        record('KWAuthentifiant', {
          Title: 'S',
          Login: 'alice',
          Email: 'a@example.com'
        })
      )
      expect(parseDashlaneXml(xml)[0].data.customFields).toEqual([
        { type: 'note', note: 'Email: a@example.com' }
      ])
    })

    it('keeps SecondaryLogin as a custom field', () => {
      const xml = wrap(
        record('KWAuthentifiant', {
          Title: 'S',
          Login: 'alice',
          SecondaryLogin: 'alt'
        })
      )
      expect(parseDashlaneXml(xml)[0].data.customFields).toEqual([
        { type: 'note', note: 'Alternate username: alt' }
      ])
    })

    it('falls back to the url host when there is no title', () => {
      const xml = wrap(
        record('KWAuthentifiant', { Url: 'https://example.com/login' })
      )
      expect(parseDashlaneXml(xml)[0].data.title).toBe('example.com')
    })

    // TrustedUrlGroup nests further KWDataItem elements inside the record; the
    // record's own fields must win over anything nested beneath it.
    it('is not confused by nested KWDataList children', () => {
      const xml = wrap(
        `<KWAuthentifiant>
          <KWDataItem key="Title"><![CDATA[Real]]></KWDataItem>
          <KWDataItem key="Login"><![CDATA[alice]]></KWDataItem>
          <KWDataList key="TrustedUrlGroup">
            <KWDataCollection key="0">
              <KWDataItem key="TrustedUrl"><![CDATA[https://other.example]]></KWDataItem>
            </KWDataCollection>
          </KWDataList>
        </KWAuthentifiant>`
      )

      const login = parseDashlaneXml(xml)[0]
      expect(login.data.title).toBe('Real')
      expect(login.data.username).toBe('alice')
    })
  })

  describe('KWSecureNote', () => {
    it('maps a secure note', () => {
      const xml = wrap(
        record('KWSecureNote', {
          Title: 'Wifi',
          Content: 'hunter2',
          Category: 'Home'
        })
      )

      expect(parseDashlaneXml(xml)).toEqual([
        {
          type: 'note',
          folder: 'Home',
          isFavorite: false,
          data: { title: 'Wifi', note: 'hunter2', customFields: [] }
        }
      ])
    })
  })

  describe('KWPaymentMean_creditCard', () => {
    it('maps a credit card and normalises the expiry', () => {
      const xml = wrap(
        record('KWPaymentMean_creditCard', {
          Name: 'Personal Visa',
          OwnerName: 'Guy Jordan',
          CardNumber: '4111111111111111',
          SecurityCode: '123',
          ExpireMonth: '3',
          ExpireYear: '2028',
          Bank: 'Big Bank',
          CCNote: 'spare'
        })
      )

      expect(parseDashlaneXml(xml)[0]).toEqual({
        type: 'creditCard',
        folder: null,
        isFavorite: false,
        data: {
          title: 'Personal Visa',
          name: 'Guy Jordan',
          number: '4111111111111111',
          expireDate: '03/28',
          securityCode: '123',
          pinCode: '',
          note: 'spare',
          customFields: [{ type: 'note', note: 'Bank: Big Bank' }]
        }
      })
    })
  })

  describe('KWPasskey', () => {
    // The vault's credential schema requires WebAuthn attestation data that
    // Dashlane does not export, so the passkey is preserved as a login rather
    // than rebuilt as a credential that could not authenticate.
    it('imports a passkey as a login carrying its metadata', () => {
      const xml = wrap(
        record('KWPasskey', {
          ItemName: 'GitHub',
          RpId: 'github.com',
          RpName: 'GitHub',
          CredentialId: 'abc123',
          KeyAlgorithm: '-7',
          UserDisplayName: 'alice'
        })
      )

      const passkey = parseDashlaneXml(xml)[0]
      expect(passkey.type).toBe('login')
      expect(passkey.data.title).toBe('GitHub')
      expect(passkey.data.username).toBe('alice')
      expect(passkey.data.websites).toEqual(['https://github.com'])
      expect(passkey.data.note).toMatch(/re-register the passkey/)
      expect(passkey.data.customFields).toEqual([
        { type: 'note', note: 'Relying party: GitHub' },
        { type: 'note', note: 'Credential ID: abc123' },
        { type: 'note', note: 'Key algorithm: -7' }
      ])
    })
  })

  describe('personal details', () => {
    it('merges the separate personal records into one identity', () => {
      const xml = wrap(
        record('KWIdentity', {
          Title: 'Me',
          FirstName: 'Guy',
          MiddleName: 'A',
          LastName: 'Jordan',
          BirthDate: '1990-01-01'
        }),
        record('KWAddress', {
          AddressFull: '1 Test St',
          City: 'Sydney',
          State: 'NSW',
          ZipCode: '2000',
          Country: 'AU'
        }),
        record('KWEmail', { Email: 'guy@example.com' }),
        record('KWPhone', { Number: '+61400000000' })
      )

      const result = parseDashlaneXml(xml)

      expect(result).toHaveLength(1)
      expect(result[0]).toEqual({
        type: 'identity',
        folder: null,
        isFavorite: false,
        data: {
          title: 'Me',
          fullName: 'Guy A Jordan',
          email: 'guy@example.com',
          phoneNumber: '+61400000000',
          address: '1 Test St',
          zip: '2000',
          city: 'Sydney',
          region: 'NSW',
          country: 'AU',
          note: '',
          customFields: [{ type: 'note', note: 'Date of birth: 1990-01-01' }]
        }
      })
    })

    it('keeps surplus emails and phones as their own records', () => {
      const xml = wrap(
        record('KWIdentity', { FirstName: 'Guy', LastName: 'Jordan' }),
        record('KWEmail', { Email: 'a@example.com', EmailName: 'Primary' }),
        record('KWEmail', { Email: 'b@example.com', EmailName: 'Backup' }),
        record('KWPhone', { Number: '1' }),
        record('KWPhone', { Number: '2', PhoneName: 'Mobile' })
      )

      const result = parseDashlaneXml(xml)
      const titles = result.map((r) => r.data.title)

      expect(result).toHaveLength(3)
      expect(titles).toContain('Backup')
      expect(titles).toContain('Mobile')
    })

    it('emits one record per identity when there are several people', () => {
      const xml = wrap(
        record('KWIdentity', { FirstName: 'Guy', LastName: 'Jordan' }),
        record('KWIdentity', { FirstName: 'Sam', LastName: 'Smith' })
      )

      expect(parseDashlaneXml(xml)).toHaveLength(2)
    })

    it('maps a personal website', () => {
      const xml = wrap(
        record('KWIdentity', { FirstName: 'Guy' }),
        record('KWPersonalWebsite', { Name: 'Blog', Website: 'example.com' })
      )

      const site = parseDashlaneXml(xml).find((r) => r.data.title === 'Blog')
      expect(site.data.customFields).toEqual([
        { type: 'note', note: 'Website: example.com' }
      ])
    })
  })

  describe('KWCollection', () => {
    // Collections are stored the other way round from categories: the record
    // does not name its folder, the collection lists its members' ids.
    const collection = (name, ...memberIds) =>
      `<KWCollection>` +
      `<KWDataItem key="Name"><![CDATA[${name}]]></KWDataItem>` +
      `<KWDataList key="VaultItems">` +
      memberIds
        .map(
          (id) =>
            `<KWDataCollection key="0">` +
            `<KWDataItem key="Id"><![CDATA[${id}]]></KWDataItem>` +
            `<KWDataItem key="Type"><![CDATA[KWAuthentifiant]]></KWDataItem>` +
            `</KWDataCollection>`
        )
        .join('') +
      `</KWDataList></KWCollection>`

    it('uses the collection name as the folder', () => {
      const xml = wrap(
        record('KWAuthentifiant', { Id: 'id-1', Title: 'S' }),
        collection('Banking', 'id-1')
      )

      expect(parseDashlaneXml(xml)[0].folder).toBe('Banking')
    })

    // Collections are the grouping the user maintains today, so they win.
    it('prefers a collection over the older Category field', () => {
      const xml = wrap(
        record('KWAuthentifiant', { Id: 'id-1', Title: 'S', Category: 'Old' }),
        collection('Banking', 'id-1')
      )

      expect(parseDashlaneXml(xml)[0].folder).toBe('Banking')
    })

    it('falls back to Category when the record is in no collection', () => {
      const xml = wrap(
        record('KWAuthentifiant', { Id: 'id-1', Title: 'S', Category: 'Old' }),
        collection('Banking', 'other-id')
      )

      expect(parseDashlaneXml(xml)[0].folder).toBe('Old')
    })

    // The vault stores one folder per record, so surplus memberships are kept
    // as notes rather than discarded.
    it('keeps surplus collection memberships as custom fields', () => {
      const xml = wrap(
        record('KWAuthentifiant', { Id: 'id-1', Title: 'S' }),
        collection('Banking', 'id-1'),
        collection('Personal', 'id-1'),
        collection('Archive', 'id-1')
      )

      const login = parseDashlaneXml(xml)[0]
      expect(login.folder).toBe('Banking')
      expect(login.data.customFields).toEqual([
        { type: 'note', note: 'Also in collection: Personal' },
        { type: 'note', note: 'Also in collection: Archive' }
      ])
    })

    it('does not repeat a collection listed twice', () => {
      const xml = wrap(
        record('KWAuthentifiant', { Id: 'id-1', Title: 'S' }),
        collection('Banking', 'id-1', 'id-1')
      )

      const login = parseDashlaneXml(xml)[0]
      expect(login.folder).toBe('Banking')
      expect(login.data.customFields).toEqual([])
    })

    it('applies collections to notes and cards too', () => {
      const xml = wrap(
        record('KWSecureNote', { Id: 'n-1', Title: 'N' }),
        record('KWPaymentMean_creditCard', { Id: 'c-1', Name: 'C' }),
        collection('Finance', 'n-1', 'c-1')
      )

      expect(parseDashlaneXml(xml).map((r) => r.folder)).toEqual([
        'Finance',
        'Finance'
      ])
    })

    // The membership list nests Id items beneath the collection; the
    // collection's own fields must not be read from them.
    it('does not mistake a member id for the collection name', () => {
      const xml = wrap(
        record('KWAuthentifiant', { Id: 'id-1', Title: 'S' }),
        collection('Banking', 'id-1')
      )

      expect(parseDashlaneXml(xml)).toHaveLength(1)
      expect(parseDashlaneXml(xml)[0].folder).toBe('Banking')
    })

    it('ignores a collection with no name', () => {
      const xml = wrap(
        record('KWAuthentifiant', { Id: 'id-1', Title: 'S', Category: 'Old' }),
        '<KWCollection><KWDataList key="VaultItems"><KWDataCollection key="0">' +
          '<KWDataItem key="Id"><![CDATA[id-1]]></KWDataItem>' +
          '</KWDataCollection></KWDataList></KWCollection>'
      )

      expect(parseDashlaneXml(xml)[0].folder).toBe('Old')
    })
  })

  describe('observed vault shape', () => {
    // Mirrors the real export: records sit under a top-level KWDataList, each
    // login wraps its own TrustedUrlGroup, and collections carry membership.
    const VAULT =
      '<root><KWDataList key="vault">' +
      '<KWAuthentifiant>' +
      '<KWDataItem key="Id">ID-A</KWDataItem>' +
      '<KWDataItem key="Title">GitHub</KWDataItem>' +
      '<KWDataItem key="Login">alice</KWDataItem>' +
      '<KWDataItem key="Category">OldCat</KWDataItem>' +
      '<KWDataItem key="IsFavorite">true</KWDataItem>' +
      '<KWDataList key="TrustedUrlGroup"><KWDataCollection key="0">' +
      '<KWDataItem key="Id">SHOULD-NOT-WIN</KWDataItem>' +
      '<KWDataItem key="TrustedUrl">https://evil.example</KWDataItem>' +
      '</KWDataCollection></KWDataList>' +
      '</KWAuthentifiant>' +
      '<KWSecureNote>' +
      '<KWDataItem key="Id">ID-N</KWDataItem>' +
      '<KWDataItem key="Title">Wifi</KWDataItem>' +
      '<KWDataItem key="Content">hunter2</KWDataItem>' +
      '</KWSecureNote>' +
      '<KWCollection>' +
      '<KWDataItem key="Id">COL-1</KWDataItem>' +
      '<KWDataItem key="Name">Banking</KWDataItem>' +
      '<KWDataList key="VaultItems">' +
      '<KWDataCollection key="0"><KWDataItem key="Id">ID-A</KWDataItem></KWDataCollection>' +
      '<KWDataCollection key="1"><KWDataItem key="Id">ID-N</KWDataItem></KWDataCollection>' +
      '</KWDataList></KWCollection>' +
      '<KWCollection>' +
      '<KWDataItem key="Id">COL-2</KWDataItem>' +
      '<KWDataItem key="Name">Personal</KWDataItem>' +
      '<KWDataList key="VaultItems">' +
      '<KWDataCollection key="0"><KWDataItem key="Id">ID-A</KWDataItem></KWDataCollection>' +
      '</KWDataList></KWCollection>' +
      '</KWDataList></root>'

    it('resolves collections across records nested under a top-level list', () => {
      const [login, note] = parseDashlaneXml(VAULT)

      expect(login.folder).toBe('Banking')
      expect(login.isFavorite).toBe(true)
      expect(login.data.title).toBe('GitHub')
      expect(login.data.customFields).toEqual([
        { type: 'note', note: 'Also in collection: Personal' }
      ])

      expect(note.folder).toBe('Banking')
      expect(note.data.note).toBe('hunter2')
    })

    // The membership list and the trusted-url group both nest an Id, which must
    // not be mistaken for the record's own id when resolving collections.
    it('does not let a nested Id shadow the record id', () => {
      const [login] = parseDashlaneXml(VAULT)
      // Resolution succeeded, so the record id read as ID-A and not the nested one.
      expect(login.folder).toBe('Banking')
    })
  })

  describe('malformed document tolerance', () => {
    // xmldom refuses to attach a CDATA section to the document itself
    // ("Unexpected node type 4 for parent node type 9"), which aborted the
    // whole import even though every record was readable.
    it('parses despite a CDATA section outside the root element', () => {
      const xml =
        '<![CDATA[stray]]>' +
        wrap(record('KWAuthentifiant', { Title: 'S', Login: 'alice' }))

      const [login] = parseDashlaneXml(xml)
      expect(login.data.title).toBe('S')
      expect(login.data.username).toBe('alice')
    })

    it('parses with trailing content after the root element', () => {
      const xml =
        wrap(record('KWAuthentifiant', { Title: 'S' })) + '<![CDATA[trailing]]>'

      expect(parseDashlaneXml(xml)).toHaveLength(1)
    })

    it('strips an xml declaration before wrapping', () => {
      const xml =
        '<?xml version="1.0" encoding="UTF-8"?>' +
        wrap(record('KWAuthentifiant', { Title: 'S' }))

      expect(parseDashlaneXml(xml)).toHaveLength(1)
    })

    it('strips a byte order mark', () => {
      const xml = '\ufeff' + wrap(record('KWAuthentifiant', { Title: 'S' }))
      expect(parseDashlaneXml(xml)).toHaveLength(1)
    })

    it('handles several sibling roots', () => {
      const xml =
        wrap(record('KWAuthentifiant', { Title: 'A' })) +
        wrap(record('KWSecureNote', { Title: 'B', Content: 'c' }))

      expect(parseDashlaneXml(xml).map((r) => r.type)).toEqual([
        'login',
        'note'
      ])
    })

    // Tolerance must not extend to accepting an empty import silently.
    it('still throws when nothing parses', () => {
      expect(() => parseDashlaneXml('<![CDATA[only junk]]>')).toThrow(
        'No Dashlane records found in export'
      )
    })
  })

  describe('edge cases', () => {
    // Guards the direct-children optimisation: an unexpected extra level of
    // nesting must still yield a mapped record, not a silently empty one.
    it('falls back to a descendant search when fields are nested deeper', () => {
      const xml = wrap(
        '<KWAuthentifiant><KWDataList key="wrapper">' +
          '<KWDataItem key="Title"><![CDATA[Nested]]></KWDataItem>' +
          '<KWDataItem key="Login"><![CDATA[alice]]></KWDataItem>' +
          '</KWDataList></KWAuthentifiant>'
      )

      const login = parseDashlaneXml(xml)[0]
      expect(login.data.title).toBe('Nested')
      expect(login.data.username).toBe('alice')
    })

    it('throws when the xml contains no records', () => {
      expect(() => parseDashlaneXml('<root></root>')).toThrow(
        'No Dashlane records found in export'
      )
    })

    it('handles a vault with every record type at once', () => {
      const xml = wrap(
        record('KWAuthentifiant', { Title: 'L' }),
        record('KWSecureNote', { Title: 'N' }),
        record('KWPaymentMean_creditCard', { Name: 'C' }),
        record('KWPasskey', { ItemName: 'P' }),
        record('KWIdentity', { FirstName: 'I' })
      )

      expect(parseDashlaneXml(xml).map((r) => r.type)).toEqual([
        'login',
        'note',
        'creditCard',
        'login',
        'identity'
      ])
    })
  })
})
