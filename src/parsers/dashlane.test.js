import {
  parseDashlaneCSV,
  parseDashlaneData,
  parseDashlaneExport
} from './dashlane'

const toCsv = (rows) =>
  rows
    .map((row) =>
      row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(',')
    )
    .join('\n')

const CREDENTIALS_HEADERS = [
  'username',
  'username2',
  'username3',
  'title',
  'password',
  'note',
  'url',
  'category',
  'otpSecret',
  'otpUrl'
]

const PAYMENTS_HEADERS = [
  'type',
  'account_name',
  'account_holder',
  'cc_number',
  'code',
  'expiration_month',
  'expiration_year',
  'routing_number',
  'account_number',
  'country',
  'issuing_bank'
]

const IDS_HEADERS = [
  'type',
  'number',
  'name',
  'issue_date',
  'expiration_date',
  'place_of_issue',
  'state'
]

const PERSONAL_INFO_HEADERS = [
  'type',
  'title',
  'first_name',
  'middle_name',
  'last_name',
  'login',
  'date_of_birth',
  'place_of_birth',
  'email',
  'email_type',
  'item_name',
  'phone_number',
  'address',
  'country',
  'state',
  'city',
  'zip',
  'address_recipient',
  'address_building',
  'address_apartment',
  'address_floor',
  'address_door_code',
  'job_title',
  'url'
]

describe('parseDashlaneCSV', () => {
  describe('credentials.csv', () => {
    it('parses a credential into a login record', () => {
      const csv = toCsv([
        CREDENTIALS_HEADERS,
        [
          'user1',
          '',
          '',
          'My Site',
          'pass1',
          'some note',
          'example.com',
          'Work',
          '',
          ''
        ]
      ])

      expect(parseDashlaneCSV(csv)).toEqual([
        {
          type: 'login',
          folder: 'Work',
          isFavorite: false,
          data: {
            title: 'My Site',
            username: 'user1',
            password: 'pass1',
            note: 'some note',
            websites: ['https://example.com'],
            customFields: []
          }
        }
      ])
    })

    it('maps otpUrl to otpInput in preference to otpSecret', () => {
      const csv = toCsv([
        CREDENTIALS_HEADERS,
        [
          'user1',
          '',
          '',
          'My Site',
          'pass1',
          '',
          '',
          '',
          'JBSWY3DPEHPK3PXP',
          'otpauth://totp/My%20Site:user1?secret=JBSWY3DPEHPK3PXP&issuer=My+Site'
        ]
      ])

      expect(parseDashlaneCSV(csv)[0].data.otpInput).toBe(
        'otpauth://totp/My%20Site:user1?secret=JBSWY3DPEHPK3PXP&issuer=My+Site'
      )
    })

    it('falls back to the bare otpSecret when no otpUrl is present', () => {
      const csv = toCsv([
        CREDENTIALS_HEADERS,
        [
          'user1',
          '',
          '',
          'My Site',
          'pass1',
          '',
          '',
          '',
          'JBSWY3DPEHPK3PXP',
          ''
        ]
      ])

      expect(parseDashlaneCSV(csv)[0].data.otpInput).toBe('JBSWY3DPEHPK3PXP')
    })

    it('omits otpInput entirely when there is no OTP', () => {
      const csv = toCsv([
        CREDENTIALS_HEADERS,
        ['user1', '', '', 'My Site', 'pass1', '', '', '', '', '']
      ])

      expect(parseDashlaneCSV(csv)[0].data).not.toHaveProperty('otpInput')
    })

    it('keeps alternate usernames as custom fields', () => {
      const csv = toCsv([
        CREDENTIALS_HEADERS,
        [
          'user1',
          'alt@example.com',
          '+61400000000',
          'My Site',
          'pass1',
          '',
          '',
          '',
          '',
          ''
        ]
      ])

      expect(parseDashlaneCSV(csv)[0].data.customFields).toEqual([
        { type: 'note', note: 'Alternate username: alt@example.com' },
        { type: 'note', note: 'Alternate username: +61400000000' }
      ])
    })

    it('falls back to the url hostname when the title is empty', () => {
      const csv = toCsv([
        CREDENTIALS_HEADERS,
        [
          'user1',
          '',
          '',
          '',
          'pass1',
          '',
          'https://example.com/login',
          '',
          '',
          ''
        ]
      ])

      expect(parseDashlaneCSV(csv)[0].data.title).toBe('example.com')
    })

    it('falls back to the username when there is no title or url', () => {
      const csv = toCsv([
        CREDENTIALS_HEADERS,
        ['user1', '', '', '', 'pass1', '', '', '', '', '']
      ])

      expect(parseDashlaneCSV(csv)[0].data.title).toBe('user1')
    })

    it('leaves websites empty when there is no url', () => {
      const csv = toCsv([
        CREDENTIALS_HEADERS,
        ['user1', '', '', 'My Site', 'pass1', '', '', '', '', '']
      ])

      expect(parseDashlaneCSV(csv)[0].data.websites).toEqual([])
    })
  })

  describe('securenotes.csv', () => {
    it('parses a secure note', () => {
      const csv = toCsv([
        ['title', 'note'],
        ['Wifi', 'the password is hunter2']
      ])

      expect(parseDashlaneCSV(csv)).toEqual([
        {
          type: 'note',
          folder: null,
          isFavorite: false,
          data: {
            title: 'Wifi',
            note: 'the password is hunter2',
            customFields: []
          }
        }
      ])
    })

    it('preserves embedded newlines and commas in a note', () => {
      const csv = toCsv([
        ['title', 'note'],
        ['Recovery', 'line one\nline two, with a comma']
      ])

      expect(parseDashlaneCSV(csv)[0].data.note).toBe(
        'line one\nline two, with a comma'
      )
    })
  })

  describe('payments.csv', () => {
    it('parses a credit card', () => {
      const csv = toCsv([
        PAYMENTS_HEADERS,
        [
          'credit_card',
          'Personal Visa',
          'Guy Jordan',
          '4111111111111111',
          '123',
          '3',
          '2028',
          '',
          '',
          'AU',
          'Big Bank'
        ]
      ])

      expect(parseDashlaneCSV(csv)).toEqual([
        {
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
            note: '',
            customFields: [
              { type: 'note', note: 'Issuing bank: Big Bank' },
              { type: 'note', note: 'Country: AU' }
            ]
          }
        }
      ])
    })

    it('parses a bank account as a custom record', () => {
      const csv = toCsv([
        PAYMENTS_HEADERS,
        [
          'bank',
          'Everyday',
          'Guy Jordan',
          '',
          '',
          '',
          '',
          '062000',
          '12345678',
          'AU',
          'Big Bank'
        ]
      ])

      expect(parseDashlaneCSV(csv)).toEqual([
        {
          type: 'custom',
          folder: null,
          isFavorite: false,
          data: {
            title: 'Everyday',
            customFields: [
              { type: 'note', note: 'Account holder: Guy Jordan' },
              { type: 'note', note: 'Account number: 12345678' },
              { type: 'note', note: 'Routing number: 062000' },
              { type: 'note', note: 'Issuing bank: Big Bank' },
              { type: 'note', note: 'Country: AU' }
            ]
          }
        }
      ])
    })

    it('handles a missing expiry without producing a stray slash', () => {
      const csv = toCsv([
        PAYMENTS_HEADERS,
        ['credit_card', 'Card', 'Guy', '4111', '', '', '', '', '', '', '']
      ])

      expect(parseDashlaneCSV(csv)[0].data.expireDate).toBe('')
    })

    it('truncates a four-digit year to two digits', () => {
      const csv = toCsv([
        PAYMENTS_HEADERS,
        ['credit_card', 'Card', 'Guy', '4111', '', '11', '2031', '', '', '', '']
      ])

      expect(parseDashlaneCSV(csv)[0].data.expireDate).toBe('11/31')
    })
  })

  describe('ids.csv', () => {
    it('maps a passport onto the dedicated passport fields', () => {
      const csv = toCsv([
        IDS_HEADERS,
        [
          'passport',
          'PA1234567',
          'Guy Jordan',
          '2020-01-15',
          '2030-01-15',
          'Australia',
          ''
        ]
      ])

      expect(parseDashlaneCSV(csv)).toEqual([
        {
          type: 'identity',
          folder: null,
          isFavorite: false,
          data: {
            title: 'Passport — Guy Jordan',
            customFields: [],
            passportNumber: 'PA1234567',
            passportDateOfIssue: '2020-01-15',
            passportExpiryDate: '2030-01-15',
            passportIssuingCountry: 'Australia',
            passportFullName: 'Guy Jordan'
          }
        }
      ])
    })

    it('maps a driving licence onto its own fields and keeps the name as fullName', () => {
      const csv = toCsv([
        IDS_HEADERS,
        [
          'license',
          'DL987',
          'Guy Jordan',
          '2019-06-01',
          '2029-06-01',
          'Australia',
          'NSW'
        ]
      ])

      expect(parseDashlaneCSV(csv)[0].data).toEqual({
        title: 'Driving licence — Guy Jordan',
        customFields: [{ type: 'note', note: 'State: NSW' }],
        drivingLicenseNumber: 'DL987',
        drivingLicenseDateOfIssue: '2019-06-01',
        drivingLicenseExpiryDate: '2029-06-01',
        drivingLicenseIssuingCountry: 'Australia',
        fullName: 'Guy Jordan'
      })
    })

    it('maps an id card onto its own fields', () => {
      const csv = toCsv([
        IDS_HEADERS,
        [
          'id_card',
          'ID555',
          'Guy Jordan',
          '2021-02-02',
          '2031-02-02',
          'Australia',
          ''
        ]
      ])

      expect(parseDashlaneCSV(csv)[0].data.idCardNumber).toBe('ID555')
    })

    it('preserves a social security number as notes rather than dropping it', () => {
      const csv = toCsv([
        IDS_HEADERS,
        ['social_security', '123-45-6789', 'Guy Jordan', '', '', '', '']
      ])

      expect(parseDashlaneCSV(csv)[0].data).toEqual({
        title: 'Guy Jordan',
        fullName: 'Guy Jordan',
        customFields: [
          { type: 'note', note: 'Social security number: 123-45-6789' }
        ]
      })
    })

    it('preserves a tax number as notes', () => {
      const csv = toCsv([
        IDS_HEADERS,
        ['tax_number', 'TFN123', '', '', '', '', '']
      ])

      expect(parseDashlaneCSV(csv)[0].data.title).toBe('Tax number')
      expect(parseDashlaneCSV(csv)[0].data.customFields).toEqual([
        { type: 'note', note: 'Tax number number: TFN123' }
      ])
    })
  })

  describe('personalinfo.csv', () => {
    const personalRow = (overrides) => {
      const row = PERSONAL_INFO_HEADERS.map((header) => overrides[header] ?? '')
      return row
    }

    it('merges typed rows into a single identity when there is one name row', () => {
      const csv = toCsv([
        PERSONAL_INFO_HEADERS,
        personalRow({
          type: 'name',
          first_name: 'Guy',
          last_name: 'Jordan',
          item_name: 'Me',
          date_of_birth: '1990-01-01'
        }),
        personalRow({ type: 'email', email: 'guy@example.com' }),
        personalRow({ type: 'phone', phone_number: '0400 000 000' }),
        personalRow({
          type: 'address',
          address: '1 Test St',
          city: 'Sydney',
          state: 'NSW',
          zip: '2000',
          country: 'AU'
        })
      ])

      const result = parseDashlaneCSV(csv)

      expect(result).toHaveLength(1)
      expect(result[0]).toEqual({
        type: 'identity',
        folder: null,
        isFavorite: false,
        data: {
          title: 'Me',
          fullName: 'Guy Jordan',
          email: 'guy@example.com',
          phoneNumber: '+0400000000',
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

    it('emits one identity per row when there are multiple people', () => {
      const csv = toCsv([
        PERSONAL_INFO_HEADERS,
        personalRow({ type: 'name', first_name: 'Guy', last_name: 'Jordan' }),
        personalRow({ type: 'name', first_name: 'Sam', last_name: 'Smith' })
      ])

      const result = parseDashlaneCSV(csv)

      expect(result).toHaveLength(2)
      expect(result.map((r) => r.data.fullName)).toEqual([
        'Guy Jordan',
        'Sam Smith'
      ])
    })

    it('includes a middle name in fullName', () => {
      const csv = toCsv([
        PERSONAL_INFO_HEADERS,
        personalRow({
          type: 'name',
          first_name: 'Guy',
          middle_name: 'A',
          last_name: 'Jordan'
        })
      ])

      expect(parseDashlaneCSV(csv)[0].data.fullName).toBe('Guy A Jordan')
    })

    it('preserves an already-international phone number', () => {
      const csv = toCsv([
        PERSONAL_INFO_HEADERS,
        personalRow({ type: 'name', first_name: 'Guy' }),
        personalRow({ type: 'phone', phone_number: '+61 400 000 000' })
      ])

      expect(parseDashlaneCSV(csv)[0].data.phoneNumber).toBe('+61 400 000 000')
    })
  })

  describe('file detection and edge cases', () => {
    it('throws on an unrecognized header row', () => {
      const csv = toCsv([
        ['foo', 'bar'],
        ['1', '2']
      ])

      expect(() => parseDashlaneCSV(csv)).toThrow(
        'Unrecognized Dashlane CSV file'
      )
    })

    it('returns an empty array for empty input', () => {
      expect(parseDashlaneCSV('')).toEqual([])
    })

    it('returns an empty array for a header row with no data', () => {
      expect(parseDashlaneCSV(toCsv([CREDENTIALS_HEADERS]))).toEqual([])
    })

    it('skips blank trailing rows', () => {
      const csv = `${toCsv([
        CREDENTIALS_HEADERS,
        ['user1', '', '', 'My Site', 'pass1', '', '', '', '', '']
      ])}\n`

      expect(parseDashlaneCSV(csv)).toHaveLength(1)
    })
  })
})

describe('parseDashlaneData', () => {
  it('parses a single csv file', () => {
    const csv = toCsv([
      ['title', 'note'],
      ['Wifi', 'hunter2']
    ])

    expect(parseDashlaneData(csv, 'csv')).toHaveLength(1)
  })

  it('combines every csv from the export zip', () => {
    const credentials = toCsv([
      CREDENTIALS_HEADERS,
      ['user1', '', '', 'My Site', 'pass1', '', '', '', '', '']
    ])
    const notes = toCsv([
      ['title', 'note'],
      ['Wifi', 'hunter2']
    ])

    const result = parseDashlaneData([credentials, notes], 'csv')

    expect(result).toHaveLength(2)
    expect(result.map((r) => r.type)).toEqual(['login', 'note'])
  })

  it('ignores empty files in the array', () => {
    const notes = toCsv([
      ['title', 'note'],
      ['Wifi', 'hunter2']
    ])

    expect(parseDashlaneData(['', notes, null], 'csv')).toHaveLength(1)
  })

  it('throws on an unsupported file type', () => {
    expect(() => parseDashlaneData('{}', 'json')).toThrow(
      'Unsupported file type, please use CSV'
    )
  })

  // A .dash export is encrypted and needs a password, so it is routed to
  // parseDashlaneExport rather than being rejected outright.
  it('points a .dash file at parseDashlaneExport', () => {
    expect(() => parseDashlaneData('', 'dash')).toThrow(
      'use parseDashlaneExport with the export password'
    )
  })
})

describe('parseDashlaneExport', () => {
  // Builds a genuine encrypted container so the whole path — decrypt, inflate,
  // parse XML, map records — is exercised end to end rather than mocked.
  const buildEncryptedExport = async (xml, password) => {
    const { createCipheriv, createHash, createHmac, randomBytes } =
      await import('node:crypto')
    const { deflateRawSync } = await import('node:zlib')
    const { argon2d } = await import('@noble/hashes/argon2')

    const cost = { t: 1, m: 256, p: 1 }
    const salt = randomBytes(16)
    const iv = randomBytes(16)

    const derived = argon2d(new TextEncoder().encode(password), salt, {
      ...cost,
      dkLen: 32
    })
    const combined = createHash('sha512').update(Buffer.from(derived)).digest()

    const payload = Buffer.concat([
      Buffer.alloc(6),
      deflateRawSync(Buffer.from(xml))
    ])
    const cipher = createCipheriv('aes-256-cbc', combined.subarray(0, 32), iv)
    const ciphertext = Buffer.concat([cipher.update(payload), cipher.final()])
    const mac = createHmac('sha256', combined.subarray(32, 64))
      .update(Buffer.concat([iv, ciphertext]))
      .digest()

    const base64 = Buffer.concat([
      Buffer.from(
        `$1$argon2d$16$${cost.t}$${cost.m}$${cost.p}$aes256$cbchmac$16$`,
        'ascii'
      ),
      salt,
      iv,
      mac,
      ciphertext
    ]).toString('base64')

    return [
      '---- Dashlane Secured Export ----',
      '---- Data BEGIN ----',
      base64,
      '---- Data END ----'
    ].join('\n')
  }

  const VAULT_XML =
    '<root>' +
    '<KWAuthentifiant>' +
    '<KWDataItem key="Title"><![CDATA[GitHub]]></KWDataItem>' +
    '<KWDataItem key="Login"><![CDATA[alice]]></KWDataItem>' +
    '<KWDataItem key="Password"><![CDATA[s3cret]]></KWDataItem>' +
    '<KWDataItem key="Url"><![CDATA[https://github.com]]></KWDataItem>' +
    '<KWDataItem key="IsFavorite"><![CDATA[true]]></KWDataItem>' +
    '<KWDataItem key="OtpSecret"><![CDATA[JBSWY3DPEHPK3PXP]]></KWDataItem>' +
    '<KWDataItem key="Category"><![CDATA[Dev]]></KWDataItem>' +
    '</KWAuthentifiant>' +
    '<KWSecureNote>' +
    '<KWDataItem key="Title"><![CDATA[Wifi]]></KWDataItem>' +
    '<KWDataItem key="Content"><![CDATA[hunter2]]></KWDataItem>' +
    '</KWSecureNote>' +
    '</root>'

  it('decrypts and converts a secure export to records', async () => {
    const file = await buildEncryptedExport(VAULT_XML, 'export-pw')

    await expect(parseDashlaneExport(file, 'export-pw')).resolves.toEqual([
      {
        type: 'login',
        folder: 'Dev',
        isFavorite: true,
        data: {
          title: 'GitHub',
          username: 'alice',
          password: 's3cret',
          note: '',
          websites: ['https://github.com'],
          customFields: [],
          otpInput: 'JBSWY3DPEHPK3PXP'
        }
      },
      {
        type: 'note',
        folder: null,
        isFavorite: false,
        data: { title: 'Wifi', note: 'hunter2', customFields: [] }
      }
    ])
  })

  it('surfaces a wrong password rather than importing garbage', async () => {
    const file = await buildEncryptedExport(VAULT_XML, 'export-pw')

    await expect(parseDashlaneExport(file, 'wrong')).rejects.toThrow(
      'Incorrect password for this Dashlane export'
    )
  })
})
