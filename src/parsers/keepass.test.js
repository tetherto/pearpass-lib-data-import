import { parseKeepassData, parseKeepassCsv } from './keepass'

jest.mock('../utils/addHttps', () => ({
    addHttps: jest.fn((url) => `https://${url.replace(/^https?:\/\//, '')}`)
}))

describe('parseKeepassCsv', () => {
    it('parses KeePassXC CSV correctly', () => {
        const csv = [
            '"Group","Title","Username","Password","URL","Notes","TOTP","Icon","Last Modified","Created"',
            '"Root","Email Account","user@example.com","securepass123","","","","0","2024-01-15T10:30:00Z","2024-01-15T10:25:00Z"',
            '"Root","Work Email","john.doe@company.com","mypassword456","mail.company.com","Important work account","","0","2024-01-16T14:20:00Z","2024-01-16T14:15:00Z"'
        ].join('\n')

        const result = parseKeepassCsv(csv)

        expect(result).toHaveLength(2)

        expect(result[0]).toEqual({
            type: 'login',
            data: {
                title: 'Email Account',
                username: 'user@example.com',
                password: 'securepass123',
                websites: [],
                note: '',
                customFields: [],
                totp: ''
            },
            folder: 'Root',
            isFavorite: false
        })

        expect(result[1]).toEqual({
            type: 'login',
            data: {
                title: 'Work Email',
                username: 'john.doe@company.com',
                password: 'mypassword456',
                websites: ['https://mail.company.com'],
                note: 'Important work account',
                customFields: [],
                totp: ''
            },
            folder: 'Root',
            isFavorite: false
        })
    })
})

describe('parseKeepassData', () => {
    it('calls parseKeepassCsv for csv fileType', () => {
        const csv = '"Group","Title"\n"G","T"'
        const result = parseKeepassData(csv, 'csv')
        expect(Array.isArray(result)).toBe(true)
    })

    it('throws error for unsupported JSON', () => {
        expect(() => parseKeepassData('{}', 'json')).toThrow(
            'KeePassXC JSON import not yet supported, please use CSV.'
        )
    })
})
