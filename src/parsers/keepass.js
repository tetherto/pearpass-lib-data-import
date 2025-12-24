import { getRowsFromCsv } from '../utils/getRowsFromCsv'
import { addHttps } from '../utils/addHttps'

export const parseKeepassCsv = (csvText) => {
  const result = []

  const [headers, ...rows] = getRowsFromCsv(csvText)

  for (const row of rows) {
    const rowData = Object.fromEntries(row.map((v, i) => [headers[i], v]))
    // KeePassXC CSV Headers based on user file:
    // "Group","Title","Username","Password","URL","Notes","TOTP","Icon","Last Modified","Created"
    
    // Map to normalized keys to handle potential casing differences if any, though the user file shows Capitalized
    const entry = {}
    Object.keys(rowData).forEach(key => {
      entry[key.toLowerCase()] = rowData[key]
    })

    const data = {
      title: entry.title || '',
      username: entry.username || '',
      password: entry.password || '',
      websites: entry.url ? [addHttps(entry.url)] : [],
      note: entry.notes || '',
      customFields: [],
      totp: entry.totp || ''
    }

    result.push({
      type: 'login', // KeePassXC doesn't distinguish types in CSV, default to login
      data,
      folder: entry.group || null,
      isFavorite: false // Not present in CSV
    })
  }

  return result
}

export const parseKeepassData = (data, fileType) => {
  if (fileType === 'csv') {
    return parseKeepassCsv(data)
  }
  
  // KeePassXC also exports JSON but structure needs to be seen. For now only CSV supported as per request.
  if (fileType === 'json') {
      throw new Error('KeePassXC JSON import not yet supported, please use CSV.')
  }

  throw new Error('Unsupported file type, please use (KeePassXC) CSV')
}
