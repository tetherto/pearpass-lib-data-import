export const OTP_PROVIDERS = {
  googleMigration: 'google-migration',
  otpUri: 'otp-uri',
  unknown: 'unknown'
}

/** Public result status values returned by normalizeImport */
export const STATUS = {
  complete: 'complete',
  incompleteBatch: 'incomplete-batch',
  /** Internal batch-assembly state, not exposed to consumers */
  ready: 'ready'
}

export const OTP_TYPE = {
  TOTP: 'TOTP',
  HOTP: 'HOTP'
}

export const OTP_ALGORITHM = {
  SHA1: 'SHA1',
  SHA256: 'SHA256',
  SHA512: 'SHA512'
}
