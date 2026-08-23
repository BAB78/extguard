import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';

export interface LicenseCrypto {
  generateLicenseKey(): string;
  hashLicenseKey(licenseKey: string): string;
  hashMachineId(machineId: string): string;
  encryptLicenseKey(licenseKey: string): string;
  decryptLicenseKey(ciphertext: string): string;
  hashesEqual(left: string, right: string): boolean;
}

export function createLicenseCrypto(pepper: string, encryptionKey: Buffer): LicenseCrypto {
  if (encryptionKey.length !== 32) throw new Error('License encryption key must be 32 bytes');

  const digest = (domain: string, value: string): string =>
    createHmac('sha256', pepper).update(domain).update('\0').update(value).digest('hex');

  return {
    generateLicenseKey: () => `EXTG_${randomBytes(32).toString('base64url')}`,
    hashLicenseKey: (licenseKey) => digest('license-key-v1', licenseKey.trim()),
    hashMachineId: (machineId) => digest('machine-id-v1', machineId.toLowerCase()),
    encryptLicenseKey: (licenseKey) => {
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', encryptionKey, iv);
      const encrypted = Buffer.concat([cipher.update(licenseKey, 'utf8'), cipher.final()]);
      const tag = cipher.getAuthTag();
      return ['v1', iv.toString('base64url'), tag.toString('base64url'), encrypted.toString('base64url')].join('.');
    },
    decryptLicenseKey: (ciphertext) => {
      const [version, ivEncoded, tagEncoded, bodyEncoded] = ciphertext.split('.');
      if (version !== 'v1' || !ivEncoded || !tagEncoded || !bodyEncoded) {
        throw new Error('Unsupported license ciphertext');
      }
      const decipher = createDecipheriv('aes-256-gcm', encryptionKey, Buffer.from(ivEncoded, 'base64url'));
      decipher.setAuthTag(Buffer.from(tagEncoded, 'base64url'));
      return Buffer.concat([
        decipher.update(Buffer.from(bodyEncoded, 'base64url')),
        decipher.final(),
      ]).toString('utf8');
    },
    hashesEqual: (left, right) => {
      const leftBuffer = Buffer.from(left, 'hex');
      const rightBuffer = Buffer.from(right, 'hex');
      return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
    },
  };
}
