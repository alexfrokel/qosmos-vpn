import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

export function catalogKey(value = process.env.QOSMOS_CATALOG_KEY) {
    const key = Buffer.from(value?.trim() ?? '', 'base64');
    if (key.length !== 32) throw new Error('The catalog key must encode 32 bytes');
    return key;
}

export function seal(key, aad, plaintext) {
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, nonce);
    cipher.setAAD(Buffer.from(aad));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
    return JSON.stringify({ version: 2, nonce: nonce.toString('base64'), ciphertext: ciphertext.toString('base64') }) + '\n';
}

export function open(key, aad, document) {
    const { version, nonce, ciphertext } = JSON.parse(document);
    if (version !== 2) throw new Error('Unknown encryption format');
    const payload = Buffer.from(ciphertext, 'base64');
    const cipher = createDecipheriv('aes-256-gcm', key, Buffer.from(nonce, 'base64'));
    cipher.setAAD(Buffer.from(aad));
    cipher.setAuthTag(payload.subarray(-16));
    return Buffer.concat([cipher.update(payload.subarray(0, -16)), cipher.final()]);
}
