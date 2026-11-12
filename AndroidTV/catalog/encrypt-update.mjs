import { createCipheriv, createHash, createHmac, randomBytes } from 'node:crypto';
import { closeSync, openSync, readFileSync, writeFileSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { catalogKey, seal } from './crypto.mjs';

const [apk, keyFile, version, codeText, destination] = process.argv.slice(2);
const code = Number(codeText);
if (!destination || !/^\d+\.\d+\.\d+$/.test(version) || !Number.isSafeInteger(code) || code < 1) {
    throw new Error('Usage: node encrypt-update.mjs APK key-file version version-code output-directory');
}
const secret = catalogKey(readFileSync(keyFile, 'utf8'));
const key = createHmac('sha256', secret).update('Qosmos TV APK v1').digest();
const prefix = randomBytes(8);
const chunkSize = 1024 * 1024;
const plaintext = readFileSync(apk);
if (plaintext.length < 1 || plaintext.length > 128 * chunkSize) throw new Error('APK size exceeds the TV limit');

const asset = openSync(join(destination, 'Qosmos-TV.apk.enc'), 'wx', 0o600);
try {
    for (let offset = 0; offset < plaintext.length; offset += chunkSize) {
        const nonce = Buffer.alloc(12);
        prefix.copy(nonce);
        nonce.writeUInt32BE(offset / chunkSize, 8);
        const cipher = createCipheriv('aes-256-gcm', key, nonce);
        const encrypted = Buffer.concat([cipher.update(plaintext.subarray(offset, offset + chunkSize)), cipher.final(), cipher.getAuthTag()]);
        writeSync(asset, encrypted);
    }
} finally {
    closeSync(asset);
}

const update = JSON.stringify({ version, code, size: plaintext.length, prefix: prefix.toString('base64'),
    sha256: createHash('sha256').update(plaintext).digest('hex') });
writeFileSync(join(destination, 'update.json'), seal(secret, 'Qosmos TV update v1', update), { mode: 0o600, flag: 'wx' });
