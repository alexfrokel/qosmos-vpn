import { createCipheriv, randomBytes } from 'node:crypto';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const [profilesDirectory, destination] = process.argv.slice(2);
if (!destination) throw new Error('Usage: node publish.mjs profiles catalog.json');

const profiles = [];
for (const file of readdirSync(profilesDirectory).filter(name => name.endsWith('.txt')).sort()) {
    for (const line of readFileSync(join(profilesDirectory, file), 'utf8').split(/\r?\n/)) {
        const link = line.trim();
        if (!link || link.startsWith('#')) continue;
        try {
            const url = new URL(link);
            const settings = url.searchParams;
            if (url.protocol !== 'vless:' || !url.hostname || !url.username
                || settings.get('security') !== 'reality'
                || !['tcp', 'raw'].includes(settings.get('type') ?? 'tcp')
                || settings.has('sshUser') || settings.has('cfHost')) throw new Error();
        } catch {
            throw new Error(`Invalid direct VLESS Reality profile in ${file}`);
        }
        profiles.push(link);
    }
}
const plaintext = Buffer.from(profiles.join('\n'), 'utf8');
if (profiles.length > 50 || plaintext.length > 256 * 1024) throw new Error('Too many profiles');

const key = Buffer.from(process.env.QOSMOS_CATALOG_KEY ?? '', 'base64');
if (key.length !== 32) throw new Error('QOSMOS_CATALOG_KEY must encode 32 bytes');
const nonce = randomBytes(12);
const cipher = createCipheriv('aes-256-gcm', key, nonce);
cipher.setAAD(Buffer.from('Qosmos TV catalog v2', 'utf8'));
const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);

const catalog = JSON.stringify({ version: 2, nonce: nonce.toString('base64'),
    ciphertext: ciphertext.toString('base64') });
if (Buffer.byteLength(catalog) > 512 * 1024) throw new Error('Catalog exceeds the client limit');
writeFileSync(destination, `${catalog}\n`, { mode: 0o600 });
