import { constants, createCipheriv, createHash, createPublicKey, randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const [profilesDirectory, devicesDirectory, destination] = process.argv.slice(2);
if (!destination) throw new Error('Usage: node publish.mjs profiles devices catalog.json');

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

const key = randomBytes(32);
const nonce = randomBytes(12);
const cipher = createCipheriv('aes-256-gcm', key, nonce);
cipher.setAAD(Buffer.from('Qosmos TV catalog v1', 'utf8'));
const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);

const devices = {};
for (const file of readdirSync(devicesDirectory).filter(name => name.endsWith('.der')).sort()) {
    const path = join(devicesDirectory, file);
    const der = readFileSync(path);
    const publicKey = createPublicKey({ key: der, format: 'der', type: 'spki' });
    const id = createHash('sha256').update(der).digest('base64url');
    if (file !== `${id}.der` || publicKey.asymmetricKeyType !== 'rsa'
        || publicKey.asymmetricKeyDetails.modulusLength !== 2048) throw new Error('Invalid device public key');
    const wrap = spawnSync('openssl', ['pkeyutl', '-encrypt', '-pubin', '-keyform', 'DER', '-inkey', path,
        '-pkeyopt', 'rsa_padding_mode:oaep', '-pkeyopt', 'rsa_oaep_md:sha256', '-pkeyopt', 'rsa_mgf1_md:sha1'],
        { input: key });
    if (wrap.status !== 0) throw new Error('Could not encrypt the catalog key');
    devices[id] = wrap.stdout.toString('base64');
}

const catalog = JSON.stringify({ version: 1, nonce: nonce.toString('base64'),
    ciphertext: ciphertext.toString('base64'), devices });
if (Buffer.byteLength(catalog) > 512 * 1024) throw new Error('Catalog exceeds the client limit');
writeFileSync(destination, `${catalog}\n`, { mode: 0o600 });
