import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const VERSION = 'v1';
const ALGORITHM = 'aes-256-gcm';
const IV_BYTES = 12;
const KEY_BYTES = 32;

function getKey() {
    const raw = process.env.MFA_ENCRYPTION_KEY;
    if (!raw){
        throw new Error('MFA_ENCRYPTION_KEY environment variable is not set');
    }
    const key  = Buffer.from(raw, 'base64');
    if (key.length !== KEY_BYTES) {
        throw new Error(`MFA_ENCRYPTION_KEY must be ${KEY_BYTES} bytes encoded as base64`);    }
    return key;
}

function decryptFailed(){
    const err = new Error('Encrypted secret could not be decrypted');
    err.code = 'SECRET_DECRYPT_FAILED';
    return err;
}

export function encryptSecret(plainText, context){
    if (!plainText || !context){
        throw new TypeError('Plain text and context are required');
    }
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv(ALGORITHM, getKey(), iv);
    cipher.setAAD(Buffer.from(context));
    const cipherText = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return [VERSION, iv, tag, cipherText].map((p, i) => (i === 0 ? p : p.toString('base64url'))).join(':');
}

export function decryptSecret(stored, context){
    const parts = typeof stored === 'string' ? stored.split(':') : [];
    if (parts.length !== 4 || parts[0] !== VERSION){
        throw decryptFailed();
    }
    const [, iv, tag, cipherText] = parts.map((p, i) => (i === 0 ? p : Buffer.from(p, 'base64url')));
    try{
        const decipher = createDecipheriv(ALGORITHM, getKey(), iv);
        decipher.setAAD(Buffer.from(context));
        decipher.setAuthTag(tag);
        return Buffer.concat([decipher.update(cipherText), decipher.final()]).toString('utf8');
    } catch {
        throw decryptFailed();
    }
}
