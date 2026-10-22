import { generateSecret, generateURI, verify } from 'otplib';

const ISSUER = 'Library Portal';
const PERIOD_SECONDS = 30;
const CODE_PATTERN = /^\d{6}$/;

export function createSecret() {
    return generateSecret();
}

export function buildOtpauthUrl(username, secret) {
    return generateURI({issuer : ISSUER, label : username, secret});
}

export async function verifyCode(secret, code, lastUsedStep = null) {
        if (typeof code !== 'string' || !CODE_PATTERN.test(code)){
        return null;
    }
    const result = await verify({
        secret,
        token: code,
        epochTolerance: PERIOD_SECONDS,
        afterTimeStep: lastUsedStep ?? undefined,
    });
    return result.valid ? result.timeStep : null;
}
