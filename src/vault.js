// Passphrase encryption for the seed at rest.
//
// The seed is the identity: anyone holding it can post as you forever, and it
// cannot be rotated without abandoning the did. Plaintext on disk means any
// process, backup, or sync client that reads the file owns the identity.
//
// scrypt (memory-hard, so a stolen file resists GPU cracking) -> AES-256-GCM
// (authenticated, so a tampered file fails loudly instead of yielding garbage).

import crypto from 'node:crypto';

export const PASSPHRASE_ENV = 'AGENT_PASSPHRASE';

// N=2^15 costs ~100ms and 32 MiB per attempt — unnoticeable once per command,
// expensive across a dictionary.
const KDF = { name: 'scrypt', N: 32768, r: 8, p: 1, keylen: 32 };

function deriveKey(passphrase, salt) {
  return crypto.scryptSync(passphrase.normalize('NFKC'), salt, KDF.keylen, {
    N: KDF.N,
    r: KDF.r,
    p: KDF.p,
    // Node's default maxmem (32 MiB) is exactly at the limit for N=2^15; raise it.
    maxmem: 128 * 1024 * 1024,
  });
}

export function passphraseFromEnv() {
  const p = process.env[PASSPHRASE_ENV];
  return p && p.length > 0 ? p : null;
}

export function encryptSeed(seed, passphrase) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', deriveKey(passphrase, salt), iv);
  const ct = Buffer.concat([cipher.update(seed), cipher.final()]);
  return {
    kdf: KDF,
    salt: salt.toString('base64url'),
    iv: iv.toString('base64url'),
    tag: cipher.getAuthTag().toString('base64url'),
    ct: ct.toString('base64url'),
  };
}

export function decryptSeed(box, passphrase) {
  const salt = Buffer.from(box.salt, 'base64url');
  const key = crypto.scryptSync(passphrase.normalize('NFKC'), salt, box.kdf.keylen, {
    N: box.kdf.N,
    r: box.kdf.r,
    p: box.kdf.p,
    maxmem: 128 * 1024 * 1024,
  });
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(box.iv, 'base64url'));
  decipher.setAuthTag(Buffer.from(box.tag, 'base64url'));
  try {
    return Buffer.concat([decipher.update(Buffer.from(box.ct, 'base64url')), decipher.final()]);
  } catch {
    // GCM tag mismatch: wrong passphrase, or the file was altered. Same signal
    // either way — we cannot distinguish, and must not guess.
    throw new Error(
      `could not decrypt identity — wrong ${PASSPHRASE_ENV}, or the file has been modified`,
    );
  }
}
