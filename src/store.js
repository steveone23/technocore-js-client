// Local key storage. The seed never leaves this machine.
//
// Two on-disk formats, both readable:
//   v1  { seed }        plaintext — what `keygen` wrote before encryption existed
//   v2  { crypto: {…} } scrypt + AES-256-GCM, unlocked by $AGENT_PASSPHRASE
//
// v1 keeps working so an existing identity is never stranded; `encrypt` upgrades
// it in place.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateIdentity, identityFromSeed, b64url } from './did.js';
import { encryptSeed, decryptSeed, passphraseFromEnv, PASSPHRASE_ENV } from './vault.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const KEY_DIR = path.join(ROOT, 'keys');
export const KEY_FILE = path.join(KEY_DIR, 'identity.json');

export function exists() {
  return fs.existsSync(KEY_FILE);
}

function readRecord() {
  if (!exists()) throw new Error(`no identity found at ${KEY_FILE} — run: npm run keygen`);
  return JSON.parse(fs.readFileSync(KEY_FILE, 'utf8'));
}

function writeRecord(record) {
  fs.mkdirSync(KEY_DIR, { recursive: true });
  // 0o600 is a no-op on Windows but correct everywhere else.
  fs.writeFileSync(KEY_FILE, JSON.stringify(record, null, 2) + '\n', { mode: 0o600 });
}

/** Build the stored record for a seed, encrypting when a passphrase is available. */
function pack({ did, fp, nick, seed, createdAt }) {
  const passphrase = passphraseFromEnv();
  const base = { v: passphrase ? 2 : 1, did, fp, nick: nick ?? null, createdAt };
  return passphrase
    ? { ...base, crypto: encryptSeed(seed, passphrase) }
    : { ...base, seed: b64url(seed) };
}

export function create({ nick, force = false } = {}) {
  if (exists() && !force) {
    throw new Error(`identity already exists at ${KEY_FILE} — refusing to overwrite (use --force)`);
  }
  const id = generateIdentity();
  writeRecord(
    pack({ ...id, nick, createdAt: new Date().toISOString() }),
  );
  return { ...id, nick: nick ?? null, encrypted: Boolean(passphraseFromEnv()) };
}

export function load() {
  const record = readRecord();

  let seedB64url;
  if (record.crypto) {
    const passphrase = passphraseFromEnv();
    if (!passphrase) {
      throw new Error(`identity is encrypted — set ${PASSPHRASE_ENV} to unlock it`);
    }
    seedB64url = b64url(decryptSeed(record.crypto, passphrase));
  } else if (record.seed) {
    seedB64url = record.seed;
  } else {
    throw new Error(`identity file has neither 'seed' nor 'crypto': ${KEY_FILE}`);
  }

  const id = identityFromSeed(seedB64url);
  // The did is stored alongside the seed; if they disagree the file is corrupt
  // and signing would produce a did nobody can attribute to us.
  if (record.did && record.did !== id.did) {
    throw new Error(`stored did does not match seed (file corrupt?): ${record.did} vs ${id.did}`);
  }
  return { ...id, nick: record.nick ?? null, encrypted: Boolean(record.crypto) };
}

/** Re-write the identity encrypted. Requires $AGENT_PASSPHRASE. */
export function encrypt() {
  const passphrase = passphraseFromEnv();
  if (!passphrase) throw new Error(`set ${PASSPHRASE_ENV} to the passphrase you want to use`);

  const record = readRecord();
  if (record.crypto) return { already: true };

  const id = load();
  writeRecord(pack({ ...id, createdAt: record.createdAt ?? new Date().toISOString() }));
  return { already: false, did: id.did };
}

export function setNick(nick) {
  const record = readRecord();
  record.nick = nick;
  writeRecord(record);
}
