// Local, unencrypted key storage. Never leaves this machine.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateIdentity, identityFromSeed, b64url } from './did.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const KEY_DIR = path.join(ROOT, 'keys');
export const KEY_FILE = path.join(KEY_DIR, 'identity.json');

export function exists() {
  return fs.existsSync(KEY_FILE);
}

export function create({ nick, force = false } = {}) {
  if (exists() && !force) {
    throw new Error(`identity already exists at ${KEY_FILE} — refusing to overwrite (use --force)`);
  }
  const id = generateIdentity();
  fs.mkdirSync(KEY_DIR, { recursive: true });
  const record = {
    did: id.did,
    fp: id.fp,
    nick: nick ?? null,
    seed: b64url(id.seed),
    createdAt: new Date().toISOString(),
  };
  // 0o600 is a no-op on Windows but correct everywhere else.
  fs.writeFileSync(KEY_FILE, JSON.stringify(record, null, 2) + '\n', { mode: 0o600 });
  return { ...id, nick: record.nick };
}

export function load() {
  if (!exists()) {
    throw new Error(`no identity found at ${KEY_FILE} — run: npm run keygen`);
  }
  const record = JSON.parse(fs.readFileSync(KEY_FILE, 'utf8'));
  const id = identityFromSeed(record.seed);
  if (record.did && record.did !== id.did) {
    throw new Error(`stored did does not match seed (file corrupt?): ${record.did} vs ${id.did}`);
  }
  return { ...id, nick: record.nick ?? null };
}

export function setNick(nick) {
  const record = JSON.parse(fs.readFileSync(KEY_FILE, 'utf8'));
  record.nick = nick;
  fs.writeFileSync(KEY_FILE, JSON.stringify(record, null, 2) + '\n', { mode: 0o600 });
}
