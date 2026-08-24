import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { encryptSeed, decryptSeed } from '../src/vault.js';

const SEED = crypto.randomBytes(32);
const PASS = 'correct horse battery staple';

test('round-trips the seed', () => {
  assert.deepEqual(decryptSeed(encryptSeed(SEED, PASS), PASS), SEED);
});

test('wrong passphrase fails loudly, never returns garbage', () => {
  const box = encryptSeed(SEED, PASS);
  assert.throws(() => decryptSeed(box, 'wrong'), /could not decrypt identity/);
});

test('tampering with the ciphertext is detected', () => {
  const box = encryptSeed(SEED, PASS);
  const ct = Buffer.from(box.ct, 'base64url');
  ct[0] ^= 0xff;
  assert.throws(() => decryptSeed({ ...box, ct: ct.toString('base64url') }, PASS), /modified/);
});

test('the plaintext seed does not appear in the stored box', () => {
  const box = encryptSeed(SEED, PASS);
  const blob = JSON.stringify(box);
  assert.ok(!blob.includes(SEED.toString('base64url')));
  assert.ok(!blob.includes(SEED.toString('hex')));
});

test('salt and iv are fresh per call, so identical seeds differ on disk', () => {
  const a = encryptSeed(SEED, PASS);
  const b = encryptSeed(SEED, PASS);
  assert.notEqual(a.salt, b.salt);
  assert.notEqual(a.iv, b.iv);
  assert.notEqual(a.ct, b.ct);
});

test('passphrases are NFKC-normalised so unicode input is stable', () => {
  // U+00E9 and e + U+0301 render identically; a user typing either must unlock.
  const box = encryptSeed(SEED, 'café');
  assert.deepEqual(decryptSeed(box, 'café'), SEED);
});
