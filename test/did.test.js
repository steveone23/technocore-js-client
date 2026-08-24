import test from 'node:test';
import assert from 'node:assert/strict';
import {
  generateIdentity,
  identityFromSeed,
  fingerprint,
  sign,
  verify,
  signMessage,
  signNote,
  singleLineSweep,
  b64url,
} from '../src/did.js';

test('did:key uses the ed25519-pub multicodec, so it always starts z6Mk', () => {
  for (let i = 0; i < 20; i++) {
    const { did } = generateIdentity();
    assert.match(did, /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{40,45}$/);
  }
});

test('seed round-trips to the same did', () => {
  const id = generateIdentity();
  const restored = identityFromSeed(b64url(id.seed));
  assert.equal(restored.did, id.did);
  assert.equal(restored.fp, id.fp);
});

test('fingerprint is 16 hex chars of sha256 over the did STRING', () => {
  // Fixed vector so a refactor cannot silently change the hashing input.
  assert.equal(fingerprint('did:key:z6MkTest'), '601964fdcc0c1ebf');
  assert.match(fingerprint(generateIdentity().did), /^[0-9a-f]{16}$/);
});

test('signature is 86 unpadded base64url chars and verifies', () => {
  const id = generateIdentity();
  const sig = sign(id.privateKey, 'lobby|1|hello');
  assert.equal(sig.length, 86);
  assert.doesNotMatch(sig, /[+/=]/);
  assert.ok(verify(id.publicKey, 'lobby|1|hello', sig));
  assert.ok(!verify(id.publicKey, 'lobby|2|hello', sig));
});

test('message signature covers room|nonce|text', () => {
  const id = generateIdentity();
  const { sig, text, nonce } = signMessage({
    privateKey: id.privateKey,
    room: 'lobby',
    nonce: 42,
    text: 'hi',
  });
  assert.equal(nonce, '42');
  assert.ok(verify(id.publicKey, `lobby|42|${text}`, sig));
});

test('note signature covers ns|key|nonce|value', () => {
  const id = generateIdentity();
  const { sig, value } = signNote({
    privateKey: id.privateKey,
    ns: 'did',
    key: 'abc',
    nonce: 7,
    value: 'mailbox:mb-x',
  });
  assert.ok(verify(id.publicKey, `did|abc|7|${value}`, sig));
});

test('sweep strips control and format chars, and we sign the swept bytes', () => {
  assert.equal(singleLineSweep('a\nb\tc'), 'a b c');
  assert.equal(singleLineSweep('a‍b'), 'a b'); // ZWJ is Cf
  assert.equal(singleLineSweep('héllo ✓'), 'héllo ✓');

  const id = generateIdentity();
  const { sig, text } = signMessage({
    privateKey: id.privateKey,
    room: 'lobby',
    nonce: 1,
    text: 'line\none',
  });
  assert.equal(text, 'line one');
  // Must verify against the stored form, not the original.
  assert.ok(verify(id.publicKey, 'lobby|1|line one', sig));
});
