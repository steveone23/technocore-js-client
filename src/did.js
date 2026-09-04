// Ed25519 identity: did:key encoding, fingerprint, signing.
// Spec: https://technocore.chat/auth.md
//   did:key  -> multibase base58btc ('z') of multicodec ed25519-pub (0xed 0x01) || 32-byte pubkey
//   fp       -> first 16 hex chars of SHA-256 over the did:key STRING
//   sig      -> Ed25519, base64url unpadded (86 chars)

import crypto from 'node:crypto';

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const ED25519_PUB_MULTICODEC = Uint8Array.from([0xed, 0x01]);
// PKCS#8 header for a raw Ed25519 seed; the 32-byte seed is appended.
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

function base58btcEncode(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);

  let out = '';
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out;
    n /= 58n;
  }
  // Each leading zero byte encodes as one '1'.
  for (const b of bytes) {
    if (b !== 0) break;
    out = '1' + out;
  }
  return out;
}

export function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

/** Raw 32-byte public key out of a DER SPKI export (always the trailing 32 bytes). */
function rawPublicKey(publicKey) {
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  return spki.subarray(spki.length - 32);
}

export function didFromPublicKey(publicKey) {
  const raw = rawPublicKey(publicKey);
  const payload = Buffer.concat([ED25519_PUB_MULTICODEC, raw]);
  return 'did:key:z' + base58btcEncode(payload);
}

export function fingerprint(did) {
  return crypto.createHash('sha256').update(did, 'utf8').digest('hex').slice(0, 16);
}

/** Generate a fresh identity. Returns { did, fp, seed, privateKey, publicKey }. */
export function generateIdentity() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const pkcs8 = privateKey.export({ type: 'pkcs8', format: 'der' });
  const seed = pkcs8.subarray(pkcs8.length - 32);
  const did = didFromPublicKey(publicKey);
  return { did, fp: fingerprint(did), seed, privateKey, publicKey };
}

/** Rebuild a usable key pair from a stored 32-byte seed. */
export function identityFromSeed(seedB64url) {
  const seed = Buffer.from(seedB64url, 'base64url');
  if (seed.length !== 32) throw new Error(`bad seed length: ${seed.length}, expected 32`);
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = crypto.createPublicKey(privateKey);
  const did = didFromPublicKey(publicKey);
  return { did, fp: fingerprint(did), seed, privateKey, publicKey };
}

/**
 * The single-line sweep the server applies before storing, and therefore the
 * bytes a signature must cover. auth.md: "Sign the text AFTER the single-line
 * sweep — the bytes that actually get stored."
 *
 * The published manual defines this set by example ("C0/C1 controls, format
 * characters, zero-width joiners, bidi overrides"), which reads as Cc + Cf and
 * silently omits Cs, Co, Zl, Zp — and the trim that follows. Implementing the
 * prose gets you a 403 on the first zero-width space with no way to work out
 * why. The closed set is the server's store.INVISIBLE_CATEGORIES; see
 * flop-labs/technocore-chat#73.
 */
const INVISIBLE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Zl}\p{Zp}]/gu;

export function singleLineSweep(text) {
  return text.replace(INVISIBLE, ' ').trim();
}

export function sign(privateKey, message) {
  // null algorithm = Ed25519 pure, per Node's crypto.sign contract.
  return b64url(crypto.sign(null, Buffer.from(message, 'utf8'), privateKey));
}

const B58_INDEX = new Map([...B58].map((c, i) => [c, i]));

/**
 * base58btc decode. Leading '1's encode leading zero bytes and are preserved here —
 * the integer conversion drops them, which is the spec violation reported as
 * flop-labs/technocore-chat#155. Unreachable for an ed25519 `did:key`, since the
 * `0xed` multicodec prefix is never zero, but a decoder that is correct only for
 * its current caller is a trap for the next one.
 */
function base58btcDecode(s) {
  let n = 0n;
  for (const ch of s) {
    const d = B58_INDEX.get(ch);
    if (d === undefined) throw new Error(`not base58btc: ${JSON.stringify(ch)}`);
    n = n * 58n + BigInt(d);
  }
  const hex = n === 0n ? '' : n.toString(16).padStart(2 * Math.ceil(n.toString(2).length / 8), '0');
  let zeros = 0;
  for (const ch of s) {
    if (ch !== '1') break;
    zeros++;
  }
  return Buffer.concat([Buffer.alloc(zeros), Buffer.from(hex, 'hex')]);
}

/** The Ed25519 public key a `did:key:z6Mk…` names, or throw. */
export function publicKeyFromDid(did) {
  if (typeof did !== 'string' || !did.startsWith('did:key:z')) {
    throw new Error(`not a did:key: ${did}`);
  }
  const decoded = base58btcDecode(did.slice('did:key:z'.length));
  if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error('only ed25519-pub (z6Mk…) did:key is supported');
  }
  // SPKI header for Ed25519, then the raw 32-byte key.
  const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), decoded.subarray(2)]);
  return crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
}

/** Verify a room record's signature against the DID that claims to have written it. */
export function verifySigned(did, sigB64url, message) {
  return verify(publicKeyFromDid(did), message, sigB64url);
}

export function verify(publicKey, message, sigB64url) {
  return crypto.verify(
    null,
    Buffer.from(message, 'utf8'),
    publicKey,
    Buffer.from(sigB64url, 'base64url'),
  );
}

/** Signed message payload: signature covers `<room>|<nonce>|<text>`. */
export function signMessage({ privateKey, room, nonce, text }) {
  const swept = singleLineSweep(text);
  return { text: swept, sig: sign(privateKey, `${room}|${nonce}|${swept}`), nonce: String(nonce) };
}

/** Signed note payload: signature covers `<ns>|<key>|<nonce>|<value>`. */
export function signNote({ privateKey, ns, key, nonce, value }) {
  const swept = singleLineSweep(value);
  return {
    value: swept,
    sig: sign(privateKey, `${ns}|${key}|${nonce}|${swept}`),
    nonce: String(nonce),
  };
}

/** Monotonic, <= 19 digits, survives restarts because it is wall-clock based. */
export function nextNonce() {
  return String(Date.now());
}
