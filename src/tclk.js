// tclk/1 — escrowed deals between agents who meet in a technocore room.
//
// The protocol is a convention layer, not a service: technocore orders signed
// frames and holds nothing. Money lives on a settlement rail named in the offer,
// and as of tclk 0.1.0 no rail holds value — `paper` is the rehearsal rail.
//
// Frames come from @flop-labs/tclk rather than being reimplemented here. The spec
// is explicit that two implementations disagreeing on canonicalisation disagree on
// every contract id, and the reference implementation's test suite is the stated
// anti-drift gate. This is the same failure we documented on technocore-chat#75,
// where the one rule outside the docs was the one every independent client got
// wrong. The core client (did.js, client.js) stays dependency-free; this module is
// where the dependency lives.
//
// Spec: https://github.com/flop-labs/tclk/blob/main/SPEC.md

import {
  OFFER_ROOM,
  capabilityToken,
  dealRoom,
  encodeFrame,
  generateHashLock,
  makeAccept,
  makeOffer,
  tryDecodeFrame,
} from '@flop-labs/tclk';

import * as api from './client.js';
import { signMessage, nextNonce, verifySigned as verifySignature } from './did.js';

export { OFFER_ROOM, capabilityToken, dealRoom, generateHashLock };

/**
 * Post one frame through the signed lane.
 *
 * Two nonces are in play and they are not the same thing: the frame carries its
 * own protocol nonce, and the transport signature covers `<room>|<nonce>|<text>`
 * with a separate monotonic one. Conflating them silently breaks replay guards on
 * whichever side loses.
 *
 * The spec requires the stored bytes to equal the signed bytes, which is why
 * frames are ASCII-escaped. `signMessage` sweeps before signing, so a frame that
 * changed under the sweep would be signed as something the wire never carried —
 * it cannot happen for ASCII, and this asserts rather than assumes it.
 */
async function postFrame(id, room, frame) {
  const text = encodeFrame(frame);
  const payload = signMessage({ privateKey: id.privateKey, room, nonce: nextNonce(), text });

  if (payload.text !== text) {
    throw new Error('frame changed under the single-line sweep — refusing to sign different bytes');
  }

  const res = await api.saySigned(room, { did: id.did, ...payload });
  return { seq: res.seq, text, frame };
}

/** Open an offer in the public rendezvous room. Either side may open; `role` says which. */
export async function postOffer(id, { role, amount, asset, rails, lock = 'hash', ttlMs = 3600_000, job }) {
  const now = Date.now();
  const offer = makeOffer({
    from: id.did,
    role,
    amount: String(amount),
    asset,
    lock,
    rails,
    // claimByMs < refundAfterMs strictly; the gap is the payee's safe claim window.
    expiresMs: now + ttlMs,
    claimByMs: now + ttlMs * 2,
    refundAfterMs: now + ttlMs * 3,
    ...(job ? { job } : {}),
  });
  return postFrame(id, OFFER_ROOM, offer);
}

/**
 * Accept someone's offer. Returns the secret too — losing it loses the claim, so
 * the caller must persist it before the counterparty locks anything.
 */
export async function acceptOffer(id, offer) {
  if (offer.lock !== 'hash') {
    throw new Error(`only hash locks are supported here, offer wants ${offer.lock}`);
  }
  const { preimage, hash } = generateHashLock();
  const accept = makeAccept(offer, { from: id.did, statement: hash });
  const posted = await postFrame(id, OFFER_ROOM, accept);
  return { ...posted, secret: preimage, contract: accept.contract, room: dealRoom(accept.contract) };
}

/**
 * Offers we could actually take, newest first.
 *
 * Filters on the three things that decide whether an offer is workable rather than
 * merely present: it is still open, it wants a side we can take, and it settles on
 * a rail we accept. `from` is checked against the transport-verified sender because
 * the spec requires them to match — a frame claiming someone else's DID is data,
 * not a commitment.
 *
 * What it deliberately does not do is rank or auto-accept. Accepting is nearly free
 * on a paper rail, which is exactly why a queue of accepts proves nothing; the
 * judgement about whether work is real stays with a human.
 */
export function workableOffers(entries, { ourRails = ['paper'], role = 'payee', now = Date.now() } = {}) {
  const wantedFrom = role === 'payee' ? 'payer' : 'payee';
  const rails = new Set(ourRails);
  const seen = new Set();
  const out = [];

  for (const e of entries) {
    const f = e.frame;
    if (f.type !== 'offer' || f.role !== wantedFrom) continue;
    if (f.from !== e.from) continue; // frame `from` must equal the signed sender
    if (typeof f.expiresMs === 'number' && f.expiresMs <= now) continue;
    if (!Array.isArray(f.rails) || !f.rails.some((r) => rails.has(r))) continue;
    if (seen.has(f.id)) continue; // one offer, many re-posts
    seen.add(f.id);
    out.push(e);
  }
  return out.sort((a, b) => b.seq - a.seq);
}

/**
 * Parse a room's JSON view, keeping `nonce` a string.
 *
 * Nonces are up to 19 ASCII digits (the int64 ceiling the spec allows), and
 * JSON.parse turns them into IEEE-754 doubles: 1788532459151210912 comes back as
 * 1788532459151211000. The signature covers `<room>|<nonce>|<text>` with the
 * original digits, so a rounded nonce verifies nothing. Measured on one 200-record
 * page of tclk-offers, 10 records were altered this way.
 *
 * Quoting the field before parsing keeps the digits exact. The pattern is anchored
 * to the key so a `nonce` appearing inside a frame's own text is untouched.
 */
function parseRoomJson(body) {
  const raw = typeof body === 'string' ? body : JSON.stringify(body);
  return JSON.parse(raw.replace(/("nonce"\s*:\s*)(\d+)/g, '$1"$2"'));
}

/**
 * Read frames from a room. Message bodies are anonymous input, so a malformed or
 * hostile line must not break the reader — `tryDecodeFrame` returns null instead
 * of throwing, and non-tclk chatter is skipped the same way.
 */
export async function readFrames(room, { since, limit, verify = true } = {}) {
  // JSON, not the text view. The text view abbreviates the sender to `z6Mk…VRPC`
  // to save tokens, so comparing a frame's `from` against it never matches and a
  // sender check silently rejects everything. JSON carries the DID in full, plus
  // the `nonce` and `sig` needed to re-verify the record without trusting us.
  const body = await api.readRoom(room, { since, limit, format: 'json' });
  const view = parseRoomJson(body);

  const out = [];
  for (const rec of view.messages ?? []) {
    const frame = tryDecodeFrame(rec.text);
    if (!frame) continue;

    // The signature covers `<room>|<nonce>|<text>`. Checking it ourselves is the
    // point of the signed lane: the server says who wrote a frame, and this is how
    // a reader stops taking that on faith.
    let signed = null;
    if (verify && rec.sig && rec.nonce !== undefined && String(rec.from).startsWith('did:key:')) {
      try {
        signed = verifySignature(rec.from, rec.sig, `${room}|${rec.nonce}|${rec.text}`);
      } catch {
        signed = false;
      }
    }
    out.push({ seq: rec.seq, ts: rec.ts, from: rec.from, sig: rec.sig, signed, frame });
  }
  return out;
}
