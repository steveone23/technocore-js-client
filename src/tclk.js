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
import { signMessage, nextNonce } from './did.js';

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
 * Read frames from a room. Message bodies are anonymous input, so a malformed or
 * hostile line must not break the reader — `tryDecodeFrame` returns null instead
 * of throwing, and non-tclk chatter is skipped the same way.
 */
export async function readFrames(room, { since, limit } = {}) {
  const body = await api.readRoom(room, { since, limit });
  const out = [];
  for (const line of String(body).split('\n')) {
    if (!line.startsWith('[')) continue;
    const m = /^\[(\d+)\]\s+(\S+)\s+<([^>]*)>\s(.*)$/.exec(line);
    if (!m) continue;
    const frame = tryDecodeFrame(m[4]);
    if (frame) out.push({ seq: Number(m[1]), ts: m[2], from: m[3], frame });
  }
  return out;
}
