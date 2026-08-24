// Do the two signed write lanes accept the same texts?
//
//   GET  /r/<room>/say-signed/<did>/<sig>/<nonce>/<text>   text is a path segment
//   POST /r/<room>                                          text is a JSON field
//
// The signature covers the same bytes either way, so any divergence is the
// transport, not the protocol. A path segment cannot carry every string a JSON
// field can, and a client author picking the GET lane (the one the service
// advertises as sufficient) needs to know which strings those are.
//
// Network test: node test/live-lane-parity.js

import * as store from '../src/store.js';
import * as api from '../src/client.js';
import { signMessage, singleLineSweep } from '../src/did.js';

const ROOM = `e-parity-${Date.now().toString(36)}`;

// Each is legal in a message (4096 chars, any text) but awkward in a path segment.
const CASES = [
  ['plain', 'hello parity'],
  ['space', 'a b'],
  ['slash', 'a/b'],
  ['percent', 'a%b'],
  ['hash', 'a#b'],
  ['question', 'a?b'],
  ['plus', 'a+b'],
  ['backslash', 'a\\b'],
  ['dot-segment', 'a/../b'],
  ['double-slash', 'a//b'],
  ['ampersand', 'a&b'],
  ['unicode', 'héllo ✓'],
];

const id = store.load();

/** GET lane: every segment percent-encoded, including the text. */
async function viaGet(room, { did, sig, nonce, text }) {
  const seg = encodeURIComponent(text);
  const res = await api.rawGet(`/r/${room}/say-signed/${did}/${sig}/${nonce}/${seg}`);
  return res;
}

async function storedText(room) {
  const body = await api.readRoom(room, { since: 0 });
  const lines = String(body).split('\n').filter((l) => l.startsWith('['));
  const last = lines.at(-1) ?? '';
  return last.replace(/^\[\d+\]\s+\S+\s+<[^>]*>\s/, '');
}

console.log(`room ${ROOM}`);
console.log(`did  ${id.did}\n`);
console.log('case            GET lane              POST lane             agree');
console.log('-'.repeat(72));

for (const [label, raw] of CASES) {
  const expected = singleLineSweep(raw);
  const results = {};

  for (const lane of ['get', 'post']) {
    const payload = signMessage({ privateKey: id.privateKey, room: ROOM, nonce: Date.now(), text: raw });
    try {
      if (lane === 'get') await viaGet(ROOM, { did: id.did, ...payload });
      else await api.saySigned(ROOM, { did: id.did, ...payload });

      const got = await storedText(ROOM);
      results[lane] = got === expected ? 'ok' : `stored ${JSON.stringify(got)}`;
    } catch (err) {
      const m = /HTTP (\d+)/.exec(err.message);
      results[lane] = m ? `HTTP ${m[1]}` : err.message.slice(0, 18);
    }
    await new Promise((r) => setTimeout(r, 400));
  }

  const agree = results.get === results.post ? '' : '  <-- DIVERGES';
  console.log(
    `${label.padEnd(15)} ${results.get.padEnd(21)} ${results.post.padEnd(21)} ${
      results.get === results.post ? 'yes' : 'NO'
    }${agree}`,
  );
}
