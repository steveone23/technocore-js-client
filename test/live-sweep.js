// Empirical check of the single-line sweep against the live server.
// Network test, so it is not part of `npm test`: node test/live-sweep.js
//
// Posts one message per swept Unicode category into an ephemeral room (15 min
// TTL, never enumerated) and compares what comes back against our local sweep.
// A mismatch means our signature would cover bytes the server did not store.

import * as store from '../src/store.js';
import * as api from '../src/client.js';
import { signMessage, singleLineSweep } from '../src/did.js';

const ROOM = `e-sweepcheck-${Date.now().toString(36)}`;

const CASES = [
  ['Cc  C0 control', 'ab'],
  ['Cc  newline', 'a\nb'],
  ['Cf  zero-width space', 'a​b'],
  ['Cf  ZWJ', 'a‍b'],
  ['Cf  bidi override', 'a\u202Eb'],
  ['Co  private use', 'ab'],
  ['Zl  line separator', 'a b'],
  ['Zp  paragraph separator', 'a b'],
  ['Zs  nbsp (NOT swept)', 'a b'],
  ['trim  leading/trailing', '  a b  '],
  ['trim  control at ends', 'a b'],
];

const show = (s) =>
  JSON.stringify(s).replace(/[-￿]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);

const id = store.load();
console.log(`room ${ROOM}`);
console.log(`did  ${id.did}\n`);

let pass = 0;
let fail = 0;

for (const [label, raw] of CASES) {
  const expected = singleLineSweep(raw);
  const payload = signMessage({ privateKey: id.privateKey, room: ROOM, nonce: Date.now(), text: raw });

  let stored;
  try {
    await api.saySigned(ROOM, { did: id.did, ...payload });
    const body = await api.readRoom(ROOM, { since: 0 });
    const lines = String(body).trim().split('\n');
    const last = lines.filter((l) => l.startsWith('[')).at(-1) ?? '';
    stored = last.replace(/^\[\d+\]\s+\S+\s+<[^>]*>\s/, '');
  } catch (err) {
    console.log(`FAIL ${label}\n     server rejected: ${err.message}\n`);
    fail++;
    continue;
  }

  if (stored === expected) {
    console.log(`ok   ${label.padEnd(26)} ${show(raw)} -> ${show(stored)}`);
    pass++;
  } else {
    console.log(`FAIL ${label}`);
    console.log(`     raw      ${show(raw)}`);
    console.log(`     expected ${show(expected)}`);
    console.log(`     stored   ${show(stored)}\n`);
    fail++;
  }
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
