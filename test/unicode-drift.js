// How much can the swept set actually drift between Unicode versions?
//
// Raised on flop-labs/technocore-chat#75: Node's \p{gc=...} reads its host's
// Unicode database, so two runtimes can disagree about what INVISIBLE_CATEGORIES
// contains, and a disagreement means a signature covering bytes the server did
// not store — a 403 with no explanation.
//
// True in principle. This measures the exposure, and checks whether the frozen
// categories can be pinned as literal ranges so only the moving one is left
// depending on the runtime.
//
//   node test/unicode-drift.js

import { createHash } from 'node:crypto';

const MAX = 0x10ffff;
const cp2s = (cp) => (cp <= 0xffff ? String.fromCharCode(cp) : String.fromCodePoint(cp));

/** Every codepoint the runtime assigns to `cat`, as sorted [start, end] ranges. */
function rangesOf(cat) {
  const re = new RegExp(`\\p{gc=${cat}}`, 'u');
  const ranges = [];
  let start = null;
  for (let cp = 0; cp <= MAX; cp++) {
    if (re.test(cp2s(cp))) {
      if (start === null) start = cp;
    } else if (start !== null) {
      ranges.push([start, cp - 1]);
      start = null;
    }
  }
  if (start !== null) ranges.push([start, MAX]);
  return ranges;
}

const size = (rs) => rs.reduce((n, [a, b]) => n + (b - a + 1), 0);
const hex = (cp) => 'U+' + cp.toString(16).toUpperCase().padStart(4, '0');
const show = (rs) => rs.map(([a, b]) => (a === b ? hex(a) : `${hex(a)}..${hex(b)}`)).join(' ');

/**
 * A digest of the exact membership, not of its size. Two Unicode versions can
 * agree on a count while disagreeing about which codepoints are in it, and
 * comparing counts across runtimes would call that a match. Run this on several
 * runtimes and compare digests to see real drift.
 */
const digest = (rs) =>
  createHash('sha256')
    .update(rs.map(([a, b]) => `${a}-${b}`).join(','))
    .digest('hex')
    .slice(0, 12);

console.log(`Node ${process.version} · Unicode ${process.versions.unicode}\n`);

const CATEGORIES = ['Cc', 'Cf', 'Cs', 'Co', 'Zl', 'Zp'];
const actual = {};
for (const cat of CATEGORIES) actual[cat] = rangesOf(cat);

console.log('category  codepoints  digest        ranges');
for (const cat of CATEGORIES) {
  console.log(
    `  ${cat}     ${String(size(actual[cat])).padStart(6)}  ${digest(actual[cat])}  ` +
      show(actual[cat]).slice(0, 44),
  );
}
console.log(`  total  ${String(CATEGORIES.reduce((n, c) => n + size(actual[c]), 0)).padStart(6)}`);

// The claim under test: five of the six are fixed by Unicode's stability policy,
// so they can be written as literals and stop depending on the runtime's tables.
const PINNED = {
  Cc: [[0x0000, 0x001f], [0x007f, 0x009f]],
  Cs: [[0xd800, 0xdfff]],
  Zl: [[0x2028, 0x2028]],
  Zp: [[0x2029, 0x2029]],
  Co: [[0xe000, 0xf8ff], [0xf0000, 0xffffd], [0x100000, 0x10fffd]],
};

console.log('\npinned literal ranges vs this runtime\'s tables:');
let allMatch = true;
for (const [cat, pinned] of Object.entries(PINNED)) {
  const match = JSON.stringify(pinned) === JSON.stringify(actual[cat]);
  if (!match) allMatch = false;
  console.log(`  ${cat}  ${match ? 'exact match' : 'MISMATCH'}`);
  if (!match) {
    console.log(`      pinned  ${show(pinned)}`);
    console.log(`      runtime ${show(actual[cat])}`);
  }
}

console.log(`
Result: ${allMatch ? 'all five frozen categories reproduce exactly as literals.' : 'a pinned range disagrees with this runtime — investigate.'}

Cf is the only category left that needs the runtime's Unicode tables, and it is
${size(actual.Cf)} codepoints here. Unicode's stability policy makes assignment
append-only, so a newer runtime sweeps a superset, never a different set, and the
practical exposure between any two runtimes is the handful of format characters
assigned between their Unicode versions.

Caveat: measured on one runtime. A cross-version delta cannot be observed from a
single Node, so the direction of drift is argued from the stability policy, not
measured here.`);
