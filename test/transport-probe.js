// Which part of a Node `fetch` POST does the edge reject?
//
// technocore-chat#95 reports that POST via Node's global fetch (undici) gets a
// Cloudflare 502 after ~29s, while curl and node:https get the expected 400 for
// the same malformed body. That establishes a difference but not a cause.
//
// This isolates it by varying one thing at a time. Body is the malformed JSON `{`
// against /r/transport-probe — rejected before any room or message mutation, and
// carries no DID, signature or secret.
//
//   node test/transport-probe.js

import https from 'node:https';

const URL_ = 'https://technocore.chat/r/transport-probe';
const BODY = '{';

const ms = (t0) => `${String(Date.now() - t0).padStart(6)}ms`;

async function viaFetch(label, headers) {
  const t0 = Date.now();
  try {
    const res = await fetch(URL_, { method: 'POST', headers, body: BODY });
    const text = await res.text();
    return { label, t: ms(t0), status: res.status, hint: text.slice(0, 60).replace(/\s+/g, ' ') };
  } catch (err) {
    return { label, t: ms(t0), status: 'ERR', hint: `${err.name} ${err.cause?.code ?? ''}` };
  }
}

function viaHttps(label, headers) {
  const t0 = Date.now();
  return new Promise((resolve) => {
    const req = https.request(
      URL_,
      { method: 'POST', headers: { ...headers, 'content-length': Buffer.byteLength(BODY) } },
      (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () =>
          resolve({
            label,
            t: ms(t0),
            status: res.statusCode,
            hint: body.slice(0, 60).replace(/\s+/g, ' '),
          }),
        );
      },
    );
    req.on('error', (e) => resolve({ label, t: ms(t0), status: 'ERR', hint: `${e.name} ${e.code}` }));
    req.end(BODY);
  });
}

const JSON_CT = { 'content-type': 'application/json' };

// One variable at a time. If a curl-like UA fixes fetch, the edge is fingerprinting
// the client; if an explicit content-length fixes it, the framing is the trigger.
const CASES = [
  ['node:https baseline', () => viaHttps('node:https baseline', JSON_CT)],
  ['fetch baseline', () => viaFetch('fetch baseline', JSON_CT)],
  ['fetch + curl UA', () => viaFetch('fetch + curl UA', { ...JSON_CT, 'user-agent': 'curl/8.5.0' })],
  [
    'fetch + content-length',
    () => viaFetch('fetch + content-length', { ...JSON_CT, 'content-length': String(Buffer.byteLength(BODY)) }),
  ],
  ['fetch + accept */*', () => viaFetch('fetch + accept */*', { ...JSON_CT, accept: '*/*' })],
  ['fetch, no content-type', () => viaFetch('fetch, no content-type', {})],
  ['fetch + connection close', () => viaFetch('fetch + connection close', { ...JSON_CT, connection: 'close' })],
];

console.log(`Node ${process.version} · undici ${process.versions.undici ?? 'bundled'}`);
console.log(`POST ${URL_}  body ${JSON.stringify(BODY)}\n`);
console.log('case                      elapsed  status  response');
console.log('-'.repeat(78));

for (const [, run] of CASES) {
  const r = await run();
  console.log(`${r.label.padEnd(25)} ${r.t}  ${String(r.status).padEnd(6)}  ${r.hint}`);
  await new Promise((r) => setTimeout(r, 1500));
}

console.log(`
Reading: 400 is the correct answer (malformed JSON, refused before mutation).
A 502 after tens of seconds is the edge failing, not the application.`);
