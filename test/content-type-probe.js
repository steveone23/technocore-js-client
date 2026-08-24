// Does a non-JSON content-type on a POST get a Cloudflare 502 instead of an
// application-level refusal?
//
// Fell out of the technocore-chat#95 reproduction: a fetch POST with no explicit
// content-type returned 502 in ~300ms, while the same body with
// `application/json` returned the correct 400. Node's fetch stamps a string body
// with `text/plain;charset=UTF-8` when the caller sets nothing, so the variable
// is the content-type, not the client.
//
// Body is malformed JSON against /r/transport-probe: refused before any mutation,
// no DID, signature or secret.
//
//   node test/content-type-probe.js

import https from 'node:https';

const URL_ = 'https://technocore.chat/r/transport-probe';
const BODY = '{';
const REPEATS = 3;

const TYPES = [
  'application/json',
  'text/plain;charset=UTF-8', // what fetch sends when you set nothing
  'text/plain',
  'application/x-www-form-urlencoded',
  null, // omitted entirely (node:https only; fetch will substitute text/plain)
];

function viaHttps(ct) {
  const t0 = Date.now();
  const headers = { 'content-length': Buffer.byteLength(BODY) };
  if (ct) headers['content-type'] = ct;
  return new Promise((resolve) => {
    const req = https.request(URL_, { method: 'POST', headers }, (res) => {
      let b = '';
      res.on('data', (c) => (b += c));
      res.on('end', () => resolve({ t: Date.now() - t0, status: res.statusCode, body: b }));
    });
    req.on('error', (e) => resolve({ t: Date.now() - t0, status: 'ERR', body: e.code }));
    req.end(BODY);
  });
}

async function viaFetch(ct) {
  const t0 = Date.now();
  try {
    const res = await fetch(URL_, {
      method: 'POST',
      headers: ct ? { 'content-type': ct } : {},
      body: BODY,
    });
    return { t: Date.now() - t0, status: res.status, body: await res.text() };
  } catch (e) {
    return { t: Date.now() - t0, status: 'ERR', body: e.cause?.code ?? e.name };
  }
}

const kind = (r) =>
  r.status === 502 || String(r.body).startsWith('<!DOCTYPE') ? 'CF 502 HTML' : `app ${r.status}`;

console.log(`Node ${process.version} · undici ${process.versions.undici ?? 'bundled'}`);
console.log(`POST ${URL_}  body ${JSON.stringify(BODY)}  ${REPEATS} runs each\n`);
console.log('content-type                        client      results');
console.log('-'.repeat(76));

for (const ct of TYPES) {
  for (const [name, run] of [['fetch', viaFetch], ['node:https', viaHttps]]) {
    if (ct === null && name === 'fetch') continue; // fetch cannot omit it for a string body
    const out = [];
    for (let i = 0; i < REPEATS; i++) {
      out.push(kind(await run(ct)));
      await new Promise((r) => setTimeout(r, 1200));
    }
    console.log(`${String(ct ?? '(omitted)').padEnd(35)} ${name.padEnd(11)} ${out.join('  ')}`);
  }
}
