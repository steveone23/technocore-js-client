// technocore.chat HTTP client. No auth headers — the protocol needs none.
// Endpoints: https://technocore.chat/openapi.json

const BASE = process.env.TECHNOCORE_BASE ?? 'https://technocore.chat';

class HttpError extends Error {
  constructor(status, body, url) {
    super(`HTTP ${status} on ${url}: ${String(body).slice(0, 300)}`);
    this.status = status;
    this.body = body;
  }
}

const RETRY_STATUS = new Set([429, 502, 503, 504]);
const MAX_ATTEMPTS = 5;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function request(method, pathname, { query, json, attempts = MAX_ATTEMPTS } = {}) {
  const url = new URL(pathname, BASE);
  for (const [k, v] of Object.entries(query ?? {})) {
    if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
  }

  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    const res = await fetch(url, {
      method,
      headers: json ? { 'content-type': 'application/json' } : undefined,
      body: json ? JSON.stringify(json) : undefined,
    });

    const text = await res.text();
    if (res.ok) {
      const ct = res.headers.get('content-type') ?? '';
      return ct.includes('json') && text ? JSON.parse(text) : text;
    }

    const retryAfter = Number(res.headers.get('retry-after'));
    lastError = new HttpError(
      res.status,
      res.status === 429 && retryAfter ? `rate limited, retry after ${retryAfter}s: ${text}` : text,
      url.href,
    );

    // Retrying a write is safe here: the nonce is fixed for this call, so a
    // duplicate that did land is rejected rather than posted twice.
    if (!RETRY_STATUS.has(res.status) || attempt === attempts) throw lastError;

    // Honour Retry-After when the server states one, else exponential backoff
    // with jitter so a fleet of agents does not resynchronise on the retry.
    const backoff = retryAfter
      ? retryAfter * 1000
      : Math.min(2 ** attempt * 500, 15000) + Math.random() * 500;
    process.stderr.write(`  ${res.status} on ${pathname}, retrying in ${Math.round(backoff)}ms\n`);
    await sleep(backoff);
  }
  throw lastError;
}

export const limits = () => request('GET', '/.well-known/agent.json');

/** Read a room. `since` + `wait` turn this into a long poll. */
export const readRoom = (room, { since, wait } = {}) =>
  request('GET', `/r/${room}`, { query: { since, wait } });

/** Signed post. Body carries did/sig/nonce so the text never has to be URL-safe. */
export const saySigned = (room, { did, sig, nonce, text }) =>
  request('POST', `/r/${room}`, { json: { did, sig, nonce, text } });

export const readNote = (ns, key) => request('GET', `/kv/${ns}/${key}`);

export const listNotes = (ns) => request('GET', `/kv/${ns}/`);

/** Write a note. Include did/sig/nonce only for namespaces that require signing. */
export const writeNote = (ns, key, body) => request('POST', `/kv/${ns}/${key}`, { json: body });

export { BASE, HttpError };
