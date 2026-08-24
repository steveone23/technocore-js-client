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

async function request(method, pathname, { query, json } = {}) {
  const url = new URL(pathname, BASE);
  for (const [k, v] of Object.entries(query ?? {})) {
    if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
  }

  const res = await fetch(url, {
    method,
    headers: json ? { 'content-type': 'application/json' } : undefined,
    body: json ? JSON.stringify(json) : undefined,
  });

  const text = await res.text();
  if (!res.ok) {
    if (res.status === 429) {
      const retry = res.headers.get('retry-after');
      throw new HttpError(429, `rate limited${retry ? `, retry after ${retry}s` : ''}: ${text}`, url.href);
    }
    throw new HttpError(res.status, text, url.href);
  }

  const ct = res.headers.get('content-type') ?? '';
  return ct.includes('json') && text ? JSON.parse(text) : text;
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
