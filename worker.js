/**
 * getstash.link: static assets + the STASH shares API.
 *
 * Authority for every value and status below:
 * link-saver `docs/superpowers/specs/2026-08-24-stash-short-share-links-design.md`
 * (§4 for this file, §1 for the envelope shape, §5 for the /s/<id> viewer path).
 * On any conflict the spec wins - do not "tidy" a status or a cap here.
 *
 * The server is deliberately blind: `s:<id>` holds an AES-128-GCM envelope whose
 * key never leaves the URL fragment, so nothing here can read a share. That is
 * the whole privacy argument - this file must never gain a decode path, a
 * redirect, or a route that reveals whether an id exists to someone who does not
 * already hold it.
 *
 * Everything outside /api/* is handed to the assets binding exactly as before
 * the Worker existed.
 */

// 22 base64url chars = the 16 random bytes ShortShareCodec generates.
const ID_RE = /^[A-Za-z0-9_-]{22}$/;
const SHORT_LINK_RE = /^\/s\/[A-Za-z0-9_-]{22}$/;

const SHARE_CONTENT_TYPE = 'application/vnd.stash-share.v1';
const ENVELOPE_MAX = 65536;     // spec §1 size cap, enforced app-side too
const SHARE_TTL = 604800;       // 7 days
const REPORT_TTL = 2592000;     // 30 days
const NOTE_MAX = 500;           // chars of reporter note kept
const REPORT_BODY_MAX = 8192;   // an {id, note<=500} body is well under 1KB

// Both caps are approximate BY DESIGN (spec §4): KV counters race, and that is
// accepted - they are friction against a flood, not a quota anyone can bank on.
const IP_CAP = 30;
const IP_TTL = 3600;
const DAY_CAP = 500;
const DAY_TTL = 90000;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/api' || url.pathname.startsWith('/api/')) {
      try {
        return await handleAPI(request, url, env);
      } catch (err) {
        // A KV failure must not leak an exception page onto a branded domain -
        // but it must not vanish either. Caught exceptions are not logged for
        // us, so without this line a KV outage is an opaque 500 with nothing in
        // `wrangler tail`. console.error never reaches the client.
        console.error(err);
        return json({ error: 'internal' }, 500);
      }
    }

    // Spec §5: /s/<id> is a virtual path - no such asset exists, and the id
    // belongs to the viewer's JS, not to the server. Serve the viewer document
    // itself; the fragment key never reaches us either way.
    if (SHORT_LINK_RE.test(url.pathname)) {
      const viewer = new URL(url);
      viewer.pathname = '/s/';
      return env.ASSETS.fetch(new Request(viewer.toString(), request));
    }

    return env.ASSETS.fetch(request);
  },
};

function handleAPI(request, url, env) {
  const path = url.pathname;

  if (path === '/api/share') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    return createShare(request, env);
  }

  if (path.startsWith('/api/share/')) {
    const id = path.slice('/api/share/'.length);
    if (request.method === 'GET') return readShare(id, env);
    if (request.method === 'DELETE') return deleteShare(request, id, env);
    return methodNotAllowed('GET, DELETE');
  }

  if (path === '/api/report') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    return recordReport(request, env);
  }

  return json({ error: 'not_found' }, 404);
}

/**
 * POST /api/share - store one envelope for 7 days.
 *
 * Check order is the spec's order: shape, then size, then kill switch, then
 * caps, then collision. Nothing is written until all of them pass.
 */
async function createShare(request, env) {
  const contentType = (request.headers.get('Content-Type') || '').split(';')[0].trim().toLowerCase();
  if (contentType !== SHARE_CONTENT_TYPE) return json({ error: 'bad_content_type' }, 400);

  const id = request.headers.get('X-Stash-Share-Id') || '';
  if (!ID_RE.test(id)) return json({ error: 'bad_id' }, 400);

  // Content-Length is a courtesy check only - a lying or absent header is
  // caught by the bounded read below, which never buffers past the cap.
  const declared = request.headers.get('Content-Length');
  if (declared !== null) {
    const n = Number(declared);
    if (!Number.isInteger(n) || n < 0) return json({ error: 'bad_length' }, 400);
    if (n > ENVELOPE_MAX) return json({ error: 'too_large' }, 413);
    if (n === 0) return json({ error: 'empty' }, 400);
  }

  const read = await readBounded(request, ENVELOPE_MAX);
  if (read.over) return json({ error: 'too_large' }, 413);
  if (read.bytes.byteLength === 0) return json({ error: 'empty' }, 400);

  if ((env.SHARES_DISABLED || '0') === '1') return json({ error: 'disabled' }, 503);

  const now = new Date();
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const ipKey = `ip:${ip}:${now.toISOString().slice(0, 13)}`;   // ip:<addr>:<YYYY-MM-DDTHH> UTC
  const dayKey = `day:${now.toISOString().slice(0, 10)}`;       // day:<YYYY-MM-DD> UTC

  const [ipCount, dayCount] = await Promise.all([counter(env, ipKey), counter(env, dayKey)]);
  if (ipCount >= IP_CAP) return json({ error: 'rate_limited' }, 429);
  if (dayCount >= DAY_CAP) return json({ error: 'rate_limited' }, 429);

  // 128-bit ids do not collide; a hit here means the client reused an id or the
  // CSPRNG failed. Either way the stored envelope is never overwritten.
  const existing = await env.SHARES.get(`s:${id}`, { type: 'arrayBuffer' });
  if (existing !== null) return json({ error: 'exists' }, 409);

  const token = base64url(crypto.getRandomValues(new Uint8Array(16)));
  const tokenHash = await sha256Hex(token);

  // Sequential, and the deletion token goes FIRST - do not "optimize" these back
  // into a Promise.all. If the second write fails, the orphan left behind should
  // be a `d:`: a hash of a token for a share that does not exist, harmless and
  // gone in 7 days. The reverse order orphans an envelope nobody can revoke -
  // stored for the full 7 days, clearable only by an operator tombstone, while
  // the client sees a failure and silently falls back to a fragment link.
  await env.SHARES.put(`d:${id}`, tokenHash, { expirationTtl: SHARE_TTL });
  await env.SHARES.put(`s:${id}`, read.bytes, { expirationTtl: SHARE_TTL });

  // Counters move only for shares that actually landed in KV: the caps exist to
  // bound stored data, and a rejected request stores nothing. A failure to bump
  // is swallowed on purpose - one uncounted create against a cap that is already
  // approximate beats 500ing a share that is sitting in KV, which would strand
  // the envelope for 7 days AND hand the user the fallback link.
  try {
    await Promise.all([
      env.SHARES.put(ipKey, String(ipCount + 1), { expirationTtl: IP_TTL }),
      env.SHARES.put(dayKey, String(dayCount + 1), { expirationTtl: DAY_TTL }),
    ]);
  } catch (err) {
    console.error(err);
  }

  return json({ deletionToken: token }, 201);
}

/**
 * GET /api/share/<id> - the envelope bytes, or 410 once an operator has
 * tombstoned it. A malformed id is a miss, not a 400: the spec pins three
 * outcomes for this route and inventing a fourth would answer a question the
 * caller has no business asking.
 */
async function readShare(id, env) {
  if (!ID_RE.test(id)) return json({ error: 'not_found' }, 404);

  const tombstone = await env.SHARES.get(`t:${id}`);
  if (tombstone !== null) return json({ error: 'gone' }, 410);

  const envelope = await env.SHARES.get(`s:${id}`, { type: 'arrayBuffer' });
  if (envelope === null) return json({ error: 'not_found' }, 404);

  return new Response(envelope, {
    status: 200,
    headers: {
      'Content-Type': 'application/octet-stream',
      'Cache-Control': 'no-store',
    },
  });
}

/**
 * DELETE /api/share/<id> - sender revocation (stored today, surfaced later) and
 * the operator's fast path. Anything short of the right token is 403, including
 * a share that never existed, so this is not an existence oracle either.
 */
async function deleteShare(request, id, env) {
  const token = request.headers.get('X-Stash-Delete-Token') || '';
  if (!ID_RE.test(id) || token === '') return json({ error: 'forbidden' }, 403);

  const stored = await env.SHARES.get(`d:${id}`);
  if (stored === null) return json({ error: 'forbidden' }, 403);
  if (!constantTimeEqual(stored, await sha256Hex(token))) return json({ error: 'forbidden' }, 403);

  await Promise.all([env.SHARES.delete(`s:${id}`), env.SHARES.delete(`d:${id}`)]);
  return new Response(null, { status: 204, headers: { 'Cache-Control': 'no-store' } });
}

/**
 * POST /api/report - always 202, whatever happens. A different answer for an
 * unknown id would turn the report button into an id-probing tool, so a
 * malformed body, an unknown id and a stored report are indistinguishable from
 * outside. Reports are unauthenticated by design; the note cap and the 30-day
 * TTL are what bound the damage.
 */
async function recordReport(request, env) {
  try {
    const read = await readBounded(request, REPORT_BODY_MAX);
    if (!read.over && read.bytes.byteLength > 0) {
      const body = JSON.parse(new TextDecoder().decode(read.bytes));
      const id = body && typeof body.id === 'string' ? body.id : '';
      if (ID_RE.test(id)) {
        const note = body && typeof body.note === 'string' ? body.note.slice(0, NOTE_MAX) : '';
        await env.SHARES.put(`r:${id}:${Date.now()}`, note, { expirationTtl: REPORT_TTL });
      }
    }
  } catch (err) {
    // Bad JSON, KV trouble, anything: the caller still hears 202. Logged
    // because the silent case that matters is a KV outage quietly dropping
    // every report on the floor; a malformed body logging too is cheap.
    console.error(err);
  }
  return new Response(null, { status: 202, headers: { 'Cache-Control': 'no-store' } });
}

/**
 * Read the body without ever buffering more than `max` bytes, so an unbounded
 * or misdeclared upload costs us one chunk, not its own size in memory.
 */
async function readBounded(request, max) {
  if (!request.body) return { over: false, bytes: new Uint8Array(0) };

  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel();
      return { over: true, bytes: new Uint8Array(0) };
    }
    chunks.push(value);
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { over: false, bytes };
}

async function counter(env, key) {
  const raw = await env.SHARES.get(key);
  if (raw === null) return 0;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

function base64url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Both sides are always SHA-256 hex digests, never the token itself, so a timing
 * leak here would reveal digest bytes an attacker cannot invert back into a
 * token - this is not load-bearing. It stays anyway because it costs nothing and
 * a plain `===` would be one refactor away from being wrong the day someone
 * compares a raw secret with it.
 */
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function json(body, status, extraHeaders) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      ...extraHeaders,
    },
  });
}

function methodNotAllowed(allow) {
  return json({ error: 'method_not_allowed' }, 405, { Allow: allow });
}
