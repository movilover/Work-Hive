/**
 * lib/owa.mjs — offerwall.ad bridge for the WorkHive admin panel (Vercel Functions).
 *
 *   /api/offers    GET   Admin-only. Proxies offerwall.ad (Bearer key stays on the server).
 *   /api/postback  POST  offerwall.ad S2S webhook. HMAC-SHA256 verified, idempotent, credits users/{subid}.
 *   /api/go        GET   Optional click bridge (linkMode = bridge).
 *   /api/health    GET
 *
 * Environment variables (Vercel → Settings → Environment Variables): see ENV-VARIABLES.md
 *
 * ASSUMPTIONS TO CONFIRM against your offerwall.ad dashboard docs (they are isolated in the
 * `FIELD ALIASES` block + verifySignature so they take one line to change):
 *   1. Signature = HMAC-SHA256(webhookSecret, RAW request body), hex (optionally "sha256=" prefixed) or base64.
 *   2. Webhook is a POST with JSON; event names conversion.approved / conversion.held / conversion.rejected|reversed.
 *   3. `subid` in the webhook is the value we sent when fetching offers (= the Firestore users/{uid} id).
 */

const NETWORK = 'offerwallad';
const SUBID_SENTINEL = '__SUBID__';
const enc = new TextEncoder();
const dec = new TextDecoder();

/* ───────────────────────── generic helpers ───────────────────────── */

const json = (data, status = 200, extra = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extra },
  });

/** Firestore-safe document key. MUST match docKey() in the admin panel patch. */
export const docKey = (v) => String(v).replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 200);
export const round4 = (n) => Math.round(n * 1e4) / 1e4;

function b64urlToBytes(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
function bytesToB64url(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
const strToB64url = (s) => bytesToB64url(enc.encode(s));

function corsHeaders(req, env) {
  const origin = req.headers.get('Origin') || '';
  const allowed = (env.ALLOWED_ORIGIN || '').split(',').map((s) => s.trim()).filter(Boolean);
  if (!allowed.includes(origin)) return {};
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Max-Age': '600',
    Vary: 'Origin',
  };
}

/* ───────────────────── 1. webhook signature (HMAC-SHA256) ───────────────────── */

function decodeSignature(header) {
  let sig = String(header || '').trim();
  if (/^sha256=/i.test(sig)) sig = sig.slice(7);
  if (/^[0-9a-fA-F]{64}$/.test(sig)) {
    return Uint8Array.from(sig.match(/../g).map((h) => parseInt(h, 16)));
  }
  try { // base64 / base64url variant
    const bytes = b64urlToBytes(sig);
    return bytes.length === 32 ? bytes : null;
  } catch { return null; }
}

/**
 * Verifies HMAC-SHA256(secret, rawBody) against the X-Offerwall-Ad-Signature header.
 * crypto.subtle.verify performs a constant-time comparison. `rawBody` MUST be the untouched bytes.
 */
export async function verifySignature(secret, rawBody, header) {
  if (!secret || !header) return false;
  const sigBytes = decodeSignature(header);
  if (!sigBytes) return false;
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  return crypto.subtle.verify('HMAC', key, sigBytes, rawBody);
}

/* ───────────────────── 2. payload parsing (FIELD ALIASES) ───────────────────── */

const ALIASES = {
  event: ['event', 'type', 'event_type'],
  conversionId: ['conversion_id', 'transaction_id', 'txid', 'tx_id', 'lead_id'],
  subid: ['subid', 'sub_id', 'user_id', 's1'],
  offerId: ['offer_id', 'offerId', 'campaign_id'],
  payout: ['payout', 'payout_usd', 'amount', 'revenue', 'reward'],
};

export function parseWebhook(body) {
  const data = body && typeof body.data === 'object' && body.data ? body.data : {};
  const pick = (names) => {
    for (const src of [data, body || {}]) {
      for (const k of names) if (src[k] != null && src[k] !== '') return src[k];
    }
    return undefined;
  };
  const rawEvent = String(pick(ALIASES.event) || body?.status || '').toLowerCase();
  let kind = 'other';
  if (/approved|completed|success/.test(rawEvent)) kind = 'approved';
  else if (/held|hold|pending/.test(rawEvent)) kind = 'held';
  else if (/reject|revers|chargeback|declin|fraud|cancel/.test(rawEvent)) kind = 'reversed';

  const payout = Number(pick(ALIASES.payout));
  return {
    rawEvent,
    kind,
    conversionId: pick(ALIASES.conversionId) != null ? String(pick(ALIASES.conversionId)) : '',
    subid: pick(ALIASES.subid) != null ? String(pick(ALIASES.subid)) : '',
    offerId: pick(ALIASES.offerId) != null ? String(pick(ALIASES.offerId)) : '',
    payout: Number.isFinite(payout) && payout >= 0 ? payout : 0,
  };
}

/** Firestore doc ids can't contain "/" etc. — a subid is used as users/{subid}, so validate strictly. */
export const isSafeUid = (s) => /^[A-Za-z0-9_-]{1,128}$/.test(s);

/**
 * State machine. existing = status of cpaPostbacks/{id} or undefined when the conversion is new.
 * Only ONE path ever credits money: (new|held) --approved--> credited. Everything else is a no-op or bookkeeping.
 */
export function decide(existing, kind) {
  if (kind === 'other') return { action: 'noop' }; // informational events (created/clicked/...) never touch state
  if (existing === undefined) {
    if (kind === 'approved') return { action: 'create', status: 'credited', credit: true };
    if (kind === 'held') return { action: 'create', status: 'held', credit: false };
    return { action: 'create', status: 'reversed', credit: false }; // kind === 'reversed'
  }
  if (existing === 'held') {
    if (kind === 'approved') return { action: 'update', status: 'credited', credit: true };
    if (kind === 'reversed') return { action: 'update', status: 'reversed', credit: false };
    return { action: 'noop' };
  }
  // A reversal AFTER we credited is flagged for a human; we never auto-claw-back (balance may be withdrawn already).
  if (existing === 'credited' && kind === 'reversed') return { action: 'update', status: 'reversed_after_credit', credit: false };
  return { action: 'noop' }; // credited / pending / failed / reversed: terminal for the webhook
}

/* ───────────────────── 3. Firestore REST (service account) ───────────────────── */

let tokenCache = { token: null, exp: 0 };
export const _resetCaches = () => { tokenCache = { token: null, exp: 0 }; jwkCache = { keys: null, exp: 0 }; };

async function getAccessToken(env) {
  const now = Math.floor(Date.now() / 1000);
  if (tokenCache.token && tokenCache.exp - 60 > now) return tokenCache.token;
  const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
  const unsigned =
    strToB64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' })) + '.' +
    strToB64url(JSON.stringify({
      iss: sa.client_email, scope: 'https://www.googleapis.com/auth/datastore',
      aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600,
    }));
  const pem = sa.private_key.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, '');
  const key = await crypto.subtle.importKey(
    'pkcs8', Uint8Array.from(atob(pem), (c) => c.charCodeAt(0)),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign'],
  );
  const sig = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc.encode(unsigned)));
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: unsigned + '.' + bytesToB64url(sig) }),
  });
  if (!res.ok) throw new Error('google_token_' + res.status);
  const j = await res.json();
  tokenCache = { token: j.access_token, exp: now + (j.expires_in || 3600) };
  return tokenCache.token;
}

const fsRoot = (env) => `projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents`;
const docName = (env, path) => `${fsRoot(env)}/${path}`;

function fv(v) {
  if (v === null || v === undefined) return { nullValue: null };
  if (typeof v === 'string') return { stringValue: v };
  if (typeof v === 'boolean') return { booleanValue: v };
  if (typeof v === 'number') return { doubleValue: v };
  if (Array.isArray(v)) return { arrayValue: { values: v.map(fv) } };
  return { mapValue: { fields: toFields(v) } };
}
const toFields = (o) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, fv(v)]));
export const numField = (f) => (f && f.doubleValue != null ? Number(f.doubleValue) : f && f.integerValue != null ? Number(f.integerValue) : NaN);

async function fsGet(env, path) {
  const res = await fetch(`https://firestore.googleapis.com/v1/${docName(env, path)}`, {
    headers: { Authorization: `Bearer ${await getAccessToken(env)}` },
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`firestore_get_${res.status}`);
  return res.json(); // { name, fields, updateTime }
}

/** Atomic multi-write commit. Returns {ok:true} | {ok:false, conflict:true} on precondition failure. */
async function fsCommit(env, writes) {
  const res = await fetch(`https://firestore.googleapis.com/v1/${fsRoot(env)}:commit`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${await getAccessToken(env)}`, 'content-type': 'application/json' },
    body: JSON.stringify({ writes }),
  });
  if (res.ok) return { ok: true };
  let status = '';
  try { status = (await res.json()).error?.status || ''; } catch { /* ignore */ }
  if (['ALREADY_EXISTS', 'FAILED_PRECONDITION', 'ABORTED', 'NOT_FOUND'].includes(status)) return { ok: false, conflict: true, status };
  throw new Error(`firestore_commit_${res.status}_${status}`);
}

const randomId = () => bytesToB64url(crypto.getRandomValues(new Uint8Array(15)));

/* ───────────────────── 4. POST /postback ───────────────────── */

async function resolveReward(env, c) {
  const share = Number(env.DEFAULT_SHARE_PCT) || 60;
  const maxAuto = Number(env.MAX_AUTO_CREDIT) || 25;
  const suggested = round4((c.payout * share) / 100);
  const task = c.offerId ? await fsGet(env, `cpaTasks/${NETWORK}_${docKey(c.offerId)}`) : null;
  const custom = task ? numField(task.fields?.customPayout) : NaN;
  if (!(custom > 0)) return { amount: suggested, auto: false, why: 'no_custom_reward' };
  if (custom > maxAuto) return { amount: round4(custom), auto: false, why: 'above_max_auto_credit' };
  return { amount: round4(custom), auto: true };
}

export async function handlePostback(req, env) {
  if (req.method !== 'POST') return json({ ok: false, error: 'method_not_allowed' }, 405);

  if (Number(req.headers.get('content-length')) > 64 * 1024) return json({ ok: false, error: 'payload_too_large' }, 413);
  const raw = await req.arrayBuffer();
  if (raw.byteLength > 64 * 1024) return json({ ok: false, error: 'payload_too_large' }, 413);

  // Authenticate BEFORE touching the body or the database.
  const valid = await verifySignature(env.OFFERWALL_WEBHOOK_SECRET, raw, req.headers.get('X-Offerwall-Ad-Signature'));
  if (!valid) {
    console.warn('postback rejected: invalid signature');
    return json({ ok: false, error: 'invalid_signature' }, 401);
  }

  let body;
  try { body = JSON.parse(dec.decode(raw)); } catch { return json({ ok: false, error: 'invalid_json' }, 400); }
  const c = parseWebhook(body);
  const payloadText = dec.decode(raw).slice(0, 4000);
  if (c.kind === 'other') return json({ ok: true, ignored: true, event: c.rawEvent });
  if (!c.conversionId) return json({ ok: false, error: 'missing_conversion_id' }, 400);

  const convPath = `cpaPostbacks/${NETWORK}_${docKey(c.conversionId)}`;
  const convName = docName(env, convPath);
  const base = {
    network: NETWORK, transactionId: c.conversionId, userId: c.subid.slice(0, 200), offerId: c.offerId.slice(0, 200),
    event: c.rawEvent, rawPayout: c.payout, source: 'webhook', signatureVerified: true, payload: payloadText,
  };

  // Authentic but unusable (bad/missing subid): keep an audit row for the admin, tell the network "received".
  if (!isSafeUid(c.subid)) {
    await fsCommit(env, [{
      update: { name: convName, fields: toFields({ ...base, amount: 0, status: 'failed', error: 'invalid_subid' }) },
      updateTransforms: [{ fieldPath: 'receivedAt', setToServerValue: 'REQUEST_TIME' }],
      currentDocument: { exists: false },
    }]).catch(() => {});
    return json({ ok: true, status: 'failed', error: 'invalid_subid' });
  }

  for (let attempt = 0; attempt < 3; attempt++) {
    const existing = await fsGet(env, convPath);
    const existingStatus = existing ? existing.fields?.status?.stringValue || 'unknown' : undefined;
    const d = decide(existingStatus, c.kind);
    if (d.action === 'noop') return json({ ok: true, status: existingStatus, duplicate: true });

    let status = d.status, credit = d.credit, extra = {};
    let amount = existing ? numField(existing.fields?.amount) || 0 : 0; // reversals keep whatever was recorded before
    const userPath = `users/${c.subid}`;

    if (d.credit || status === 'held') {
      const reward = await resolveReward(env, c);
      amount = reward.amount; // held rows show what WOULD be paid; credited rows what WAS paid
      if (d.credit) {
        const user = await fsGet(env, userPath);
        if (!user) { status = 'failed'; credit = false; extra = { error: 'user_not_found' }; }
        else if (!reward.auto) { status = 'pending'; credit = false; extra = { needsManualCredit: true, reviewReason: reward.why }; }
      }
    }
    const reward = { amount };

    const fields = { ...base, amount, status, ...extra };
    const transforms = [{ fieldPath: 'receivedAt', setToServerValue: 'REQUEST_TIME' }];
    if (credit) {
      fields.creditedBy = 'auto_webhook';
      transforms.push({ fieldPath: 'creditedAt', setToServerValue: 'REQUEST_TIME' });
    }

    const writes = [];
    if (!existing) {
      writes.push({ update: { name: convName, fields: toFields(fields) }, updateTransforms: transforms, currentDocument: { exists: false } });
    } else {
      // Update only what changes; precondition on updateTime = optimistic concurrency.
      const mask = Object.keys(fields).filter((k) => !['network', 'transactionId', 'userId', 'offerId', 'source', 'payload'].includes(k));
      writes.push({
        update: { name: convName, fields: toFields(fields) },
        updateMask: { fieldPaths: mask },
        updateTransforms: transforms.filter((t) => t.fieldPath !== 'receivedAt'),
        currentDocument: { updateTime: existing.updateTime },
      });
    }

    if (credit) {
      // Same shape of update the panel's manual credit performs (balance, totalEarned, task counters).
      writes.push({
        update: { name: docName(env, userPath) }, updateMask: { fieldPaths: [] },
        updateTransforms: [
          { fieldPath: 'balance', increment: { doubleValue: reward.amount } },
          { fieldPath: 'totalEarned', increment: { doubleValue: reward.amount } },
          { fieldPath: 'tasksCompleted', increment: { integerValue: '1' } },
          { fieldPath: 'approvedTasks', increment: { integerValue: '1' } },
        ],
        currentDocument: { exists: true },
      });
      writes.push({
        update: {
          name: docName(env, `users/${c.subid}/notifications/${randomId()}`),
          fields: toFields({ title: '🎉 টাস্ক সম্পন্ন হয়েছে', msg: `আপনার ব্যালেন্সে $${reward.amount.toFixed(2)} যোগ হয়েছে।`, icon: '💰', unread: true }),
        },
        updateTransforms: [{ fieldPath: 'createdAt', setToServerValue: 'REQUEST_TIME' }],
        currentDocument: { exists: false },
      });
    }

    const r = await fsCommit(env, writes);
    if (r.ok) {
      console.log(`postback ${c.conversionId}: ${status}${credit ? ` +$${reward.amount} -> ${c.subid}` : ''}`);
      return json({ ok: true, status, credited: credit, amount: credit ? reward.amount : undefined });
    }
    // conflict => a concurrent delivery won the race; loop re-reads and lands on the no-op branch.
  }
  return json({ ok: false, error: 'conflict_retry' }, 503); // network will retry; idempotency keeps it safe
}

/* ───────────────────── 5. GET /offers (admin only) ───────────────────── */

let jwkCache = { keys: null, exp: 0 };
async function getJwks() {
  const now = Date.now();
  if (jwkCache.keys && jwkCache.exp > now) return jwkCache.keys;
  const res = await fetch('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com');
  if (!res.ok) throw new Error('jwks_fetch_failed');
  jwkCache = { keys: (await res.json()).keys || [], exp: now + 3600_000 };
  return jwkCache.keys;
}

export async function verifyFirebaseIdToken(token, env, nowSec = Math.floor(Date.now() / 1000)) {
  const [h, p, s] = String(token || '').split('.');
  if (!h || !p || !s) throw new Error('malformed_token');
  const header = JSON.parse(dec.decode(b64urlToBytes(h)));
  if (header.alg !== 'RS256') throw new Error('bad_alg');
  const jwk = (await getJwks()).find((k) => k.kid === header.kid);
  if (!jwk) throw new Error('unknown_kid');
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  if (!(await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64urlToBytes(s), enc.encode(`${h}.${p}`)))) throw new Error('bad_signature');
  const claims = JSON.parse(dec.decode(b64urlToBytes(p)));
  const pid = env.FIREBASE_PROJECT_ID;
  if (claims.aud !== pid || claims.iss !== `https://securetoken.google.com/${pid}`) throw new Error('bad_audience');
  if (!(claims.exp > nowSec) || !(claims.iat <= nowSec + 60) || !claims.sub) throw new Error('expired');
  return claims;
}

/**
 * Admin gate for /api/offers. Any signed-up END USER also holds a valid Firebase ID token for this project, so identity must be
 * checked explicitly. Matches how firestore.rules decides admin: by UID (ADMIN_UIDS). ADMIN_EMAILS (verified e-mail) is optional.
 * Fails CLOSED: if neither variable is set, nobody gets in.
 */
async function requireAdmin(req, env) {
  const m = (req.headers.get('Authorization') || '').match(/^Bearer (.+)$/i);
  if (!m) throw Object.assign(new Error('missing_token'), { http: 401 });
  let claims;
  try { claims = await verifyFirebaseIdToken(m[1], env); } catch (e) { throw Object.assign(new Error('invalid_token'), { http: 401 }); }
  const list = (v) => String(v || '').split(',').map((x) => x.trim()).filter(Boolean);
  const uids = list(env.ADMIN_UIDS);
  const emails = list(env.ADMIN_EMAILS).map((x) => x.toLowerCase());
  const okUid = uids.includes(claims.sub);
  const okEmail = claims.email_verified === true && emails.includes(String(claims.email || '').toLowerCase());
  if (!okUid && !okEmail) throw Object.assign(new Error('not_admin'), { http: 403 });
  return claims;
}

const asArray = (v) => (Array.isArray(v) ? v : v == null || v === '' ? [] : [v]);
const lines = (v) => asArray(v).map((x) => (typeof x === 'string' ? x : x?.description || x?.title || x?.name || '')).filter(Boolean).join('\n');

const rawUrlOf = (o) => String(['tracking_url', 'click_url', 'tracking_link', 'url', 'link', 'offer_url'].map((k) => o[k]).find((v) => v) || '');

export function normalizeOffer(o) {
  const pick = (...ks) => { for (const k of ks) if (o[k] != null && o[k] !== '') return o[k]; return undefined; };
  const url = rawUrlOf(o);
  const category = String(pick('category', 'type', 'offer_type') || 'CPE');
  const countries = asArray(pick('countries', 'country', 'geo', 'country_code'));
  return {
    offerId: String(pick('id', 'offer_id', 'offerId', 'uuid') ?? ''),
    network: NETWORK,
    title: String(pick('title', 'name', 'offer_name') || '').trim(),
    description: String(pick('description', 'desc', 'short_description', 'details') || '').trim(),
    requirements: lines(pick('requirements', 'instructions', 'how_to', 'steps', 'goals', 'events')),
    category,
    taskType: /install|app/i.test(category) ? 'cpa_install' : 'cpa_offer',
    rawPayout: Number(pick('payout', 'payout_usd', 'reward', 'amount', 'rate')) || 0,
    country: countries.length ? countries.join(',') : 'Global',
    thumbnail: String(pick('icon', 'icon_url', 'image', 'image_url', 'thumbnail', 'logo') || ''),
    offerUrl: url.split(SUBID_SENTINEL).join('{subid}'),
    subidEmbedded: url.includes(SUBID_SENTINEL), // false => tracking link isn't plain-substitutable; use link mode "bridge"
  };
}

export function extractOffers(data) {
  if (Array.isArray(data)) return data;
  const c = data?.offers ?? data?.data?.offers ?? data?.data ?? data?.results ?? data?.items;
  return Array.isArray(c) ? c : [];
}

async function fetchOffersFromApi(env, subid, params = {}) {
  const qs = new URLSearchParams({ subid, ...params });
  const res = await fetch(`${env.OFFERWALL_API_BASE || 'https://offerwall.ad/api/v1'}/offers?${qs}`, {
    headers: { Authorization: `Bearer ${env.OFFERWALL_API_KEY}`, Accept: 'application/json' },
  });
  const text = await res.text();
  if (!res.ok) throw Object.assign(new Error(`offerwall.ad HTTP ${res.status}`), { http: 502, detail: text.slice(0, 300) });
  let data; try { data = JSON.parse(text); } catch { throw Object.assign(new Error('offerwall.ad returned non-JSON'), { http: 502 }); }
  return extractOffers(data);
}

async function handleOffers(req, env, cors) {
  await requireAdmin(req, env);
  const u = new URL(req.url);
  const limit = Math.min(100, Math.max(1, parseInt(u.searchParams.get('limit'), 10) || 50));
  const params = { limit: String(limit) };
  for (const k of ['page', 'country']) if (u.searchParams.get(k)) params[k] = u.searchParams.get(k);
  const raw = await fetchOffersFromApi(env, SUBID_SENTINEL, params);
  const offers = raw.map(normalizeOffer).filter((o) => o.offerId && o.title);
  return json({ ok: true, count: offers.length, offers, rawSample: raw[0] ?? null }, 200, cors);
}

/* ───────────────────── 6. GET /go (optional click bridge) ───────────────────── */

async function handleGo(req, env) {
  const u = new URL(req.url);
  const offer = u.searchParams.get('offer') || '';
  const subid = u.searchParams.get('subid') || '';
  if (!/^[A-Za-z0-9_.:-]{1,100}$/.test(offer) || !isSafeUid(subid)) {
    return new Response('Bad request (subid must be a real user id, not the {subid} placeholder).', { status: 400 });
  }
  // Only real users may use the bridge — stops anyone from burning our offerwall.ad API quota.
  if (!(await fsGet(env, `users/${subid}`))) return new Response('Unknown user', { status: 403 });
  const raw = await fetchOffersFromApi(env, subid, { limit: '100' });
  const hit = raw.find((o) => normalizeOffer(o).offerId === offer);
  const target = hit && rawUrlOf(hit);
  if (!target || !/^https?:\/\//i.test(target)) return new Response('Offer not available', { status: 404 });
  return Response.redirect(target, 302);
}

/* ───────────────────── router ───────────────────── */

const ROUTES = {
  health: async (req, env, cors) => json({ ok: true, service: 'workhive-owa' }, 200, cors),
  postback: async (req, env) => handlePostback(req, env),
  offers: async (req, env, cors) => (req.method === 'GET' ? handleOffers(req, env, cors) : json({ ok: false, error: 'method_not_allowed' }, 405, cors)),
  go: async (req, env) => (req.method === 'GET' ? handleGo(req, env) : json({ ok: false, error: 'method_not_allowed' }, 405)),
};

/** Used by the thin files in /api — the route is chosen by FILE, not by parsing the URL path. */
export async function route(name, req, env) {
  const cors = corsHeaders(req, env);
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
  try {
    const h = ROUTES[name];
    if (!h) return json({ ok: false, error: 'not_found' }, 404, cors);
    return await h(req, env, cors);
  } catch (e) {
    const http = e.http || 500;
    if (http >= 500) console.error('owa error:', e && e.message);
    return json({ ok: false, error: http >= 500 && http !== 502 ? 'internal_error' : e.message, detail: e.detail }, http, cors);
  }
}

// Path-based entry (kept for the test-suite and any other host).
export default {
  fetch(req, env) {
    const name = new URL(req.url).pathname.replace(/^\/api/, '').replace(/^\//, '');
    return route(name, req, env);
  },
};
