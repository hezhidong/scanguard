/**
 * ScanGuard Community Intake — Cloudflare Worker
 *
 * POST /report      — submit one event or an array of events
 * GET  /healthz     — health check
 * GET  /stats       — basic counters (public, no sensitive data)
 *
 * Events are buffered in KV and flushed to GitHub reports/community.jsonl
 * by the scheduled cron handler (every minute).
 *
 * Required KV binding:  EVENTS
 * Required secrets:     GITHUB_TOKEN, GITHUB_REPO (e.g. hezhidong/scanguard)
 * Optional:             GITHUB_BRANCH (default master), GITHUB_PATH (default reports/community.jsonl)
 */

// ── Validators ────────────────────────────────────────────────────────────

const PRIVATE_V4 = [
  /^10\./, /^172\.(1[6-9]|2\d|3[01])\./, /^192\.168\./,
  /^127\./, /^169\.254\./, /^100\.64\./, /^0\./,
  /^224\./, /^240\./,
];
const PRIVATE_V6_PREFIXES = ['fc', 'fd', 'fe80', '::1', 'ff'];
const VALID_SEVERITIES = new Set(['low', 'medium', 'high', 'critical']);
const MAX_BATCH = 100;
const MAX_BODY_BYTES = 256 * 1024;
const RATE_LIMIT_PER_MIN = 60;
const DAILY_EVENT_CAP = 2000;

function isPublicIp(ip) {
  if (!ip || typeof ip !== 'string' || ip.length > 45) return false;
  if (ip.includes(':')) {
    const lo = ip.toLowerCase();
    return !PRIVATE_V6_PREFIXES.some((p) => lo === p || lo.startsWith(p + ':'));
  }
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  for (let i = 1; i <= 4; i++) {
    const v = parseInt(m[i], 10);
    if (v < 0 || v > 255) return false;
  }
  return !PRIVATE_V4.some((re) => re.test(ip));
}

function validateEvent(e) {
  if (!e || typeof e !== 'object') return 'event must be an object';
  if (!isPublicIp(e.ip)) return `invalid or non-public ip: ${e.ip}`;
  if (typeof e.rule !== 'string' || !e.rule.trim()) return 'rule must be a non-empty string';
  if (e.severity && !VALID_SEVERITIES.has(e.severity)) return `invalid severity: ${e.severity}`;
  if (e.hits !== undefined && (!Number.isInteger(e.hits) || e.hits < 1)) return 'hits must be positive integer';
  if (!e.node_id || typeof e.node_id !== 'string') return 'node_id required';
  if (!e.node_name || typeof e.node_name !== 'string') return 'node_name required';
  if (e.rule.length > 100) return 'rule too long';
  if (e.node_id.length > 100) return 'node_id too long';
  if (e.node_name.length > 200) return 'node_name too long';
  for (const f of ['country', 'city', 'isp', 'org']) {
    if (e[f] && typeof e[f] === 'string' && e[f].length > 200) return `${f} too long`;
  }
  return null;
}

function normalizeEvent(e) {
  return {
    ts: e.ts || new Date().toISOString(),
    ip: e.ip,
    rule: e.rule,
    severity: e.severity || 'high',
    hits: e.hits || 1,
    country: e.country || '',
    city: e.city || '',
    isp: e.isp || '',
    org: e.org || '',
    node_id: e.node_id,
    node_name: e.node_name,
    source: 'community',
  };
}

// ── Helpers ───────────────────────────────────────────────────────────────

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
}

function clientIp(req) {
  return req.headers.get('cf-connecting-ip')
    || req.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
    || 'unknown';
}

async function rateLimitAllowed(kv, ip) {
  if (ip === 'unknown') return true;
  const now = Date.now();
  const minKey = `rl:m:${ip}:${Math.floor(now / 60000)}`;
  const dayKey = `rl:d:${ip}:${Math.floor(now / 86400000)}`;
  const [minC, dayC] = await Promise.all([
    kv.get(minKey, 'json').then((v) => v?.c || 0),
    kv.get(dayKey, 'json').then((v) => v?.c || 0),
  ]);
  if (minC >= RATE_LIMIT_PER_MIN || dayC >= DAILY_EVENT_CAP) return false;
  await Promise.all([
    kv.put(minKey, JSON.stringify({ c: minC + 1 }), { expirationTtl: 120 }),
    kv.put(dayKey, JSON.stringify({ c: dayC + 1 }), { expirationTtl: 90000 }),
  ]);
  return true;
}

// ── KV buffer ─────────────────────────────────────────────────────────────

async function bufferEvents(kv, events) {
  const bucket = Math.floor(Date.now() / 60000);
  const idxKey = `buf:idx:${bucket}`;
  const keys = [];
  const puts = [];
  for (const evt of events) {
    const k = `buf:evt:${crypto.randomUUID()}`;
    keys.push(k);
    puts.push(kv.put(k, JSON.stringify(evt), { expirationTtl: 3600 }));
  }
  const existing = await kv.get(idxKey, 'json');
  const all = [...(existing?.keys || []), ...keys];
  puts.push(kv.put(idxKey, JSON.stringify({ keys: all, ts: Date.now() }), { expirationTtl: 3600 }));
  await Promise.all(puts);
}

async function flushBuffer(kv, env) {
  const listed = await kv.list({ prefix: 'buf:idx:' });
  if (!listed.keys.length) return { flushed: 0 };

  let allEvents = [];
  const delIdx = [];
  const delEvt = [];

  for (const k of listed.keys) {
    const idx = await kv.get(k.name, 'json');
    if (!idx?.keys?.length) { delIdx.push(k.name); continue; }
    const evts = await Promise.all(
      idx.keys.map(async (ek) => {
        const v = await kv.get(ek, 'json');
        if (v) delEvt.push(ek);
        return v;
      }),
    );
    allEvents.push(...evts.filter(Boolean));
    delIdx.push(k.name);
  }

  if (!allEvents.length) {
    await Promise.all(delIdx.map((k) => kv.delete(k)));
    return { flushed: 0 };
  }

  // Deduplicate by ip|rule: sum hits, collect distinct nodes, max severity
  const order = { low: 0, medium: 1, high: 2, critical: 3 };
  const map = new Map();
  for (const e of allEvents) {
    const key = `${e.ip}|${e.rule}`;
    const ex = map.get(key);
    if (!ex) {
      map.set(key, { ...e, hits: e.hits || 1, _nodes: new Set([e.node_id]) });
    } else {
      ex.hits += e.hits || 1;
      ex._nodes.add(e.node_id);
      if (order[e.severity] > order[ex.severity]) ex.severity = e.severity;
    }
  }
  const finalEvents = [...map.values()].map(({ _nodes, ...rest }) => ({
    ...rest, node_count: _nodes.size,
  }));

  const result = await appendToGitHub(env, finalEvents);
  if (result.success) {
    await Promise.all([
      ...delEvt.map((k) => kv.delete(k)),
      ...delIdx.map((k) => kv.delete(k)),
    ]);
  }
  return { flushed: finalEvents.length, raw: allEvents.length, result };
}

// ── GitHub ────────────────────────────────────────────────────────────────

async function appendToGitHub(env, events) {
  const token = env.GITHUB_TOKEN;
  const repo = env.GITHUB_REPO;
  const branch = env.GITHUB_BRANCH || 'master';
  const path = env.GITHUB_PATH || 'reports/community.jsonl';
  if (!token || !repo) return { success: false, error: 'GitHub not configured' };

  const url = `https://api.github.com/repos/${repo}/contents/${path}`;
  const h = {
    authorization: `Bearer ${token}`,
    accept: 'application/vnd.github+json',
    'user-agent': 'scanguard-intake',
  };

  let sha = null;
  let existing = '';
  try {
    const r = await fetch(`${url}?ref=${branch}`, { headers: h });
    if (r.ok) {
      const meta = await r.json();
      sha = meta.sha;
      existing = atob(meta.content);
    } else if (r.status !== 404) {
      return { success: false, error: `GET ${r.status}: ${await r.text()}` };
    }
  } catch (e) {
    return { success: false, error: `GET error: ${e.message}` };
  }

  const newLines = events.map((e) => JSON.stringify(e)).join('\n');
  let content = existing
    ? existing.replace(/\s+$/, '') + '\n' + newLines + '\n'
    : newLines + '\n';

  // Rotate: keep last 10k lines if > 5MB
  if (content.length > 5 * 1024 * 1024) {
    content = content.split('\n').filter(Boolean).slice(-10000).join('\n') + '\n';
  }

  try {
    const r = await fetch(url, {
      method: 'PUT',
      headers: { ...h, 'content-type': 'application/json' },
      body: JSON.stringify({
        message: `intake: append ${events.length} community event(s)`,
        content: btoa(content),
        sha, branch,
      }),
    });
    if (!r.ok) return { success: false, error: `PUT ${r.status}: ${await r.text()}` };
    const d = await r.json();
    return { success: true, commit: d.commit?.sha?.slice(0, 10), appended: events.length };
  } catch (e) {
    return { success: false, error: `PUT error: ${e.message}` };
  }
}

// ── HTTP ──────────────────────────────────────────────────────────────────

async function handleReport(req, env) {
  if (req.method !== 'POST') return json({ error: 'method not allowed' }, 405);

  const ip = clientIp(req);
  if (!(await rateLimitAllowed(env.EVENTS, ip))) {
    return json({ error: 'rate limit exceeded' }, 429);
  }
  if (parseInt(req.headers.get('content-length') || '0', 10) > MAX_BODY_BYTES) {
    return json({ error: 'body too large' }, 413);
  }

  let payload;
  try { payload = await req.json(); }
  catch { return json({ error: 'invalid JSON' }, 400); }

  const raw = Array.isArray(payload) ? payload : [payload];
  if (raw.length > MAX_BATCH) return json({ error: `max ${MAX_BATCH} events per request` }, 400);

  const accepted = [];
  const rejected = [];
  for (const e of raw) {
    const err = validateEvent(e);
    if (err) { rejected.push({ ip: e?.ip, error: err }); continue; }
    accepted.push(normalizeEvent(e));
  }

  if (accepted.length) await bufferEvents(env.EVENTS, accepted);

  return json({
    ok: true,
    accepted: accepted.length,
    rejected: rejected.length,
    errors: rejected.length ? rejected : undefined,
  }, rejected.length && !accepted.length ? 400 : 200);
}

// ── Worker entry ──────────────────────────────────────────────────────────

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname === '/report') return handleReport(req, env);
    if (url.pathname === '/healthz') return json({ ok: true, ts: new Date().toISOString() });
    if (url.pathname === '/stats') {
      // Basic public stats (no IP data)
      return json({
        service: 'scanguard-intake',
        version: '1',
        endpoints: { report: 'POST /report', health: 'GET /healthz' },
        limits: { max_batch: MAX_BATCH, rate_per_min: RATE_LIMIT_PER_MIN, daily_cap: DAILY_EVENT_CAP },
      });
    }
    return json({ error: 'not found' }, 404);
  },

  async scheduled(event, env) {
    const result = await flushBuffer(env.EVENTS, env);
    console.log('flush:', JSON.stringify(result));
  },
};
