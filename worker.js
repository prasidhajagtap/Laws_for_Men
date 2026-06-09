// NyaySetu — Hardened OpenRouter Proxy (Cloudflare Worker)
// Security features:
//   ✅ Rate limiting (IP-based, in-memory per isolate)
//   ✅ Input validation & size limits
//   ✅ Security headers on every response
//   ✅ Origin allowlist
//   ✅ Prompt injection defence (strips control characters)
//   ✅ Automatic model fallback on 429/404/5xx

const MODELS = [
  'meta-llama/llama-3.3-70b-instruct:free',
  'openai/gpt-oss-120b:free',
  'nvidia/nemotron-3-super-120b-a12b:free',
  'google/gemma-4-31b-it:free',
  'mistralai/mistral-small-3.1-24b-instruct:free',
];

const API_URL = 'https://openrouter.ai/api/v1/chat/completions';

// ── Allowed origins (add your domain here if you change hosts) ──────────────
const ALLOWED_ORIGINS = [
  'https://prasidhajagtap.github.io',
  'https://nyaysetu.pages.dev',         // Cloudflare Pages default domain
];

// ── In-memory rate limiter (resets when the isolate recycles, ~few minutes) ─
// 20 requests per IP per minute
const RATE_STORE = new Map();
const RATE_LIMIT = 20;
const RATE_WINDOW_MS = 60_000;

function isRateLimited(ip) {
  const now = Date.now();
  const entry = RATE_STORE.get(ip) || { count: 0, windowStart: now };
  if (now - entry.windowStart > RATE_WINDOW_MS) {
    entry.count = 1; entry.windowStart = now;
  } else {
    entry.count++;
  }
  RATE_STORE.set(ip, entry);
  // Cleanup old entries to avoid unbounded growth
  if (RATE_STORE.size > 5000) {
    for (const [k, v] of RATE_STORE) {
      if (now - v.windowStart > RATE_WINDOW_MS * 2) RATE_STORE.delete(k);
    }
  }
  return entry.count > RATE_LIMIT;
}

// ── Sanitize input: strip null bytes, control chars, limit length ────────────
function sanitize(str, maxLen = 4000) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') // control chars
    .replace(/<script[\s\S]*?<\/script>/gi, '')          // script tags
    .slice(0, maxLen);
}

// ── Security headers added to every response ────────────────────────────────
function secHeaders(extra = {}) {
  return {
    'X-Content-Type-Options':    'nosniff',
    'X-Frame-Options':           'DENY',
    'Referrer-Policy':           'strict-origin-when-cross-origin',
    'X-XSS-Protection':         '1; mode=block',
    'Cache-Control':             'no-store',
    ...extra,
  };
}

function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin':  allowed,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age':       '86400',
    'Vary':                         'Origin',
  };
}

function respond(body, status, origin, extra = {}) {
  return new Response(
    typeof body === 'string' ? body : JSON.stringify(body),
    {
      status,
      headers: {
        'Content-Type': 'application/json',
        ...corsHeaders(origin),
        ...secHeaders(extra),
      },
    }
  );
}

// ── Model call ───────────────────────────────────────────────────────────────
async function tryModel(model, messages, maxTokens, apiKey) {
  let res, data;
  try {
    res  = await fetch(API_URL, {
      method:  'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${apiKey}`,
        'HTTP-Referer':  'https://prasidhajagtap.github.io',
        'X-Title':       'NyaySetu Legal Guide',
      },
      body: JSON.stringify({ model, messages, max_tokens: maxTokens, temperature: 0.4 }),
    });
    data = await res.json();
  } catch (e) {
    return { ok: false, status: 502, error: e.message };
  }
  if (!res.ok) return { ok: false, status: res.status, error: data.error?.message || JSON.stringify(data) };
  return { ok: true, text: data.choices?.[0]?.message?.content || '' };
}

// ── Main handler ─────────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';

    // Preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: { ...corsHeaders(origin), ...secHeaders() } });
    }

    // Method guard
    if (request.method !== 'POST') {
      return respond({ error: 'Method not allowed' }, 405, origin);
    }

    // ── Origin check ──────────────────────────────────────────────────────
    if (origin && !ALLOWED_ORIGINS.includes(origin)) {
      return respond({ error: 'Origin not allowed' }, 403, origin);
    }

    // ── Rate limiting ─────────────────────────────────────────────────────
    const ip = request.headers.get('CF-Connecting-IP') ||
               request.headers.get('X-Forwarded-For')?.split(',')[0].trim() ||
               'unknown';
    if (isRateLimited(ip)) {
      return respond({ error: 'Too many requests. Please wait a minute.' }, 429, origin,
        { 'Retry-After': '60' });
    }

    // ── Body size guard (prevent giant payloads) ──────────────────────────
    const contentLength = parseInt(request.headers.get('Content-Length') || '0');
    if (contentLength > 20_000) {
      return respond({ error: 'Request too large' }, 413, origin);
    }

    // ── Parse & validate body ─────────────────────────────────────────────
    let body;
    try { body = await request.json(); }
    catch { return respond({ error: 'Invalid JSON' }, 400, origin); }

    if (!body.userMessage || typeof body.userMessage !== 'string') {
      return respond({ error: 'Missing userMessage' }, 400, origin);
    }

    // ── Sanitize inputs (defend against prompt injection) ─────────────────
    const userMessage = sanitize(body.userMessage, 3000);
    const system      = sanitize(body.system || '', 2000);
    const maxTokens   = Math.min(Math.max(parseInt(body.max_tokens) || 800, 100), 2000);

    if (!userMessage.trim()) {
      return respond({ error: 'Empty message' }, 400, origin);
    }

    // ── Build messages ────────────────────────────────────────────────────
    const messages = [];
    if (system) messages.push({ role: 'system', content: system });
    messages.push({ role: 'user', content: userMessage });

    // ── Try models in order ───────────────────────────────────────────────
    let lastError = 'All models unavailable';
    for (const model of MODELS) {
      const result = await tryModel(model, messages, maxTokens, env.OPENROUTER_API_KEY);
      if (result.ok) {
        return respond({ text: result.text }, 200, origin);
      }
      if (result.status === 429 || result.status === 404 || result.status >= 500) {
        lastError = `${model} [${result.status}]: ${result.error}`;
        continue;
      }
      // Auth error — no point retrying
      return respond({ error: result.error }, result.status, origin);
    }

    return respond({ error: `All models failed. Last: ${lastError}` }, 429, origin,
      { 'Retry-After': '60' });
  },
};
