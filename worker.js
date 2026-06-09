// NyaySetu — Hardened OpenRouter Proxy (Cloudflare Worker)
// v3 — supports two modes:
//   mode: "chat"   → plain text response for the AI chat box
//   mode: "search" → structured JSON law card for any legal query
//
// Security: rate limiting, origin allowlist, input sanitisation, security headers

const MODELS = [
  'meta-llama/llama-3.3-70b-instruct:free',
  'openai/gpt-oss-120b:free',
  'nvidia/nemotron-3-super-120b-a12b:free',
  'google/gemma-4-31b-it:free',
  'mistralai/mistral-small-3.1-24b-instruct:free',
];

const API_URL = 'https://openrouter.ai/api/v1/chat/completions';

const ALLOWED_ORIGINS = [
  'https://prasidhajagtap.github.io',
  'https://nyaysetu.pages.dev',
];

// ── Rate limiter ──────────────────────────────────────────────────────────────
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
  if (RATE_STORE.size > 5000) {
    for (const [k, v] of RATE_STORE) {
      if (now - v.windowStart > RATE_WINDOW_MS * 2) RATE_STORE.delete(k);
    }
  }
  return entry.count > RATE_LIMIT;
}

function sanitize(str, maxLen = 4000) {
  if (typeof str !== 'string') return '';
  return str.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
            .replace(/<script[\s\S]*?<\/script>/gi, '')
            .slice(0, maxLen);
}

function secHeaders(extra = {}) {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Cache-Control': 'no-store',
    ...extra,
  };
}

function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
}

function respond(body, status, origin, extra = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin), ...secHeaders(extra) },
  });
}

// ── Model call ────────────────────────────────────────────────────────────────
async function tryModel(model, messages, maxTokens, apiKey) {
  let res, data;
  try {
    res = await fetch(API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
        'HTTP-Referer': 'https://prasidhajagtap.github.io',
        'X-Title': 'NyaySetu Legal Guide',
      },
      body: JSON.stringify({ model, messages, max_tokens: maxTokens, temperature: 0.3 }),
    });
    data = await res.json();
  } catch (e) {
    return { ok: false, status: 502, error: e.message };
  }
  if (!res.ok) return { ok: false, status: res.status, error: data.error?.message || JSON.stringify(data) };
  return { ok: true, text: data.choices?.[0]?.message?.content || '' };
}

async function runModels(messages, maxTokens, apiKey) {
  let lastError = 'All models unavailable';
  for (const model of MODELS) {
    const result = await tryModel(model, messages, maxTokens, apiKey);
    if (result.ok) return { ok: true, text: result.text };
    if (result.status === 429 || result.status === 404 || result.status >= 500) {
      lastError = `${model} [${result.status}]: ${result.error}`;
      continue;
    }
    return { ok: false, error: result.error, status: result.status };
  }
  return { ok: false, error: lastError, status: 429 };
}

// ── SEARCH SYSTEM PROMPT ──────────────────────────────────────────────────────
// Returns structured JSON for rendering a full law card on the website.
const SEARCH_SYSTEM = `You are NyaySetu, an expert on Indian law for men and their families.

The user will search for any Indian law, act, section, or legal situation.
You must return a JSON object that represents a complete law card for that topic.

CURRENT LAW (effective July 1, 2024):
- BNS (Act 45/2023) replaced IPC 1860
- BNSS (Act 46/2023) replaced CrPC 1973  
- BSA (Act 47/2023) replaced Indian Evidence Act 1872
- For cases filed BEFORE July 1 2024: old IPC/CrPC/IEA apply
- For cases filed AFTER July 1 2024: BNS/BNSS/BSA apply
- Always cite BOTH old and new section numbers

RETURN THIS EXACT JSON STRUCTURE (no markdown, no explanation, just the JSON):
{
  "title": "Full name of the law/act/section",
  "ref": "Act citation and section numbers (old and new if applicable)",
  "icon": "single relevant emoji",
  "tags": [
    {"l": "tag text max 3 words", "c": "ltag-o OR ltag-b OR ltag-g"}
  ],
  "expl": "2-3 sentence plain language explanation. Simple words a common person understands. Include whether this is often misused against men, key statistics if known.",
  "warn": "1 sentence most important warning for the man to know immediately.",
  "rights": [
    "Right 1 — cite relevant section number",
    "Right 2",
    "Right 3",
    "Right 4",
    "Right 5"
  ],
  "steps": [
    {"n": 1, "t": "Short action title", "d": "Detailed description of what to do, when, and how.", "tm": "Timing e.g. Day 1"},
    {"n": 2, "t": "...", "d": "...", "tm": "..."},
    {"n": 3, "t": "...", "d": "...", "tm": "..."},
    {"n": 4, "t": "...", "d": "...", "tm": "..."}
  ],
  "cases": [
    {
      "name": "Case name v. Case name (year)",
      "cite": "Court · Citation e.g. SC · (2014) 8 SCC 273",
      "ruling": "One sentence — what the court held, in plain language.",
      "impact": "One sentence — practical impact for men.",
      "copy": "Full citation text for lawyer to use in court document.",
      "url": "https://indiankanoon.org/doc/DOCID/ if you know the Indian Kanoon URL, else empty string"
    }
  ],
  "source_note": "Brief note about the act — year enacted, which ministry, last amended if known."
}

RULES:
- tags: use ltag-o (orange) for warnings, ltag-b (blue) for informational, ltag-g (green) for positive rights
- All text must be in simple English — no legal jargon
- rights: minimum 4, maximum 7 items
- steps: minimum 3, maximum 6 items  
- cases: minimum 2, maximum 5 REAL Supreme Court or High Court cases that actually exist
- Only include cases you are confident are real — if unsure of citation, set url to ""
- expl, warn, rights, steps must focus on how this law affects MEN and how they can protect themselves
- Include BOTH old (IPC/CrPC) and new (BNS/BNSS) section numbers wherever applicable`;

// ── MAIN HANDLER ──────────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: { ...corsHeaders(origin), ...secHeaders() } });
    }
    if (request.method !== 'POST') {
      return respond({ error: 'Method not allowed' }, 405, origin);
    }
    if (origin && !ALLOWED_ORIGINS.includes(origin)) {
      return respond({ error: 'Origin not allowed' }, 403, origin);
    }

    const ip = request.headers.get('CF-Connecting-IP') ||
               request.headers.get('X-Forwarded-For')?.split(',')[0].trim() || 'unknown';
    if (isRateLimited(ip)) {
      return respond({ error: 'Too many requests. Please wait a minute.' }, 429, origin, { 'Retry-After': '60' });
    }

    const contentLength = parseInt(request.headers.get('Content-Length') || '0');
    if (contentLength > 20_000) return respond({ error: 'Request too large' }, 413, origin);

    let body;
    try { body = await request.json(); }
    catch { return respond({ error: 'Invalid JSON' }, 400, origin); }

    if (!body.userMessage || typeof body.userMessage !== 'string') {
      return respond({ error: 'Missing userMessage' }, 400, origin);
    }

    const userMessage = sanitize(body.userMessage, 3000);
    const system      = sanitize(body.system || '', 2000);
    const mode        = body.mode === 'search' ? 'search' : 'chat';
    const maxTokens   = mode === 'search' ? 2000 : Math.min(Math.max(parseInt(body.max_tokens) || 800, 100), 2000);

    if (!userMessage.trim()) return respond({ error: 'Empty message' }, 400, origin);

    // ── SEARCH mode: use structured prompt, return JSON card ──────────────
    if (mode === 'search') {
      const messages = [
        { role: 'system', content: SEARCH_SYSTEM },
        { role: 'user', content: 'Search query: ' + userMessage + '\n\nReturn the JSON law card for this topic as it relates to Indian men and their legal rights. Focus on how this law can affect men, how it has been misused, and how men can protect themselves.' }
      ];
      const result = await runModels(messages, maxTokens, env.OPENROUTER_API_KEY);
      if (!result.ok) return respond({ error: result.error }, result.status || 500, origin);
      return respond({ text: result.text, mode: 'search' }, 200, origin);
    }

    // ── CHAT mode: plain conversational response ──────────────────────────
    const messages = [];
    if (system) messages.push({ role: 'system', content: system });
    messages.push({ role: 'user', content: userMessage });

    const result = await runModels(messages, maxTokens, env.OPENROUTER_API_KEY);
    if (!result.ok) return respond({ error: result.error }, result.status || 500, origin);
    return respond({ text: result.text }, 200, origin);
  },
};
