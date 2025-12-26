const ALLOWED_WIDTHS = new Set([320, 480, 640, 768, 960, 1280, 1600, 1920, 2560]);
const MAX_DPR = 2;

const ALLOWED_FIT = new Set(['cover', 'contain', 'scale-down', 'fill', 'inside', 'outside']);
type Fit = 'cover' | 'contain' | 'scale-down' | 'fill' | 'inside' | 'outside';

// ---------- Entry ----------
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname.startsWith('/raw/')) {
      return handleRaw(request, env);
    }

    if (url.pathname.startsWith('/img/')) {
      return handleImg(request, env);
    }

    return new Response('Not found', { status: 404 });
  },
};

// ---------- /raw: serve original (private) ----------
async function handleRaw(request: Request, env: Env): Promise<Response> {
  // ONLY allow internal access from our own Worker subrequest
  const token = request.headers.get('x-internal-raw-token');
  if (!token || token !== env.INTERNAL_RAW_TOKEN) {
    return new Response('Forbidden', { status: 403 });
  }

  const url = new URL(request.url);
  const key = safeKey(url.pathname.slice('/raw/'.length));
  if (!key) return new Response('Bad key', { status: 400 });

  const obj = await env.R2_BUCKET.get(key);
  if (!obj) return new Response('Not found', { status: 404 });

  const headers = new Headers();
  obj.writeHttpMetadata(headers);

  // Strong caching for originals at edge is fine because they are not public-facing.
  // But we’ll keep it short just in case.
  headers.set('Cache-Control', 'private, max-age=300');

  // If missing, best-effort content type
  if (!headers.get('Content-Type')) headers.set('Content-Type', guessContentType(key));

  return new Response(obj.body, { headers });
}

// ---------- /img: signed + resized ----------
async function handleImg(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);

  const key = safeKey(url.pathname.slice('/img/'.length));
  if (!key) return new Response('Bad key', { status: 400 });

  // Optional hotlink protection (works for normal browsers; crawlers sometimes omit referer)
//   if (!isAllowedReferer(request, env)) {
//     return new Response('Forbidden', { status: 403 });
//   }

  // Verify signature (must be valid)
  const sig = url.searchParams.get('sig') || '';
  const exp = parseInt(url.searchParams.get('exp') || '0', 10);

  if (!exp || exp < Math.floor(Date.now() / 1000)) {
    return new Response('URL expired', { status: 401 });
  }

  // Normalize transform params using allowlists (do NOT sign random params)
  const t = normalizeTransform(url.searchParams);

  const canonical = canonicalString({
    key,
    exp,
    w: t.w,
    h: t.h,
    fit: t.fit,
    q: t.q,
    dpr: t.dpr,
    // force format auto always in this system
    format: 'auto',
  });

  const expected = await hmacHex(env.IMG_SIGNING_SECRET, canonical);

  if (!timingSafeEqual(sig, expected)) {
    return new Response('Bad signature', { status: 401 });
  }

  // Fetch original through /raw (internal), then apply Cloudflare Image Resizing
  const rawUrl = new URL(`/raw/${encodeURIComponent(key)}`, url.origin);

  const resized = await fetch(rawUrl.toString(), {
    headers: {
      'x-internal-raw-token': env.INTERNAL_RAW_TOKEN,
    },
    cf: {
      image: {
        width: t.w ?? undefined,
        height: t.h ?? undefined,
        fit: t.fit,
        quality: t.q,
        dpr: t.dpr,
        format: 'auto',
        metadata: 'none',
      },
    } as any,
  });

  if (!resized.ok) {
    // Pass through origin errors (useful during debugging)
    return new Response(`Resize failed: ${resized.status}`, { status: resized.status });
  }

  const out = new Response(resized.body, resized);
  out.headers.set('Cache-Control', 'public, max-age=31536000, immutable');
  out.headers.set('Vary', 'Accept');

  // Optional: lock down sniffing
  out.headers.set('X-Content-Type-Options', 'nosniff');

  return out;
}

// ---------- Helpers ----------
function safeKey(key: string): string | null {
  const k = decodeURIComponent(key).trim();
  if (!k) return null;
  if (k.includes('..')) return null;
  // You can tighten more: only allow v1/... and only image extensions
  if (!k.startsWith('v1/')) return null;
  if (!/\.(jpg|jpeg|png|webp|avif)$/i.test(k)) return null;
  return k;
}

function normalizeTransform(sp: URLSearchParams): {
  w: number | null;
  h: number | null;
  q: number;
  fit: Fit;
  dpr: number;
} {
  const wRaw = parseInt(sp.get('w') || '0', 10);
  const hRaw = parseInt(sp.get('h') || '0', 10);

  const w = ALLOWED_WIDTHS.has(wRaw) ? wRaw : null;
  const h = ALLOWED_WIDTHS.has(hRaw) ? hRaw : null;

  // quality clamp
  const qRaw = parseInt(sp.get('q') || '80', 10);
  const q = Math.max(40, Math.min(90, Number.isFinite(qRaw) ? qRaw : 80));

  const fitRaw = (sp.get('fit') || 'cover').toLowerCase();
  const fit = (ALLOWED_FIT.has(fitRaw) ? fitRaw : 'cover') as Fit;

  const dprRaw = parseFloat(sp.get('dpr') || '1');
  const dpr = Math.max(1, Math.min(MAX_DPR, Number.isFinite(dprRaw) ? dprRaw : 1));

  // If neither w nor h provided, force a sane default width
  const finalW = w ?? 960;
  return { w: finalW, h, q, fit, dpr };
}

function canonicalString(input: {
  key: string;
  exp: number;
  w: number | null;
  h: number | null;
  fit: string;
  q: number;
  dpr: number;
  format: string;
}) {
  // Canonical order matters
  return [
    `key=${input.key}`,
    `exp=${input.exp}`,
    `w=${input.w ?? ''}`,
    `h=${input.h ?? ''}`,
    `fit=${input.fit}`,
    `q=${input.q}`,
    `dpr=${input.dpr}`,
    `format=${input.format}`,
  ].join('&');
}

async function hmacHex(secret: string, message: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sigBuf = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return bufToHex(new Uint8Array(sigBuf));
}

function bufToHex(buf: Uint8Array): string {
  let out = '';
  for (const b of buf) out += b.toString(16).padStart(2, '0');
  return out;
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let res = 0;
  for (let i = 0; i < a.length; i++) res |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return res === 0;
}

function guessContentType(key: string): string {
  const k = key.toLowerCase();
  if (k.endsWith('.png')) return 'image/png';
  if (k.endsWith('.webp')) return 'image/webp';
  if (k.endsWith('.avif')) return 'image/avif';
  return 'image/jpeg';
}

// function isAllowedReferer(request: Request, env: Env): boolean {
//   const list = (env.ALLOWED_REFERER_PREFIXES || '')
//     .split(',')
//     .map(s => s.trim())
//     .filter(Boolean);
//   if (list.length === 0) return true;

//   const ref = request.headers.get('referer');
//   if (!ref) return true; // allow empty referer (some browsers/crawlers)
//   return list.some(prefix => ref.startsWith(prefix));
// }
