import { isNumericString } from './helpers';

const ALLOWED_WIDTHS = new Set([320, 480, 640, 768, 960, 1280, 1600, 1920, 2560]);
const ALLOWED_FIT = new Set(['cover', 'contain', 'scale-down', 'crop', 'pad', 'squeeze']);
const ALLOWED_METADATA = new Set(['keep', 'copyright', 'none']);
const ALLOWED_GRAVITY = new Set(['face', 'left', 'right', 'top', 'bottom', 'center', 'auto', 'entropy']);
const ALLOWED_QUALITY = new Set(['low', 'medium-low', 'medium-high', 'high']);
const ALLOWED_FORMAT = new Set(['avif', 'webp', 'json', 'jpeg', 'png', 'baseline-jpeg', 'png-force', 'svg']);
const MAX_DPR = 2;

// ---------- Entry ----------
export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);

		if (url.pathname.startsWith('/raw/')) {
			return handleRaw(request, env);
		}

		if (url.pathname.startsWith('/transform/')) {
			return handleImg(request, env, ctx);
		}

		return new Response('Not found', { status: 404 });
	},
};

// ---------- /raw: serve original (private) ----------
async function handleRaw(request: Request, env: Env): Promise<Response> {
	const url = new URL(request.url);

	const key = safeKey(url.pathname.slice('/raw/'.length));
	if (!key) return new Response('Bad key', { status: 400 });

	// ✅ short-lived signature instead of static token
	const exp = parseInt(url.searchParams.get('exp') || '0', 10);
	const sig = url.searchParams.get('sig') || '';

	if (!exp || exp < Math.floor(Date.now() / 1000)) {
		return new Response('URL expired', { status: 401 });
	}

	const canonical = `raw|key=${key}|exp=${exp}`;
	const expected = await hmacHex(env.INTERNAL_RAW_TOKEN, canonical);

	if (!timingSafeEqual(sig, expected)) {
		return new Response('Forbidden', { status: 403 });
	}

	// Your safeKey() apparently returns something like "/v1/..."
	// You currently do key.slice(1) to remove the leading slash.
	const r2Key = key.startsWith('/') ? key.slice(1) : key;

	const obj = await env.R2_BUCKET.get(r2Key);
	if (!obj) return new Response('Not found', { status: 404 });

	const headers = new Headers();
	obj.writeHttpMetadata(headers);

	// private + short cache; raw URLs are short-lived anyway
	headers.set('Cache-Control', 'private, max-age=300');
	if (!headers.get('Content-Type')) headers.set('Content-Type', guessContentType(key));

	return new Response(obj.body, { headers });
}


// ---------- /transform: signed + resized ----------
async function handleImg(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
	const url = new URL(request.url);

	// 1) Parse + validate key
	const key = safeKey(url.pathname.slice('/transform/'.length));
	if (!key) return new Response('Bad key', { status: 400 });

	// 2) Optional hotlink protection
	if (!isAllowedReferer(request, env)) {
		return new Response('Forbidden', { status: 403 });
	}

	// 3) Verify signature (public signed URL)
	const sig = url.searchParams.get('sig') || '';
	const exp = parseInt(url.searchParams.get('exp') || '0', 10);

	if (!exp || exp < Math.floor(Date.now() / 1000)) {
		return new Response('URL expired', { status: 401 });
	}

	// Normalize transform params using allowlists (this MUST match what you sign)
	const t = normalizeTransform(url.searchParams);

	const canonical = canonicalString({
		key,
		exp,
		w: t.w,
		h: t.h,
		fit: t.fit,
		q: t.q,
		dpr: t.dpr,
		format: t.format,
		gravity: t.gravity,
		metadata: t.metadata,
		sharpen: t.sharpen,
	});

	const expected = await hmacHex(env.IMG_SIGNING_SECRET, canonical);

	if (!timingSafeEqual(sig, expected)) {
		return new Response('Bad signature', { status: 401 });
	}

	// 4) ✅ Normalized cache key (ignore sig/exp so cache hit stays high)
	const cacheUrl = new URL(url.toString());
	cacheUrl.searchParams.delete('sig');
	cacheUrl.searchParams.delete('exp');

	// Make cache key deterministic from normalized params
	if (t.w != null) cacheUrl.searchParams.set('w', String(t.w));
	else cacheUrl.searchParams.delete('w');

	if (t.h != null) cacheUrl.searchParams.set('h', String(t.h));
	else cacheUrl.searchParams.delete('h');

	cacheUrl.searchParams.set('fit', String(t.fit));
	cacheUrl.searchParams.set('q', String(t.q));
	cacheUrl.searchParams.set('dpr', String(t.dpr));
	cacheUrl.searchParams.set('format', String(t.format));

	if (t.gravity) cacheUrl.searchParams.set('gravity', String(t.gravity));
	else cacheUrl.searchParams.delete('gravity');

	if (t.metadata) cacheUrl.searchParams.set('metadata', String(t.metadata));
	else cacheUrl.searchParams.delete('metadata');

	if (typeof t.sharpen === 'number') cacheUrl.searchParams.set('sharpen', String(t.sharpen));
	else cacheUrl.searchParams.delete('sharpen');

	// Vary by Accept for format=auto (avif/webp/jpeg)
	const accept = request.headers.get('Accept') ?? '';
	const cacheKey = new Request(cacheUrl.toString(), {
		method: 'GET',
		headers: { Accept: accept },
	});

	const cached = await caches.default.match(cacheKey);
	if (cached) return cached;

	// 5) ✅ Fetch original through /raw using SHORT-LIVED signed URL (no static token)
	const rawUrl = new URL(`/raw/${encodeURIComponent(key)}`, url.origin);

	const rawExp = Math.floor(Date.now() / 1000) + 60; // 60s is enough for an internal fetch
	const rawCanonical = `raw|key=${key}|exp=${rawExp}`;
	const rawSig = await hmacHex(env.INTERNAL_RAW_TOKEN, rawCanonical);

	rawUrl.searchParams.set('exp', String(rawExp));
	rawUrl.searchParams.set('sig', rawSig);

	const resized = await fetch(rawUrl.toString(), {
		cf: {
			image: {
				width: t.w ?? undefined,
				height: t.h ?? undefined,
				fit: t.fit as RequestInitCfPropertiesImage['fit'],
				quality: t.q as RequestInitCfPropertiesImage['quality'],
				dpr: t.dpr,
				format: t.format as RequestInitCfPropertiesImage['format'],
				metadata: t.metadata as RequestInitCfPropertiesImage['metadata'],
				gravity: t.gravity as RequestInitCfPropertiesImage['gravity'],
				sharpen: t.sharpen,
			},
		},
	});

	if (!resized.ok) {
		return new Response(`Resize failed: ${resized.status}`, { status: resized.status });
	}

	// 6) Output headers + edge cache
	const out = new Response(resized.body, resized);
	out.headers.set('Cache-Control', 'public, max-age=31536000, immutable');
	out.headers.set('Vary', 'Accept');
	out.headers.set('X-Content-Type-Options', 'nosniff');

	ctx.waitUntil(caches.default.put(cacheKey, out.clone()));
	return out;
}



// ---------- Helpers ----------
function safeKey(key: string): string | null {
	const k = decodeURIComponent(key).trim();
	if (!k) return null;
	if (k.includes('..')) return null;
	// You can tighten more: only allow v1/... and only image extensions
	// if (!k.startsWith('v1/')) return null;
	if (!/\.(jpg|jpeg|png|webp|avif)$/i.test(k)) return null;
	return k;
}

function normalizeTransform(sp: URLSearchParams): {
	w: number | null;
	h: number | null;
	q: number | string;
	fit: string;
	dpr: number;
	format: string;
	metadata: string;
	gravity?: string;
	sharpen?: number;
} {
	const wRaw = parseInt(sp.get('w') || '0', 10);
	const hRaw = parseInt(sp.get('h') || '0', 10);

	const w = ALLOWED_WIDTHS.has(wRaw) ? wRaw : null;
	const h = ALLOWED_WIDTHS.has(hRaw) ? hRaw : null;

	// quality clamp
	let q: string | number = sp.get('q') ?? 85;

	if (isNumericString(q)) {
		q = parseInt(sp.get('q')!, 10);
	} else {
		if (typeof q === 'string' && !ALLOWED_QUALITY.has(q)) {
			q = 85;
		}
	}

	const fitRaw = (sp.get('fit') || 'cover').toLowerCase();
	const fit = (ALLOWED_FIT.has(fitRaw) ? fitRaw : 'cover');

	const dprRaw = parseFloat(sp.get('dpr') || '1');
	const dpr = Math.max(1, Math.min(MAX_DPR, Number.isFinite(dprRaw) ? dprRaw : 1));

	// If neither w nor h provided, force a sane default width
	const finalW = w ?? 960;

	let format = 'avif';

	if (sp.get('format') && ALLOWED_FORMAT.has(sp.get('format')!)) {
		format = sp.get('format')!;
	}

	const sharpen = sp.get('sharpen') ? parseInt(sp.get('sharpen')!, 10) : undefined;

	const metadata = sp.get('metadata') && ALLOWED_METADATA.has(sp.get('metadata')!) ? sp.get('metadata')! : 'none';

	const gravity = sp.get('gravity') && ALLOWED_GRAVITY.has(sp.get('gravity')!) ? sp.get('gravity')! : undefined;

	return { w: finalW, h, q, fit, dpr, format, sharpen, metadata, gravity };
}

function canonicalString(input: {
	key: string;
	exp: number;
	w: number | null;
	h: number | null;
	fit: string;
	q: number | string;
	dpr: number;
	format: string;
	metadata: string;
	gravity?: string;
	sharpen?: number;
}) {
	// Canonical order matters
	const canonicalString = [
		`key=${input.key}`,
		`exp=${input.exp}`,
		`w=${input.w ?? ''}`,
		`h=${input.h ?? ''}`,
		`fit=${input.fit}`,
		`q=${input.q}`,
		`dpr=${input.dpr}`,
		`format=${input.format}`,
		`metadata=${input.metadata}`,
	];

	if (input.gravity) {
		canonicalString.push(`gravity=${input.gravity}`);
	}

	if (input.sharpen) {
		canonicalString.push(`sharpen=${input.sharpen}`);
	}

	return canonicalString.join('&');
}

async function hmacHex(secret: string, message: string): Promise<string> {
	const enc = new TextEncoder();
	const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
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

function isAllowedReferer(request: Request, env: Env): boolean {
  const list = (env.ALLOWED_REFERER_PREFIXES || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
  if (list.length === 0) return true;

	const referer = request.headers.get('referer');
	const origin = request.headers.get('origin');

	if (origin) return list.some(item => origin === item)

	if (referer) return list.some((item) => referer.startsWith(item));

	return false;
}
