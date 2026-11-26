/**
 * Portable SSRF Shield + Safe Fetch (Works on both Cloudflare Workers & Node.js 22)
 * Blocks localhost, private IPv4 (RFC1918, link-local 169.254.169.254, CGNAT), IPv6 loopback/ULA/mapped,
 * non-HTTP(S) protocols, decimal/hex/octal IP obfuscations, embedded credentials, and unsafe redirect hops.
 */

const BLOCKED_HOSTS = new Set([
  "localhost",
  "localhost.localdomain",
  "metadata.google.internal",
  "metadata.goog",
  "metadata",
  "instance-data",
  "169.254.169.254",
  "0.0.0.0"
]);

const ALLOWED_METHODS = new Set(["GET", "HEAD", "OPTIONS", "POST", "QUERY"]);

export function isPrivateIpString(host) {
  const clean = String(host || "").replace(/^\[|\]$/g, "").trim().toLowerCase();
  if (!clean) return true;
  if (BLOCKED_HOSTS.has(clean) || clean.endsWith(".local") || clean.endsWith(".internal") || clean.endsWith(".localhost")) {
    return true;
  }

  // Pure integer / hex / octal IPv4 bypass attempts (e.g. 2130706433, 0x7f000001, 017700000001)
  if (/^(0x[0-9a-f]+|0[0-7]+|\d+)$/i.test(clean)) return true;

  // Shorthand dotted-numeric IPv4 bypass attempts (e.g. 127.1, 127.0.1, 0177.0.0.1, 0x7f.0.0.1)
  if (/^(?:(?:0x[0-9a-f]+|\d+)\.){1,3}(?:0x[0-9a-f]+|\d+)$/i.test(clean)) {
    const segs = clean.split(".");
    if (segs.length !== 4 || segs.some(s => /^0x/i.test(s) || (s.length > 1 && s.startsWith("0")))) {
      return true;
    }
    const [a, b, c, d] = segs.map(Number);
    if ([a, b, c, d].some(n => Number.isNaN(n) || n < 0 || n > 255)) return true;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true; // Cloud metadata / link-local
    if (a === 172 && b >= 16 && b <= 31) return true; // RFC1918
    if (a === 192 && b === 168) return true; // RFC1918
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT RFC6598
    if (a === 192 && b === 0 && (c === 0 || c === 2)) return true;
    if (a === 198 && (b === 18 || b === 19)) return true; // Benchmarking
    if (a >= 224) return true; // Multicast / reserved
    return false;
  }

  // IPv6 private / loopback / ULA / link-local / multicast / mapped IPv4
  if (clean.includes(":")) {
    const noZone = clean.split("%")[0];
    if (
      noZone === "::1" ||
      noZone === "::" ||
      /^(?:0+:){6,7}0*1?$/.test(noZone) ||
      noZone.startsWith("fc") ||
      noZone.startsWith("fd") ||
      noZone.startsWith("fe8") ||
      noZone.startsWith("fe9") ||
      noZone.startsWith("fea") ||
      noZone.startsWith("feb") ||
      noZone.startsWith("ff") ||
      noZone.startsWith("::ffff:") ||
      noZone.startsWith("64:ff9b:")
    ) {
      return true;
    }
  }
  return false;
}

export class HttpError extends Error {
  constructor(message, status = 502, upstreamStatus = null) {
    super(message);
    this.name = "HttpError";
    this.status = status;
    if (upstreamStatus !== null) this.upstreamStatus = upstreamStatus;
  }
}

export function normalizeAndValidateUrl(rawUrl) {
  let str = String(rawUrl || "").trim();
  if (!str) throw new HttpError("Missing required 'url' parameter.", 400);
  if (/\s/.test(str)) throw new HttpError("Invalid URL: whitespace is not allowed.", 400);

  // Only prepend https:// when no explicit URI scheme is present,
  // so non-HTTP schemes (file:, ftp:, gopher:, javascript:, data:) are blocked cleanly.
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(str)) {
    str = "https://" + str;
  }

  let parsed;
  try {
    parsed = new URL(str);
  } catch {
    throw new HttpError("Invalid URL format.", 400);
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new HttpError(`SSRF blocked: unsupported protocol (${parsed.protocol})`, 400);
  }
  if (parsed.username || parsed.password) {
    throw new HttpError("SSRF blocked: URLs with embedded credentials are not allowed.", 400);
  }
  if (isPrivateIpString(parsed.hostname)) {
    throw new HttpError(`SSRF blocked: private or internal target (${parsed.hostname})`, 400);
  }
  const cleanHost = parsed.hostname.replace(/^\[|\]$/g, "");
  if (!cleanHost.includes(".") || cleanHost.startsWith(".") || cleanHost.endsWith(".")) {
    throw new HttpError(`Invalid hostname: ${parsed.hostname}`, 400);
  }
  return parsed;
}

export function assertUpstreamOk(res) {
  const status = res?.response?.status ?? 0;
  if (status >= 200 && status < 400) return;
  if (status === 404 || status === 410) {
    throw new HttpError(`Target URL not found (upstream HTTP ${status}).`, 404, status);
  }
  if (status === 408 || status === 504) {
    throw new HttpError(`Upstream target timed out (HTTP ${status}).`, 504, status);
  }
  if (status === 530 || status === 523 || status === 522 || status === 521 || status === 520) {
    throw new HttpError(`Target host could not be reached (upstream HTTP ${status}).`, 502, status);
  }
  if (status === 401 || status === 403 || status === 429) {
    throw new HttpError(`Target site denied access (upstream HTTP ${status}).`, 502, status);
  }
  throw new HttpError(`Failed to fetch target URL (upstream HTTP ${status || "unknown"}).`, 502, status || null);
}

export async function safeFetch(rawUrl, opts = {}) {
  const {
    method = "GET",
    timeoutMs = 10000,
    maxRedirects = 4,
    maxBytes = 2_500_000,
    headers = {},
    body = undefined
  } = opts;

  const upperMethod = String(method || "GET").toUpperCase();
  if (!ALLOWED_METHODS.has(upperMethod)) {
    throw new HttpError(`Unsupported HTTP method: ${upperMethod}`, 400);
  }

  let current = normalizeAndValidateUrl(rawUrl);

  for (let hop = 0; hop <= maxRedirects; hop++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let res;
    try {
      const fetchInit = {
        method: upperMethod,
        redirect: "manual",
        signal: controller.signal,
        headers: {
          "User-Agent": "EdgeWebIntelBot/1.1 (+https://danlopes18-ctrl.github.io/)",
          "Accept": "text/html,application/xhtml+xml,application/xml,application/json,text/plain;q=0.9,*/*;q=0.8",
          ...headers
        }
      };
      if (body !== undefined && upperMethod !== "GET" && upperMethod !== "HEAD") {
        fetchInit.body = body;
      }
      res = await fetch(current.toString(), fetchInit);
    } catch (err) {
      if (err?.name === "AbortError") {
        throw new HttpError(`Upstream request timed out after ${timeoutMs}ms.`, 504);
      }
      throw new HttpError(`Target host could not be reached: ${err?.message || "network error"}`, 502);
    } finally {
      clearTimeout(timer);
    }

    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get("location");
      if (!loc) return { response: res, finalUrl: current.toString(), text: "", byteLength: 0 };
      // Re-validate every redirect target against SSRF shield
      current = normalizeAndValidateUrl(new URL(loc, current).toString());
      continue;
    }

    if (upperMethod === "HEAD") {
      return { response: res, finalUrl: current.toString(), text: "", byteLength: 0 };
    }

    const reader = res.body?.getReader?.();
    if (!reader) {
      const text = await res.text();
      const sliced = text.slice(0, maxBytes);
      return { response: res, finalUrl: current.toString(), text: sliced, byteLength: sliced.length };
    }
    const chunks = [];
    let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        chunks.push(value.subarray(0, value.byteLength - (total - maxBytes)));
        try { await reader.cancel(); } catch {}
        break;
      }
      chunks.push(value);
    }
    const merged = new Uint8Array(chunks.reduce((s, c) => s + c.byteLength, 0));
    let off = 0;
    for (const c of chunks) { merged.set(c, off); off += c.byteLength; }
    const text = new TextDecoder("utf-8", { fatal: false }).decode(merged);
    return { response: res, finalUrl: current.toString(), text, byteLength: merged.byteLength };
  }
  throw new HttpError("Too many redirects.", 502);
}
