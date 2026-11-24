/**
 * Portable SSRF Shield + Safe Fetch (Works on both Cloudflare Workers & Node.js 22)
 * Blocks localhost, private IPv4 (RFC1918, link-local 169.254.169.254, CGNAT), IPv6 loopback/ULA,
 * non-HTTP protocols, decimal/hex IP obfuscations, and unsafe redirect hops.
 */

const BLOCKED_HOSTS = new Set([
  "localhost",
  "localhost.localdomain",
  "metadata.google.internal",
  "metadata",
  "instance-data"
]);

export function isPrivateIpString(host) {
  const clean = String(host || "").replace(/^\[|\]$/g, "").toLowerCase();
  if (!clean) return true;
  if (BLOCKED_HOSTS.has(clean) || clean.endsWith(".local") || clean.endsWith(".internal")) return true;

  // Pure integer / hex / octal IPv4 bypass attempts (e.g. 2130706433, 0x7f000001)
  if (/^(0x[0-9a-f]+|\d+)$/i.test(clean)) return true;

  // Standard IPv4
  const ipv4 = clean.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const [a, b, c, d] = ipv4.slice(1).map(Number);
    if ([a, b, c, d].some(n => n > 255)) return true;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true; // Cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a >= 224) return true;
    return false;
  }

  // IPv6 private / loopback / mapped IPv4
  if (clean.includes(":")) {
    if (clean === "::1" || clean === "::" || clean.startsWith("fc") || clean.startsWith("fd") || clean.startsWith("fe80:") || clean.startsWith("::ffff:")) {
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
  if (!/^https?:\/\//i.test(str)) str = "https://" + str;
  let parsed;
  try {
    parsed = new URL(str);
  } catch {
    throw new HttpError("Invalid URL format.", 400);
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new HttpError(`Unsupported protocol: ${parsed.protocol}`, 400);
  }
  if (parsed.username || parsed.password) {
    throw new HttpError("URLs with embedded credentials are not allowed.", 400);
  }
  if (isPrivateIpString(parsed.hostname)) {
    throw new HttpError(`SSRF blocked: private or internal target (${parsed.hostname})`, 400);
  }
  if (!parsed.hostname.includes(".") || parsed.hostname.startsWith(".") || parsed.hostname.endsWith(".")) {
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
  const { timeoutMs = 10000, maxRedirects = 4, maxBytes = 2_500_000, headers = {} } = opts;
  let current = normalizeAndValidateUrl(rawUrl);

  for (let hop = 0; hop <= maxRedirects; hop++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let res;
    try {
      res = await fetch(current.toString(), {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: {
          "User-Agent": "EdgeWebIntelBot/1.0 (+https://danlopes18-ctrl.github.io/)",
          "Accept": "text/html,application/xhtml+xml,application/xml,application/json,text/plain;q=0.9,*/*;q=0.8",
          ...headers
        }
      });
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
      if (!loc) return { response: res, finalUrl: current.toString(), text: "" };
      current = normalizeAndValidateUrl(new URL(loc, current).toString());
      continue;
    }

    const reader = res.body?.getReader?.();
    if (!reader) {
      const text = await res.text();
      return { response: res, finalUrl: current.toString(), text: text.slice(0, maxBytes) };
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
    return { response: res, finalUrl: current.toString(), text };
  }
  throw new Error("Too many redirects.");
}
