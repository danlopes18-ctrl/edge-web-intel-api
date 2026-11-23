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

export function normalizeAndValidateUrl(rawUrl) {
  let str = String(rawUrl || "").trim();
  if (!str) throw new Error("Missing required 'url' parameter.");
  if (!/^https?:\/\//i.test(str)) str = "https://" + str;
  const parsed = new URL(str);
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error(`Unsupported protocol: ${parsed.protocol}`);
  }
  if (parsed.username || parsed.password) {
    throw new Error("URLs with embedded credentials are not allowed.");
  }
  if (isPrivateIpString(parsed.hostname)) {
    throw new Error(`SSRF blocked: private or internal target (${parsed.hostname})`);
  }
  return parsed;
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
