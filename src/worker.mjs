/**
 * Edge Web Intelligence API — Universal Fetch Handler (Cloudflare Workers + Node.js 22)
 * Monetization-ready for RapidAPI (X-RapidAPI-Proxy-Secret), API.market, Zyla & direct Bearer API Keys.
 */
import { auditWebsite, crawlMarkdown, inspectGithubOrg, parseRssFeed, extractB2bContacts } from "./engines.mjs";
import { buildOpenApiSpec } from "./openapi.mjs";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-API-Key, X-RapidAPI-Proxy-Secret, X-RapidAPI-Key, X-RapidAPI-Host"
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "X-Powered-By": "Edge-Web-Intel-API/1.0",
      ...CORS_HEADERS
    }
  });
}

function timingSafeStrEq(a, b) {
  const s1 = String(a || "");
  const s2 = String(b || "");
  if (!s1 || !s2 || s1.length !== s2.length) return false;
  let diff = 0;
  for (let i = 0; i < s1.length; i++) diff |= s1.charCodeAt(i) ^ s2.charCodeAt(i);
  return diff === 0;
}

function checkAuth(request, env = {}) {
  const rapidSecret = env.RAPIDAPI_PROXY_SECRET || "";
  const apiKey = env.API_BEARER_KEY || "";
  // Open in local/dev when neither secret is configured
  if (!rapidSecret && !apiKey) return { ok: true };

  const gotRapid = request.headers.get("x-rapidapi-proxy-secret") || "";
  const gotKey = request.headers.get("x-api-key") || "";
  const gotAuth = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "").trim();

  if (rapidSecret && timingSafeStrEq(gotRapid, rapidSecret)) return { ok: true, channel: "rapidapi" };
  if (apiKey && (timingSafeStrEq(gotKey, apiKey) || timingSafeStrEq(gotAuth, apiKey))) return { ok: true, channel: "direct" };
  return { ok: false };
}

async function readParams(request, urlObj) {
  const params = Object.fromEntries(urlObj.searchParams.entries());
  if (request.method === "POST") {
    try {
      const body = await request.json();
      if (body && typeof body === "object") Object.assign(params, body);
    } catch {
      throw new Error("Invalid JSON request body.");
    }
  }
  return params;
}

const LANDING_HTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Edge Web Intelligence API · 5 Sub-Second AI Endpoints</title>
<style>body{background:#06080E;color:#F8FAFC;font-family:system-ui,sans-serif;max-width:860px;margin:0 auto;padding:42px 20px;line-height:1.6}
h1{font-size:32px;margin-bottom:8px}code{background:rgba(255,255,255,.08);padding:2px 7px;border-radius:6px;font-family:ui-monospace,monospace}
.card{background:#0D1220;border:1px solid rgba(255,255,255,.1);border-radius:14px;padding:16px 20px;margin:14px 0}
a{color:#34D399;text-decoration:none}a:hover{text-decoration:underline}</style></head>
<body>
<h1>Edge Web Intelligence API v1.0</h1>
<p>5 zero-browser, SSRF-shielded endpoints built for AI Agents, RAG pipelines, n8n workflows &amp; B2B enrichment. <a href="/openapi.json">OpenAPI 3.1 Spec →</a></p>
<div class="card"><strong>1. Website Tech, Security &amp; llms.txt Auditor</strong><br><code>GET /v1/audit?url=https://danlopes18-ctrl.github.io/</code></div>
<div class="card"><strong>2. Fast LLM-Ready Markdown Crawler</strong><br><code>GET /v1/markdown?url=https://danlopes18-ctrl.github.io/guides/hardening-nodejs-mcp-servers.html</code></div>
<div class="card"><strong>3. GitHub Organization Velocity &amp; AI Signals</strong><br><code>GET /v1/github-org?org=danlopes18-ctrl</code></div>
<div class="card"><strong>4. RSS / Atom / JSON Feed Aggregator</strong><br><code>GET /v1/rss?url=https://hnrss.org/frontpage&amp;limit=5</code></div>
<div class="card"><strong>5. Multi-Page B2B Contact &amp; Social Extractor</strong><br><code>GET /v1/b2b-contacts?url=https://danlopes18-ctrl.github.io/</code></div>
<p style="margin-top:26px;color:#94A3B8">Built by <a href="https://danlopes18-ctrl.github.io/">Daniel Lopes · AI DevTools</a> · Also available on <a href="https://apify.com/danlopes18">Apify Store</a></p>
</body></html>`;

export default {
  async fetch(request, env = {}) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const urlObj = new URL(request.url);
    const p = urlObj.pathname.replace(/\/+$/, "") || "/";

    if (p === "/") {
      return new Response(LANDING_HTML, {
        status: 200,
        headers: { "Content-Type": "text/html; charset=utf-8", ...CORS_HEADERS }
      });
    }
    if (p === "/health") {
      return jsonResponse({ ok: true, service: "edge-web-intel-api", version: "1.0.0", endpoints: 5, timestamp: new Date().toISOString() });
    }
    if (p === "/openapi.json") {
      return jsonResponse(buildOpenApiSpec(urlObj.origin));
    }

    // Auth check for /v1/* routes
    if (p.startsWith("/v1/")) {
      const auth = checkAuth(request, env);
      if (!auth.ok) {
        return jsonResponse({ error: "Unauthorized. Provide a valid X-RapidAPI-Proxy-Secret, X-API-Key, or Bearer token." }, 401);
      }
    }

    try {
      const params = await readParams(request, urlObj);
      if (p === "/v1/audit") {
        return jsonResponse(await auditWebsite(params.url));
      }
      if (p === "/v1/markdown") {
        return jsonResponse(await crawlMarkdown(params.url));
      }
      if (p === "/v1/github-org") {
        return jsonResponse(await inspectGithubOrg(params.org || params.url, env.GITHUB_TOKEN || ""));
      }
      if (p === "/v1/rss") {
        return jsonResponse(await parseRssFeed(params.url, { keyword: params.keyword, limit: params.limit }));
      }
      if (p === "/v1/b2b-contacts") {
        return jsonResponse(await extractB2bContacts(params.url));
      }
      return jsonResponse({ error: `Route not found: ${p}`, docs: "/openapi.json" }, 404);
    } catch (err) {
      const msg = err?.message || "Unexpected error";
      const status = Number.isInteger(err?.status) && err.status >= 400 && err.status <= 599
        ? err.status
        : (/SSRF blocked|Missing|Invalid|Unsupported/i.test(msg) ? 400 : 502);
      const payload = { error: msg };
      if (Number.isInteger(err?.upstreamStatus)) payload.upstreamStatus = err.upstreamStatus;
      return jsonResponse(payload, status);
    }
  }
};
