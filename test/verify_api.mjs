/**
 * End-to-End Live QA Suite for Edge Web Intelligence API v1.1
 * Tests all 7 endpoints live + OpenAPI 3.1 + SSRF shield + fail-closed Auth enforcement.
 */
import assert from "node:assert/strict";
import { createNodeServer } from "../server.mjs";

const SECRET = "qa-rapidapi-secret-2026";
const server = createNodeServer({ RAPIDAPI_PROXY_SECRET: SECRET });

await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
const { port } = server.address();
const base = `http://127.0.0.1:${port}`;
const authHeaders = { "X-RapidAPI-Proxy-Secret": SECRET };

try {
  // 1. Health & OpenAPI 3.1
  const health = await (await fetch(`${base}/health`)).json();
  assert.equal(health.ok, true);
  assert.equal(health.endpoints, 7);
  const spec = await (await fetch(`${base}/openapi.json`)).json();
  assert.equal(spec.openapi, "3.1.0");
  assert.ok(spec.paths["/v1/audit"] && spec.paths["/v1/b2b-contacts"]);
  assert.ok(spec.paths["/v1/agent-readiness"] && spec.paths["/v1/agent-search"]);
  console.log("PASS 1/10: /health (7 endpoints) & /openapi.json (OpenAPI 3.1)");

  // 2. Auth Enforcement (Fail-closed 401 on existing + 2 new endpoints)
  for (const path of [
    "/v1/audit?url=https://danlopes18-ctrl.github.io/",
    "/v1/agent-readiness?url=https://blog.cloudflare.com/search-for-agents/",
    "/v1/agent-search?url=https://blog.cloudflare.com/search-for-agents/&query=markdown"
  ]) {
    const unauth = await fetch(`${base}${path}`);
    assert.equal(unauth.status, 401, `Expected 401 without secret on ${path}`);
  }
  console.log("PASS 2/10: Fail-closed Auth (401 without secret on /v1/audit, /v1/agent-readiness, /v1/agent-search)");

  // 3. SSRF Protection (Blocks metadata, loopback, RFC1918, IPv6, non-HTTP schemes)
  for (const bad of [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:8080",
    "http://localhost:3000",
    "http://10.0.0.1",
    "http://192.168.1.1",
    "http://[::1]/",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/"
  ]) {
    const r1 = await fetch(`${base}/v1/agent-readiness`, {
      method: "POST",
      headers: { ...authHeaders, "Content-Type": "application/json" },
      body: JSON.stringify({ url: bad })
    });
    assert.equal(r1.status, 400, `Expected 400 for SSRF on /v1/agent-readiness: ${bad}`);
    const r2 = await fetch(`${base}/v1/agent-search`, {
      method: "POST",
      headers: { ...authHeaders, "Content-Type": "application/json" },
      body: JSON.stringify({ url: bad, query: "test" })
    });
    assert.equal(r2.status, 400, `Expected 400 for SSRF on /v1/agent-search: ${bad}`);
  }
  console.log("PASS 3/10: SSRF Shield blocked 169.254.169.254, 127.0.0.1, localhost, RFC1918, [::1], file://, gopher://");

  // 4. Endpoint 1: /v1/audit
  const auditRes = await fetch(`${base}/v1/audit?url=${encodeURIComponent("https://danlopes18-ctrl.github.io/")}`, { headers: authHeaders });
  assert.equal(auditRes.status, 200);
  const audit = await auditRes.json();
  assert.equal(audit.aiReadiness.hasLlmsTxt, true);
  assert.equal(audit.aiReadiness.hasJsonLd, true);
  console.log(`PASS 4/10: /v1/audit (${audit.latencyMs}ms, llms.txt=true, score=${audit.aiReadiness.score})`);

  // 5. Endpoint 2: /v1/markdown
  const mdRes = await fetch(`${base}/v1/markdown`, {
    method: "POST",
    headers: { ...authHeaders, "Content-Type": "application/json" },
    body: JSON.stringify({ url: "https://danlopes18-ctrl.github.io/guides/hardening-nodejs-mcp-servers.html" })
  });
  assert.equal(mdRes.status, 200);
  const md = await mdRes.json();
  assert.ok(md.wordCount > 200 && md.estimatedTokens > 250 && md.markdown.includes("realpathSync"));
  console.log(`PASS 5/10: /v1/markdown (${md.latencyMs}ms, ${md.wordCount} words, ~${md.estimatedTokens} tokens)`);

  // 6. Endpoint 3 & 4: /v1/github-org + /v1/rss
  const [ghRes, rssRes] = await Promise.all([
    fetch(`${base}/v1/github-org?org=danlopes18-ctrl`, { headers: authHeaders }),
    fetch(`${base}/v1/rss?url=${encodeURIComponent("https://hnrss.org/frontpage")}&limit=5`, { headers: authHeaders })
  ]);
  assert.equal(ghRes.status, 200);
  const gh = await ghRes.json();
  assert.equal(gh.org, "danlopes18-ctrl");
  assert.ok(gh.intelligence.aiAdoptionSignals.includes("mcp"));

  assert.equal(rssRes.status, 200);
  const rss = await rssRes.json();
  assert.equal(rss.items.length, 5);
  console.log(`PASS 6/10: /v1/github-org (${gh.latencyMs}ms, velocity=${gh.intelligence.velocityScore}) + /v1/rss (${rss.latencyMs}ms, ${rss.items.length} items)`);

  // 7. Endpoint 5: /v1/b2b-contacts
  const b2bRes = await fetch(`${base}/v1/b2b-contacts?url=${encodeURIComponent("https://danlopes18-ctrl.github.io/")}`, { headers: authHeaders });
  assert.equal(b2bRes.status, 200);
  const b2b = await b2bRes.json();
  assert.ok(b2b.socials.github.length >= 1 && b2b.socials.x.length >= 1);
  console.log(`PASS 7/10: /v1/b2b-contacts (${b2b.latencyMs}ms, socials ok)`);

  // 8. NEW Endpoint 6: POST /v1/agent-readiness (Cloudflare Search for Agents live!)
  const cfReadyRes = await fetch(`${base}/v1/agent-readiness`, {
    method: "POST",
    headers: { ...authHeaders, "Content-Type": "application/json" },
    body: JSON.stringify({ url: "https://blog.cloudflare.com/search-for-agents/" })
  });
  assert.equal(cfReadyRes.status, 200);
  const cfReady = await cfReadyRes.json();
  assert.equal(cfReady.checks.well_known_search.present, true, "Cloudflare /.well-known/search detected");
  assert.equal(cfReady.checks.well_known_search.supports_query_method, true, "RFC 10008 HTTP QUERY detected");
  assert.equal(cfReady.checks.markdown_negotiation.supported, true, "Accept: text/markdown detected");
  assert.ok(cfReady.score >= 70, `Expected high score on Cloudflare, got ${cfReady.score}`);
  assert.ok(cfReady.token_savings_estimate.savings_percent > 50, "Expected >50% token savings");
  assert.equal(cfReady.cloudflare_overage_risk.pricing_watch.semantic_query_overage_usd_per_1k, 0.75);
  console.log(`PASS 8/10: /v1/agent-readiness Cloudflare (score=${cfReady.score}/${cfReady.grade}, QUERY=${cfReady.checks.well_known_search.supports_query_method}, mdSavings=${cfReady.token_savings_estimate.savings_percent}%, ${cfReady.elapsed_ms}ms)`);

  // 9. NEW Endpoint 6 (GET): /v1/agent-readiness on danlopes18-ctrl.github.io
  const ghReadyRes = await fetch(`${base}/v1/agent-readiness?url=${encodeURIComponent("https://danlopes18-ctrl.github.io/")}`, { headers: authHeaders });
  assert.equal(ghReadyRes.status, 200);
  const ghReady = await ghReadyRes.json();
  assert.equal(ghReady.checks.llms_txt.has_llms_txt, true);
  assert.ok(Array.isArray(ghReady.recommendations) && ghReady.recommendations.length >= 1);
  console.log(`PASS 9/10: /v1/agent-readiness Storefront (score=${ghReady.score}/${ghReady.grade}, llms.txt=true, recs=${ghReady.recommendations.length}, ${ghReady.elapsed_ms}ms)`);

  // 10. NEW Endpoint 7: POST /v1/agent-search (Tier 1 Cloudflare + Tier 3/4 Storefront)
  const [cfSearchRes, ghSearchRes] = await Promise.all([
    fetch(`${base}/v1/agent-search`, {
      method: "POST",
      headers: { ...authHeaders, "Content-Type": "application/json" },
      body: JSON.stringify({ url: "https://blog.cloudflare.com/search-for-agents/", query: "markdown for agents", max_chunks: 4, max_chars: 900 })
    }),
    fetch(`${base}/v1/agent-search`, {
      method: "POST",
      headers: { ...authHeaders, "Content-Type": "application/json" },
      body: JSON.stringify({ url: "https://danlopes18-ctrl.github.io/", query: "MCP servers n8n workflows", max_chunks: 4, max_chars: 900 })
    })
  ]);
  assert.equal(cfSearchRes.status, 200);
  const cfSearch = await cfSearchRes.json();
  assert.equal(cfSearch.source_tier, "tier1_well_known_search");
  assert.ok(cfSearch.chunks.length >= 1 && cfSearch.total_estimated_tokens > 0);

  assert.equal(ghSearchRes.status, 200);
  const ghSearch = await ghSearchRes.json();
  assert.ok(["tier3_llms_txt", "tier4_edge_html_to_markdown"].includes(ghSearch.source_tier));
  assert.ok(ghSearch.chunks.length >= 1 && ghSearch.total_estimated_tokens > 0);
  console.log(`PASS 10/10: /v1/agent-search (Cloudflare=${cfSearch.source_tier} [${cfSearch.chunks.length} chunks, ${cfSearch.total_estimated_tokens} tok] | Storefront=${ghSearch.source_tier} [${ghSearch.chunks.length} chunks, ${ghSearch.total_estimated_tokens} tok])`);

  console.log("\nALL_10_EDGE_API_QA_TESTS_PASSED!");
} finally {
  server.close();
}
