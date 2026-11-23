/**
 * End-to-End Live QA Suite for Edge Web Intelligence API
 * Tests all 5 endpoints live + OpenAPI 3.1 + SSRF shield + RapidAPI proxy secret enforcement.
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
  assert.equal(health.endpoints, 5);
  const spec = await (await fetch(`${base}/openapi.json`)).json();
  assert.equal(spec.openapi, "3.1.0");
  assert.ok(spec.paths["/v1/audit"] && spec.paths["/v1/b2b-contacts"]);
  console.log("PASS 1/7: /health & /openapi.json (OpenAPI 3.1)");

  // 2. Auth Enforcement (Fail-closed when RAPIDAPI_PROXY_SECRET is set)
  const unauth = await fetch(`${base}/v1/audit?url=https://danlopes18-ctrl.github.io/`);
  assert.equal(unauth.status, 401);
  console.log("PASS 2/7: RapidAPI/Bearer Auth fail-closed (401 without secret)");

  // 3. SSRF Protection (Blocks 169.254.169.254 & localhost)
  for (const bad of ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:8080", "http://[::1]/"]) {
    const r = await fetch(`${base}/v1/audit?url=${encodeURIComponent(bad)}`, { headers: authHeaders });
    assert.equal(r.status, 400, `Expected 400 for SSRF target ${bad}`);
  }
  console.log("PASS 3/7: SSRF Shield blocked 169.254.169.254, 127.0.0.1 & [::1]");

  // 4. Endpoint 1: /v1/audit
  const auditRes = await fetch(`${base}/v1/audit?url=${encodeURIComponent("https://danlopes18-ctrl.github.io/")}`, { headers: authHeaders });
  assert.equal(auditRes.status, 200);
  const audit = await auditRes.json();
  assert.equal(audit.aiReadiness.hasLlmsTxt, true);
  assert.equal(audit.aiReadiness.hasJsonLd, true);
  console.log(`PASS 4/7: /v1/audit (${audit.latencyMs}ms, llms.txt=true, score=${audit.aiReadiness.score})`);

  // 5. Endpoint 2: /v1/markdown
  const mdRes = await fetch(`${base}/v1/markdown`, {
    method: "POST",
    headers: { ...authHeaders, "Content-Type": "application/json" },
    body: JSON.stringify({ url: "https://danlopes18-ctrl.github.io/guides/hardening-nodejs-mcp-servers.html" })
  });
  assert.equal(mdRes.status, 200);
  const md = await mdRes.json();
  assert.ok(md.wordCount > 200 && md.estimatedTokens > 250 && md.markdown.includes("realpathSync"));
  console.log(`PASS 5/7: /v1/markdown (${md.latencyMs}ms, ${md.wordCount} words, ~${md.estimatedTokens} tokens)`);

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
  console.log(`PASS 6/7: /v1/github-org (${gh.latencyMs}ms, velocity=${gh.intelligence.velocityScore}) + /v1/rss (${rss.latencyMs}ms, ${rss.items.length} items)`);

  // 7. Endpoint 5: /v1/b2b-contacts
  const b2bRes = await fetch(`${base}/v1/b2b-contacts?url=${encodeURIComponent("https://danlopes18-ctrl.github.io/")}`, { headers: authHeaders });
  assert.equal(b2bRes.status, 200);
  const b2b = await b2bRes.json();
  assert.ok(b2b.socials.github.length >= 1 && b2b.socials.x.length >= 1);
  console.log(`PASS 7/7: /v1/b2b-contacts (${b2b.latencyMs}ms, socials=${JSON.stringify(b2b.socials)})`);

  console.log("\nALL_7_EDGE_API_QA_TESTS_PASSED!");
} finally {
  server.close();
}
