# Edge Web Intelligence API (Zero-Dependency · Cloudflare Workers + Node.js 22 · OpenAPI 3.1)

**5 sub-second, zero-browser Web Intelligence endpoints** engineered for **AI Agents, RAG pipelines, n8n workflows, MCP servers, and B2B lead enrichment** — running from a single portable ESM codebase on **Cloudflare Workers** (100k req/day free tier) or **Node.js 22** with **0 external npm dependencies**.

## 5 Production Endpoints

| Endpoint | Method | What It Does | Typical Latency |
| --- | --- | --- | --- |
| `/v1/audit` | `GET` / `POST` | Detects 25+ tech stacks, grades 7 HTTP security headers (`A+`–`F`), and audits `llms.txt`, `robots.txt` AI crawlers & JSON-LD | ~250–600ms |
| `/v1/markdown` | `GET` / `POST` | Streams any web page to clean boilerplate-free RAG Markdown + heading outline + LLM token count | ~180–450ms |
| `/v1/github-org` | `GET` / `POST` | Extracts GitHub org velocity score, top languages, and AI/MCP/Agent adoption markers | ~300–550ms |
| `/v1/rss` | `GET` / `POST` | Auto-discovers RSS 2.0 / Atom / JSON Feeds from homepages or direct URLs with keyword filters | ~300–600ms |
| `/v1/b2b-contacts` | `GET` / `POST` | Multi-page crawl (`/contact`, `/about`, `/team`) extracting verified public emails (role vs personal), phones, WhatsApp/booking links & socials | ~450–900ms |

Built-in utility routes: `GET /` (API overview), `GET /health`, and `GET /openapi.json` (OpenAPI 3.1 ready for RapidAPI / API.market / Zyla / Postman).

## Security Built-In (Zero npm Packages)
- **SSRF Shield (`src/ssrf.mjs`):** blocks `localhost`, `127.0.0.1`, AWS/GCP/Azure metadata (`169.254.169.254`), RFC1918, CGNAT, IPv6 loopback/ULA, obfuscated decimal/hex IPs, and re-validates every redirect hop.
- **Marketplace-Ready Auth:** supports `X-RapidAPI-Proxy-Secret`, `X-API-Key`, and `Authorization: Bearer` using constant-time comparison (fail-closed whenever secrets are configured).

## Quickstart (Node.js 22 — Zero `npm install`)

```bash
git clone https://github.com/danlopes18-ctrl/edge-web-intel-api
cd edge-web-intel-api
npm test     # Runs all 7 live QA & security assertions
npm start    # Starts server on http://localhost:8787
```

## 1-Command Deploy to Cloudflare Workers

```bash
npx wrangler login
npx wrangler secret put RAPIDAPI_PROXY_SECRET
npx wrangler deploy
```

Import `openapi.json` directly into **RapidAPI Studio**, **API.market**, or **Zyla API Hub** to monetize with recurring monthly subscriptions.

---

### Related Production Suites & Cloud Tools
- **Interactive AI DevTools Storefront & Free MIT Kits:** https://danlopes18-ctrl.github.io/
- **All 5 Apify Store Pay-per-Event Actors:** https://apify.com/danlopes18
- **Complete AI Engineering Stack (15 MCPs + 10 Guardrails + 25 n8n Workflows):** https://danlopes3.gumroad.com/l/complete-ai-engineering-stack
