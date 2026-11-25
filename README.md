# Edge Web Intelligence API (Live on API.market · Cloudflare Workers + Node.js 22 · Zero npm Deps)

[![Live on API.market](https://img.shields.io/badge/API.market-LIVE_NOW-10B981?style=for-the-badge)](https://api.market/store/danlopes18/edge-web-intel-api)
[![Zero npm Dependencies](https://img.shields.io/badge/npm_dependencies-0-38BDF8?style=for-the-badge)](https://github.com/danlopes18-ctrl/edge-web-intel-api)
[![QA Status](https://img.shields.io/badge/Cloudflare_Edge_QA-16%2F16_PASS-34D399?style=for-the-badge)](https://api.market/store/danlopes18/edge-web-intel-api)

**5 sub-second, zero-browser Web Intelligence endpoints** engineered for **AI Agents, RAG pipelines, n8n workflows, MCP servers, and B2B lead enrichment** — running from a single portable ESM codebase on **Cloudflare Workers** or **Node.js 22** with **0 external npm dependencies**.

> 🚀 **Ready to call in production right now (Free Tier + Pro/Ultra/Mega):**  
> **Subscribe & test live on API.market:** https://api.market/store/danlopes18/edge-web-intel-api

---

## 5 Production Endpoints

| Endpoint | Method | What It Does | Typical Latency |
| --- | --- | --- | --- |
| `/v1/audit` | `GET` / `POST` | Detects 25+ tech stacks, grades 7 HTTP security headers (`A+`–`F`), and audits `llms.txt`, `robots.txt` AI crawlers & JSON-LD | ~250–600ms |
| `/v1/markdown` | `GET` / `POST` | Streams any web page to clean boilerplate-free RAG Markdown + heading outline + LLM token count | ~180–450ms |
| `/v1/github-org` | `GET` / `POST` | Extracts GitHub org velocity score, top languages, and AI/MCP/Agent adoption markers | ~300–550ms |
| `/v1/rss` | `GET` / `POST` | Auto-discovers RSS 2.0 / Atom / JSON Feeds from homepages or direct URLs with keyword filters | ~300–600ms |
| `/v1/b2b-contacts` | `GET` / `POST` | Multi-page crawl (`/contact`, `/about`, `/team`) extracting verified public emails (role vs personal), phones, WhatsApp/booking links & socials | ~450–900ms |

Built-in utility routes: `GET /` (API overview), `GET /health`, and `GET /openapi.json` (OpenAPI 3.1 specification).

---

## Quickstart via API.market (Zero Infrastructure Setup)

Get your free API key in 10 seconds at **https://api.market/store/danlopes18/edge-web-intel-api**:

### cURL (RAG Markdown Extractor)
```bash
curl -G "https://prod.api.market/v1/danlopes18/edge-web-intel-api/v1/markdown" \
  --data-urlencode "url=https://stripe.com/docs" \
  -H "x-magicapi-key: YOUR_APIMARKET_KEY"
```

### JavaScript / Node.js 22 (Website AI-Readiness & Security Audit)
```js
const res = await fetch(
  "https://prod.api.market/v1/danlopes18/edge-web-intel-api/v1/audit?url=https://cloudflare.com",
  { headers: { "x-magicapi-key": process.env.APIMARKET_KEY } }
);
const audit = await res.json();
console.log(audit.security.grade, audit.aiReadiness.hasLlmsTxt, audit.techStack);
```

### Python (B2B Company Contact & Social Enrichment)
```python
import os, requests

r = requests.get(
    "https://prod.api.market/v1/danlopes18/edge-web-intel-api/v1/b2b-contacts",
    params={"url": "https://stripe.com"},
    headers={"x-magicapi-key": os.environ["APIMARKET_KEY"]},
    timeout=15,
)
print(r.json()["contacts"])
```

---

## Security Built-In (Zero npm Packages)
- **SSRF Shield (`src/ssrf.mjs`):** blocks `localhost`, `127.0.0.1`, AWS/GCP/Azure metadata (`169.254.169.254`), RFC1918, CGNAT, IPv6 loopback/ULA, obfuscated decimal/hex IPs, and re-validates every redirect hop (`400 Bad Request`).
- **Fail-Closed Auth & Honest Upstream Errors:** constant-time key verification (`401`), unreachable hosts return `502` (never fake `200`), missing pages return `404`, and non-feed RSS endpoints return `422`.

## Self-Hosting (Node.js 22 or Cloudflare Workers — Zero `npm install`)

```bash
git clone https://github.com/danlopes18-ctrl/edge-web-intel-api
cd edge-web-intel-api
npm test     # Runs live QA & security assertions
npm start    # Starts server on http://localhost:8787
```

```bash
npx wrangler login
npx wrangler secret put RAPIDAPI_PROXY_SECRET
npx wrangler deploy
```

---

### Related Production Tools & Custom Engineering Services
- **Live Managed API (Free Tier + Pro/Ultra/Mega):** https://api.market/store/danlopes18/edge-web-intel-api
- **Interactive AI DevTools Storefront & Free MIT Kits:** https://danlopes18-ctrl.github.io/
- **All 5 Apify Store Pay-per-Event Actors:** https://apify.com/danlopes18
- **Complete AI Engineering Stack (15 MCPs + 10 Guardrails + 25 n8n Workflows):** https://danlopes3.gumroad.com/l/complete-ai-engineering-stack
- **Need a Custom Edge API, Scraper, MCP Server, or n8n AI Workflow?** [Upwork Project Catalog](https://www.upwork.com/services/product/2125554456380990351) · [Fiverr (`@danlopes18`)](https://www.fiverr.com/danlopes18)
