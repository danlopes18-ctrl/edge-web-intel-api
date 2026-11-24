/**
 * OpenAPI 3.1 Specification for Edge Web Intelligence API
 * Ready for 1-click import into RapidAPI, API.market, Zyla API Hub, Postman, and OpenAI Actions.
 */
export function buildOpenApiSpec(serverUrl = "https://edge-web-intel-api.danlopes18.workers.dev") {
  return {
    openapi: "3.1.0",
    info: {
      title: "AI Web Intelligence, RAG Markdown & B2B Enrichment API",
      version: "1.0.0",
      description: "Zero-browser, sub-second edge API with 5 production endpoints: Website Tech/Security/llms.txt Auditor, LLM-Ready Markdown Crawler, GitHub Org Velocity Intelligence, RSS/Atom News Aggregator, and Multi-Page B2B Contact Extractor. SSRF-shielded.",
      contact: {
        name: "Daniel Lopes · AI DevTools",
        url: "https://danlopes18-ctrl.github.io/"
      }
    },
    servers: [{ url: serverUrl }],
    components: {
      securitySchemes: {
        RapidAPIProxySecret: { type: "apiKey", in: "header", name: "X-RapidAPI-Proxy-Secret" },
        ApiKeyHeader: { type: "apiKey", in: "header", name: "X-API-Key" },
        BearerAuth: { type: "http", scheme: "bearer" }
      }
    },
    paths: {
      "/health": {
        get: {
          summary: "Health check",
          operationId: "getHealth",
          responses: { "200": { description: "Service operational" } }
        }
      },
      "/v1/audit": {
        get: {
          summary: "Audit website tech stack, HTTP security headers & llms.txt AI readiness",
          operationId: "auditWebsiteGet",
          parameters: [{ name: "url", in: "query", required: true, schema: { type: "string", example: "https://danlopes18-ctrl.github.io/" } }],
          responses: { "200": { description: "Structured tech stack, security header grade (A+-F), and AI-readiness report" } }
        },
        post: {
          summary: "Audit website tech stack, HTTP security headers & llms.txt AI readiness (POST)",
          operationId: "auditWebsitePost",
          requestBody: {
            required: true,
            content: { "application/json": { schema: { type: "object", required: ["url"], properties: { url: { type: "string", example: "https://danlopes18-ctrl.github.io/" } } } } }
          },
          responses: { "200": { description: "Structured audit report" } }
        }
      },
      "/v1/markdown": {
        get: {
          summary: "Convert any web page to clean LLM-ready Markdown with token count",
          operationId: "crawlMarkdownGet",
          parameters: [{ name: "url", in: "query", required: true, schema: { type: "string", example: "https://danlopes18-ctrl.github.io/guides/hardening-nodejs-mcp-servers.html" } }],
          responses: { "200": { description: "Clean Markdown, heading outline, word count, and token estimate" } }
        },
        post: {
          summary: "Convert any web page to clean LLM-ready Markdown (POST)",
          operationId: "crawlMarkdownPost",
          requestBody: {
            required: true,
            content: { "application/json": { schema: { type: "object", required: ["url"], properties: { url: { type: "string" } } } } }
          },
          responses: { "200": { description: "Clean Markdown response" } }
        }
      },
      "/v1/github-org": {
        get: {
          summary: "Extract GitHub organization velocity score, tech stack & AI/MCP signals",
          operationId: "inspectGithubOrgGet",
          parameters: [{ name: "org", in: "query", required: true, schema: { type: "string", example: "danlopes18-ctrl" } }],
          responses: { "200": { description: "GitHub org profile, velocity score, AI signals, and top repos" } }
        },
        post: {
          summary: "Extract GitHub organization intelligence (POST)",
          operationId: "inspectGithubOrgPost",
          requestBody: {
            required: true,
            content: { "application/json": { schema: { type: "object", required: ["org"], properties: { org: { type: "string" } } } } }
          },
          responses: { "200": { description: "GitHub org intelligence report" } }
        }
      },
      "/v1/rss": {
        get: {
          summary: "Auto-discover & extract RSS, Atom, or JSON Feed items with keyword filtering",
          operationId: "parseRssGet",
          parameters: [
            { name: "url", in: "query", required: true, schema: { type: "string", example: "https://hnrss.org/frontpage" } },
            { name: "keyword", in: "query", required: false, schema: { type: "string" } },
            { name: "limit", in: "query", required: false, schema: { type: "integer", default: 15, minimum: 1, maximum: 50 } }
          ],
          responses: { "200": { description: "Normalized feed metadata and LLM-ready article items" } }
        },
        post: {
          summary: "Auto-discover & extract RSS/Atom/JSON Feed items (POST)",
          operationId: "parseRssPost",
          requestBody: {
            required: true,
            content: { "application/json": { schema: { type: "object", required: ["url"], properties: { url: { type: "string" }, keyword: { type: "string" }, limit: { type: "integer" } } } } }
          },
          responses: { "200": { description: "Normalized feed items" } }
        }
      },
      "/v1/b2b-contacts": {
        get: {
          summary: "Multi-page B2B email (role vs personal), phone, WhatsApp & social extractor",
          operationId: "extractB2bContactsGet",
          parameters: [{ name: "url", in: "query", required: true, schema: { type: "string", example: "https://danlopes18-ctrl.github.io/" } }],
          responses: { "200": { description: "Verified public emails, phones, booking links, and social profiles" } }
        },
        post: {
          summary: "Multi-page B2B contact extractor (POST)",
          operationId: "extractB2bContactsPost",
          requestBody: {
            required: true,
            content: { "application/json": { schema: { type: "object", required: ["url"], properties: { url: { type: "string" } } } } }
          },
          responses: { "200": { description: "B2B contact intelligence report" } }
        }
      }
    }
  };
}
