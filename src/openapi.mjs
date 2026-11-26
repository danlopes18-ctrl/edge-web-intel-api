/**
 * OpenAPI 3.1 Specification for Edge Web Intelligence API v1.1
 * Ready for 1-click import into RapidAPI, API.market, Zyla API Hub, Postman, and OpenAI Actions.
 */
export function buildOpenApiSpec(serverUrl = "https://edge-web-intel-api.danlopes18.workers.dev") {
  return {
    openapi: "3.1.0",
    info: {
      title: "AI Web Intelligence, Agent Search & B2B Enrichment API",
      version: "1.1.0",
      description: "Zero-browser, sub-second edge API with 7 production endpoints: Cloudflare Search for Agents Readiness Auditor (/.well-known/search, RFC 10008 HTTP QUERY, Accept: text/markdown, /llms.txt, robots.txt AI bots), 4-Tier Cascade Agent Search with BM25 ranking, Website Tech/Security Auditor, LLM-Ready Markdown Crawler, GitHub Org Velocity Intelligence, RSS/Atom News Aggregator, and Multi-Page B2B Contact Extractor. SSRF-shielded.",
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
      },
      schemas: {
        AgentReadinessReport: {
          type: "object",
          properties: {
            url: { type: "string" },
            origin: { type: "string" },
            status_code: { type: "integer" },
            score: { type: "integer", minimum: 0, maximum: 100 },
            grade: { type: "string", enum: ["A+", "A", "B+", "B", "C", "D", "F"] },
            checks: {
              type: "object",
              properties: {
                well_known_search: { type: "object" },
                html_discovery: { type: "object" },
                markdown_negotiation: { type: "object" },
                llms_txt: { type: "object" },
                robots_and_sitemap: { type: "object" }
              }
            },
            token_savings_estimate: {
              type: "object",
              properties: {
                source: { type: "string" },
                html_bytes: { type: "integer" },
                html_estimated_tokens: { type: "integer" },
                markdown_bytes: { type: "integer" },
                markdown_estimated_tokens: { type: "integer" },
                bytes_saved: { type: "integer" },
                tokens_saved: { type: "integer" },
                savings_percent: { type: "number" },
                estimated_usd_saved_per_10k_fetches_at_3_per_1m_tokens: { type: "number" }
              }
            },
            cloudflare_overage_risk: {
              type: "object",
              properties: {
                detected_cloudflare_edge: { type: "boolean" },
                risk_level: { type: "string", enum: ["low", "medium", "high"] },
                pricing_watch: { type: "object" },
                assessment: { type: "string" }
              }
            },
            recommendations: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  priority: { type: "string" },
                  code: { type: "string" },
                  title: { type: "string" },
                  detail: { type: "string" }
                }
              }
            },
            elapsed_ms: { type: "integer" }
          }
        },
        AgentSearchResponse: {
          type: "object",
          properties: {
            url: { type: "string" },
            query: { type: "string" },
            source_tier: {
              type: "string",
              enum: [
                "tier1_well_known_search",
                "tier2_markdown_negotiation",
                "tier3_llms_txt",
                "tier4_edge_html_to_markdown"
              ]
            },
            discovered_endpoints: {
              type: "object",
              properties: {
                well_known_search: { type: ["string", "null"] },
                agent_endpoint: { type: ["string", "null"] },
                markdown_negotiation: { type: "boolean" },
                llms_txt: { type: ["string", "null"] }
              }
            },
            chunks: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  rank: { type: "integer" },
                  score: { type: "number" },
                  heading: { type: "string" },
                  text: { type: "string" },
                  estimated_tokens: { type: "integer" }
                }
              }
            },
            total_estimated_tokens: { type: "integer" },
            elapsed_ms: { type: "integer" }
          }
        }
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
      "/v1/agent-readiness": {
        get: {
          summary: "Audit any website for Cloudflare Search for Agents & AI-readiness (Cascade Discovery)",
          description: "Probes /.well-known/search (RFC 10008 HTTP QUERY / GET / POST), HTML <meta name=\"agent:endpoint\"> & <link rel=\"search\">, Accept: text/markdown (Markdown for Agents, Vary: Accept, x-markdown-tokens), /llms.txt & /llms-full.txt, and /robots.txt AI crawler policies + /sitemap.xml. Returns score (0-100), grade (A+-F), token savings, Cloudflare $0.75/1k overage risk, and actionable recommendations.",
          operationId: "auditAgentReadinessGet",
          parameters: [
            {
              name: "url",
              in: "query",
              required: true,
              schema: { type: "string", example: "https://blog.cloudflare.com/search-for-agents/" }
            }
          ],
          responses: {
            "200": {
              description: "Structured Agent Readiness audit report",
              content: { "application/json": { schema: { $ref: "#/components/schemas/AgentReadinessReport" } } }
            },
            "400": { description: "Invalid URL or SSRF target blocked" },
            "401": { description: "Unauthorized" }
          }
        },
        post: {
          summary: "Audit any website for Cloudflare Search for Agents & AI-readiness (POST)",
          operationId: "auditAgentReadinessPost",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["url"],
                  properties: {
                    url: { type: "string", example: "https://blog.cloudflare.com/search-for-agents/" }
                  }
                }
              }
            }
          },
          responses: {
            "200": {
              description: "Structured Agent Readiness audit report",
              content: { "application/json": { schema: { $ref: "#/components/schemas/AgentReadinessReport" } } }
            },
            "400": { description: "Invalid URL or SSRF target blocked" },
            "401": { description: "Unauthorized" }
          }
        }
      },
      "/v1/agent-search": {
        get: {
          summary: "4-Tier Cascade Discovery agent-first search with BM25 chunk ranking (GET)",
          description: "Guarantees high-signal chunks on 100% of sites on Day 1: Tier 1 /.well-known/search -> Tier 2 Accept: text/markdown -> Tier 3 /llms.txt -> Tier 4 Edge HTML-to-Markdown + deterministic BM25 chunk ranking.",
          operationId: "agentSearchCascadeGet",
          parameters: [
            { name: "url", in: "query", required: true, schema: { type: "string", example: "https://blog.cloudflare.com/search-for-agents/" } },
            { name: "query", in: "query", required: true, schema: { type: "string", example: "markdown tokens query method" } },
            { name: "max_chunks", in: "query", required: false, schema: { type: "integer", default: 5, minimum: 1, maximum: 15 } },
            { name: "max_chars", in: "query", required: false, schema: { type: "integer", default: 1200, minimum: 200, maximum: 4000 } }
          ],
          responses: {
            "200": {
              description: "Ranked agent-ready chunks with source tier and token counts",
              content: { "application/json": { schema: { $ref: "#/components/schemas/AgentSearchResponse" } } }
            },
            "400": { description: "Invalid parameters or SSRF target blocked" },
            "401": { description: "Unauthorized" }
          }
        },
        post: {
          summary: "4-Tier Cascade Discovery agent-first search with BM25 chunk ranking (POST)",
          operationId: "agentSearchCascadePost",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["url", "query"],
                  properties: {
                    url: { type: "string", example: "https://blog.cloudflare.com/search-for-agents/" },
                    query: { type: "string", example: "search for agents markdown" },
                    max_chunks: { type: "integer", default: 5, minimum: 1, maximum: 15 },
                    max_chars: { type: "integer", default: 1200, minimum: 200, maximum: 4000 }
                  }
                }
              }
            }
          },
          responses: {
            "200": {
              description: "Ranked agent-ready chunks with source tier and token counts",
              content: { "application/json": { schema: { $ref: "#/components/schemas/AgentSearchResponse" } } }
            },
            "400": { description: "Invalid parameters or SSRF target blocked" },
            "401": { description: "Unauthorized" }
          }
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
