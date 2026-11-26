/**
 * 5 Zero-Browser Web Intelligence Engines (Pure Portable ESM — Cloudflare Workers + Node.js 22)
 */
import { HttpError, assertUpstreamOk, normalizeAndValidateUrl, safeFetch } from "./ssrf.mjs";

function decodeEntities(s) {
  return String(s || "")
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&nbsp;/g, " ")
    .replace(/&#x([0-9a-fA-F]+);/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)));
}

function stripTags(html) {
  return decodeEntities(String(html || "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim());
}

// ============================================================================
// ENGINE 1: Website Tech Stack, Security Headers & AI-Readiness (llms.txt) Auditor
// ============================================================================
const TECH_SIGNATURES = [
  ["Next.js", /_next\/static|__NEXT_DATA__/i],
  ["React", /react-dom|data-reactroot|__REACT/i],
  ["Vue.js", /__VUE__|vue\.runtime/i],
  ["Nuxt", /__NUXT__|\/_nuxt\//i],
  ["Astro", /astro-island|generator" content="Astro/i],
  ["Tailwind CSS", /tailwindcss|class="[^"]*\b(flex|grid|bg-slate|text-slate|px-\d|py-\d)\b/i],
  ["WordPress", /wp-content\/|wp-includes\//i],
  ["Shopify", /cdn\.shopify\.com|Shopify\.theme/i],
  ["Webflow", /webflow\.com|data-wf-site/i],
  ["Stripe", /js\.stripe\.com|stripe\.com/i],
  ["Google Analytics / GTM", /googletagmanager\.com|gtag\(/i],
  ["PostHog", /posthog\.com|posthog-js/i],
  ["Plausible", /plausible\.io\/js/i],
  ["Intercom", /widget\.intercom\.io/i],
  ["HubSpot", /js\.hs-scripts\.com|hs-analytics/i],
  ["Sentry", /browser\.sentry-cdn\.com|sentry\.io/i]
];

const SECURITY_HEADERS = [
  "strict-transport-security",
  "content-security-policy",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
  "cross-origin-opener-policy"
];

export async function auditWebsite(rawUrl) {
  const t0 = Date.now();
  const parsed = normalizeAndValidateUrl(rawUrl);
  const origin = parsed.origin;

  const [mainRes, llmsRes, robotsRes] = await Promise.all([
    safeFetch(parsed.toString(), { timeoutMs: 10000 }),
    safeFetch(`${origin}/llms.txt`, { timeoutMs: 5000 }).catch(() => null),
    safeFetch(`${origin}/robots.txt`, { timeoutMs: 5000 }).catch(() => null)
  ]);

  assertUpstreamOk(mainRes);

  const html = mainRes.text || "";
  const hdrs = mainRes.response.headers;
  const title = stripTags((html.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || "");
  const metaDesc = decodeEntities((html.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']+)["']/i) || [])[1] || "");

  // Tech stack detection
  const techStack = [];
  for (const [name, re] of TECH_SIGNATURES) {
    if (re.test(html)) techStack.push(name);
  }
  const server = hdrs.get("server") || "";
  const poweredBy = hdrs.get("x-powered-by") || "";
  if (/cloudflare/i.test(server) || hdrs.get("cf-ray")) techStack.push("Cloudflare");
  if (/vercel/i.test(server) || hdrs.get("x-vercel-id")) techStack.push("Vercel");
  if (/netlify/i.test(server) || hdrs.get("x-nf-request-id")) techStack.push("Netlify");
  if (/github\.com/i.test(server) || hdrs.get("x-github-request-id")) techStack.push("GitHub Pages");
  if (poweredBy && !techStack.includes(poweredBy)) techStack.push(poweredBy);

  // Security headers grading
  const headersMap = {};
  let secScore = 0;
  for (const h of SECURITY_HEADERS) {
    const present = Boolean(hdrs.get(h));
    headersMap[h] = present;
    if (present) secScore += 1;
  }
  const grade = secScore >= 6 ? "A+" : secScore === 5 ? "A" : secScore === 4 ? "B" : secScore === 3 ? "C" : secScore === 2 ? "D" : "F";

  // AI readiness (llms.txt + robots.txt + JSON-LD + sitemap)
  const hasLlmsTxt = Boolean(llmsRes && llmsRes.response.status === 200 && llmsRes.text.trim().length > 20 && !/<html/i.test(llmsRes.text));
  const robotsTxt = robotsRes && robotsRes.response.status === 200 ? robotsRes.text : "";
  const hasJsonLd = /application\/ld\+json/i.test(html);
  const hasSitemap = /sitemap:/i.test(robotsTxt);
  const aiBotsBlocked = [];
  for (const bot of ["GPTBot", "ClaudeBot", "PerplexityBot", "CCBot", "Google-Extended"]) {
    const re = new RegExp(`User-agent:\\s*${bot}[\\s\\S]{0,120}Disallow:\\s*/\\s*($|\\n)`, "i");
    if (re.test(robotsTxt)) aiBotsBlocked.push(bot);
  }
  const aiReadinessScore = Math.min(100, (hasLlmsTxt ? 40 : 0) + (hasJsonLd ? 25 : 0) + (hasSitemap ? 15 : 0) + (metaDesc ? 10 : 0) + (aiBotsBlocked.length === 0 ? 10 : 0));

  return {
    url: mainRes.finalUrl,
    statusCode: mainRes.response.status,
    latencyMs: Date.now() - t0,
    meta: { title, description: metaDesc },
    techStack: [...new Set(techStack)],
    security: { grade, score: `${secScore}/${SECURITY_HEADERS.length}`, headers: headersMap },
    aiReadiness: {
      score: aiReadinessScore,
      hasLlmsTxt,
      llmsTxtPreview: hasLlmsTxt ? llmsRes.text.trim().slice(0, 320) : null,
      hasJsonLd,
      hasSitemapInRobots: hasSitemap,
      aiBotsBlocked
    }
  };
}

// ============================================================================
// SHARED HTML -> MARKDOWN & BM25 UTILITIES
// ============================================================================
export function htmlToCleanMarkdown(html, finalUrl) {
  const rawHtml = String(html || "");
  const title = stripTags((rawHtml.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || "");
  const mainMatch = rawHtml.match(/<(main|article)[^>]*>([\s\S]*?)<\/\1>/i);
  let body = mainMatch ? mainMatch[2] : (rawHtml.match(/<body[^>]*>([\s\S]*?)<\/body>/i)?.[1] || rawHtml);

  body = body
    .replace(/<(script|style|noscript|svg|iframe|nav|footer|aside|template)[^>]*>[\s\S]*?<\/\1>/gi, "\n")
    .replace(/<!--[\s\S]*?-->/g, "");

  const headings = [];
  for (const m of body.matchAll(/<h([1-4])[^>]*>([\s\S]*?)<\/h\1>/gi)) {
    const txt = stripTags(m[2]);
    if (txt) headings.push({ level: Number(m[1]), text: txt });
  }

  let md = body
    .replace(/<pre[^>]*><code[^>]*>([\s\S]*?)<\/code><\/pre>/gi, (_, c) => `\n\`\`\`\n${decodeEntities(c.replace(/<[^>]+>/g, "")).trim()}\n\`\`\`\n`)
    .replace(/<h1[^>]*>([\s\S]*?)<\/h1>/gi, (_, x) => `\n# ${stripTags(x)}\n`)
    .replace(/<h2[^>]*>([\s\S]*?)<\/h2>/gi, (_, x) => `\n## ${stripTags(x)}\n`)
    .replace(/<h3[^>]*>([\s\S]*?)<\/h3>/gi, (_, x) => `\n### ${stripTags(x)}\n`)
    .replace(/<h4[^>]*>([\s\S]*?)<\/h4>/gi, (_, x) => `\n#### ${stripTags(x)}\n`)
    .replace(/<li[^>]*>([\s\S]*?)<\/li>/gi, (_, x) => `- ${stripTags(x)}\n`)
    .replace(/<a[^>]+href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi, (_, href, txt) => {
      const label = stripTags(txt);
      if (!label || href.startsWith("javascript:")) return label;
      try { return `[${label}](${new URL(href, finalUrl).toString()})`; } catch { return label; }
    })
    .replace(/<code[^>]*>([\s\S]*?)<\/code>/gi, (_, x) => `\`${stripTags(x)}\``)
    .replace(/<(p|div|section|br|tr)[^>]*>/gi, "\n")
    .replace(/<[^>]+>/g, "");

  md = decodeEntities(md)
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();

  return { title, headings, markdown: md };
}

// ============================================================================
// ENGINE 2: Fast LLM-Ready HTML-to-Markdown Converter (RAG / MCP)
// ============================================================================
export async function crawlMarkdown(rawUrl) {
  const t0 = Date.now();
  const res = await safeFetch(rawUrl, { timeoutMs: 10000 });
  assertUpstreamOk(res);
  const { title, headings, markdown: md } = htmlToCleanMarkdown(res.text || "", res.finalUrl);

  const words = md ? md.split(/\s+/).length : 0;
  const estimatedTokens = Math.ceil(md.length / 4);

  return {
    url: res.finalUrl,
    statusCode: res.response.status,
    latencyMs: Date.now() - t0,
    title,
    wordCount: words,
    estimatedTokens,
    headings: headings.slice(0, 40),
    markdown: md.slice(0, 60000)
  };
}

// ============================================================================
// ENGINE 3: GitHub Organization & Repo Velocity / AI-Adoption Intelligence
// ============================================================================
export async function inspectGithubOrg(orgInput, githubToken = "") {
  const t0 = Date.now();
  const org = String(orgInput || "")
    .trim()
    .replace(/^https?:\/\/github\.com\//i, "")
    .split("/")[0]
    .replace(/[^a-zA-Z0-9-]/g, "");
  if (!org) throw new HttpError("Missing or invalid 'org' parameter.", 400);

  const headers = { Accept: "application/vnd.github+json" };
  if (githubToken) headers.Authorization = `Bearer ${githubToken}`;

  const [profRes, reposRes] = await Promise.all([
    safeFetch(`https://api.github.com/users/${org}`, { timeoutMs: 9000, headers }),
    safeFetch(`https://api.github.com/users/${org}/repos?sort=updated&per_page=15`, { timeoutMs: 9000, headers })
  ]);

  if (profRes.response.status === 404) {
    throw new HttpError(`GitHub user or organization '${org}' not found.`, 404, 404);
  }
  if (profRes.response.status !== 200) {
    throw new HttpError(`GitHub lookup failed (HTTP ${profRes.response.status}) for '${org}'.`, 502, profRes.response.status);
  }

  const profile = JSON.parse(profRes.text);
  const repos = reposRes.response.status === 200 ? JSON.parse(reposRes.text) : [];
  const totalStars = repos.reduce((s, r) => s + (r.stargazers_count || 0), 0);
  const langCounts = {};
  const aiSignals = new Set();
  const now = Date.now();
  let recentlyActive = 0;

  for (const r of repos) {
    if (r.language) langCounts[r.language] = (langCounts[r.language] || 0) + 1;
    const pushedAgeDays = (now - Date.parse(r.pushed_at || 0)) / 86400000;
    if (pushedAgeDays <= 30) recentlyActive += 1;
    const blob = `${r.name} ${r.description || ""} ${(r.topics || []).join(" ")}`.toLowerCase();
    for (const kw of ["mcp", "llm", "ai-agent", "rag", "openai", "claude", "n8n", "langchain", "vector"]) {
      if (blob.includes(kw)) aiSignals.add(kw);
    }
  }

  const topLanguages = Object.entries(langCounts).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([l]) => l);
  const velocityScore = Math.min(100, recentlyActive * 10 + Math.min(35, Math.floor(Math.log10(totalStars + 1) * 12)) + aiSignals.size * 5);

  return {
    org: profile.login,
    type: profile.type,
    name: profile.name,
    bio: profile.bio,
    blog: profile.blog || null,
    location: profile.location || null,
    email: profile.email || null,
    followers: profile.followers,
    publicRepos: profile.public_repos,
    latencyMs: Date.now() - t0,
    intelligence: {
      velocityScore,
      recentlyActiveRepos30d: recentlyActive,
      sampledTopStars: totalStars,
      topLanguages,
      aiAdoptionSignals: [...aiSignals]
    },
    topRepos: repos.slice(0, 8).map(r => ({
      name: r.name,
      url: r.html_url,
      stars: r.stargazers_count,
      forks: r.forks_count,
      language: r.language,
      pushedAt: r.pushed_at,
      description: r.description
    }))
  };
}

// ============================================================================
// ENGINE 4: RSS, Atom & JSON Feed Auto-Discovery & LLM News Aggregator
// ============================================================================
function extractTag(block, tag) {
  const m = block.match(new RegExp(`<${tag}[^>]*>(?:<!\\[CDATA\\[)?([\\s\\S]*?)(?:\\]\\]>)?<\\/${tag}>`, "i"));
  return m ? decodeEntities(m[1]).trim() : "";
}

export async function parseRssFeed(rawUrl, { keyword = "", limit = 15 } = {}) {
  const t0 = Date.now();
  const maxItems = Math.max(1, Math.min(50, Number(limit) || 15));
  let res = await safeFetch(rawUrl, { timeoutMs: 10000 });
  assertUpstreamOk(res);
  let feedUrl = res.finalUrl;
  let body = res.text || "";

  // Auto-discover RSS/Atom link if caller passed an HTML homepage
  if (/<html/i.test(body.slice(0, 1200))) {
    const linkTag = body.match(/<link[^>]+type=["']application\/(rss\+xml|atom\+xml|feed\+json)["'][^>]*>/i);
    const href = linkTag?.[0]?.match(/href=["']([^"']+)["']/i)?.[1];
    if (href) {
      feedUrl = new URL(href, feedUrl).toString();
      res = await safeFetch(feedUrl, { timeoutMs: 10000 });
      assertUpstreamOk(res);
      body = res.text || "";
    }
  }

  let items = [];
  let feedTitle = "";
  let recognizedFeed = false;

  if (body.trim().startsWith("{")) {
    let j;
    try {
      j = JSON.parse(body);
    } catch {
      throw new HttpError("Target URL returned invalid JSON instead of a feed.", 422);
    }
    if (!Array.isArray(j?.items)) {
      throw new HttpError("No valid JSON Feed found at target URL.", 422);
    }
    recognizedFeed = true;
    feedTitle = j.title || "";
    items = j.items.map(it => ({
      title: it.title || "",
      url: it.url || it.external_url || "",
      publishedAt: it.date_published || it.date_modified || null,
      summary: stripTags(it.summary || it.content_text || it.content_html || "").slice(0, 320)
    }));
  } else if (/<entry[\s>]/i.test(body) || /<feed[\s>]/i.test(body)) {
    recognizedFeed = true;
    feedTitle = stripTags(extractTag(body.split(/<entry[\s>]/i)[0], "title"));
    for (const m of body.matchAll(/<entry[\s>]([\s\S]*?)<\/entry>/gi)) {
      const b = m[1];
      const href = b.match(/<link[^>]+href=["']([^"']+)["']/i)?.[1] || extractTag(b, "id");
      items.push({
        title: stripTags(extractTag(b, "title")),
        url: href,
        publishedAt: extractTag(b, "published") || extractTag(b, "updated") || null,
        summary: stripTags(extractTag(b, "summary") || extractTag(b, "content")).slice(0, 320)
      });
    }
  } else if (/<item[\s>]/i.test(body) || /<rss[\s>]/i.test(body) || /<rdf:RDF[\s>]/i.test(body)) {
    recognizedFeed = true;
    feedTitle = stripTags(extractTag(body.split(/<item[\s>]/i)[0], "title"));
    for (const m of body.matchAll(/<item[\s>]([\s\S]*?)<\/item>/gi)) {
      const b = m[1];
      items.push({
        title: stripTags(extractTag(b, "title")),
        url: extractTag(b, "link") || extractTag(b, "guid"),
        publishedAt: extractTag(b, "pubDate") || extractTag(b, "dc:date") || null,
        summary: stripTags(extractTag(b, "description") || extractTag(b, "content:encoded")).slice(0, 320)
      });
    }
  }

  if (!recognizedFeed) {
    throw new HttpError("No valid RSS, Atom, or JSON feed found at target URL.", 422);
  }

  const kw = String(keyword || "").trim().toLowerCase();
  if (kw) {
    items = items.filter(it => `${it.title} ${it.summary}`.toLowerCase().includes(kw));
  }

  return {
    feedUrl,
    feedTitle,
    latencyMs: Date.now() - t0,
    totalReturned: Math.min(items.length, maxItems),
    items: items.slice(0, maxItems)
  };
}

// ============================================================================
// ENGINE 5: Multi-Page B2B Contact, Email, Phone & Social Profile Extractor
// ============================================================================
const ROLE_PREFIXES = new Set([
  "info", "contact", "sales", "support", "hello", "hi", "team", "admin",
  "press", "media", "billing", "careers", "jobs", "legal", "privacy",
  "security", "help", "partners", "marketing", "enterprise", "feedback",
  "inquiries", "enquiries", "office", "general", "hr", "ir", "investors",
  "compliance", "abuse", "dmca", "editorial", "news", "pr", "dev", "developers"
]);

const PLACEHOLDER_LOCAL_PARTS = new Set([
  "user", "username", "yourname", "your.name", "your-name", "your_name",
  "you", "name", "firstname", "first.last", "firstname.lastname",
  "john.doe", "johndoe", "jane.doe", "janedoe", "jane.smith", "john.smith",
  "jane.diaz", "jenny.rosen", "john", "jane", "test", "testuser", "demo",
  "sample", "placeholder", "email", "someone", "nobody", "example", "exemplo",
  "foo", "bar", "baz", "noreply", "no-reply", "donotreply", "do-not-reply",
  "mailer-daemon", "postmaster"
]);

const PLACEHOLDER_DOMAIN_RE = /(?:^|\.)(?:example|exemplo|ejemplo|exemple|beispiel)\.[a-z.]{2,}$|(?:^|\.)(?:test|invalid|localhost|localdomain)$|(?:^|\.)(?:domain|yourdomain|company|yourcompany|acme|acmecorp|mailinator|placeholder|sample|demo|mysite|website|email|foo|bar)\.(?:com|org|net|io|co|co\.uk)$/i;

const TECH_JUNK_EMAIL_RE = /(?:^|\.)(?:sentry\.io|wixpress\.com|schema\.org|w3\.org|googleapis\.com|gstatic\.com|cloudfront\.net|gravatar\.com)$|\.(?:png|jpg|jpeg|svg|gif|webp|ico|css|js|mjs|woff|woff2|ttf|eot|map|json|xml|pdf)$/i;

const STRICT_EMAIL_RE = /^[a-z0-9][a-z0-9._%+-]{0,63}@[a-z0-9-]+(?:\.[a-z0-9-]+)+$/;
const EMAIL_SCAN_RE = /(?<![a-zA-Z0-9._%+-])([a-zA-Z0-9][a-zA-Z0-9._%+-]{0,63}@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)(?![a-zA-Z0-9._%+-])/g;
const SOCIAL_URL_RE = /https?:\/\/(?:www\.)?(?:linkedin\.com\/(?:company|in)\/[^\s"'<>\\]+|x\.com\/[A-Za-z0-9_]{2,20}|twitter\.com\/[A-Za-z0-9_]{2,20}|github\.com\/[A-Za-z0-9_-]{2,40}|instagram\.com\/[A-Za-z0-9_.]{2,30}|youtube\.com\/(?:@|c\/|channel\/)[^\s"'<>\\]+|wa\.me\/\d+|calendly\.com\/[^\s"'<>\\]+|cal\.com\/[^\s"'<>\\]+)/gi;

function cleanAndValidateEmail(raw) {
  let candidate = String(raw || "").trim().replace(/^mailto:/i, "").split("?")[0].trim();
  try { candidate = decodeURIComponent(candidate); } catch {}
  candidate = decodeEntities(candidate).trim().replace(/^[^a-zA-Z0-9]+|[^a-zA-Z0-9]+$/g, "").toLowerCase();
  if (!candidate || candidate.length > 254) return null;
  if (!STRICT_EMAIL_RE.test(candidate)) return null;
  // Reject escaped Unicode artifacts such as "u003esales@..."
  if (/^u00[0-9a-f]{2}/i.test(candidate)) return null;
  const atIdx = candidate.indexOf("@");
  const local = candidate.slice(0, atIdx);
  const domain = candidate.slice(atIdx + 1);
  if (!local || !domain || local.includes("..") || domain.includes("..")) return null;
  if (PLACEHOLDER_LOCAL_PARTS.has(local)) return null;
  if (PLACEHOLDER_DOMAIN_RE.test(domain) || TECH_JUNK_EMAIL_RE.test(domain)) return null;
  const tld = domain.split(".").pop() || "";
  if (tld.length < 2 || tld.length > 12 || /\d/.test(tld)) return null;
  return candidate;
}

function addSocialUrl(socials, rawLink) {
  const link = decodeEntities(String(rawLink || "")).replace(/[.,;)'"\\]+$/, "");
  if (!/^https?:\/\//i.test(link)) return;
  if (/linkedin\.com/i.test(link)) socials.linkedin.add(link);
  else if (/x\.com|twitter\.com/i.test(link)) socials.x.add(link);
  else if (/github\.com/i.test(link)) socials.github.add(link);
  else if (/instagram\.com/i.test(link)) socials.instagram.add(link);
  else if (/youtube\.com/i.test(link)) socials.youtube.add(link);
  else socials.bookingOrWhatsapp.add(link);
}

function collectJsonLdContacts(node, emailsMap, phones, socials) {
  if (!node || typeof node !== "object") return;
  if (Array.isArray(node)) {
    for (const item of node) collectJsonLdContacts(item, emailsMap, phones, socials);
    return;
  }
  if (typeof node.email === "string") {
    const clean = cleanAndValidateEmail(node.email);
    if (clean) emailsMap.set(clean, ROLE_PREFIXES.has(clean.split("@")[0]) ? "role" : "personal");
  }
  if (typeof node.telephone === "string") {
    const tel = node.telephone.trim();
    if (/^[+\d][\d\s().-]{7,18}\d$/.test(tel)) phones.add(tel);
  }
  if (node.sameAs) {
    const list = Array.isArray(node.sameAs) ? node.sameAs : [node.sameAs];
    for (const item of list) {
      if (typeof item === "string" && SOCIAL_URL_RE.test(item)) {
        SOCIAL_URL_RE.lastIndex = 0;
        addSocialUrl(socials, item);
      }
      SOCIAL_URL_RE.lastIndex = 0;
    }
  }
  for (const val of Object.values(node)) {
    if (val && typeof val === "object") collectJsonLdContacts(val, emailsMap, phones, socials);
  }
}

export async function extractB2bContacts(rawUrl) {
  const t0 = Date.now();
  const parsed = normalizeAndValidateUrl(rawUrl);
  const main = await safeFetch(parsed.toString(), { timeoutMs: 10000 });
  assertUpstreamOk(main);
  const pages = [{ url: main.finalUrl, html: main.text || "" }];

  // Discover up to 3 internal contact/about/team pages
  const subLinks = new Set();
  for (const m of (main.text || "").matchAll(/href=["']([^"'#]+)["']/gi)) {
    const href = m[1];
    if (/\/(contact|about|team|company|support|legal)/i.test(href)) {
      try {
        const u = new URL(href, main.finalUrl);
        if (u.origin === new URL(main.finalUrl).origin && u.toString() !== main.finalUrl) {
          subLinks.add(u.toString());
        }
      } catch {}
    }
    if (subLinks.size >= 3) break;
  }

  if (subLinks.size > 0) {
    const extras = await Promise.all([...subLinks].map(u => safeFetch(u, { timeoutMs: 6000 }).catch(() => null)));
    for (const ex of extras) {
      if (ex && ex.response.status === 200) pages.push({ url: ex.finalUrl, html: ex.text || "" });
    }
  }

  const emailsMap = new Map();
  const phones = new Set();
  const socials = { linkedin: new Set(), x: new Set(), github: new Set(), instagram: new Set(), youtube: new Set(), bookingOrWhatsapp: new Set() };

  const addEmail = raw => {
    const clean = cleanAndValidateEmail(raw);
    if (!clean) return;
    const prefix = clean.split("@")[0];
    emailsMap.set(clean, ROLE_PREFIXES.has(prefix) ? "role" : "personal");
  };

  for (const p of pages) {
    const rawHtml = p.html || "";

    // 1. Parse structured JSON-LD blocks (legitimate Organization / ContactPoint metadata)
    for (const jm of rawHtml.matchAll(/<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)) {
      try {
        collectJsonLdContacts(JSON.parse(jm[1]), emailsMap, phones, socials);
      } catch {}
    }

    // 2. Strip executable/non-visible blocks (<script>, <style>, <svg>, <noscript>, <template>, comments)
    //    so SSR i18n bundles, UI demo mockups, and escaped JSON strings never pollute results.
    const htmlNoScripts = rawHtml
      .replace(/<(script|style|noscript|svg|template)[^>]*>[\s\S]*?<\/\1>/gi, " ")
      .replace(/<!--[\s\S]*?-->/g, " ");

    // 3. Extract explicit mailto: links
    for (const m of htmlNoScripts.matchAll(/href=["']\s*mailto:([^"'#]+)["']/gi)) {
      addEmail(m[1]);
    }

    // 4. Extract plain visible text emails (strip all HTML tags first so <input placeholder="..."> is never matched)
    const visibleText = decodeEntities(htmlNoScripts.replace(/<[^>]+>/g, " "));
    for (const m of visibleText.matchAll(EMAIL_SCAN_RE)) {
      addEmail(m[1]);
    }

    // 5. Extract tel: phone numbers and social profile links from non-script HTML
    const cleanHtmlAttrs = decodeEntities(htmlNoScripts);
    for (const m of cleanHtmlAttrs.matchAll(/(?:tel:|href=["']tel:)([+\d][\d\s().-]{7,18}\d)/gi)) {
      phones.add(m[1].trim());
    }
    for (const m of cleanHtmlAttrs.matchAll(SOCIAL_URL_RE)) {
      addSocialUrl(socials, m[0]);
    }
  }

  return {
    url: main.finalUrl,
    pagesScanned: pages.map(p => p.url),
    latencyMs: Date.now() - t0,
    emails: [...emailsMap.entries()].map(([email, type]) => ({ email, type })),
    phones: [...phones],
    socials: Object.fromEntries(Object.entries(socials).map(([k, v]) => [k, [...v]]))
  };
}

// ============================================================================
// ENGINE 6 & 7 HELPERS: Cascade Discovery, AI Robots Parser & BM25 Chunker
// ============================================================================
const AI_BOTS = [
  "GPTBot",
  "ClaudeBot",
  "PerplexityBot",
  "OAI-SearchBot",
  "Google-Extended",
  "CCBot"
];

const STOPWORDS = new Set([
  "the", "and", "for", "with", "that", "this", "from", "are", "was", "were",
  "have", "has", "had", "not", "but", "you", "your", "into", "about", "what",
  "when", "where", "how", "why", "can", "all", "any", "our", "out", "use",
  "using", "its", "they", "them", "their", "will", "would", "could", "should"
]);

function estimateTokenCount(text) {
  const s = String(text || "");
  if (!s) return 0;
  return Math.ceil(s.length / 4);
}

function byteSizeUtf8(text) {
  return new TextEncoder().encode(String(text || "")).byteLength;
}

function extractMetaContent(html, metaName) {
  const escaped = metaName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re1 = new RegExp(`<meta[^>]+name=["']${escaped}["'][^>]+content=["']([^"']+)["']`, "i");
  const re2 = new RegExp(`<meta[^>]+content=["']([^"']+)["'][^>]+name=["']${escaped}["']`, "i");
  const m = html.match(re1) || html.match(re2);
  return m ? decodeEntities(m[1]).trim() : null;
}

function parseMarkdownFrontmatterAgent(md) {
  const m = String(md || "").match(/^---\r?\n([\s\S]{1,4000}?)\r?\n---/);
  if (!m) return null;
  const fm = m[1];
  if (!/(?:^|\n)agent\s*:/i.test(fm)) return null;
  const endpoint = (fm.match(/^\s+endpoint:\s*["']?([^"'\r\n]+)["']?/m) || [])[1]?.trim() || null;
  const method = (fm.match(/^\s+method:\s*["']?([^"'\r\n]+)["']?/m) || [])[1]?.trim() || null;
  const instructions = (fm.match(/^\s+instructions:\s*["']?([^"'\r\n]+)["']?/m) || [])[1]?.trim() || null;
  const documentation = (fm.match(/^\s+documentation:\s*["']?([^"'\r\n]+)["']?/m) || [])[1]?.trim() || null;
  return { endpoint, method, instructions, documentation };
}

function parseHtmlDiscovery(html, baseUrl, headers) {
  const agentEndpoint = extractMetaContent(html, "agent:endpoint");
  const agentMethod = extractMetaContent(html, "agent:method");
  const agentInstructions = extractMetaContent(html, "agent:instructions");
  const agentDocumentation = extractMetaContent(html, "agent:documentation");

  const linkRelSearch = [];
  for (const m of String(html || "").matchAll(/<link\b[^>]*rel=["'][^"']*\bsearch\b[^"']*["'][^>]*>/gi)) {
    const tag = m[0];
    const href = tag.match(/href=["']([^"']+)["']/i)?.[1] || null;
    const type = tag.match(/type=["']([^"']+)["']/i)?.[1] || null;
    const title = tag.match(/title=["']([^"']+)["']/i)?.[1] || null;
    let resolved = href;
    if (href) {
      try { resolved = new URL(href, baseUrl).toString(); } catch {}
    }
    linkRelSearch.push({ href: resolved, type, title });
  }

  const linkHeader = headers?.get?.("link") || "";
  const linkRelations = [];
  for (const m of linkHeader.matchAll(/<([^>]+)>([^,]*)/g)) {
    const rel = m[2].match(/rel=["']?([^;"'\s]+)/i)?.[1] || null;
    const type = m[2].match(/type=["']?([^;"'\s]+)/i)?.[1] || null;
    if (rel && /search|api-catalog|describedby|sitemap|alternate|service-desc/i.test(rel)) {
      let resolved = m[1];
      try { resolved = new URL(m[1], baseUrl).toString(); } catch {}
      linkRelations.push({ rel, href: resolved, type });
    }
  }

  return {
    agent_endpoint: agentEndpoint,
    agent_method: agentMethod,
    agent_instructions: agentInstructions,
    agent_documentation: agentDocumentation,
    link_rel_search: linkRelSearch,
    link_header_relations: linkRelations
  };
}

function parseRobotsTxtAiBots(robotsTxt) {
  const text = String(robotsTxt || "");
  const sitemaps = [];
  const groups = [];
  let currentAgents = [];
  let currentRules = [];
  let sawRule = false;

  const flush = () => {
    if (currentAgents.length > 0) {
      groups.push({ agents: currentAgents, rules: currentRules });
    }
    currentAgents = [];
    currentRules = [];
    sawRule = false;
  };

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, "").trim();
    if (!line) continue;
    const idx = line.indexOf(":");
    if (idx === -1) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const val = line.slice(idx + 1).trim();

    if (key === "sitemap" && val) {
      sitemaps.push(val);
    } else if (key === "user-agent" && val) {
      if (sawRule) flush();
      currentAgents.push(val.toLowerCase());
    } else if ((key === "disallow" || key === "allow") && currentAgents.length > 0) {
      sawRule = true;
      currentRules.push({ type: key, path: val });
    }
  }
  flush();

  const evaluateRules = rules => {
    const hasRootAllow = rules.some(r => r.type === "allow" && r.path === "/");
    const hasRootDisallow = rules.some(r => r.type === "disallow" && r.path === "/");
    const hasEmptyDisallow = rules.some(r => r.type === "disallow" && r.path === "");
    const hasSubDisallow = rules.some(r => r.type === "disallow" && r.path.length > 1);
    if (hasRootDisallow && !hasRootAllow) return "blocked";
    if (hasRootAllow || hasEmptyDisallow) return "allowed";
    if (hasSubDisallow) return "partial";
    return "unspecified";
  };

  const wildcardRules = groups.filter(g => g.agents.includes("*")).flatMap(g => g.rules);
  const bots = {};
  const blocked = [];
  const allowed = [];

  for (const bot of AI_BOTS) {
    const botLower = bot.toLowerCase();
    const specificRules = groups.filter(g => g.agents.includes(botLower)).flatMap(g => g.rules);
    let policy;
    if (specificRules.length > 0) {
      policy = evaluateRules(specificRules);
    } else if (wildcardRules.length > 0) {
      const wp = evaluateRules(wildcardRules);
      policy = wp === "blocked" ? "blocked_by_wildcard" : wp === "partial" ? "partial_by_wildcard" : "allowed_default";
    } else {
      policy = "unspecified";
    }
    bots[bot] = policy;
    if (policy === "blocked" || policy === "blocked_by_wildcard") blocked.push(bot);
    else allowed.push(bot);
  }

  return { bots, blocked, allowed, sitemaps: [...new Set(sitemaps)] };
}

function tokenize(text) {
  const raw = String(text || "")
    .toLowerCase()
    .replace(/[^a-z0-9\u00c0-\u024f]+/g, " ")
    .trim()
    .split(/\s+/)
    .filter(w => w.length >= 2);
  const filtered = raw.filter(w => !STOPWORDS.has(w));
  return filtered.length > 0 ? filtered : raw;
}

function chunkMarkdown(md, maxChars = 1200) {
  const clean = String(md || "").replace(/^---\r?\n[\s\S]{1,4000}?\r?\n---\r?\n?/, "").trim();
  if (!clean) return [];

  const lines = clean.split(/\r?\n/);
  const sections = [];
  let currentHeading = "Introduction";
  let buf = [];

  const pushSection = () => {
    const text = buf.join("\n").trim();
    if (text) sections.push({ heading: currentHeading, text });
    buf = [];
  };

  for (const line of lines) {
    const hm = line.match(/^(#{1,4})\s+(.+)$/);
    if (hm) {
      pushSection();
      currentHeading = hm[2].trim().slice(0, 160);
    } else {
      buf.push(line);
    }
  }
  pushSection();

  const chunks = [];
  for (const sec of sections) {
    if (sec.text.length <= maxChars) {
      chunks.push({ heading: sec.heading, text: sec.text, idx: chunks.length });
      continue;
    }
    const paras = sec.text.split(/\n{2,}/);
    let acc = "";
    for (const p of paras) {
      if ((acc ? acc.length + 2 : 0) + p.length <= maxChars) {
        acc = acc ? `${acc}\n\n${p}` : p;
      } else {
        if (acc) chunks.push({ heading: sec.heading, text: acc, idx: chunks.length });
        if (p.length <= maxChars) {
          acc = p;
        } else {
          for (let i = 0; i < p.length; i += maxChars) {
            chunks.push({ heading: sec.heading, text: p.slice(i, i + maxChars).trim(), idx: chunks.length });
          }
          acc = "";
        }
      }
    }
    if (acc) chunks.push({ heading: sec.heading, text: acc, idx: chunks.length });
  }

  return chunks.filter(c => c.text.length >= 20 || chunks.length === 1);
}

function rankChunksBM25(chunks, query, maxChunks = 5) {
  if (!chunks.length) return [];
  const qTerms = tokenize(query);
  const qLower = String(query || "").trim().toLowerCase();

  const docs = chunks.map(c => {
    const tokens = tokenize(`${c.heading} ${c.text}`);
    const tf = new Map();
    for (const t of tokens) tf.set(t, (tf.get(t) || 0) + 1);
    return { ...c, tokens, len: Math.max(1, tokens.length), tf, headingLower: c.heading.toLowerCase(), textLower: c.text.toLowerCase() };
  });

  const N = docs.length;
  const avgdl = docs.reduce((s, d) => s + d.len, 0) / Math.max(1, N);
  const df = new Map();
  for (const term of new Set(qTerms)) {
    let count = 0;
    for (const d of docs) if (d.tf.has(term)) count++;
    df.set(term, count);
  }

  const k1 = 1.5;
  const b = 0.75;
  const scored = docs.map(d => {
    let score = 0;
    for (const term of qTerms) {
      const f = d.tf.get(term) || 0;
      if (f === 0) continue;
      const nq = df.get(term) || 0;
      const idf = Math.log(1 + (N - nq + 0.5) / (nq + 0.5));
      score += idf * ((f * (k1 + 1)) / (f + k1 * (1 - b + b * (d.len / avgdl))));
      if (d.headingLower.includes(term)) score += 1.25;
    }
    if (qLower.length >= 3 && (d.headingLower.includes(qLower) || d.textLower.includes(qLower))) {
      score += 2.5;
    }
    return {
      heading: d.heading,
      text: d.text,
      score: Number(score.toFixed(4)),
      idx: d.idx
    };
  });

  scored.sort((a, b) => (b.score - a.score) || (a.idx - b.idx));
  return scored.slice(0, maxChunks).map((c, i) => ({
    rank: i + 1,
    score: c.score,
    heading: c.heading,
    text: c.text,
    estimated_tokens: estimateTokenCount(c.text)
  }));
}

function parseWellKnownSearchResponse(body, contentType, query, maxChunks, maxChars) {
  const ct = String(contentType || "").toLowerCase();
  const trimmed = String(body || "").trim();
  if (!trimmed) return [];

  // 1. JSON search results format
  if (ct.includes("application/json") || trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      const parsed = JSON.parse(trimmed);
      const list = Array.isArray(parsed)
        ? parsed
        : (Array.isArray(parsed?.results) ? parsed.results : (Array.isArray(parsed?.hits) ? parsed.hits : (Array.isArray(parsed?.items) ? parsed.items : [])));
      if (list.length > 0) {
        return list.slice(0, maxChunks).map((item, i) => {
          const heading = String(item.title || item.heading || item.url || item.path || `Result ${i + 1}`).slice(0, 180);
          const rawText = String(item.text || item.content || item.snippet || item.markdown || item.description || JSON.stringify(item)).trim();
          const text = rawText.slice(0, maxChars);
          return {
            rank: i + 1,
            score: typeof item.score === "number" ? Number(item.score.toFixed(4)) : Number((1 / (i + 1)).toFixed(4)),
            heading,
            text,
            estimated_tokens: estimateTokenCount(text)
          };
        });
      }
    } catch {}
  }

  // 2. Cloudflare Search for Agents Markdown format: "## <url_or_path> (score: 0.988)\n<content>"
  const cfBlocks = trimmed.split(/\n(?=##\s+\S+)/);
  const parsedCf = [];
  for (const blk of cfBlocks) {
    const m = blk.match(/^##\s+(.+?)(?:\s+\(score:\s*([0-9.]+)\))?\s*\r?\n([\s\S]+)$/);
    if (!m) continue;
    const heading = m[1].trim().slice(0, 200);
    const nativeScore = m[2] ? Number(m[2]) : null;
    const cleanBody = m[3]
      .replace(/^---\r?\n[\s\S]{1,1500}?\r?\n---\r?\n?/, "")
      .replace(/\n---\s*$/, "")
      .trim()
      .slice(0, maxChars);
    if (cleanBody.length >= 15) {
      parsedCf.push({ heading, nativeScore, text: cleanBody });
    }
  }
  if (parsedCf.length > 0) {
    return parsedCf.slice(0, maxChunks).map((c, i) => ({
      rank: i + 1,
      score: c.nativeScore !== null ? Number(c.nativeScore.toFixed(4)) : Number((1 / (i + 1)).toFixed(4)),
      heading: c.heading,
      text: c.text,
      estimated_tokens: estimateTokenCount(c.text)
    }));
  }

  // 3. Generic Markdown/text search response fallback -> BM25 chunking
  const chunks = chunkMarkdown(trimmed, maxChars);
  return rankChunksBM25(chunks, query, maxChunks);
}

// ============================================================================
// ENGINE 6: Cloudflare Search for Agents & AI-Readiness Cascade Auditor
// ============================================================================
export async function auditAgentReadiness(rawUrl) {
  const t0 = Date.now();
  const parsed = normalizeAndValidateUrl(rawUrl);
  const origin = parsed.origin;
  const targetUrl = parsed.toString();

  const [htmlRes, mdRes, wkGetRes, wkOptRes, llmsRes, llmsFullRes, robotsRes, sitemapHeadRes] = await Promise.all([
    safeFetch(targetUrl, {
      timeoutMs: 10000,
      maxBytes: 1_500_000,
      headers: { Accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8" }
    }),
    safeFetch(targetUrl, {
      timeoutMs: 9000,
      maxBytes: 1_500_000,
      headers: { Accept: "text/markdown, text/plain;q=0.9, text/html;q=0.5" }
    }).catch(() => null),
    safeFetch(`${origin}/.well-known/search`, {
      timeoutMs: 6000,
      maxBytes: 128_000,
      headers: { Accept: "application/json, text/markdown, text/plain;q=0.9, */*;q=0.5" }
    }).catch(() => null),
    safeFetch(`${origin}/.well-known/search`, {
      method: "OPTIONS",
      timeoutMs: 5000,
      maxBytes: 16_000
    }).catch(() => null),
    safeFetch(`${origin}/llms.txt`, { timeoutMs: 5000, maxBytes: 256_000 }).catch(() => null),
    safeFetch(`${origin}/llms-full.txt`, { timeoutMs: 5000, maxBytes: 256_000 }).catch(() => null),
    safeFetch(`${origin}/robots.txt`, { timeoutMs: 5000, maxBytes: 128_000 }).catch(() => null),
    safeFetch(`${origin}/sitemap.xml`, { method: "HEAD", timeoutMs: 5000 }).catch(() => null)
  ]);

  assertUpstreamOk(htmlRes);

  const html = htmlRes.text || "";
  const htmlHeaders = htmlRes.response.headers;
  const htmlBytes = htmlRes.byteLength || byteSizeUtf8(html);

  // (i) Markdown for Agents negotiation (Accept: text/markdown)
  const mdContentType = mdRes?.response?.headers?.get("content-type") || "";
  const mdSupported = Boolean(mdRes && mdRes.response.status === 200 && /text\/markdown/i.test(mdContentType));
  const mdVary = mdRes?.response?.headers?.get("vary") || htmlHeaders.get("vary") || "";
  const varyIncludesAccept = /\baccept\b/i.test(mdVary);
  const xMarkdownTokensRaw = mdRes?.response?.headers?.get("x-markdown-tokens") || htmlHeaders.get("x-markdown-tokens") || null;
  const xMarkdownTokens = xMarkdownTokensRaw && /^\d+$/.test(xMarkdownTokensRaw.trim()) ? Number(xMarkdownTokensRaw.trim()) : null;
  const frontmatterAgent = mdSupported ? parseMarkdownFrontmatterAgent(mdRes.text || "") : null;

  // (ii) HTML & header discovery
  const htmlDiscovery = parseHtmlDiscovery(html, htmlRes.finalUrl, htmlHeaders);
  const discoveredAgentEndpoint = htmlDiscovery.agent_endpoint || frontmatterAgent?.endpoint || null;
  const discoveredAgentMethod = htmlDiscovery.agent_method || frontmatterAgent?.method || null;

  // (iii) /.well-known/search (RFC 10008 / Cloudflare Search for Agents)
  const wkGetStatus = wkGetRes?.response?.status ?? null;
  const wkGetCt = (wkGetRes?.response?.headers?.get("content-type") || "").toLowerCase();
  const wkGetBody = (wkGetRes?.text || "").trim();
  const wkOptStatus = wkOptRes?.response?.status ?? null;
  const allowHeader = wkOptRes?.response?.headers?.get("allow") || wkGetRes?.response?.headers?.get("allow") || "";
  const allowedMethods = allowHeader
    ? allowHeader.split(",").map(s => s.trim().toUpperCase()).filter(Boolean)
    : [];

  let wkJsonManifest = null;
  if (wkGetStatus === 200 && (wkGetCt.includes("application/json") || wkGetBody.startsWith("{"))) {
    try { wkJsonManifest = JSON.parse(wkGetBody); } catch {}
  }

  const isCfMissingQueryPrompt = wkGetStatus === 400 && /missing\s+query|parameter|\?q=/i.test(wkGetBody);
  const isWkNonHtml200 = wkGetStatus === 200 && !/<html[\s>]/i.test(wkGetBody.slice(0, 600)) && wkGetBody.length > 5;
  const isWkAllowActive = allowedMethods.includes("QUERY") || (wkOptStatus === 405 && /query/i.test(wkOptRes?.text || ""));
  const wellKnownPresent = Boolean(isCfMissingQueryPrompt || isWkNonHtml200 || isWkAllowActive);

  if (wkJsonManifest && Array.isArray(wkJsonManifest.methods)) {
    for (const m of wkJsonManifest.methods) {
      const u = String(m || "").toUpperCase();
      if (u && !allowedMethods.includes(u)) allowedMethods.push(u);
    }
  }
  if (discoveredAgentMethod && !allowedMethods.includes(discoveredAgentMethod.toUpperCase()) && wellKnownPresent) {
    allowedMethods.push(discoveredAgentMethod.toUpperCase());
  }
  const supportsQueryMethod = allowedMethods.includes("QUERY") || /QUERY/.test(wkOptRes?.text || "");

  const wellKnownFormat = !wellKnownPresent
    ? "none"
    : wkJsonManifest
      ? "json-manifest"
      : isCfMissingQueryPrompt
        ? "cloudflare-search-for-agents"
        : /<opensearchdescription/i.test(wkGetBody)
          ? "opensearch-xml"
          : wkGetCt.includes("text/markdown")
            ? "markdown-search"
            : "text-endpoint";

  // (iv) /llms.txt & /llms-full.txt
  const hasLlmsTxt = Boolean(llmsRes && llmsRes.response.status === 200 && llmsRes.text.trim().length > 20 && !/<html[\s>]/i.test(llmsRes.text.slice(0, 600)));
  const hasLlmsFullTxt = Boolean(llmsFullRes && llmsFullRes.response.status === 200 && llmsFullRes.text.trim().length > 20 && !/<html[\s>]/i.test(llmsFullRes.text.slice(0, 600)));

  // (v) /robots.txt AI bots & /sitemap.xml
  const hasRobotsTxt = Boolean(robotsRes && robotsRes.response.status === 200 && !/<html[\s>]/i.test((robotsRes.text || "").slice(0, 400)));
  const robotsParsed = parseRobotsTxtAiBots(hasRobotsTxt ? robotsRes.text : "");
  const hasSitemapXml = Boolean(
    (sitemapHeadRes && sitemapHeadRes.response.status >= 200 && sitemapHeadRes.response.status < 400) ||
    robotsParsed.sitemaps.length > 0 ||
    htmlDiscovery.link_header_relations.some(r => r.rel === "sitemap")
  );

  // Token savings calculation (real native Markdown if supported, otherwise Edge HTML->Markdown simulation)
  const effectiveMd = mdSupported ? (mdRes.text || "") : htmlToCleanMarkdown(html, htmlRes.finalUrl).markdown;
  const markdownBytes = mdSupported ? (mdRes.byteLength || byteSizeUtf8(effectiveMd)) : byteSizeUtf8(effectiveMd);
  const htmlTokens = estimateTokenCount(html);
  const markdownTokens = xMarkdownTokens ?? estimateTokenCount(effectiveMd);
  const bytesSaved = Math.max(0, htmlBytes - markdownBytes);
  const tokensSaved = Math.max(0, htmlTokens - markdownTokens);
  const savingsPercent = htmlBytes > 0 ? Number(((bytesSaved / htmlBytes) * 100).toFixed(1)) : 0;
  const usdSavedPer10kFetches = Number((((tokensSaved * 10000) / 1_000_000) * 3.0).toFixed(2));

  // Score (0-100) & Grade (A+..F)
  let score = 0;
  if (wellKnownPresent) score += 25;
  if (supportsQueryMethod) score += 5;
  if (discoveredAgentEndpoint || htmlDiscovery.link_rel_search.length > 0) score += 10;
  if (mdSupported) score += 25;
  if (mdSupported && (varyIncludesAccept || xMarkdownTokens !== null)) score += 5;
  if (hasLlmsTxt) score += 15;
  if (hasLlmsFullTxt) score += 5;
  if (robotsParsed.blocked.length === 0) score += 5;
  if (hasSitemapXml) score += 5;
  score = Math.min(100, Math.max(0, score));

  const grade = score >= 95 ? "A+" : score >= 85 ? "A" : score >= 75 ? "B+" : score >= 65 ? "B" : score >= 50 ? "C" : score >= 35 ? "D" : "F";

  // Cloudflare Overage Risk Analysis
  const onCloudflare = Boolean(htmlHeaders.get("cf-ray") || /cloudflare/i.test(htmlHeaders.get("server") || ""));
  const hasRateLimitHeader = Boolean(htmlHeaders.get("ratelimit-limit") || htmlHeaders.get("x-ratelimit-limit") || wkGetRes?.response?.headers?.get("x-ratelimit-limit"));
  const overageRiskLevel = wellKnownPresent && onCloudflare && !hasRateLimitHeader
    ? "high"
    : (wellKnownPresent ? "medium" : "low");

  const cloudflareOverageRisk = {
    detected_cloudflare_edge: onCloudflare,
    risk_level: overageRiskLevel,
    pricing_watch: {
      semantic_query_overage_usd_per_1k: 0.75,
      free_indexing_limit_pages_per_day: 500,
      native_markdown_for_agents_min_plan: "Cloudflare Pro ($20/mo+)"
    },
    assessment: overageRiskLevel === "high"
      ? "Public /.well-known/search detected on Cloudflare Edge without visible rate-limit headers. Unthrottled AI scrapers can trigger $0.75/1k semantic search overages and exhaust the 500 pages/day free indexing cap."
      : overageRiskLevel === "medium"
        ? "Search endpoint exposed — enforce WAF rate limiting and Edge Cache API TTLs before scaling agent traffic."
        : onCloudflare
          ? "Cloudflare Edge detected without Search for Agents enabled. You can deploy a $0 Edge Worker polyfill for Accept: text/markdown + BM25 /.well-known/search on the Free tier without paying $20/mo Pro or $0.75/1k query overages."
          : "Not currently exposed to Cloudflare AI Search query overages. Adopting a Cloudflare Free Worker gateway adds agent-readiness at $0/mo."
  };

  // Actionable Recommendations
  const recommendations = [];
  if (!wellKnownPresent) {
    recommendations.push({
      priority: "P0",
      code: "ADD_WELL_KNOWN_SEARCH",
      title: "Expose /.well-known/search with GET + RFC 10008 HTTP QUERY support",
      detail: "Return concise Markdown search results (and Allow: GET, HEAD, QUERY) so agents query relevant chunks instead of crawling full HTML pages."
    });
  } else if (!supportsQueryMethod) {
    recommendations.push({
      priority: "P2",
      code: "ADD_HTTP_QUERY_METHOD",
      title: "Advertise RFC 10008 HTTP QUERY support on /.well-known/search",
      detail: "Support safe, idempotent QUERY requests with query payloads in the body and include QUERY in the Allow header."
    });
  }
  if (!discoveredAgentEndpoint && htmlDiscovery.link_rel_search.length === 0) {
    recommendations.push({
      priority: "P1",
      code: "ADD_AGENT_DISCOVERY_META",
      title: "Add <meta name=\"agent:endpoint\"> and <link rel=\"search\"> to HTML <head>",
      detail: `Declare <meta name="agent:endpoint" content="${origin}/.well-known/search?q={query}"> and <meta name="agent:method" content="GET"> for automatic Cascade Discovery.`
    });
  }
  if (!mdSupported) {
    recommendations.push({
      priority: "P0",
      code: "ENABLE_MARKDOWN_NEGOTIATION",
      title: `Serve text/markdown on Accept: text/markdown (est. ${savingsPercent}% payload reduction)`,
      detail: `Converting HTML (${htmlBytes} B) to Markdown (${markdownBytes} B) saves ~${tokensSaved} tokens/fetch (~$${usdSavedPer10kFetches} per 10k LLM fetches at $3/1M input tokens). Include Vary: Accept and x-markdown-tokens headers.`
    });
  } else if (!varyIncludesAccept || xMarkdownTokens === null) {
    recommendations.push({
      priority: "P2",
      code: "ADD_MARKDOWN_HEADERS",
      title: "Add Vary: Accept and x-markdown-tokens response headers",
      detail: "Vary: Accept prevents CDN cache poisoning between browsers and agents; x-markdown-tokens enables agent context-window budgeting before reading the body."
    });
  }
  if (!hasLlmsTxt) {
    recommendations.push({
      priority: "P1",
      code: "ADD_LLMS_TXT",
      title: "Publish /llms.txt (and optional /llms-full.txt)",
      detail: "Provide a curated Markdown directory of high-signal docs, pricing, and API references for Tier 3 Cascade Discovery."
    });
  }
  if (robotsParsed.blocked.length > 0) {
    recommendations.push({
      priority: "P1",
      code: "REVIEW_AI_BOT_BLOCKS",
      title: `Review robots.txt blocks affecting ${robotsParsed.blocked.join(", ")}`,
      detail: "Explicitly separate search/retrieval bots (OAI-SearchBot, PerplexityBot, ClaudeBot) from training crawlers (CCBot, Google-Extended) so your site stays discoverable to user-triggered agents."
    });
  }
  if (!hasSitemapXml) {
    recommendations.push({
      priority: "P2",
      code: "PUBLISH_SITEMAP_XML",
      title: "Publish /sitemap.xml and declare Sitemap: in /robots.txt",
      detail: "Automated agent search indexers rely on sitemap.xml to discover canonical pages within the 500 pages/day free indexing tier."
    });
  }
  if (overageRiskLevel === "high") {
    recommendations.push({
      priority: "P0",
      code: "ADD_WAF_OVERAGE_GUARDRAIL",
      title: "Add Cloudflare WAF Rate Limiting & Edge caching on /.well-known/search",
      detail: "Protect against runaway $0.75/1k semantic search query bills by caching popular queries at the Edge and rate-limiting high-burst IPs/ASNs."
    });
  }

  return {
    url: htmlRes.finalUrl,
    origin,
    status_code: htmlRes.response.status,
    score,
    grade,
    checks: {
      well_known_search: {
        present: wellKnownPresent,
        url: `${origin}/.well-known/search`,
        get_status: wkGetStatus,
        options_status: wkOptStatus,
        format: wellKnownFormat,
        supports_query_method: supportsQueryMethod,
        allowed_methods: allowedMethods,
        manifest_preview: wellKnownPresent ? wkGetBody.slice(0, 320) : null
      },
      html_discovery: {
        ...htmlDiscovery,
        markdown_frontmatter_agent: frontmatterAgent,
        resolved_agent_endpoint: discoveredAgentEndpoint
      },
      markdown_negotiation: {
        supported: mdSupported,
        content_type: mdContentType || null,
        x_markdown_tokens: xMarkdownTokens,
        vary_header: mdVary || null,
        vary_includes_accept: varyIncludesAccept,
        markdown_bytes: mdSupported ? markdownBytes : null
      },
      llms_txt: {
        has_llms_txt: hasLlmsTxt,
        llms_txt_bytes: hasLlmsTxt ? (llmsRes.byteLength || byteSizeUtf8(llmsRes.text)) : 0,
        has_llms_full_txt: hasLlmsFullTxt,
        llms_full_txt_bytes: hasLlmsFullTxt ? (llmsFullRes.byteLength || byteSizeUtf8(llmsFullRes.text)) : 0,
        preview: hasLlmsTxt ? llmsRes.text.trim().slice(0, 320) : null
      },
      robots_and_sitemap: {
        has_robots_txt: hasRobotsTxt,
        has_sitemap_xml: hasSitemapXml,
        sitemap_urls: robotsParsed.sitemaps,
        ai_bots: robotsParsed.bots,
        blocked_bots: robotsParsed.blocked,
        allowed_bots: robotsParsed.allowed
      }
    },
    token_savings_estimate: {
      source: mdSupported ? "native_markdown_negotiation" : "edge_html_to_markdown_simulation",
      html_bytes: htmlBytes,
      html_estimated_tokens: htmlTokens,
      markdown_bytes: markdownBytes,
      markdown_estimated_tokens: markdownTokens,
      bytes_saved: bytesSaved,
      tokens_saved: tokensSaved,
      savings_percent: savingsPercent,
      estimated_usd_saved_per_10k_fetches_at_3_per_1m_tokens: usdSavedPer10kFetches
    },
    cloudflare_overage_risk: cloudflareOverageRisk,
    recommendations,
    elapsed_ms: Date.now() - t0
  };
}

// ============================================================================
// ENGINE 7: Agent-First Cascade Search (4-Tier Zero-Failure Retrieval + BM25)
// ============================================================================
function buildEndpointQueryUrl(templateOrUrl, origin, query) {
  const encoded = encodeURIComponent(query);
  if (!templateOrUrl) return `${origin}/.well-known/search?q=${encoded}`;
  let candidate = String(templateOrUrl).trim();
  if (candidate.includes("{query}")) {
    candidate = candidate.replace(/\{query\}/g, encoded);
  } else if (candidate.includes("{searchTerms}")) {
    candidate = candidate.replace(/\{searchTerms\}/g, encoded);
  } else {
    const resolved = new URL(candidate, origin);
    if (!resolved.searchParams.has("q")) resolved.searchParams.set("q", query);
    candidate = resolved.toString();
  }
  const validated = normalizeAndValidateUrl(new URL(candidate, origin).toString());
  return validated.toString();
}

export async function agentSearchCascade(rawUrl, rawQuery, opts = {}) {
  const t0 = Date.now();
  const parsed = normalizeAndValidateUrl(rawUrl);
  const query = String(rawQuery || "").trim();
  if (!query) throw new HttpError("Missing required 'query' parameter.", 400);
  if (query.length > 500) throw new HttpError("Parameter 'query' exceeds 500 character limit.", 400);

  const maxChunks = Math.max(1, Math.min(15, Number(opts.max_chunks ?? opts.maxChunks) || 5));
  const maxChars = Math.max(200, Math.min(4000, Number(opts.max_chars ?? opts.maxChars) || 1200));
  const origin = parsed.origin;
  const targetUrl = parsed.toString();

  // Parallel initial cascade probes: target page (with Markdown preference) + /.well-known/search?q=
  const defaultWkUrl = `${origin}/.well-known/search?q=${encodeURIComponent(query)}`;
  const [pageRes, wkRes] = await Promise.all([
    safeFetch(targetUrl, {
      timeoutMs: 10000,
      maxBytes: 1_500_000,
      headers: { Accept: "text/markdown, text/html;q=0.9, application/xhtml+xml;q=0.8, text/plain;q=0.7" }
    }),
    safeFetch(defaultWkUrl, {
      timeoutMs: 7000,
      maxBytes: 512_000,
      headers: { Accept: "text/markdown, application/json, text/plain;q=0.9" }
    }).catch(() => null)
  ]);

  assertUpstreamOk(pageRes);

  const pageCt = (pageRes.response.headers.get("content-type") || "").toLowerCase();
  const pageIsMarkdown = pageRes.response.status === 200 && pageCt.includes("text/markdown");
  const pageBody = pageRes.text || "";

  const frontmatterAgent = pageIsMarkdown ? parseMarkdownFrontmatterAgent(pageBody) : null;
  const htmlDiscovery = !pageIsMarkdown ? parseHtmlDiscovery(pageBody, pageRes.finalUrl, pageRes.response.headers) : null;
  const discoveredAgentEndpoint = frontmatterAgent?.endpoint || htmlDiscovery?.agent_endpoint || null;

  const discoveredEndpoints = {
    well_known_search: null,
    agent_endpoint: discoveredAgentEndpoint,
    markdown_negotiation: pageIsMarkdown,
    llms_txt: null
  };

  // TIER 1: /.well-known/search or HTML/frontmatter-discovered safe agent:endpoint
  const isWkSuccess = wkRes && wkRes.response.status === 200 && !/<html[\s>]/i.test((wkRes.text || "").slice(0, 600)) && (wkRes.text || "").trim().length > 20;
  if (isWkSuccess) {
    discoveredEndpoints.well_known_search = `${origin}/.well-known/search`;
    const chunks = parseWellKnownSearchResponse(wkRes.text, wkRes.response.headers.get("content-type"), query, maxChunks, maxChars);
    if (chunks.length > 0) {
      return {
        url: pageRes.finalUrl,
        query,
        source_tier: "tier1_well_known_search",
        discovered_endpoints: discoveredEndpoints,
        chunks,
        total_estimated_tokens: chunks.reduce((s, c) => s + c.estimated_tokens, 0),
        elapsed_ms: Date.now() - t0
      };
    }
  } else if (discoveredAgentEndpoint) {
    // Try custom agent:endpoint (re-validated via SSRF shield inside buildEndpointQueryUrl + safeFetch)
    try {
      const customSearchUrl = buildEndpointQueryUrl(discoveredAgentEndpoint, origin, query);
      if (customSearchUrl !== defaultWkUrl) {
        const customRes = await safeFetch(customSearchUrl, {
          timeoutMs: 6000,
          maxBytes: 512_000,
          headers: { Accept: "text/markdown, application/json, text/plain;q=0.9" }
        });
        if (customRes.response.status === 200 && !/<html[\s>]/i.test((customRes.text || "").slice(0, 600))) {
          const chunks = parseWellKnownSearchResponse(customRes.text, customRes.response.headers.get("content-type"), query, maxChunks, maxChars);
          if (chunks.length > 0) {
            discoveredEndpoints.well_known_search = customRes.finalUrl;
            return {
              url: pageRes.finalUrl,
              query,
              source_tier: "tier1_well_known_search",
              discovered_endpoints: discoveredEndpoints,
              chunks,
              total_estimated_tokens: chunks.reduce((s, c) => s + c.estimated_tokens, 0),
              elapsed_ms: Date.now() - t0
            };
          }
        }
      }
    } catch {
      // Safe fallback to Tier 2/3/4 if custom endpoint fails or is blocked by SSRF shield
    }
  }

  // TIER 2: Native Accept: text/markdown negotiation
  if (pageIsMarkdown) {
    const chunks = rankChunksBM25(chunkMarkdown(pageBody, maxChars), query, maxChunks);
    if (chunks.length > 0) {
      return {
        url: pageRes.finalUrl,
        query,
        source_tier: "tier2_markdown_negotiation",
        discovered_endpoints: discoveredEndpoints,
        chunks,
        total_estimated_tokens: chunks.reduce((s, c) => s + c.estimated_tokens, 0),
        elapsed_ms: Date.now() - t0
      };
    }
  }

  // TIER 3: /llms.txt (preferred when valid and matches query terms)
  const llmsRes = await safeFetch(`${origin}/llms.txt`, { timeoutMs: 5000, maxBytes: 256_000 }).catch(() => null);
  const hasValidLlms = Boolean(llmsRes && llmsRes.response.status === 200 && (llmsRes.text || "").trim().length > 20 && !/<html[\s>]/i.test((llmsRes.text || "").slice(0, 600)));
  if (hasValidLlms) {
    discoveredEndpoints.llms_txt = `${origin}/llms.txt`;
    const llmsChunks = rankChunksBM25(chunkMarkdown(llmsRes.text, maxChars), query, maxChunks);
    const topScore = llmsChunks[0]?.score || 0;
    const isRootPath = parsed.pathname === "/" || parsed.pathname === "";
    if (llmsChunks.length > 0 && (topScore > 0 || isRootPath)) {
      return {
        url: pageRes.finalUrl,
        query,
        source_tier: "tier3_llms_txt",
        discovered_endpoints: discoveredEndpoints,
        chunks: llmsChunks,
        total_estimated_tokens: llmsChunks.reduce((s, c) => s + c.estimated_tokens, 0),
        elapsed_ms: Date.now() - t0
      };
    }
  }

  // TIER 4: Edge HTML -> Clean Markdown + deterministic BM25 chunk ranking (100% Day-1 fallback)
  const { markdown } = htmlToCleanMarkdown(pageBody, pageRes.finalUrl);
  const fallbackChunks = rankChunksBM25(chunkMarkdown(markdown, maxChars), query, maxChunks);

  return {
    url: pageRes.finalUrl,
    query,
    source_tier: "tier4_edge_html_to_markdown",
    discovered_endpoints: discoveredEndpoints,
    chunks: fallbackChunks,
    total_estimated_tokens: fallbackChunks.reduce((s, c) => s + c.estimated_tokens, 0),
    elapsed_ms: Date.now() - t0
  };
}
