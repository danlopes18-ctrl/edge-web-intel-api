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
// ENGINE 2: Fast LLM-Ready HTML-to-Markdown Converter (RAG / MCP)
// ============================================================================
export async function crawlMarkdown(rawUrl) {
  const t0 = Date.now();
  const res = await safeFetch(rawUrl, { timeoutMs: 10000 });
  assertUpstreamOk(res);
  let html = res.text || "";

  const title = stripTags((html.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || "");
  const mainMatch = html.match(/<(main|article)[^>]*>([\s\S]*?)<\/\1>/i);
  let body = mainMatch ? mainMatch[2] : (html.match(/<body[^>]*>([\s\S]*?)<\/body>/i)?.[1] || html);

  // Strip noise
  body = body
    .replace(/<(script|style|noscript|svg|iframe|nav|footer|aside)[^>]*>[\s\S]*?<\/\1>/gi, "\n")
    .replace(/<!--[\s\S]*?-->/g, "");

  // Extract headings outline
  const headings = [];
  for (const m of body.matchAll(/<h([1-4])[^>]*>([\s\S]*?)<\/h\1>/gi)) {
    const txt = stripTags(m[2]);
    if (txt) headings.push({ level: Number(m[1]), text: txt });
  }

  // Convert structural tags to clean Markdown
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
      try { return `[${label}](${new URL(href, res.finalUrl).toString()})`; } catch { return label; }
    })
    .replace(/<code[^>]*>([\s\S]*?)<\/code>/gi, (_, x) => `\`${stripTags(x)}\``)
    .replace(/<(p|div|section|br|tr)[^>]*>/gi, "\n")
    .replace(/<[^>]+>/g, "");

  md = decodeEntities(md)
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();

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
