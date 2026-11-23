/**
 * Zero-dependency Node.js 22 HTTP Server wrapper for Edge Web Intelligence API.
 * Runs the exact same Web Fetch handler used by Cloudflare Workers.
 */
import http from "node:http";
import worker from "./src/worker.mjs";

const PORT = Number(process.env.PORT || 8787);
const HOST = process.env.HOST || "0.0.0.0";

export function createNodeServer(env = process.env) {
  return http.createServer(async (req, res) => {
    try {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const body = chunks.length > 0 && req.method !== "GET" && req.method !== "HEAD" ? Buffer.concat(chunks) : undefined;

      const fullUrl = `http://${req.headers.host || `127.0.0.1:${PORT}`}${req.url}`;
      const webReq = new Request(fullUrl, {
        method: req.method,
        headers: req.headers,
        body
      });
      const webRes = await worker.fetch(webReq, env);
      res.writeHead(webRes.status, Object.fromEntries(webRes.headers.entries()));
      const buf = Buffer.from(await webRes.arrayBuffer());
      res.end(buf);
    } catch (err) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: err?.message || "Internal server error" }));
    }
  });
}

if (import.meta.url === `file:///${process.argv[1]?.replace(/\\/g, "/")}`) {
  const srv = createNodeServer();
  srv.listen(PORT, HOST, () => {
    console.log(`Edge Web Intelligence API listening on http://${HOST}:${PORT} (OpenAPI: /openapi.json)`);
  });
}
