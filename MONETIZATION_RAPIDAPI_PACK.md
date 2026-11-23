# 💰 Guia Rápido de Monetização Recorrente em Dólar — Máquina #5 (`edge-web-intel-api`)

Todo o código, segurança SSRF, autenticação `X-RapidAPI-Proxy-Secret`, testes QA ao vivo e o arquivo `openapi.json` (OpenAPI 3.1) **já estão 100% prontos e testados**.

## Passo 1 — Subir na Cloudflare Workers (Grátis até 100.000 requisições/dia!)
No PowerShell dentro da pasta `edge-web-intel-api`:
```powershell
npx wrangler login
npx wrangler deploy
```
Isso vai te dar uma URL global instantânea (ex: `https://edge-web-intel-api.<seu-subdominio>.workers.dev`).

## Passo 2 — Publicar no RapidAPI / API.market / Zyla (Assinatura Mensal em Dólar)
1. Crie/abra sua conta de criador em **https://rapidapi.com/studio** (ou **https://api.market** / **https://zylalabs.com**).
2. Clique em **Add New API → Import OpenAPI** e suba o arquivo `openapi.json` desta pasta.
3. Em **Base URL**, cole a URL da sua Cloudflare Worker.
4. Em **Security / Proxy Secret**, copie o `X-RapidAPI-Proxy-Secret` gerado pelo RapidAPI e configure na Cloudflare:
   ```powershell
   npx wrangler secret put RAPIDAPI_PROXY_SECRET
   ```
5. Configure os **4 planos recorrentes em dólar**:
   - **Basic (Free):** US$ 0/mês — 100 requisições/mês (atrai devs e testes)
   - **Pro:** **US$ 19/mês** — 5.000 requisições/mês (excedente US$ 0,004/req)
   - **Ultra:** **US$ 49/mês** — 25.000 requisições/mês (excedente US$ 0,002/req)
   - **Mega:** **US$ 149/mês** — 100.000 requisições/mês (agências & pipelines RAG)
6. Conecte seu recebimento (**Payoneer USD** já aprovada ou **Wise USD**). Pronto: **renda mensal recorrente em dólar com custo de servidor ZERO!**
