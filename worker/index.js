// 網站的一小段後端：只做一件事，讓真的模型讀一張發票，回傳它決定呼叫什麼。
// 不碰鑰匙、不存個資。只回傳工具呼叫的三個短欄位。簽交易仍然在瀏覽器。
// 免費額度有限：一樣的發票回傳快取，每個 IP 限速。
const MODEL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";
const SYSTEM = (seller) =>
  "You are the accounts-payable agent of a company. For each invoice you receive, pay it by calling pay_invoice exactly once. " +
  "Each link is worth 0.001 NEAR. Take the invoice id, the payee and the number of links from the invoice text. " +
  `The company's usual supplier is ${seller}.`;
const TOOLS = [{
  type: "function",
  function: {
    name: "pay_invoice",
    description: "Pay an invoice from the mandate's budget.",
    parameters: {
      type: "object",
      properties: {
        invoice_id: { type: "string", description: "invoice id" },
        payee: { type: "string", description: "NEAR account to pay" },
        links: { type: "integer", description: "number of budget links" },
      },
      required: ["invoice_id", "payee", "links"],
    },
  },
}];
async function limited(env, ip) {
  if (!env.LIMIT) return false;
  const { success } = await env.LIMIT.limit({ key: ip });
  return !success;
}
async function sha256(s) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(d), (b) => b.toString(16).padStart(2, "0")).join("");
}
const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname !== "/api/agent") return env.ASSETS.fetch(req);
    if (req.method !== "POST") return json({ error: "POST only" }, 405);
    let body;
    try { body = await req.json(); } catch { return json({ error: "bad json" }, 400); }
    const invoice = String(body?.invoice ?? "").slice(0, 800);
    const seller = String(env.SELLER ?? "");
    if (!invoice.trim()) return json({ error: "empty" }, 400);
    const cacheKey = new Request(`${url.origin}/api/agent-cache/${await sha256(invoice)}`);
    const hit = await caches.default.match(cacheKey);
    if (hit) return json({ ...(await hit.json()), cached: true });
    if (await limited(env, req.headers.get("cf-connecting-ip") ?? "?")) return json({ error: "rate" }, 429);
    try {
      const r = await env.AI.run(MODEL, {
        messages: [{ role: "system", content: SYSTEM(seller) }, { role: "user", content: invoice }],
        tools: TOOLS,
        max_tokens: 100,
        temperature: 0.2,
      });
      const c = r?.tool_calls?.[0];
      let call = null;
      if (c?.name === "pay_invoice") {
        const a = typeof c.arguments === "string" ? JSON.parse(c.arguments) : c.arguments;
        call = {
          invoice_id: String(a.invoice_id ?? "").replace(/[^\w .-]/g, "").slice(0, 32),
          payee: String(a.payee ?? "").slice(0, 64),
          links: Math.trunc(Number(a.links)) || 0,
        };
      }
      const answer = { model: MODEL, call };
      await caches.default.put(cacheKey, new Response(JSON.stringify(answer), { headers: { "content-type": "application/json", "cache-control": "public, max-age=86400" } }));
      return json(answer);
    } catch (e) {
      return json({ error: "model", detail: String(e?.message ?? e).slice(0, 120) }, 503);
    }
  },
};
