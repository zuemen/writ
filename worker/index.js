// 網站的一小段後端：只做一件事，讓真的模型讀一張發票，回傳它決定呼叫什麼。
// 不存資料、不碰鑰匙、不回傳模型的文字，所以不能拿來當免費聊天機器人。簽交易仍然在瀏覽器。
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
const hits = new Map();
function limited(ip) {
  const now = Date.now();
  const recent = (hits.get(ip) ?? []).filter((t) => now - t < 60_000);
  recent.push(now);
  hits.set(ip, recent);
  if (hits.size > 5000) hits.clear();
  return recent.length > 8;
}
const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname !== "/api/agent") return env.ASSETS.fetch(req);
    if (req.method !== "POST") return json({ error: "POST only" }, 405);
    if (limited(req.headers.get("cf-connecting-ip") ?? "?")) return json({ error: "rate" }, 429);
    let body;
    try { body = await req.json(); } catch { return json({ error: "bad json" }, 400); }
    const invoice = String(body?.invoice ?? "").slice(0, 800);
    const seller = String(body?.seller ?? "").slice(0, 64);
    if (!invoice.trim()) return json({ error: "empty" }, 400);
    try {
      const r = await env.AI.run(MODEL, {
        messages: [{ role: "system", content: SYSTEM(seller) }, { role: "user", content: invoice }],
        tools: TOOLS,
        max_tokens: 200,
        temperature: 0.2,
      });
      const c = r?.tool_calls?.[0];
      if (c?.name !== "pay_invoice") return json({ model: MODEL, call: null });
      const a = typeof c.arguments === "string" ? JSON.parse(c.arguments) : c.arguments;
      return json({
        model: MODEL,
        call: { invoice_id: String(a.invoice_id ?? "").slice(0, 80), payee: String(a.payee ?? "").slice(0, 64), links: Math.trunc(Number(a.links)) || 0 },
      });
    } catch (e) {
      return json({ error: "model", detail: String(e?.message ?? e).slice(0, 120) }, 503);
    }
  },
};
