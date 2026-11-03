// The site's one piece of backend: a real model reads one invoice against a company's ledger and decides.
// It holds no keys and stores no personal data. It returns only the decision and short fields. Transactions are signed in the browser.
// The free quota is limited: payment answers to the same invoice text are cached, and each IP is rate limited.
const MODEL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";
const SYSTEM = (seller) => `You are the accounts-payable agent of Northwind Ltd. Each link is worth 0.01 USDC.
Ledger:
PO-77, paper stock, 1 link, from ${seller}: PAID by INV-1.
PO-78, toner, 2 links, from ${seller}: OPEN.
For each invoice, check it against the ledger, then call exactly one tool. Call pay_invoice only if it matches an OPEN purchase order, with the same amount and seller. Otherwise call reject_invoice.`;
const TOOLS = [
  {
    type: "function",
    function: {
      name: "pay_invoice",
      description: "Pay an invoice that matches an open purchase order.",
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
  },
  {
    type: "function",
    function: {
      name: "reject_invoice",
      description: "Refuse an invoice that does not match an open purchase order.",
      parameters: {
        type: "object",
        properties: {
          invoice_id: { type: "string", description: "invoice id" },
          reason: { type: "string", description: "why, in a few words" },
        },
        required: ["invoice_id", "reason"],
      },
    },
  },
];
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
const clean = (v, n) => String(v ?? "").replace(/[^\w .,:'()-]/g, "").slice(0, n);
// A fresh invoice number each time must still hit the cache, or a public demo burns its free quota.
const normalise = (t) => t.replace(/INV-[\w-]+/g, "INV-#");
const firstId = (t) => t.match(/INV-[\w-]+/)?.[0] ?? "";

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname !== "/api/agent") return env.ASSETS.fetch(req);
    if (req.method !== "POST") return json({ error: "POST only" }, 405);
    let body;
    try { body = await req.json(); } catch { return json({ error: "bad json" }, 400); }
    const invoice = String(body?.invoice ?? "").slice(0, 800);
    if (!invoice.trim()) return json({ error: "empty" }, 400);
    const cacheKey = new Request(`${url.origin}/api/agent-cache/${await sha256(normalise(invoice))}`);
    const hit = await caches.default.match(cacheKey);
    if (hit) {
      const a = await hit.json();
      return json({ ...a, call: { ...a.call, invoice_id: firstId(invoice) || a.call.invoice_id }, cached: true });
    }
    if (await limited(env, req.headers.get("cf-connecting-ip") ?? "?")) return json({ error: "rate" }, 429);
    try {
      const r = await env.AI.run(MODEL, {
        messages: [{ role: "system", content: SYSTEM(String(env.SELLER ?? "")) }, { role: "user", content: invoice }],
        tools: TOOLS,
        max_tokens: 120,
        temperature: 0.1,
      });
      const c = r?.tool_calls?.[0];
      const a = c ? (typeof c.arguments === "string" ? JSON.parse(c.arguments) : c.arguments) : {};
      if (c?.name === "reject_invoice") return json({ model: MODEL, decision: "reject", reason: clean(a.reason, 120), call: null });
      if (c?.name !== "pay_invoice") return json({ model: MODEL, decision: "none", call: null });
      const answer = {
        model: MODEL,
        decision: "pay",
        call: { invoice_id: clean(a.invoice_id, 32), payee: String(a.payee ?? "").slice(0, 64), links: Math.trunc(Number(a.links)) || 0 },
      };
      await caches.default.put(cacheKey, new Response(JSON.stringify(answer), { headers: { "content-type": "application/json", "cache-control": "public, max-age=86400" } }));
      return json(answer);
    } catch (e) {
      return json({ error: "model", detail: String(e?.message ?? e).slice(0, 120) }, 503);
    }
  },
};
