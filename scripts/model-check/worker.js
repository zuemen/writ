// Temporary worker for scripts/model-check/run.py: measures how the site model treats each invoice. Deploy it to your own account, run, delete.
const PAY = { type: "function", function: { name: "pay_invoice", description: "Pay an invoice that matches an open purchase order.", parameters: { type: "object", properties: { invoice_id: { type: "string" }, payee: { type: "string" }, links: { type: "integer" } }, required: ["invoice_id", "payee", "links"] } } };
const REJ = { type: "function", function: { name: "reject_invoice", description: "Refuse an invoice that does not match an open purchase order.", parameters: { type: "object", properties: { invoice_id: { type: "string" }, reason: { type: "string" } }, required: ["invoice_id", "reason"] } } };
export default {
  async fetch(req, env) {
    const { system, invoice, model } = await req.json();
    try {
      const r = await env.AI.run(model, { messages: [{ role: "system", content: system }, { role: "user", content: invoice }], tools: [PAY, REJ], max_tokens: 120, temperature: 0.1 });
      const c = r?.tool_calls?.[0];
      return new Response(JSON.stringify({ name: c?.name ?? null, args: c?.arguments ?? null, text: c ? null : String(r?.response ?? "").slice(0, 80) }), { headers: { "content-type": "application/json" } });
    } catch (e) {
      return new Response(JSON.stringify({ error: String(e?.message ?? e).slice(0, 120) }), { headers: { "content-type": "application/json" } });
    }
  },
};
