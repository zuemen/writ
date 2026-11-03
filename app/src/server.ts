/**
 * make ui: local web UI (http://localhost:8787), three views on one page: legal entity HR / agent / merchant (anyone).
 * Connects only to the local sandbox. Each button calls the same function in flow.ts as the CLI demo.
 */
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { ROOT, view, fmt } from "./near.js";
import { A, INJECTED_INVOICE, balance, pay, present, register, releaseUnseal, requestUnseal, revoke, verifierCheck } from "./flow.js";
import { keriState } from "./keri.js";

const PORT = Number(process.env.PORT ?? 8787);
type Entry = { t: number; who: string; text: string; kind: "ok" | "reject" | "protocol" | "info"; hash?: string };
let log: Entry[] = [];
let cell: string | null = null;
let keriRevoked = false;
let base: Record<string, bigint> = {};
const add = (e: Omit<Entry, "t">) => log.push({ t: Date.now(), ...e });

async function snapshot() {
  const a = A();
  const bal: Record<string, string> = {};
  for (const k of ["merchant", "attacker", "acme"]) {
    const b = await balance(a[k].id);
    if (base[k] === undefined) base[k] = b;
    bal[k] = (b >= base[k] ? "+" : "−") + fmt(b >= base[k] ? b - base[k] : base[k] - b);
  }
  const st = keriState();
  return {
    accounts: Object.fromEntries(Object.entries(a).map(([k, v]) => [k, v.id])),
    keri: { le: st.le, human: st.human, agent: st.agent, ecr: st.ecr, amc: st.amc, agent_near_pk: st.agent_near_pk, ecrRevoked: keriRevoked },
    cell,
    present: cell ? await present(cell) : null,
    unseal: cell ? await view(a.writ.id, "get_unseal", { cell }) : null,
    stats: await view(a.writ.id, "stats"),
    balances: bal,
    invoice: INJECTED_INVOICE(a.attacker.id),
    log,
  };
}

async function act(path: string) {
  const a = A();
  if (path === "/api/register") {
    const r = await register("5");
    r.checks.forEach((c) => add({ who: "verifier", text: c.replace(/^✓ /, "✓ "), kind: "info" }));
    if (!r.ok) return add({ who: "verifier", text: "refused: " + r.error, kind: "reject" });
    cell = r.cell;
    add({ who: a.acme.id, text: `register → cell #${cell}, 5 NEAR deposited (0.35 fee, rest is the vault); agent key added as function-call key (spend only)`, kind: "ok", hash: r.hash });
  } else if (path === "/api/pay" || path === "/api/pay-injected") {
    if (!cell) return add({ who: "agent", text: "no mandate yet", kind: "info" });
    const injected = path.endsWith("injected");
    const to = injected ? a.attacker.id : a.merchant.id;
    const r = await pay(cell, injected ? 2 : 1, to, injected ? "INV-0043" : "INV-0042");
    if (r.value?.Paid) add({ who: "agent", text: `spend → ${to}: PAID ${fmt(r.value.Paid.amount)} (link ${r.value.Paid.idx}/${r.value.Paid.idx + r.value.Paid.remaining_links})`, kind: "ok", hash: r.hash });
    else if (r.value?.Rejected) add({ who: "agent", text: `spend → ${to}: POLICY REJECTED ${r.value.Rejected.reason} (strike ${r.value.Rejected.strikes}/3${r.value.Rejected.tripped ? ", key deleted" : ""})`, kind: "reject", hash: r.hash });
    else add({ who: "agent", text: `spend → ${to}: ${r.tag ?? "ERROR"} — ${r.error} (rejected by the protocol, no transaction)`, kind: "protocol" });
  } else if (path === "/api/revoke") {
    if (!cell) return;
    const r = await revoke(cell);
    keriRevoked = true;
    add({ who: "HR", text: `employee's ECR revoked in KERI: TEL rev ${r.rev.rev_said.slice(0, 10)}… anchored by ixn sn=${r.rev.ixn_sn} (off-chain)`, kind: "info" });
    if (r.error) add({ who: "merchant", text: "revoke_by_kel failed: " + r.error, kind: "reject" });
    else add({ who: a.merchant.id, text: "submits signed ixn → revoke_by_kel opens the ECR commitment, verifies Ed25519 + seal → agent key deleted", kind: "ok", hash: r.hash });
  } else if (path === "/api/unseal-request") {
    if (!cell) return;
    const r = await requestUnseal(cell);
    if (r.error) add({ who: a.regulator.id, text: "request_unseal failed: " + r.error, kind: "reject" });
    else add({ who: a.regulator.id, text: `request_unseal (reason hash of "${r.reason}") → public; 10 s waiting period starts`, kind: "info", hash: r.hash });
  } else if (path === "/api/unseal-release") {
    if (!cell) return;
    const r = await releaseUnseal(cell);
    if (r.error) add({ who: a.verifier.id, text: `release_unseal → ${r.error}`, kind: "reject", hash: r.hash });
    else add({ who: a.verifier.id, text: `release_unseal: sha256(LEI|salt) matches the registration commitment → LEI ${r.lei} disclosed (public tx)`, kind: "ok", hash: r.hash });
  } else if (path === "/api/verify") {
    const v = verifierCheck();
    add({ who: "verifier", text: v.ok ? "chain valid" : "REFUSED — " + v.out[0], kind: v.ok ? "info" : "reject" });
  } else if (path === "/api/reset") {
    // Clean restart: restart the local sandbox (chain state reset) and set up again
    execFileSync(join(ROOT, "scripts/sandbox.sh"), ["stop"], { stdio: "ignore" });
    execFileSync(join(ROOT, "scripts/sandbox.sh"), ["start"], { stdio: "ignore" });
    execFileSync("npx", ["tsx", "src/setup.ts"], { cwd: join(ROOT, "app"), stdio: "ignore" });
    log = []; cell = null; keriRevoked = false; base = {};
    add({ who: "setup", text: "fresh accounts, contract and mock vLEI ecosystem", kind: "info" });
  }
}

createServer(async (req, res) => {
  try {
    if (req.method === "GET" && (req.url === "/" || req.url === "/index.html")) {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      return res.end(readFileSync(join(ROOT, "app/web/index.html")));
    }
    if (req.method === "POST" && req.url?.startsWith("/api/")) await act(req.url);
    if (req.url?.startsWith("/api/")) {
      const body = JSON.stringify(await snapshot(), (_k, v) => (typeof v === "bigint" ? v.toString() : v));
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(body);
    }
    res.writeHead(404).end();
  } catch (e) {
    console.error(e);
    if (res.headersSent) return res.end();
    res.writeHead(500, { "content-type": "application/json" }).end(JSON.stringify({ error: String(e) }));
  }
}).listen(PORT, () => console.log(`Writ UI on http://localhost:${PORT}  (sandbox ${process.env.NEAR_RPC ?? "http://127.0.0.1:3030"})`));
