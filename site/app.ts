/**
 * 「鑰匙公開」頁：沒有伺服器，瀏覽器直接用公開的 agent 私鑰簽真的 testnet 交易。
 * config.json 只存在 hosted 頁（scripts/build_site.sh 產生），不進 repo。
 */
import { Account, JsonRpcProvider, KeyPairSigner, actions, teraToGas, type KeyPairString } from "near-api-js";

type Cfg = { rpc: string; contract: string; cell: string; merchant: string; agent_pk: string; agent_sk: KeyPairString; spent_link: string; first_payment_tx: string };
const $ = (id: string) => document.getElementById(id)!;
const cfg: Cfg = await (await fetch("config.json")).json();
const provider = new JsonRpcProvider({ url: cfg.rpc });
const agent = new Account(cfg.contract, provider, KeyPairSigner.fromSecretKey(cfg.agent_sk));
const near = (y: string) => (Number(BigInt(y) / 10n ** 21n) / 1000).toFixed(3);
const explorer = (h: string) => `https://testnet.nearblocks.io/txns/${h}`;
const randomHex = () => Array.from(crypto.getRandomValues(new Uint8Array(32)), (b) => b.toString(16).padStart(2, "0")).join("");
const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);

async function refresh() {
  const c: any = await provider.callFunction({ contractId: cfg.contract, method: "get_cell", args: { cell: cfg.cell } });
  $("vault").textContent = near(c.vault.toString());
  $("paid").textContent = String(c.spends);
  $("rejected").textContent = String(c.rejects);
  $("links").textContent = `${c.idx} of ${c.n}`;
}

type Out = { kind: "blocked" | "paid" | "error"; verdict: string; why: string; hash?: string };

function explainReject(reason: string): string {
  return ({
    SCOPE: "That account is not a permitted counterparty in the mandate.",
    CHAIN: "The budget is a hash chain. Without the next preimage, which only the employee holds, this key cannot spend.",
    LIMIT: "More links than the mandate holds.",
    PER_TX: "Above the per-payment cap in the mandate.",
    DUPLICATE: "This invoice was already paid.",
    INVOICE: "The invoice hash is not a valid sha256.",
    RATE: "Above the daily rate in the mandate.",
    FUNDS: "The vault cannot cover this payment.",
    EXPIRED: "The mandate has expired.",
  } as Record<string, string>)[reason] ?? "Rejected by the contract.";
}

// near-api-js 回傳的是人類可讀訊息，不是 nearcore 的錯誤名
const ALIASES: Record<string, string> = {
  MethodNameMismatch: "does not allow method",
  RequiresFullAccess: "requires full access",
  DepositWithFunctionCall: "Deposit is not allowed",
  ReceiverMismatch: "does not allow receiver",
  NotEnoughAllowance: "allowance",
  AccessKeyNotFound: "does not exist",
};

function explainProtocol(err: string): Out {
  for (const [name, why] of [
    ["MethodNameMismatch", "This key may call one method, spend. NEAR refuses anything else before contract code runs."],
    ["RequiresFullAccess", "A function-call key cannot send a plain transfer. NEAR refuses it before it becomes a transaction."],
    ["DepositWithFunctionCall", "A function-call key cannot attach a deposit, so it cannot call token transfers directly."],
    ["ReceiverMismatch", "This key only works against the Writ contract."],
    ["NotEnoughAllowance", "The key's gas allowance ran out from all the attempts. This is not a security failure; the funder refills it."],
    ["AccessKeyNotFound", "The key is gone."],
  ] as const) {
    if (err.includes(name) || (ALIASES[name] && err.includes(ALIASES[name]))) return { kind: "blocked", verdict: name, why };
  }
  return { kind: "error", verdict: "Error", why: err.slice(0, 200) };
}

async function send(act: () => Promise<any>): Promise<Out> {
  try {
    const r = await act();
    const st = r.status;
    const hash = r.transaction?.hash;
    if (st?.SuccessValue !== undefined) {
      const v = JSON.parse(atob(st.SuccessValue) || "null");
      if (v?.Rejected) return { kind: "blocked", verdict: `Rejected: ${v.Rejected.reason}`, why: explainReject(v.Rejected.reason), hash };
      if (v?.Paid) return { kind: "paid", verdict: "Paid", why: `The contract paid ${near(v.Paid.amount)} NEAR. If you did this without the employee's link, you found a real bug. Please open an issue.`, hash };
    }
    return explainProtocol(JSON.stringify(st?.Failure ?? st ?? r)) && { ...explainProtocol(JSON.stringify(st?.Failure ?? st ?? r)), hash };
  } catch (e: any) {
    return explainProtocol(`${e?.message ?? ""} ${JSON.stringify(e, (_k, v) => (typeof v === "bigint" ? v.toString() : v))}`);
  }
}

const spend = (preimage: string, j: number, to: string, gas = "20") => () =>
  agent.signAndSendTransaction({
    receiverId: cfg.contract,
    actions: [actions.functionCall("spend", { preimage, j, to, invoice_hash: randomHex() }, teraToGas(gas), 0n)],
    throwOnFailure: false,
    waitUntil: "EXECUTED_OPTIMISTIC",
  } as any);

const ATTEMPTS: Record<string, () => () => Promise<any>> = {
  self: () => spend(cfg.spent_link, 1, ($("to") as HTMLInputElement).value.trim() || "attacker.testnet"),
  guess: () => spend(randomHex(), 1, cfg.merchant),
  replay: () => spend(cfg.spent_link, 1, cfg.merchant),
  drain: () => spend(randomHex(), 50, cfg.merchant),
  transfer: () => () => agent.signAndSendTransaction({ receiverId: "attacker.testnet", actions: [actions.transfer(1n)], throwOnFailure: false } as any),
  admin: () => () => agent.signAndSendTransaction({ receiverId: cfg.contract, actions: [actions.functionCall("set_verifier", { account: "attacker.testnet", pk_hex: "00".repeat(32) }, teraToGas("20"), 0n)], throwOnFailure: false } as any),
  deposit: () => () => agent.signAndSendTransaction({ receiverId: cfg.contract, actions: [actions.functionCall("spend", {}, teraToGas("20"), 1n)], throwOnFailure: false } as any),
};

function show(label: string, o: Out) {
  const row = document.createElement("li");
  row.className = o.kind;
  row.innerHTML = `<div class="v"><b>${esc(o.verdict)}</b>${o.hash ? ` <a href="${explorer(o.hash)}" target="_blank" rel="noopener">view transaction</a>` : ` <span class="muted">refused by the protocol, no transaction</span>`}</div><div class="a">${esc(label)}</div><div class="w">${esc(o.why)}</div>`;
  $("log").prepend(row);
}

document.querySelectorAll<HTMLButtonElement>("button[data-attack]").forEach((b) => {
  b.addEventListener("click", async () => {
    const all = document.querySelectorAll<HTMLButtonElement>("button[data-attack]");
    all.forEach((x) => (x.disabled = true));
    const label = b.textContent ?? "";
    b.textContent = "Signing…";
    const out = await send(ATTEMPTS[b.dataset.attack!]());
    b.textContent = label;
    all.forEach((x) => (x.disabled = false));
    show(label, out);
    refresh().catch(() => {});
  });
});

$("key").textContent = cfg.agent_sk;
$("contract").textContent = cfg.contract;
$("contract").setAttribute("href", `https://testnet.nearblocks.io/address/${cfg.contract}`);
$("merchant").textContent = cfg.merchant;
$("firstpay").setAttribute("href", explorer(cfg.first_payment_tx));
$("copy").addEventListener("click", async () => {
  await navigator.clipboard.writeText(cfg.agent_sk);
  $("copy").textContent = "Copied";
  setTimeout(() => ($("copy").textContent = "Copy"), 1500);
});
await refresh();
setInterval(() => refresh().catch(() => {}), 15000);
