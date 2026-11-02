//! Writ —— GLEIF Agent Mandate Credential（AMC）的鏈上執行層
//!
//! 一句話：憑證時（credential-time）冷驗一次，執行時（runtime）每筆一個雜湊檢查，撤銷在下一個區塊生效。
//!
//! 角色
//!   - owner：部署者，只做一件事——維護「白名單驗證者」清單（account + Ed25519 公鑰）。
//!   - verifier（驗證者）：鏈下驗完 LE vLEI → ECR（人）→ AMC → agent 委派 AID 整條鏈，簽一張 attestation。
//!   - funder（法人出資帳號）：拿 attestation 呼叫 register 並入金；可隨時撤銷自己的委任。
//!   - agent：持有一把 Ed25519 鑰匙，同時是 KERI 委派 AID 的簽章鑰與本合約帳號上的 function-call key。
//!
//! 每筆 spend 檢查五個謂詞（對應 GLEIF 討論稿 Annex A p.44 的 AMC 四項 + 撤銷）：
//!   1. 鏈有效    —— register 時驗證者簽章已在鏈上驗過（冷驗一次）
//!   2. 未撤銷    —— 鑰匙還在合約帳號上（協定層保證；被刪就簽不出交易）
//!   3. 額度內    —— PayWord：sha256^j(preimage) == w_cur 且 idx + j <= n；另有每日鏈節速率
//!   4. 對手在範圍內 —— to ∈ scope
//!   5. 未過期    —— block_timestamp <= valid_until
//!
//! 政策拒絕不 panic：回傳 Verdict::Rejected，交易成功、有 tx hash、事件與計數留在鏈上。
//! 連續被拒 TRIPWIRE 次 → 合約自動刪掉 agent 的鑰匙（被 prompt injection 的 agent 試三次就自殺）。

use near_sdk::json_types::{Base64VecU8, U128, U64};
use near_sdk::serde_json::{self, Value};
use near_sdk::store::{IterableMap, LookupMap, LookupSet};
use near_sdk::{
    env, near, require, AccountId, Allowance, BorshStorageKey, Gas, NearToken, PanicOnDefault, Promise,
    PromiseError, PromiseOrValue, PublicKey,
};

/// 給 agent 鑰匙的預設 gas allowance（agent 交易的 gas 從合約帳號扣，這是單把鑰匙能燒掉的上限）。
pub const DEFAULT_ALLOWANCE: NearToken = NearToken::from_millinear(250);
/// 開格費 = 整把鑰匙的 gas 上限 + 儲存。一格燒光 allowance 也動不到別格的金庫。
pub const REGISTER_FEE: NearToken = NearToken::from_millinear(350);
/// 每節鏈節預付一筆發票紀錄的儲存（n 節最多 n 筆付款）。
const STORAGE_PER_INVOICE: u128 = 1_000_000_000_000_000_000_000;
/// attestation 簽出後多久內要拿去開格：驗證者看到的「未撤銷」不能無限期沿用。
pub const MAX_ATTESTATION_AGE_NS: u64 = 3_600_000_000_000;

/// 子 agent 的 gas 上限。雇用費從上層金庫扣，所以子 agent 燒的 gas 也是這棵樹自己付的。
pub const CHILD_ALLOWANCE: NearToken = NearToken::from_millinear(100);
const CHILD_STORAGE: u128 = 15_000_000_000_000_000_000_000;
/// 一棵樹最多幾層、幾格：撤銷要在一筆交易內刪掉整棵樹，所以大小要有上限。
pub const MAX_DEPTH: u32 = 3;
pub const MAX_TREE: u32 = 16;

fn hire_fee(n: u32) -> u128 {
    CHILD_ALLOWANCE.as_yoctonear() + CHILD_STORAGE + (n as u128) * STORAGE_PER_INVOICE
}

fn register_fee(n: u32) -> u128 {
    REGISTER_FEE.as_yoctonear() + (n as u128) * STORAGE_PER_INVOICE
}
/// agent 鑰匙能呼叫的方法——只有這一個寫入方法。
pub const AGENT_METHODS: &str = "spend,hire,dismiss";
/// scope 最多幾個收款人。
pub const MAX_SCOPE: usize = 16;
const NS_PER_DAY: u64 = 86_400_000_000_000;
const GAS_FOR_CALLBACK: Gas = Gas::from_tgas(25); // 要付得起撤銷後的 ft_transfer（10）＋ on_refund（5）
const GAS_FOR_REFUND_CB: Gas = Gas::from_tgas(5);
const MAX_EVIDENCE: usize = 128;
const GAS_FOR_FT: Gas = Gas::from_tgas(10);

#[derive(BorshStorageKey)]
#[near]
enum StorageKey {
    Verifiers,
    Cells,
    KeyToCell,
    Supervisors,
    Unseals,
    UsedAmcs,
    PaidInvoices,
}

/// 格的狀態。Revoked / Tripped 之後鑰匙已不在合約帳號上。
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub enum Status {
    Active,
    /// 撤銷。by：誰觸發；evidence：KERI rev 事件的 SAID（或 "manual"）。
    Revoked { by: AccountId, evidence: String },
    /// tripwire：連續被拒太多次，合約自動刪鑰匙。
    Tripped,
}

/// 一個委任格 = 一張 AMC 在鏈上的執行狀態。
#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct Cell {
    pub amc_said: String,          // AMC 的 SAID（憑證本身不上鏈）
    pub issuer_aid: String,        // AMC 簽發者的 KERI AID —— 撤銷事件的 i 必須是它
    pub issuer_pk: String,         // AMC 簽發者（人）當前的 Ed25519 公鑰 hex —— revoke_by_kel 用
    pub agent_pk: PublicKey,       // agent 的鑰匙（= KERI 委派 AID 的簽章鑰）
    pub verifier: AccountId,       // 哪個驗證者擔保了這條鏈
    pub funder: AccountId,         // 法人出資帳號（入金、撤銷、續命）
    pub lei_commit: String,        // sha256(LEI ‖ salt) hex —— LEI 本身不上鏈
    pub ecr_commit: String,        // sha256(LE 公鑰 hex|ECR SAID|salt) hex —— HR 撤銷 ECR 時才打開
    pub scope: Vec<AccountId>,     // 允許的交易對手
    pub valid_until: U64,          // 有效期（Unix ns）
    pub unit: U128,                // 每個鏈節值多少 yoctoNEAR
    pub n: u32,                    // 鏈長（總額度 = n × unit）
    pub idx: u32,                  // 已消耗幾節
    pub w_cur: String,             // 目前的鏈頭 hex（初始 = w0）
    pub daily_links: u32,          // 每日最多可消耗幾節（速率）
    pub max_links: u32,            // 單筆最多幾節（AMC 的交易上限）
    pub max_strikes: u32,          // 連續拒絕幾次刪鑰匙；0 = 不自動刪（寫在憑證裡）
    pub day: u64,                  // 速率計數所屬的日
    pub day_used: u32,             // 當日已消耗幾節
    pub vault: U128,               // 這格可動用的金庫餘額
    pub unclaimed: U128,           // 關格退款失敗的金額，法人可用 claim_refund 重領
    pub spends: u32,
    pub rejects: u32,              // 累計拒絕
    pub strikes: u32,              // 連續拒絕（成功一筆就歸零）
    pub status: Status,
    /// None = NEAR 原生代幣；Some(token) = NEP-141（例如穩定幣），金庫以該代幣最小單位計
    pub asset: Option<AccountId>,
    pub root: u64,                 // 這棵樹的根格（根格指向自己）
    pub parent: Option<u64>,       // 雇用它的格
    pub depth: u32,                // 根格 = 0
    pub children: Vec<u64>,        // 它雇用的格
    pub tree_size: u32,            // 整棵樹幾格（只在根格維護）
}

/// spend 的判決。被擋不是錯誤，是正常結果。
#[near(serializers = [json])]
#[derive(Debug, PartialEq)]
pub enum Verdict {
    Paid { cell: U64, amount: U128, idx: u32, remaining_links: u32 },
    Hired { cell: U64, child: U64, links: u32, remaining_links: u32 },
    Rejected { cell: U64, reason: String, strikes: u32, tripped: bool },
}

/// register 的參數（驗證者簽的就是這些欄位的規範字串，見 attestation_message）。
#[near(serializers = [json])]
#[derive(Clone)]
pub struct RegisterArgs {
    pub amc_said: String,
    pub issuer_aid: String,
    pub issuer_pk: String,
    pub agent_pk: PublicKey,
    pub w0: String,
    pub n: u32,
    pub unit: U128,
    pub scope: Vec<AccountId>,
    pub valid_until: U64,
    pub daily_links: u32,
    pub max_links: u32,
    pub max_strikes: u32,
    pub lei_commit: String,
    pub ecr_commit: String,
    pub verifier: AccountId,
    /// 驗證者驗鏈的時間（ns）。太舊就不能開格。
    pub attested_at: U64,
    /// 驗證者對 attestation_message 的 Ed25519 簽章（hex，64 bytes）
    pub signature: String,
    /// 結算資產：省略 = NEAR；NEP-141 合約帳號 = 以該代幣支付（綁在 attestation 裡）
    #[serde(default)]
    pub asset: Option<AccountId>,
}

/// agent 雇用子 agent 的條件。全部只能比上層更窄，合約逐項檢查。
#[near(serializers = [json])]
#[derive(Clone)]
pub struct HireArgs {
    pub agent_pk: PublicKey,
    pub w0: String,
    pub scope: Vec<AccountId>,
    pub valid_until: U64,
    pub daily_links: u32,
    pub max_links: u32,
}

/// 打開 ecr_commit：HR（法人）撤銷 ECR 時用。LE 公鑰與 ECR SAID 平常不上鏈。
#[near(serializers = [json])]
#[derive(Clone)]
pub struct EcrOpening {
    pub le_aid: String,
    pub le_pk: String,
    pub ecr_said: String,
    pub salt: String,
}

/// 全域計數（README 首頁總表用）。
#[near(serializers = [borsh, json])]
#[derive(Clone, Default)]
pub struct Stats {
    pub cells: u64,
    pub paid: u64,
    pub paid_yocto: U128,
    pub rejected: u64,
    pub tripped: u64,
    pub revoked: u64,
}

/// 監理方調閱（tier-1 解封：只揭露 LEI）。解封本身就是一筆公開交易。
#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct Unseal {
    pub requester: AccountId,
    pub reason_hash: String,   // 調閱理由（例如法院命令）的 sha256 hex；理由本文不上鏈
    pub requested_at: U64,     // ns
    pub objected: bool,        // 法人提出異議：公開留痕，不是否決（GLEIF 討論稿 p.28–29 的 view-key 模型）
    pub lei: Option<String>,   // 揭露後才有
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    owner: AccountId,
    verifiers: IterableMap<AccountId, String>, // account → Ed25519 公鑰 hex
    cells: LookupMap<u64, Cell>,
    key_to_cell: LookupMap<PublicKey, u64>,
    next_id: u64,
    vault_total: u128, // 所有格的金庫總和；合約餘額必須 >= 這個數
    stats: Stats,
    supervisors: IterableMap<AccountId, bool>,
    unseals: LookupMap<u64, Unseal>,
    unseal_delay_ns: u64,
    used_amcs: LookupMap<String, u64>, // 一張 AMC 只能開一格；撤銷後不能用同一張 attestation 復活
    paid_invoices: LookupSet<Vec<u8>>, // cell id ‖ 發票雜湊：同一張發票不能付兩次
}

// ---------------- 小工具 ----------------

fn hex32(s: &str, what: &str) -> [u8; 32] {
    let v = hex::decode(s).unwrap_or_else(|_| env::panic_str(&format!("BAD_HEX:{}", what)));
    v.as_slice().try_into().unwrap_or_else(|_| env::panic_str(&format!("BAD_LEN:{}", what)))
}

fn event(name: &str, data: Value) {
    let ev = serde_json::json!({"standard": "writ", "version": "1.0.0", "event": name, "data": [data]});
    env::log_str(&format!("EVENT_JSON:{}", ev));
}

/// 規範的 attestation 字串：驗證者鏈下簽這段 bytes，合約鏈上重建再驗。
/// 欄位順序固定、以 \n 分隔；agent_pk 用 NEAR 字串格式（ed25519:<base58>）。
pub fn attestation_message(a: &RegisterArgs, funder: &AccountId, contract: &AccountId) -> String {
    let scope: Vec<&str> = a.scope.iter().map(|s| s.as_str()).collect();
    format!(
        "writ:attest:v3\ncontract={}\namc={}\nissuer_aid={}\nissuer_pk={}\nagent_pk={}\nw0={}\nn={}\nunit={}\nscope={}\nvalid_until={}\ndaily_links={}\nmax_links={}\nmax_strikes={}\nlei_commit={}\necr_commit={}\nfunder={}\nverifier={}\nattested_at={}\nasset={}",
        contract,
        a.amc_said,
        a.issuer_aid,
        a.issuer_pk,
        String::from(&a.agent_pk),
        a.w0,
        a.n,
        a.unit.0,
        scope.join(","),
        a.valid_until.0,
        a.daily_links,
        a.max_links,
        a.max_strikes,
        a.lei_commit,
        a.ecr_commit,
        funder,
        a.verifier,
        a.attested_at.0,
        a.asset.as_ref().map(|t| t.as_str()).unwrap_or("near")
    )
}

#[near]
impl Contract {
    /// owner：維護驗證者與監理方白名單的帳號，應該是另一個帳號，這樣合約帳號才能刪掉 full-access key。
    /// 部署、初始化、刪 full-access key 放在同一個 batch（make testnet 就是這樣做），#[private] 防搶先初始化。
    /// unseal_delay_secs：監理方提出調閱到驗證者可以揭露之間的公開等待期（預設 2 分鐘）。
    #[init]
    #[private]
    pub fn new(owner: AccountId, unseal_delay_secs: Option<u64>) -> Self {
        Self {
            owner,
            verifiers: IterableMap::new(StorageKey::Verifiers),
            cells: LookupMap::new(StorageKey::Cells),
            key_to_cell: LookupMap::new(StorageKey::KeyToCell),
            next_id: 1,
            vault_total: 0,
            stats: Stats::default(),
            supervisors: IterableMap::new(StorageKey::Supervisors),
            unseals: LookupMap::new(StorageKey::Unseals),
            unseal_delay_ns: unseal_delay_secs.unwrap_or(120) * 1_000_000_000,
            used_amcs: LookupMap::new(StorageKey::UsedAmcs),
            paid_invoices: LookupSet::new(StorageKey::PaidInvoices),
        }
    }

    // ================= 管理：白名單驗證者 =================

    pub fn set_verifier(&mut self, account: AccountId, pk_hex: Option<String>) {
        require!(env::predecessor_account_id() == self.owner, "ONLY_OWNER");
        match pk_hex {
            Some(pk) => {
                hex32(&pk, "verifier_pk");
                self.verifiers.insert(account, pk);
            }
            None => {
                self.verifiers.remove(&account);
            }
        }
    }

    // ================= 憑證時：開格（冷驗一次） =================

    /// 法人出資帳號帶著驗證者的 attestation 呼叫；附帶的 NEAR 扣掉開格費後進這格的金庫。
    /// 合約在「自己的帳號」上掛一把只能呼叫 spend 的 function-call key 給 agent（Keypom 模式）。
    #[payable]
    pub fn register(&mut self, args: RegisterArgs) -> U64 {
        let funder = env::predecessor_account_id();
        let deposit = env::attached_deposit();
        let fee = register_fee(args.n);
        require!(deposit.as_yoctonear() > fee, "DEPOSIT_BELOW_FEE");
        require!(args.n > 0 && args.daily_links > 0 && args.max_links > 0, "BAD_LIMITS");
        require!(env::block_timestamp().saturating_sub(args.attested_at.0) <= MAX_ATTESTATION_AGE_NS, "STALE_ATTESTATION");
        require!(!args.scope.is_empty() && args.scope.len() <= MAX_SCOPE, "BAD_SCOPE");
        require!(args.valid_until.0 > env::block_timestamp(), "ALREADY_EXPIRED");
        require!(!self.key_to_cell.contains_key(&args.agent_pk), "KEY_IN_USE");
        hex32(&args.w0, "w0");
        hex32(&args.issuer_pk, "issuer_pk");
        hex32(&args.lei_commit, "lei_commit");
        hex32(&args.ecr_commit, "ecr_commit");
        require!(!self.used_amcs.contains_key(&args.amc_said), "AMC_ALREADY_USED");

        // 謂詞 1：鏈有效 —— 白名單驗證者的簽章
        let vpk_hex = self.verifiers.get(&args.verifier).unwrap_or_else(|| env::panic_str("UNKNOWN_VERIFIER"));
        let vpk = hex32(vpk_hex, "verifier_pk");
        let sig: [u8; 64] = hex::decode(&args.signature)
            .ok()
            .and_then(|v| v.as_slice().try_into().ok())
            .unwrap_or_else(|| env::panic_str("BAD_SIGNATURE_ENCODING"));
        let msg = attestation_message(&args, &funder, &env::current_account_id());
        require!(env::ed25519_verify(&sig, msg.as_bytes(), &vpk), "BAD_ATTESTATION");

        // NEAR 格：附帶的 NEAR 扣掉開格費進金庫。代幣格：附帶的 NEAR 全當開格費／gas 準備，金庫用 ft_transfer_call 入金。
        let vault = if args.asset.is_none() { deposit.as_yoctonear() - fee } else { 0 };
        let id = self.next_id;
        self.next_id += 1;
        let cell = Cell {
            amc_said: args.amc_said.clone(),
            issuer_aid: args.issuer_aid.clone(),
            issuer_pk: args.issuer_pk.clone(),
            agent_pk: args.agent_pk.clone(),
            verifier: args.verifier.clone(),
            funder: funder.clone(),
            lei_commit: args.lei_commit.clone(),
            ecr_commit: args.ecr_commit.clone(),
            scope: args.scope.clone(),
            valid_until: args.valid_until,
            unit: args.unit,
            n: args.n,
            idx: 0,
            w_cur: args.w0.to_lowercase(),
            daily_links: args.daily_links,
            max_links: args.max_links,
            max_strikes: args.max_strikes,
            day: env::block_timestamp() / NS_PER_DAY,
            day_used: 0,
            vault: U128(vault),
            unclaimed: U128(0),
            spends: 0,
            rejects: 0,
            strikes: 0,
            status: Status::Active,
            asset: args.asset.clone(),
            root: id,
            parent: None,
            depth: 0,
            children: vec![],
            tree_size: 1,
        };
        self.cells.insert(id, cell);
        self.key_to_cell.insert(args.agent_pk.clone(), id);
        self.used_amcs.insert(args.amc_said.clone(), id);
        self.vault_total += vault;
        self.stats.cells += 1;
        event(
            "registered",
            serde_json::json!({"cell": id.to_string(), "amc_said": args.amc_said, "agent_pk": String::from(&args.agent_pk),
                               "verifier": args.verifier, "vault": vault.to_string(), "n": args.n, "unit": args.unit.0.to_string()}),
        );
        if args.asset.is_some() && deposit.as_yoctonear() > fee {
            // 代幣格的金庫是代幣，超過開格費的 NEAR 退回
            Promise::new(funder.clone()).transfer(NearToken::from_yoctonear(deposit.as_yoctonear() - fee)).detach();
        }
        Promise::new(env::current_account_id())
            .add_access_key_allowance(
                args.agent_pk,
                Allowance::limited(DEFAULT_ALLOWANCE).unwrap(),
                env::current_account_id(),
                AGENT_METHODS.to_string(),
            )
            .detach();
        U64(id)
    }

    /// 法人追加入金。
    #[payable]
    pub fn top_up(&mut self, cell: U64) {
        let mut c = self.cells.get(&cell.0).cloned().unwrap_or_else(|| env::panic_str("NO_CELL"));
        require!(env::predecessor_account_id() == c.funder, "ONLY_FUNDER");
        require!(c.status == Status::Active, "NOT_ACTIVE");
        require!(c.asset.is_none(), "TOKEN_CELL_USE_FT_TRANSFER_CALL");
        let d = env::attached_deposit().as_yoctonear();
        c.vault = U128(c.vault.0 + d);
        self.vault_total += d;
        self.cells.insert(cell.0, c);
    }

    // ================= 執行時：每筆一個雜湊檢查 =================

    /// 只有 agent 的 function-call key 能呼叫（signer 必須是合約帳號本身）。
    /// preimage：人鏈下撥給 agent 的鏈節（hex）；j：這筆要消耗幾節；金額 = j × unit。
    /// invoice_hash：這筆付款對應的發票 sha256（hex）。同一格不能付同一張發票兩次，也是對帳的依據。
    pub fn spend(&mut self, preimage: String, j: u32, to: AccountId, invoice_hash: String) -> PromiseOrValue<Verdict> {
        require!(env::signer_account_id() == env::current_account_id(), "NOT_AGENT_KEY");
        let pk = env::signer_account_pk();
        let id = *self.key_to_cell.get(&pk).unwrap_or_else(|| env::panic_str("NO_CELL"));
        let mut c = self.cells.get(&id).cloned().unwrap();
        // 協定層已保證鑰匙存在＝未撤銷；狀態欄位是給人看的雙重保險
        require!(c.status == Status::Active, "NOT_ACTIVE");

        let now = env::block_timestamp();
        let today = now / NS_PER_DAY;
        if today != c.day {
            c.day = today;
            c.day_used = 0;
        }

        let invoice_key = Self::invoice_key(id, &invoice_hash);
        // 依序檢查：過期 → 對手 → 發票 → 單筆上限 → 額度（鏈長）→ 雜湊鏈 → 速率 → 金庫
        let reason: Option<&str> = if now > c.valid_until.0 {
            Some("EXPIRED")
        } else if !c.scope.iter().any(|s| *s == to) {
            Some("SCOPE")
        } else if invoice_key.is_none() {
            Some("INVOICE")
        } else if self.paid_invoices.contains(invoice_key.as_ref().unwrap()) {
            Some("DUPLICATE")
        } else if j > c.max_links {
            Some("PER_TX")
        } else if j == 0 || c.idx.saturating_add(j) > c.n {
            Some("LIMIT")
        } else if !Self::chain_ok(&preimage, j, &c.w_cur) {
            Some("CHAIN")
        } else if c.day_used.saturating_add(j) > c.daily_links {
            Some("RATE")
        } else if c.vault.0 < (j as u128) * c.unit.0 {
            Some("FUNDS")
        } else {
            None
        };

        if let Some(r) = reason {
            event("rejected", serde_json::json!({"cell": id.to_string(), "reason": r, "to": to, "j": j, "strikes": c.strikes + 1}));
            return PromiseOrValue::Value(self.reject(id, c, pk, r));
        }

        // 通過：推進鏈頭、扣額度、扣金庫，然後轉帳
        let amount = (j as u128) * c.unit.0;
        self.paid_invoices.insert(invoice_key.unwrap());
        c.w_cur = preimage.to_lowercase();
        c.idx += j;
        c.day_used += j;
        c.vault = U128(c.vault.0 - amount);
        c.spends += 1;
        c.strikes = 0;
        if c.asset.is_none() {
            self.vault_total -= amount; // vault_total 只追蹤 NEAR 金庫
        }
        let idx = c.idx;
        let remaining = c.n - c.idx;
        let asset = c.asset.clone();
        self.cells.insert(id, c);

        // 跨 receipt 沒有原子回滾：先扣（預留），callback 失敗再退回金庫
        // 代幣格：合約自己發 receipt 附 1 yocto 呼叫 ft_transfer（agent 的 FC key 不能附存款，合約可以）
        let payout = match &asset {
            None => Promise::new(to.clone()).transfer(NearToken::from_yoctonear(amount)),
            Some(token) => Promise::new(token.clone()).function_call(
                "ft_transfer".to_string(),
                serde_json::to_vec(&serde_json::json!({"receiver_id": to, "amount": amount.to_string(), "memo": format!("writ cell {}", id)})).unwrap(),
                NearToken::from_yoctonear(1),
                GAS_FOR_FT,
            ),
        };
        // 交易的最終結果就是轉帳的真正結果：Paid 只在錢真的到了才出現
        payout
            .then(Self::ext(env::current_account_id()).with_static_gas(GAS_FOR_CALLBACK).on_transfer(U64(id), U128(amount), invoice_hash, to, idx, remaining))
            .into()
    }

    /// agent 雇用子 agent：用自己的鏈節換出一段預算給它。
    /// 子 agent 能動用的錢，一定是員工已經撥給上層的鏈節；對手、期限、速率、單筆上限只能更窄。
    /// 政策拒絕跟 spend 一樣：回傳 Rejected、留痕、算 strike。
    pub fn hire(&mut self, preimage: String, j: u32, child: HireArgs) -> Verdict {
        require!(env::signer_account_id() == env::current_account_id(), "NOT_AGENT_KEY");
        let pk = env::signer_account_pk();
        let id = *self.key_to_cell.get(&pk).unwrap_or_else(|| env::panic_str("NO_CELL"));
        let mut c = self.cells.get(&id).cloned().unwrap();
        require!(c.status == Status::Active, "NOT_ACTIVE");
        let now = env::block_timestamp();
        let today = now / NS_PER_DAY;
        if today != c.day {
            c.day = today;
            c.day_used = 0;
        }
        let amount = (j as u128).saturating_mul(c.unit.0);
        // 雇用費由根格（公司）付：子 agent 的金庫只有撥給它的預算，付不起也不該付
        let root_cell = if c.root == id { None } else { self.cells.get(&c.root).cloned() };
        let tree_size = root_cell.as_ref().map(|r| r.tree_size).unwrap_or(c.tree_size);
        let fee = hire_fee(j);
        let funded = match &root_cell {
            None => c.vault.0 >= amount.saturating_add(fee),
            Some(r) => c.vault.0 >= amount && r.vault.0 >= fee,
        };
        let w0_ok = hex::decode(&child.w0).map(|v| v.len() == 32).unwrap_or(false);
        let reason: Option<&str> = if now > c.valid_until.0 {
            Some("EXPIRED")
        } else if c.asset.is_some() {
            Some("HIRE_TOKEN")
        } else if child.scope.is_empty() || !child.scope.iter().all(|s| c.scope.contains(s)) {
            Some("HIRE_SCOPE")
        } else if child.valid_until.0 > c.valid_until.0
            || child.valid_until.0 <= now
            || child.daily_links == 0
            || child.daily_links > c.daily_links
            || child.max_links == 0
            || child.max_links > c.max_links
            || !w0_ok
        {
            Some("HIRE_TERMS")
        } else if c.depth + 1 > MAX_DEPTH {
            Some("HIRE_DEPTH")
        } else if tree_size >= MAX_TREE {
            Some("HIRE_TREE")
        } else if self.key_to_cell.contains_key(&child.agent_pk) {
            Some("HIRE_KEY")
        } else if j == 0 || c.idx.saturating_add(j) > c.n {
            Some("LIMIT")
        } else if !Self::chain_ok(&preimage, j, &c.w_cur) {
            Some("CHAIN")
        } else if c.day_used.saturating_add(j) > c.daily_links {
            Some("RATE")
        } else if !funded {
            Some("FUNDS")
        } else {
            None
        };
        if let Some(r) = reason {
            event("rejected", serde_json::json!({"cell": id.to_string(), "reason": r, "j": j, "strikes": c.strikes + 1}));
            return self.reject(id, c, pk, r);
        }

        c.w_cur = preimage.to_lowercase();
        c.idx += j;
        c.day_used += j;
        c.strikes = 0;
        c.vault = U128(c.vault.0 - amount - if root_cell.is_none() { fee } else { 0 });
        self.vault_total -= fee; // 費用留在合約付儲存與 gas；amount 只是換格，總額不變
        let child_id = self.next_id;
        self.next_id += 1;
        c.children.push(child_id);
        let cell = Cell {
            amc_said: format!("{}/sub-{}", c.amc_said, child_id),
            issuer_aid: String::new(),
            issuer_pk: String::new(),
            agent_pk: child.agent_pk.clone(),
            verifier: c.verifier.clone(),
            funder: c.funder.clone(),
            lei_commit: c.lei_commit.clone(),
            ecr_commit: String::new(),
            scope: child.scope,
            valid_until: child.valid_until,
            unit: c.unit,
            n: j,
            idx: 0,
            w_cur: child.w0.to_lowercase(),
            daily_links: child.daily_links,
            max_links: child.max_links,
            max_strikes: if c.max_strikes == 0 { 3 } else { c.max_strikes },
            day: today,
            day_used: 0,
            vault: U128(amount),
            unclaimed: U128(0),
            spends: 0,
            rejects: 0,
            strikes: 0,
            status: Status::Active,
            asset: None,
            root: c.root,
            parent: Some(id),
            depth: c.depth + 1,
            children: vec![],
            tree_size: 0,
        };
        self.cells.insert(child_id, cell);
        self.key_to_cell.insert(child.agent_pk.clone(), child_id);
        self.stats.cells += 1;
        let remaining = c.n - c.idx;
        match root_cell {
            None => {
                c.tree_size += 1;
                self.cells.insert(id, c);
            }
            Some(mut r) => {
                r.tree_size += 1;
                r.vault = U128(r.vault.0 - fee);
                self.cells.insert(c.root, r);
                self.cells.insert(id, c);
            }
        }
        event("hired", serde_json::json!({"cell": id.to_string(), "child": child_id.to_string(), "links": j, "agent_pk": String::from(&child.agent_pk)}));
        Promise::new(env::current_account_id())
            .add_access_key_allowance(
                child.agent_pk,
                Allowance::limited(CHILD_ALLOWANCE).unwrap(),
                env::current_account_id(),
                AGENT_METHODS.to_string(),
            )
            .detach();
        Verdict::Hired { cell: U64(id), child: U64(child_id), links: j, remaining_links: remaining }
    }

    /// agent 解僱自己雇用的子 agent（連同它底下的樹）。剩餘的錢退回法人。
    pub fn dismiss(&mut self, child: U64) {
        require!(env::signer_account_id() == env::current_account_id(), "NOT_AGENT_KEY");
        let pk = env::signer_account_pk();
        let id = *self.key_to_cell.get(&pk).unwrap_or_else(|| env::panic_str("NO_CELL"));
        let c = self.cells.get(&child.0).cloned().unwrap_or_else(|| env::panic_str("NO_CELL"));
        require!(c.parent == Some(id), "NOT_PARENT");
        self.close(child.0, c, Status::Revoked { by: env::current_account_id(), evidence: format!("dismissed by cell {}", id) });
    }

    /// 政策拒絕：計 strike，連續太多次刪鑰匙。回傳 Rejected，交易本身成功。
    fn reject(&mut self, id: u64, mut c: Cell, pk: PublicKey, r: &str) -> Verdict {
        c.rejects += 1;
        c.strikes += 1;
        self.stats.rejected += 1;
        let tripped = c.max_strikes > 0 && c.strikes >= c.max_strikes;
        if tripped {
            c.status = Status::Tripped;
            self.stats.tripped += 1;
            self.key_to_cell.remove(&pk);
            event("tripped", serde_json::json!({"cell": id.to_string(), "agent_pk": String::from(&pk)}));
            Promise::new(env::current_account_id()).delete_key(pk).detach();
        }
        let strikes = c.strikes;
        self.cells.insert(id, c);
        Verdict::Rejected { cell: U64(id), reason: r.to_string(), strikes, tripped }
    }

    #[private]
    pub fn on_transfer(&mut self, cell: U64, amount: U128, invoice_hash: String, to: AccountId, idx: u32, remaining: u32, #[callback_result] r: Result<(), PromiseError>) -> Verdict {
        let Some(mut c) = self.cells.get(&cell.0).cloned() else { env::panic_str("NO_CELL") };
        if r.is_ok() {
            self.stats.paid += 1;
            if c.asset.is_none() {
                self.stats.paid_yocto = U128(self.stats.paid_yocto.0 + amount.0);
            }
            event("paid", serde_json::json!({"cell": cell.0.to_string(), "to": to, "amount": amount.0.to_string(), "idx": idx, "invoice": invoice_hash}));
            return Verdict::Paid { cell, amount, idx, remaining_links: remaining };
        }
        // 沒付成：這張發票還能再付；鏈節已消耗不退（防重放）；錢退回金庫
        if let Some(k) = Self::invoice_key(cell.0, &invoice_hash) {
            self.paid_invoices.remove(&k);
        }
        c.spends = c.spends.saturating_sub(1);
        let strikes = c.strikes;
        if matches!(c.status, Status::Revoked { .. }) {
            // 轉帳途中格已被撤銷：關閉的格不能再領錢，直接退給法人
            let (asset, funder) = (c.asset.clone(), c.funder.clone());
            self.cells.insert(cell.0, c);
            self.pay_out(cell.0, &asset, funder, amount.0, format!("writ cell {} closed", cell.0));
        } else {
            c.vault = U128(c.vault.0 + amount.0);
            if c.asset.is_none() {
                self.vault_total += amount.0;
            }
            self.cells.insert(cell.0, c);
        }
        event("refunded", serde_json::json!({"cell": cell.0.to_string(), "amount": amount.0.to_string()}));
        Verdict::Rejected { cell, reason: "TRANSFER_FAILED".to_string(), strikes, tripped: false }
    }

    fn invoice_key(cell: u64, invoice_hash: &str) -> Option<Vec<u8>> {
        let raw = hex::decode(invoice_hash).ok()?;
        if raw.len() != 32 {
            return None;
        }
        let mut k = cell.to_le_bytes().to_vec();
        k.extend_from_slice(&raw);
        Some(k)
    }

    fn chain_ok(preimage: &str, j: u32, w_cur: &str) -> bool {
        let Ok(mut cur) = hex::decode(preimage) else { return false };
        if cur.len() != 32 {
            return false;
        }
        for _ in 0..j {
            cur = env::sha256(&cur);
        }
        hex::encode(cur) == w_cur.to_lowercase()
    }

    // ================= 撤銷 =================

    /// 手動撤銷：法人出資帳號、該格的驗證者、或 owner 可呼叫。
    /// evidence：KERI rev 事件的 SAID（watcher 帶入）或 "manual"。
    pub fn revoke(&mut self, cell: U64, evidence: String) {
        let c = self.cells.get(&cell.0).cloned().unwrap_or_else(|| env::panic_str("NO_CELL"));
        let who = env::predecessor_account_id();
        require!(evidence.len() <= MAX_EVIDENCE, "EVIDENCE_TOO_LONG");
        require!(who == c.funder || (who == c.verifier && self.verifiers.contains_key(&who)) || who == self.owner, "NOT_AUTHORIZED");
        self.close(cell.0, c, Status::Revoked { by: who, evidence });
    }

    /// 無須信任的撤銷：任何人提交 AMC 簽發者 KEL 上錨定撤銷的 ixn 事件（原始 bytes）＋簽章，
    /// 合約驗簽並確認 seal = {i: 這格的 AMC SAID, s: "1"}（簡單 TEL：sn 0 = iss，sn 1 只能是 rev）。
    /// 限制：簽發者若輪替金鑰，issuer_pk 需由驗證者重新 attest（README 揭露）。
    ///
    /// ecr 省略：員工（AMC 簽發者）撤銷 AMC。
    /// ecr 帶上：HR（法人）撤銷員工的 ECR，員工離職也不需要他配合；打開承諾會公開 LE 的公鑰。
    pub fn revoke_by_kel(&mut self, cell: U64, ixn: Base64VecU8, signature: Base64VecU8, ecr: Option<EcrOpening>) {
        let c = self.cells.get(&cell.0).cloned().unwrap_or_else(|| env::panic_str("NO_CELL"));
        let sig: [u8; 64] = signature.0.as_slice().try_into().unwrap_or_else(|_| env::panic_str("BAD_SIG_LEN"));
        let (aid, pk_hex, said) = match &ecr {
            None => (c.issuer_aid.clone(), c.issuer_pk.clone(), c.amc_said.clone()),
            Some(o) => {
                let digest = hex::encode(env::sha256(format!("{}|{}|{}|{}", o.le_aid, o.le_pk, o.ecr_said, o.salt).as_bytes()));
                require!(digest == c.ecr_commit, "BAD_ECR_OPENING");
                (o.le_aid.clone(), o.le_pk.clone(), o.ecr_said.clone())
            }
        };
        let pk = hex32(&pk_hex, "signer_pk");
        require!(env::ed25519_verify(&sig, &ixn.0, &pk), "BAD_KEL_SIGNATURE");
        let ev: Value = serde_json::from_slice(&ixn.0).unwrap_or_else(|_| env::panic_str("BAD_IXN_JSON"));
        require!(ev["t"] == "ixn", "NOT_IXN");
        require!(ev["i"] == aid.as_str(), "WRONG_AID");
        let seals = ev["a"].as_array().unwrap_or_else(|| env::panic_str("NO_SEALS"));
        let rev = seals
            .iter()
            .find(|s| s["i"] == said.as_str() && s["s"] == "1")
            .unwrap_or_else(|| env::panic_str("NO_REVOCATION_SEAL"));
        let rev_said = rev["d"].as_str().unwrap_or("").to_string();
        require!(!rev_said.is_empty(), "NO_REVOCATION_SEAL");
        let who = env::predecessor_account_id();
        self.close(cell.0, c, Status::Revoked { by: who, evidence: rev_said });
    }

    /// 關格：刪鑰匙、剩餘金庫退回法人。
    /// 也關閉它雇用的整棵子樹：一筆交易刪掉所有鑰匙，錢全部退回法人。
    fn close(&mut self, id: u64, c: Cell, status: Status) {
        require!(c.status == Status::Active || matches!(c.status, Status::Tripped), "ALREADY_CLOSED");
        let (asset, funder) = (c.asset.clone(), c.funder.clone());
        let mut refund = 0u128;
        let mut keys: Vec<PublicKey> = vec![];
        let mut stack: Vec<(u64, Cell, Status)> = vec![(id, c, status)];
        while let Some((cid, mut cell, st)) = stack.pop() {
            if cell.status == Status::Active {
                keys.push(cell.agent_pk.clone()); // tripped 的格鑰匙已刪過；再刪會失敗
            }
            let part = cell.vault.0;
            refund += part;
            cell.vault = U128(0);
            cell.status = st.clone();
            self.key_to_cell.remove(&cell.agent_pk);
            self.stats.revoked += 1;
            event("revoked", serde_json::json!({"cell": cid.to_string(), "status": st, "refund": part.to_string()}));
            for k in cell.children.iter() {
                if let Some(ch) = self.cells.get(k).cloned() {
                    if ch.status == Status::Active || matches!(ch.status, Status::Tripped) {
                        let by = match &st { Status::Revoked { by, .. } => by.clone(), _ => env::current_account_id() };
                        stack.push((*k, ch, Status::Revoked { by, evidence: format!("parent cell {} closed", cid) }));
                    }
                }
            }
            self.cells.insert(cid, cell);
        }
        if asset.is_none() {
            self.vault_total -= refund;
        }
        if let Some((first, rest)) = keys.split_first() {
            let mut batch = Promise::new(env::current_account_id()).delete_key(first.clone());
            for k in rest {
                batch = batch.delete_key(k.clone());
            }
            batch.detach();
        }
        if refund > 0 {
            self.pay_out(id, &asset, funder, refund, format!("writ cell {} closed", id));
        }
    }

    /// 把 NEAR 或 NEP-141 退給法人；失敗就記在 unclaimed，不會憑空消失。
    fn pay_out(&self, cell: u64, asset: &Option<AccountId>, to: AccountId, amount: u128, memo: String) {
        let p = match asset {
            None => Promise::new(to).transfer(NearToken::from_yoctonear(amount)),
            Some(token) => Promise::new(token.clone()).function_call(
                "ft_transfer".to_string(),
                serde_json::to_vec(&serde_json::json!({"receiver_id": to, "amount": amount.to_string(), "memo": memo})).unwrap(),
                NearToken::from_yoctonear(1),
                GAS_FOR_FT,
            ),
        };
        p.then(Self::ext(env::current_account_id()).with_static_gas(GAS_FOR_REFUND_CB).on_refund(U64(cell), U128(amount))).detach();
    }

    #[private]
    pub fn on_refund(&mut self, cell: U64, amount: U128, #[callback_result] r: Result<(), PromiseError>) {
        if r.is_ok() {
            return;
        }
        if let Some(mut c) = self.cells.get(&cell.0).cloned() {
            c.unclaimed = U128(c.unclaimed.0 + amount.0);
            if c.asset.is_none() {
                self.vault_total += amount.0;
            }
            self.cells.insert(cell.0, c);
            event("refund_failed", serde_json::json!({"cell": cell.0.to_string(), "amount": amount.0.to_string()}));
        }
    }

    /// 關格退款失敗時（例如法人當時沒在代幣註冊），法人補好條件後重領。
    pub fn claim_refund(&mut self, cell: U64) {
        let mut c = self.cells.get(&cell.0).cloned().unwrap_or_else(|| env::panic_str("NO_CELL"));
        require!(env::predecessor_account_id() == c.funder, "ONLY_FUNDER");
        let amount = c.unclaimed.0;
        require!(amount > 0, "NOTHING_TO_CLAIM");
        c.unclaimed = U128(0);
        if c.asset.is_none() {
            self.vault_total -= amount;
        }
        let (asset, funder) = (c.asset.clone(), c.funder.clone());
        self.cells.insert(cell.0, c);
        self.pay_out(cell.0, &asset, funder, amount, format!("writ cell {} refund", cell.0));
    }

    /// 續命：gas allowance 用完時由法人或驗證者重掛同一把鑰匙（同 batch 先刪後加）。
    /// 呼叫者要附上新 allowance 的費用，否則串通的 agent 可以無限燒合約餘額（等於吃別格的金庫）。
    #[payable]
    pub fn refresh_key(&mut self, cell: U64) {
        require!(env::attached_deposit() >= DEFAULT_ALLOWANCE, "REFRESH_UNPAID");
        let c = self.cells.get(&cell.0).cloned().unwrap_or_else(|| env::panic_str("NO_CELL"));
        let who = env::predecessor_account_id();
        require!(who == c.funder || (who == c.verifier && self.verifiers.contains_key(&who)), "NOT_AUTHORIZED");
        require!(c.status == Status::Active, "NOT_ACTIVE");
        Promise::new(env::current_account_id())
            .delete_key(c.agent_pk.clone())
            .add_access_key_allowance(
                c.agent_pk,
                Allowance::limited(DEFAULT_ALLOWANCE).unwrap(),
                env::current_account_id(),
                AGENT_METHODS.to_string(),
            )
            .detach();
        event("refreshed", serde_json::json!({"cell": cell.0.to_string()}));
    }

    /// tripwire 跳掉之後由法人恢復：三張惡意發票不該讓整個委任作廢。要付新鑰匙的 gas 上限，並公開留痕。
    #[payable]
    pub fn reinstate(&mut self, cell: U64) {
        let mut c = self.cells.get(&cell.0).cloned().unwrap_or_else(|| env::panic_str("NO_CELL"));
        require!(env::predecessor_account_id() == c.funder, "ONLY_FUNDER");
        require!(c.status == Status::Tripped, "NOT_TRIPPED");
        require!(env::attached_deposit() >= DEFAULT_ALLOWANCE, "REINSTATE_UNPAID");
        require!(!self.key_to_cell.contains_key(&c.agent_pk), "KEY_IN_USE");
        c.status = Status::Active;
        c.strikes = 0;
        self.key_to_cell.insert(c.agent_pk.clone(), cell.0);
        Promise::new(env::current_account_id())
            .add_access_key_allowance(
                c.agent_pk.clone(),
                Allowance::limited(DEFAULT_ALLOWANCE).unwrap(),
                env::current_account_id(),
                AGENT_METHODS.to_string(),
            )
            .detach();
        self.cells.insert(cell.0, c);
        event("reinstated", serde_json::json!({"cell": cell.0.to_string()}));
    }

    /// 簽發人輪替金鑰後，該格的驗證者重新驗過 KEL 再更新撤銷用的鑰匙（否則新鑰簽的撤銷事件會被拒）。
    pub fn update_signers(&mut self, cell: U64, issuer_aid: String, issuer_pk: String, ecr_commit: String) {
        let mut c = self.cells.get(&cell.0).cloned().unwrap_or_else(|| env::panic_str("NO_CELL"));
        require!(env::predecessor_account_id() == c.verifier && self.verifiers.contains_key(&c.verifier), "ONLY_CELL_VERIFIER");
        require!(c.status == Status::Active, "NOT_ACTIVE");
        require!(c.parent.is_none(), "NOT_ROOT");
        hex32(&issuer_pk, "issuer_pk");
        hex32(&ecr_commit, "ecr_commit");
        c.issuer_aid = issuer_aid;
        c.issuer_pk = issuer_pk.clone();
        c.ecr_commit = ecr_commit;
        self.cells.insert(cell.0, c);
        event("signers_updated", serde_json::json!({"cell": cell.0.to_string(), "issuer_pk": issuer_pk}));
    }

    /// NEP-141 入金：法人 ft_transfer_call(writ, amount, msg = "<cell id>")。
    /// 只收「該格綁定的代幣」且「寄件人是該格的法人」；其他一律退回（回傳 amount），不 panic。
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> U128 {
        let token = env::predecessor_account_id();
        let Ok(id) = msg.trim().parse::<u64>() else { return amount };
        let Some(mut c) = self.cells.get(&id).cloned() else { return amount };
        if c.asset.as_ref() != Some(&token) || c.funder != sender_id || c.status != Status::Active {
            event("deposit_refused", serde_json::json!({"cell": id.to_string(), "token": token, "sender": sender_id}));
            return amount;
        }
        c.vault = U128(c.vault.0 + amount.0);
        self.cells.insert(id, c);
        event("deposited", serde_json::json!({"cell": id.to_string(), "token": token, "amount": amount.0.to_string()}));
        U128(0)
    }

    // ================= 監理調閱（tier-1：只揭露 LEI） =================

    pub fn set_supervisor(&mut self, account: AccountId, enabled: bool) {
        require!(env::predecessor_account_id() == self.owner, "ONLY_OWNER");
        if enabled {
            self.supervisors.insert(account, true);
        } else {
            self.supervisors.remove(&account);
        }
    }

    /// 白名單監理方提出調閱。從這一刻起所有人都看得到「誰、為何（雜湊）、何時」要求揭露這格。
    pub fn request_unseal(&mut self, cell: U64, reason_hash: String) {
        let who = env::predecessor_account_id();
        require!(self.supervisors.get(&who).copied().unwrap_or(false), "NOT_SUPERVISOR");
        require!(self.cells.contains_key(&cell.0), "NO_CELL");
        if let Some(u) = self.unseals.get(&cell.0) {
            // 提出者若已被移出白名單，它的請求不再占住這格
            require!(u.lei.is_none() && !self.supervisors.contains_key(&u.requester), "ALREADY_REQUESTED");
        }
        hex32(&reason_hash, "reason_hash");
        let at = env::block_timestamp();
        self.unseals.insert(cell.0, Unseal { requester: who.clone(), reason_hash: reason_hash.clone(), requested_at: U64(at), objected: false, lei: None });
        event("unseal_requested", serde_json::json!({"cell": cell.0.to_string(), "requester": who, "reason_hash": reason_hash,
              "releasable_at": (at + self.unseal_delay_ns).to_string()}));
    }

    /// 法人可在揭露前提出異議：公開留痕，交由鏈外（法院）處理；不阻止揭露。
    pub fn object_unseal(&mut self, cell: U64) {
        let c = self.cells.get(&cell.0).unwrap_or_else(|| env::panic_str("NO_CELL"));
        require!(env::predecessor_account_id() == c.funder, "ONLY_FUNDER");
        let mut u = self.unseals.get(&cell.0).cloned().unwrap_or_else(|| env::panic_str("NO_REQUEST"));
        require!(u.lei.is_none(), "ALREADY_RELEASED");
        u.objected = true;
        self.unseals.insert(cell.0, u);
        event("unseal_objected", serde_json::json!({"cell": cell.0.to_string()}));
    }

    /// 等待期過後，這格的驗證者揭露 (LEI, salt)；合約檢查 sha256(LEI|salt) == 開格時的承諾。
    /// 驗證者無法揭露一個跟當初承諾不同的 LEI——這就是 GLEIF 討論稿 p.42 說的 reliance record。
    pub fn release_unseal(&mut self, cell: U64, lei: String, salt: String) {
        let c = self.cells.get(&cell.0).cloned().unwrap_or_else(|| env::panic_str("NO_CELL"));
        require!(env::predecessor_account_id() == c.verifier && self.verifiers.contains_key(&c.verifier), "ONLY_CELL_VERIFIER");
        let mut u = self.unseals.get(&cell.0).cloned().unwrap_or_else(|| env::panic_str("NO_REQUEST"));
        require!(u.lei.is_none(), "ALREADY_RELEASED");
        require!(self.supervisors.contains_key(&u.requester), "REQUESTER_REMOVED");
        require!(env::block_timestamp() >= u.requested_at.0 + self.unseal_delay_ns, "TOO_EARLY");
        let digest = hex::encode(env::sha256(format!("{}|{}", lei, salt).as_bytes()));
        require!(digest == c.lei_commit, "COMMIT_MISMATCH");
        u.lei = Some(lei.clone());
        let (requester, objected) = (u.requester.clone(), u.objected);
        self.unseals.insert(cell.0, u);
        event("unsealed", serde_json::json!({"cell": cell.0.to_string(), "lei": lei, "requester": requester, "objected": objected}));
    }

    pub fn get_unseal(&self, cell: U64) -> Option<Unseal> {
        self.unseals.get(&cell.0).cloned()
    }

    // ================= 給商家／任何人看的 =================

    pub fn invoice_paid(&self, cell: U64, invoice_hash: String) -> bool {
        Self::invoice_key(cell.0, &invoice_hash).is_some_and(|k| self.paid_invoices.contains(&k))
    }

    pub fn get_cell(&self, cell: U64) -> Option<Cell> {
        self.cells.get(&cell.0).cloned()
    }

    pub fn cell_of(&self, agent_pk: PublicKey) -> Option<U64> {
        self.key_to_cell.get(&agent_pk).map(|i| U64(*i))
    }

    /// 商家要看的五個謂詞（不含 LEI）。
    pub fn present(&self, cell: U64) -> Option<Value> {
        let c = self.cells.get(&cell.0)?;
        let now = env::block_timestamp();
        Some(serde_json::json!({
            "cell": cell.0.to_string(),
            "chain_valid": self.verifiers.contains_key(&c.verifier),
            "verifier": c.verifier,
            "not_revoked": c.status == Status::Active,
            "not_expired": now <= c.valid_until.0,
            "within_limit": { "used": c.idx, "of": c.n, "unit": c.unit.0.to_string(), "max_links_per_payment": c.max_links },
            "scope": c.scope,
            "amc_said": c.amc_said,
            "lei": self.unseals.get(&cell.0).and_then(|u| u.lei.clone()).unwrap_or_else(|| "sealed".to_string()),
            "lei_commit": c.lei_commit,
            "status": c.status,
            "parent": c.parent.map(|p| p.to_string()),
            "children": c.children.iter().map(|k| k.to_string()).collect::<Vec<_>>(),
            "depth": c.depth,
        }))
    }

    pub fn verifiers(&self) -> Vec<(AccountId, String)> {
        self.verifiers.iter().map(|(a, k)| (a.clone(), k.clone())).collect()
    }

    pub fn stats(&self) -> Stats {
        self.stats.clone()
    }

    /// 償付能力：合約餘額必須涵蓋所有 NEAR 格的金庫總和（任何人都能檢查）。
    pub fn solvency(&self) -> Value {
        let balance = env::account_balance().as_yoctonear();
        let storage = (env::storage_usage() as u128) * env::storage_byte_cost().as_yoctonear();
        serde_json::json!({"vault_total": self.vault_total.to_string(), "balance": balance.to_string(), "storage": storage.to_string(),
                           "solvent": balance >= storage.saturating_add(self.vault_total)})
    }

    /// 讓驗證者確認自己要簽的 bytes 跟合約重建的一致。
    pub fn attestation_preview(&self, args: RegisterArgs, funder: AccountId) -> String {
        attestation_message(&args, &funder, &env::current_account_id())
    }

    pub fn owner(&self) -> AccountId {
        self.owner.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{get_created_receipts, VMContextBuilder};
    use near_sdk::{testing_env, PromiseResult};

    /// 轉帳途中格被撤銷，轉帳又失敗：錢不能卡在已關閉的格，要直接退給法人。
    #[test]
    fn failed_transfer_on_a_revoked_cell_refunds_the_funder() {
        let writ: AccountId = "writ.near".parse().unwrap();
        let funder: AccountId = "funder.near".parse().unwrap();
        let ctx = |results: Vec<PromiseResult>| {
            let c = VMContextBuilder::new()
                .current_account_id(writ.clone())
                .predecessor_account_id(writ.clone())
                .account_balance(NearToken::from_near(10))
                .build();
            testing_env!(c, near_sdk::test_vm_config(), near_sdk::RuntimeFeesConfig::test(), Default::default(), results);
        };
        ctx(vec![]);
        let mut w = Contract::new(writ.clone(), None);
        let pk: PublicKey = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp".parse().unwrap();
        let cell = |status: Status| Cell {
            amc_said: "E".into(), issuer_aid: String::new(), issuer_pk: String::new(), agent_pk: pk.clone(), verifier: writ.clone(), funder: funder.clone(),
            lei_commit: String::new(), ecr_commit: String::new(), scope: vec![], valid_until: U64(0), unit: U128(1), n: 1, idx: 1, unclaimed: U128(0),
            root: 1, parent: None, depth: 0, children: vec![], tree_size: 1, w_cur: String::new(), daily_links: 1, max_links: 1, max_strikes: 3, day: 0, day_used: 1, vault: U128(0), spends: 1, rejects: 0, strikes: 0, status, asset: None,
        };
        w.cells.insert(1, cell(Status::Revoked { by: funder.clone(), evidence: "x".into() }));
        w.cells.insert(2, cell(Status::Active));

        ctx(vec![PromiseResult::Failed]);
        assert!(matches!(w.on_transfer(U64(1), U128(5), "00".repeat(32), funder.clone(), 1, 0, Err(PromiseError::Failed)), Verdict::Rejected { .. }));
        assert_eq!(w.cells.get(&1).unwrap().vault.0, 0, "closed cell must not hold money");
        assert_eq!(w.vault_total, 0);
        let receipts = get_created_receipts();
        assert!(receipts.iter().any(|r| r.receiver_id == funder), "refund goes to the funder");

        ctx(vec![PromiseResult::Failed]);
        assert!(matches!(w.on_transfer(U64(2), U128(5), "00".repeat(32), funder.clone(), 1, 0, Err(PromiseError::Failed)), Verdict::Rejected { .. }));
        assert_eq!(w.cells.get(&2).unwrap().vault.0, 5, "active cell gets the money back");
        assert_eq!(w.vault_total, 5);
    }
}
