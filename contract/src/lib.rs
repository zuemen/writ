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
use near_sdk::store::{IterableMap, LookupMap};
use near_sdk::{
    env, near, require, AccountId, Allowance, BorshStorageKey, Gas, NearToken, PanicOnDefault, Promise,
    PromiseError, PublicKey,
};

/// 連續拒絕幾次就自動刪鑰匙。
pub const TRIPWIRE: u32 = 3;
/// 開格費：留在合約裡付鑰匙與狀態的儲存、以及 agent 交易的 gas（allowance 從合約帳號扣）。
pub const REGISTER_FEE: NearToken = NearToken::from_millinear(100);
/// 給 agent 鑰匙的預設 gas allowance。
pub const DEFAULT_ALLOWANCE: NearToken = NearToken::from_millinear(250);
/// agent 鑰匙能呼叫的方法——只有這一個寫入方法。
pub const AGENT_METHODS: &str = "spend";
/// scope 最多幾個收款人。
pub const MAX_SCOPE: usize = 16;
const NS_PER_DAY: u64 = 86_400_000_000_000;
const GAS_FOR_CALLBACK: Gas = Gas::from_tgas(5);
const GAS_FOR_FT: Gas = Gas::from_tgas(10);

#[derive(BorshStorageKey)]
#[near]
enum StorageKey {
    Verifiers,
    Cells,
    KeyToCell,
    Supervisors,
    Unseals,
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
    pub issuer_pk: String,         // AMC 簽發者（人）當前的 Ed25519 公鑰 hex —— revoke_by_kel 用
    pub agent_pk: PublicKey,       // agent 的鑰匙（= KERI 委派 AID 的簽章鑰）
    pub verifier: AccountId,       // 哪個驗證者擔保了這條鏈
    pub funder: AccountId,         // 法人出資帳號（入金、撤銷、續命）
    pub lei_commit: String,        // sha256(LEI ‖ salt) hex —— LEI 本身不上鏈
    pub scope: Vec<AccountId>,     // 允許的交易對手
    pub valid_until: U64,          // 有效期（Unix ns）
    pub unit: U128,                // 每個鏈節值多少 yoctoNEAR
    pub n: u32,                    // 鏈長（總額度 = n × unit）
    pub idx: u32,                  // 已消耗幾節
    pub w_cur: String,             // 目前的鏈頭 hex（初始 = w0）
    pub daily_links: u32,          // 每日最多可消耗幾節（速率）
    pub day: u64,                  // 速率計數所屬的日
    pub day_used: u32,             // 當日已消耗幾節
    pub vault: U128,               // 這格可動用的金庫餘額
    pub spends: u32,
    pub rejects: u32,              // 累計拒絕
    pub strikes: u32,              // 連續拒絕（成功一筆就歸零）
    pub status: Status,
    /// None = NEAR 原生代幣；Some(token) = NEP-141（例如穩定幣），金庫以該代幣最小單位計
    pub asset: Option<AccountId>,
}

/// spend 的判決。被擋不是錯誤，是正常結果。
#[near(serializers = [json])]
#[derive(Debug, PartialEq)]
pub enum Verdict {
    Paid { cell: U64, amount: U128, idx: u32, remaining_links: u32 },
    Rejected { cell: U64, reason: String, strikes: u32, tripped: bool },
}

/// register 的參數（驗證者簽的就是這些欄位的規範字串，見 attestation_message）。
#[near(serializers = [json])]
#[derive(Clone)]
pub struct RegisterArgs {
    pub amc_said: String,
    pub issuer_pk: String,
    pub agent_pk: PublicKey,
    pub w0: String,
    pub n: u32,
    pub unit: U128,
    pub scope: Vec<AccountId>,
    pub valid_until: U64,
    pub daily_links: u32,
    pub lei_commit: String,
    pub verifier: AccountId,
    /// 驗證者對 attestation_message 的 Ed25519 簽章（hex，64 bytes）
    pub signature: String,
    /// 結算資產：省略 = NEAR；NEP-141 合約帳號 = 以該代幣支付（綁在 attestation 裡）
    #[serde(default)]
    pub asset: Option<AccountId>,
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
pub fn attestation_message(a: &RegisterArgs, funder: &AccountId) -> String {
    let scope: Vec<&str> = a.scope.iter().map(|s| s.as_str()).collect();
    format!(
        "writ:attest:v1\namc={}\nissuer_pk={}\nagent_pk={}\nw0={}\nn={}\nunit={}\nscope={}\nvalid_until={}\ndaily_links={}\nlei_commit={}\nfunder={}\nverifier={}\nasset={}",
        a.amc_said,
        a.issuer_pk,
        String::from(&a.agent_pk),
        a.w0,
        a.n,
        a.unit.0,
        scope.join(","),
        a.valid_until.0,
        a.daily_links,
        a.lei_commit,
        funder,
        a.verifier,
        a.asset.as_ref().map(|t| t.as_str()).unwrap_or("near")
    )
}

#[near]
impl Contract {
    /// unseal_delay_secs：監理方提出調閱到驗證者可以揭露之間的公開等待期（預設 2 分鐘）。
    #[init]
    pub fn new(unseal_delay_secs: Option<u64>) -> Self {
        Self {
            owner: env::predecessor_account_id(),
            verifiers: IterableMap::new(StorageKey::Verifiers),
            cells: LookupMap::new(StorageKey::Cells),
            key_to_cell: LookupMap::new(StorageKey::KeyToCell),
            next_id: 1,
            vault_total: 0,
            stats: Stats::default(),
            supervisors: IterableMap::new(StorageKey::Supervisors),
            unseals: LookupMap::new(StorageKey::Unseals),
            unseal_delay_ns: unseal_delay_secs.unwrap_or(120) * 1_000_000_000,
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
        require!(deposit > REGISTER_FEE, "DEPOSIT_BELOW_FEE");
        require!(args.n > 0 && args.daily_links > 0, "BAD_LIMITS");
        require!(!args.scope.is_empty() && args.scope.len() <= MAX_SCOPE, "BAD_SCOPE");
        require!(args.valid_until.0 > env::block_timestamp(), "ALREADY_EXPIRED");
        require!(!self.key_to_cell.contains_key(&args.agent_pk), "KEY_IN_USE");
        hex32(&args.w0, "w0");
        hex32(&args.issuer_pk, "issuer_pk");
        hex32(&args.lei_commit, "lei_commit");

        // 謂詞 1：鏈有效 —— 白名單驗證者的簽章
        let vpk_hex = self.verifiers.get(&args.verifier).unwrap_or_else(|| env::panic_str("UNKNOWN_VERIFIER"));
        let vpk = hex32(vpk_hex, "verifier_pk");
        let sig: [u8; 64] = hex::decode(&args.signature)
            .ok()
            .and_then(|v| v.as_slice().try_into().ok())
            .unwrap_or_else(|| env::panic_str("BAD_SIGNATURE_ENCODING"));
        let msg = attestation_message(&args, &funder);
        require!(env::ed25519_verify(&sig, msg.as_bytes(), &vpk), "BAD_ATTESTATION");

        // NEAR 格：附帶的 NEAR 扣掉開格費進金庫。代幣格：附帶的 NEAR 全當開格費／gas 準備，金庫用 ft_transfer_call 入金。
        let vault = if args.asset.is_none() { deposit.as_yoctonear() - REGISTER_FEE.as_yoctonear() } else { 0 };
        let id = self.next_id;
        self.next_id += 1;
        let cell = Cell {
            amc_said: args.amc_said.clone(),
            issuer_pk: args.issuer_pk.clone(),
            agent_pk: args.agent_pk.clone(),
            verifier: args.verifier.clone(),
            funder: funder.clone(),
            lei_commit: args.lei_commit.clone(),
            scope: args.scope.clone(),
            valid_until: args.valid_until,
            unit: args.unit,
            n: args.n,
            idx: 0,
            w_cur: args.w0.to_lowercase(),
            daily_links: args.daily_links,
            day: env::block_timestamp() / NS_PER_DAY,
            day_used: 0,
            vault: U128(vault),
            spends: 0,
            rejects: 0,
            strikes: 0,
            status: Status::Active,
            asset: args.asset.clone(),
        };
        self.cells.insert(id, cell);
        self.key_to_cell.insert(args.agent_pk.clone(), id);
        self.vault_total += vault;
        self.stats.cells += 1;
        event(
            "registered",
            serde_json::json!({"cell": id.to_string(), "amc_said": args.amc_said, "agent_pk": String::from(&args.agent_pk),
                               "verifier": args.verifier, "vault": vault.to_string(), "n": args.n, "unit": args.unit.0.to_string()}),
        );
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
    pub fn spend(&mut self, preimage: String, j: u32, to: AccountId) -> Verdict {
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

        // 依序檢查：過期 → 對手 → 額度（鏈長）→ 雜湊鏈 → 速率 → 金庫
        let reason: Option<&str> = if now > c.valid_until.0 {
            Some("EXPIRED")
        } else if !c.scope.iter().any(|s| *s == to) {
            Some("SCOPE")
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
            c.rejects += 1;
            c.strikes += 1;
            self.stats.rejected += 1;
            let tripped = c.strikes >= TRIPWIRE;
            event("rejected", serde_json::json!({"cell": id.to_string(), "reason": r, "to": to, "j": j, "strikes": c.strikes}));
            if tripped {
                c.status = Status::Tripped;
                self.stats.tripped += 1;
                self.key_to_cell.remove(&pk);
                event("tripped", serde_json::json!({"cell": id.to_string(), "agent_pk": String::from(&pk)}));
                Promise::new(env::current_account_id()).delete_key(pk).detach();
            }
            let strikes = c.strikes;
            self.cells.insert(id, c);
            return Verdict::Rejected { cell: U64(id), reason: r.to_string(), strikes, tripped };
        }

        // 通過：推進鏈頭、扣額度、扣金庫，然後轉帳
        let amount = (j as u128) * c.unit.0;
        c.w_cur = preimage.to_lowercase();
        c.idx += j;
        c.day_used += j;
        c.vault = U128(c.vault.0 - amount);
        c.spends += 1;
        c.strikes = 0;
        if c.asset.is_none() {
            self.vault_total -= amount; // vault_total 只追蹤 NEAR 金庫
        }
        self.stats.paid += 1;
        if c.asset.is_none() {
            self.stats.paid_yocto = U128(self.stats.paid_yocto.0 + amount);
        }
        let idx = c.idx;
        let remaining = c.n - c.idx;
        let asset = c.asset.clone();
        self.cells.insert(id, c);
        event("paid", serde_json::json!({"cell": id.to_string(), "to": to, "amount": amount.to_string(), "idx": idx}));

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
        payout
            .then(Self::ext(env::current_account_id()).with_static_gas(GAS_FOR_CALLBACK).on_transfer(U64(id), U128(amount)))
            .detach();
        Verdict::Paid { cell: U64(id), amount: U128(amount), idx, remaining_links: remaining }
    }

    #[private]
    pub fn on_transfer(&mut self, cell: U64, amount: U128, #[callback_result] r: Result<(), PromiseError>) -> bool {
        if r.is_ok() {
            return true;
        }
        // 轉帳失敗（例如收款帳號不存在）：錢退回金庫；鏈節已消耗不退（防重放）
        if let Some(mut c) = self.cells.get(&cell.0).cloned() {
            c.vault = U128(c.vault.0 + amount.0);
            if c.asset.is_none() {
                self.vault_total += amount.0;
            }
            self.cells.insert(cell.0, c);
        }
        event("refunded", serde_json::json!({"cell": cell.0.to_string(), "amount": amount.0.to_string()}));
        false
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
        require!(who == c.funder || who == c.verifier || who == self.owner, "NOT_AUTHORIZED");
        self.close(cell.0, c, Status::Revoked { by: who, evidence });
    }

    /// 無須信任的撤銷：任何人提交 AMC 簽發者 KEL 上錨定撤銷的 ixn 事件（原始 bytes）＋簽章，
    /// 合約驗簽並確認 seal = {i: 這格的 AMC SAID, s: "1"}（簡單 TEL：sn 0 = iss，sn 1 只能是 rev）。
    /// 限制：簽發者若輪替金鑰，issuer_pk 需由驗證者重新 attest（README 揭露）。
    pub fn revoke_by_kel(&mut self, cell: U64, ixn: Base64VecU8, signature: Base64VecU8) {
        let c = self.cells.get(&cell.0).cloned().unwrap_or_else(|| env::panic_str("NO_CELL"));
        let sig: [u8; 64] = signature.0.as_slice().try_into().unwrap_or_else(|_| env::panic_str("BAD_SIG_LEN"));
        let pk = hex32(&c.issuer_pk, "issuer_pk");
        require!(env::ed25519_verify(&sig, &ixn.0, &pk), "BAD_KEL_SIGNATURE");
        let ev: Value = serde_json::from_slice(&ixn.0).unwrap_or_else(|_| env::panic_str("BAD_IXN_JSON"));
        require!(ev["t"] == "ixn", "NOT_IXN");
        let seals = ev["a"].as_array().unwrap_or_else(|| env::panic_str("NO_SEALS"));
        let rev = seals
            .iter()
            .find(|s| s["i"] == c.amc_said.as_str() && s["s"] == "1")
            .unwrap_or_else(|| env::panic_str("NO_REVOCATION_SEAL"));
        let rev_said = rev["d"].as_str().unwrap_or("").to_string();
        let who = env::predecessor_account_id();
        self.close(cell.0, c, Status::Revoked { by: who, evidence: rev_said });
    }

    /// 關格：刪鑰匙、剩餘金庫退回法人。
    fn close(&mut self, id: u64, mut c: Cell, status: Status) {
        require!(c.status == Status::Active || matches!(c.status, Status::Tripped), "ALREADY_CLOSED");
        let refund = c.vault.0;
        let was_active = c.status == Status::Active;
        c.vault = U128(0);
        c.status = status.clone();
        let asset = c.asset.clone();
        if asset.is_none() {
            self.vault_total -= refund;
        }
        self.stats.revoked += 1;
        self.key_to_cell.remove(&c.agent_pk);
        let pk = c.agent_pk.clone();
        let funder = c.funder.clone();
        self.cells.insert(id, c);
        event("revoked", serde_json::json!({"cell": id.to_string(), "status": status, "refund": refund.to_string()}));
        if was_active {
            // tripped 的格鑰匙已刪過；再刪會失敗
            Promise::new(env::current_account_id()).delete_key(pk).detach();
        }
        if refund > 0 {
            match asset {
                None => Promise::new(funder).transfer(NearToken::from_yoctonear(refund)).detach(),
                Some(token) => Promise::new(token)
                    .function_call(
                        "ft_transfer".to_string(),
                        serde_json::to_vec(&serde_json::json!({"receiver_id": funder, "amount": refund.to_string(), "memo": format!("writ cell {} closed", id)})).unwrap(),
                        NearToken::from_yoctonear(1),
                        GAS_FOR_FT,
                    )
                    .detach(),
            }
        }
    }

    /// 續命：gas allowance 用完時由法人或驗證者重掛同一把鑰匙（同 batch 先刪後加）。
    pub fn refresh_key(&mut self, cell: U64) {
        let c = self.cells.get(&cell.0).cloned().unwrap_or_else(|| env::panic_str("NO_CELL"));
        let who = env::predecessor_account_id();
        require!(who == c.funder || who == c.verifier, "NOT_AUTHORIZED");
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
        require!(!self.unseals.contains_key(&cell.0), "ALREADY_REQUESTED");
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
        require!(env::predecessor_account_id() == c.verifier, "ONLY_CELL_VERIFIER");
        let mut u = self.unseals.get(&cell.0).cloned().unwrap_or_else(|| env::panic_str("NO_REQUEST"));
        require!(u.lei.is_none(), "ALREADY_RELEASED");
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
            "chain_valid": true,
            "verifier": c.verifier,
            "not_revoked": c.status == Status::Active,
            "not_expired": now <= c.valid_until.0,
            "within_limit": { "used": c.idx, "of": c.n, "unit": c.unit.0.to_string() },
            "scope": c.scope,
            "amc_said": c.amc_said,
            "lei": self.unseals.get(&cell.0).and_then(|u| u.lei.clone()).unwrap_or_else(|| "sealed".to_string()),
            "lei_commit": c.lei_commit,
            "status": c.status,
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
        serde_json::json!({"vault_total": self.vault_total.to_string(), "balance": balance.to_string(),
                           "solvent": balance >= self.vault_total})
    }

    /// 讓驗證者確認自己要簽的 bytes 跟合約重建的一致。
    pub fn attestation_preview(&self, args: RegisterArgs, funder: AccountId) -> String {
        attestation_message(&args, &funder)
    }

    pub fn owner(&self) -> AccountId {
        self.owner.clone()
    }
}
