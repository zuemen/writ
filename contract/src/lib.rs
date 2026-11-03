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
const CHILD_STORAGE: u128 = 20_000_000_000_000_000_000_000;
/// 一棵樹最多幾層、幾格：撤銷要在一筆交易內刪掉整棵樹，所以大小要有上限。
pub const MAX_DEPTH: u32 = 3;
pub const MAX_TREE: u32 = 16;

fn hire_fee(n: u32) -> u128 {
    CHILD_ALLOWANCE.as_yoctonear() + CHILD_STORAGE + (n as u128) * STORAGE_PER_INVOICE
}

fn register_fee(n: u32) -> u128 {
    REGISTER_FEE.as_yoctonear() + (n as u128) * STORAGE_PER_INVOICE
}

/// 這張單要付幾期：max(1, ceil((due_at - now) / 30 天))。不滿一期算一期；已過到期日也算一期。
fn fee_periods(due_at: u64, now: u64) -> u128 {
    let left = due_at.saturating_sub(now) as u128;
    let period = NS_PER_PERIOD as u128;
    ((left + period - 1) / period).max(1)
}

/// 保證費 = 金額 × 每期費率 × 期數 / 10000。
fn guarantee_fee(amount: u128, premium_bps: u32, periods: u128) -> u128 {
    amount * (premium_bps as u128) * periods / 10_000
}
/// agent 鑰匙能呼叫的方法——只有這一個寫入方法。
pub const AGENT_METHODS: &str = "spend,hire,dismiss,open_credit,settle";
/// scope 最多幾個收款人。
pub const MAX_SCOPE: usize = 16;
const NS_PER_DAY: u64 = 86_400_000_000_000;
/// 保證費按天期計價：premium_bps 是每一期（30 天）的費率。
pub const NS_PER_PERIOD: u64 = 30 * NS_PER_DAY;
const GAS_FOR_CALLBACK: Gas = Gas::from_tgas(25); // 要付得起撤銷後的 ft_transfer（10）＋ on_refund（5）
const GAS_FOR_REFUND_CB: Gas = Gas::from_tgas(5);
const MAX_EVIDENCE: usize = 128;
/// 一筆信用紀錄的儲存（單據約 430 bytes＋單一賣方曝險紀錄約 250 bytes），開單時從根格金庫收，不退。
const CREDIT_STORAGE: u128 = 7_000_000_000_000_000_000_000;
const GAS_FOR_FT: Gas = Gas::from_tgas(10);
/// 賣方規則的儲存押金（1000 bytes，夠放 MAX_POLICY_GUARANTORS 個帳號）。第一次設定時收，刪除規則不退。
pub const SELLER_POLICY_STORAGE: u128 = 10_000_000_000_000_000_000_000;
pub const MAX_POLICY_GUARANTORS: usize = 8;
/// 保證人帳簿最多記幾個賣方。滿了就換掉曝險最小的，所以 top_sellers 只是前幾大，不是完整清單。
pub const MAX_BOOK_SELLERS: usize = 8;
const TOP_SELLERS: usize = 5;

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
    Credits,
    Terms,
    Stakes,
    Claimable,
    Entities,
    UsedKeys,
    PendingInvoices,
    Policies,
    SellerExposure,
    TokenTotal,
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
    pub near_reserve: U128,        // 代幣樹的根格才有：開格時留下的 NEAR，付單據儲存與雇用費
}

/// spend 的判決。被擋不是錯誤，是正常結果。
#[near(serializers = [json])]
#[derive(Debug, PartialEq)]
pub enum Verdict {
    Paid { cell: U64, amount: U128, idx: u32, remaining_links: u32 },
    Hired { cell: U64, child: U64, links: u32, remaining_links: u32 },
    CreditOpened { cell: U64, credit: U64, amount: U128, due_at: U64 },
    CreditSettled { credit: U64, amount: U128 },
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
    /// 信用條款：省略 = 這格不能賒帳
    #[serde(default)]
    pub credit: Option<CreditArgs>,
}

/// 保證費誰付。Buyer：賣方接受時從根格金庫收；Seller：賣方收款時從貨款扣，取消的單不收。
#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FeePayer {
    Buyer,
    Seller,
}

/// 信用條款：驗證者（同時是具名保證人）簽進 attestation，開格後不能改。
#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct CreditArgs {
    pub limit: U128,            // 未結清總額上限
    pub bond_bps: u32,          // 保證金比例（萬分比），賣方接受時逐筆鎖定
    pub premium_bps: u32,       // 保證費（每 30 天的萬分比，不滿一期算一期），賣方接受時由公司金庫付給保證人，不退
    pub min_tenor: U64,         // 到期日距今最短（秒），防注入把到期設成幾秒後
    pub max_tenor: U64,
    pub terms_hash: String,     // 公司簽過的條款雜湊（準據法、同意揭露等）
    pub terms_sig: String,      // LE 對 (合約, AMC, terms_hash, LEI) 的簽章 hex；揭露時才驗，防栽贓
    pub entity_tag: String,     // 保證人給這家公司的固定假名，跨格累積紀錄
    pub arbiter: AccountId,     // 爭議仲裁人，不得是保證人
    pub fee_payer: FeePayer,    // 保證費誰付，簽進 attestation
    pub seller_cap_bps: u32,    // 單一賣方的曝險上限（質押的萬分比）；0 = 不限。防串通賣方把質押一次領走
    pub asset: Option<AccountId>, // 信用的計價資產，簽進 attestation，必須等於這格的資產；None = NEAR
}

/// 一棵樹的信用狀態（只存在根格）。
#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct CreditTerms {
    pub args: CreditArgs,
    pub guarantor: AccountId,
    pub terms_ecr_commit: String,
    pub outstanding: U128,      // 未結清總額
    pub bond_locked: U128,      // 已鎖定的保證金（在根格金庫內）
    pub open_debts: u32,        // 欠保證人的筆數；大於 0 就不能再賒
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub enum CreditStatus {
    Open,       // agent 開單，賣方還沒接受
    Accepted,   // 賣方接受，保證金與保證人曝險已鎖
    Delivered,  // 賣方已交貨，到期沒付才有違約
    Disputed,   // 公司附全額押金提出爭議
    Settled,    // 已付
    Cancelled,  // 逾時未接受，或仲裁判賣方敗
    Defaulted,  // 已賠給賣方，欠保證人（或已由保證金賠完）
    Reimbursed, // 公司已還保證人，維持封存
    Enforced,   // 追償期滿，整棵樹已斷電，可揭露
}

#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct Credit {
    pub id: U64,
    pub cell: U64,
    pub root: U64,
    pub seller: AccountId,
    pub amount: U128,           // 目前金額；用量單交貨時可能縮小
    pub original_amount: U128,  // 開單時的上限
    pub asset: Option<AccountId>, // 金額的單位；None = NEAR
    pub invoice_hash: String,
    pub opened_at: U64,
    pub due_at: U64,
    pub status: CreditStatus,
    pub bond_locked: U128,
    pub exposure: U128,         // 保證人為這筆承擔的金額
    pub fee: U128,              // 賣方接受時定下的保證費：買方付的已收，賣方付的等收款時才扣
    pub fee_periods: u32,       // 接受時算出的期數；用量單縮小時賣方付的費用照這個重算
    pub delivery_hash: Option<String>,
    pub delivered_at: U64,
    pub dispute_escrow: U128,
    pub debt: U128,             // 保證人實際賠付、公司還沒還的金額
    pub recourse_until: U64,
}

/// 保證人的質押。
#[near(serializers = [borsh, json])]
#[derive(Clone, Default)]
pub struct Stake {
    pub amount: U128,
    pub exposure: U128,
    pub unstake_at: U64, // 0 = 沒有申請提領
    pub earned: U128,    // 累計收到的保證費
    pub claims_paid: U128, // 累計用質押賠給賣方的金額
    pub recovered: U128,   // 累計從公司追回的金額
    pub sellers: Vec<AccountId>, // 曝險來源的賣方（有上限，見 MAX_BOOK_SELLERS）
}

/// 賣方的自動授信規則：訂單符合就出貨，不符合就回傳原因。
#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct SellerPolicy {
    pub max_amount: U128,
    pub max_tenor_secs: U64,
    pub min_bond_bps: u32,
    pub max_defaults: u32,            // 公司假名最多幾筆違約紀錄
    pub guarantors: Vec<AccountId>,   // 核准的保證人；空 = 都接受
}

/// check_order 的回傳：ok = 現在呼叫 accept_credit 會成功。
#[near(serializers = [json])]
pub struct OrderCheck {
    pub ok: bool,
    pub reasons: Vec<String>,
    pub order: Value,
}

/// 接受一張單要動的錢，以及錢不夠或曝險超限的理由。
struct Quote {
    fee: u128,
    periods: u128,
    charge: u128, // 接受當下從根格金庫收的費用：買方付 = fee，賣方付 = 0
    bond: u128,
    exposure: u128,
    failures: Vec<String>,
}

/// 假名的付款紀錄，風險卡顯示。
#[near(serializers = [borsh, json])]
#[derive(Clone, Default)]
pub struct EntityRecord {
    pub settled: u32,
    pub settled_amount: U128,
    pub defaults: u32,
    pub first_seen: U64,
}

/// 時間窗（秒）。示範時設短，正式部署用預設值。
#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct Windows {
    pub accept_ttl: U64,
    pub inspect: U64,       // 交貨後至少這麼久才能請求違約，公司有時間提出爭議
    pub grace: U64,
    pub recourse: U64,
    pub dispute_timeout: U64,
    pub unstake_delay: U64,
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

#[near(contract_state, contract_metadata(version = "0.2.0", link = "https://github.com/zuemen/writ", standard(standard = "nep297", version = "1.0.0")))]
#[derive(PanicOnDefault)]
pub struct Contract {
    owner: AccountId,
    verifiers: IterableMap<AccountId, String>, // account → Ed25519 公鑰 hex
    cells: LookupMap<u64, Cell>,
    key_to_cell: LookupMap<PublicKey, u64>,
    next_id: u64,
    vault_total: u128, // 所有 NEAR 帳目的總和；合約餘額必須 >= 這個數。代幣另記在 token_total
    stats: Stats,
    supervisors: IterableMap<AccountId, bool>,
    unseals: LookupMap<u64, Unseal>,
    unseal_delay_ns: u64,
    used_amcs: LookupMap<String, u64>, // 一張 AMC 只能開一格；撤銷後不能用同一張 attestation 復活
    paid_invoices: LookupSet<Vec<u8>>, // cell id ‖ 發票雜湊：同一張發票不能付兩次
    pending_invoices: LookupSet<Vec<u8>>, // 發票已占用但賣方沒拿到錢：開單到付清之間，或仲裁判公司勝之後
    used_keys: LookupSet<PublicKey>, // 鑰匙一生只用一次：解僱、撤銷、tripwire 之後都不能再被雇用或開格
    credits: LookupMap<u64, Credit>,
    terms: LookupMap<u64, CreditTerms>,
    stakes: LookupMap<(AccountId, Option<AccountId>), Stake>, // (保證人, 資產)：不同資產的質押互不支援
    claimable: LookupMap<(AccountId, Option<AccountId>), u128>, // (帳號, 資產)；先記帳後提領：賣方自己來領
    entities: LookupMap<String, EntityRecord>,
    next_credit: u64,
    windows: Windows,
    policies: LookupMap<AccountId, SellerPolicy>,
    seller_exposure: LookupMap<(AccountId, Option<AccountId>, AccountId), u128>, // (保證人, 資產, 賣方) → 曝險；歸零就刪
    token_total: LookupMap<AccountId, u128>, // 每種代幣的帳目總和；合約在該代幣的餘額必須 >= 這個數
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
        "writ:attest:v6\ncontract={}\namc={}\nissuer_aid={}\nissuer_pk={}\nagent_pk={}\nw0={}\nn={}\nunit={}\nscope={}\nvalid_until={}\ndaily_links={}\nmax_links={}\nmax_strikes={}\nlei_commit={}\necr_commit={}\nfunder={}\nverifier={}\nattested_at={}\nasset={}\ncredit={}",
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
        a.asset.as_ref().map(|t| t.as_str()).unwrap_or("near"),
        a.credit.as_ref().map(|c| format!("{},{},{},{},{},{},{},{},{},{:?},{},{}", c.limit.0, c.bond_bps, c.premium_bps, c.min_tenor.0, c.max_tenor.0, c.terms_hash, c.terms_sig, c.entity_tag, c.arbiter, c.fee_payer, c.seller_cap_bps, c.asset.as_ref().map(|t| t.as_str()).unwrap_or("near"))).unwrap_or_else(|| "none".to_string())
    )
}

#[near]
impl Contract {
    /// owner：維護驗證者與監理方白名單的帳號，應該是另一個帳號，這樣合約帳號才能刪掉 full-access key。
    /// 部署、初始化、刪 full-access key 放在同一個 batch（make testnet 就是這樣做），#[private] 防搶先初始化。
    /// unseal_delay_secs：監理方提出調閱到驗證者可以揭露之間的公開等待期（預設 2 分鐘）。
    #[init]
    #[private]
    pub fn new(owner: AccountId, unseal_delay_secs: Option<u64>, windows: Option<Windows>) -> Self {
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
            pending_invoices: LookupSet::new(StorageKey::PendingInvoices),
            used_keys: LookupSet::new(StorageKey::UsedKeys),
            credits: LookupMap::new(StorageKey::Credits),
            terms: LookupMap::new(StorageKey::Terms),
            stakes: LookupMap::new(StorageKey::Stakes),
            claimable: LookupMap::new(StorageKey::Claimable),
            entities: LookupMap::new(StorageKey::Entities),
            next_credit: 1,
            windows: windows.unwrap_or(Windows {
                accept_ttl: U64(86_400),
                inspect: U64(3 * 86_400),
                grace: U64(3 * 86_400),
                recourse: U64(14 * 86_400),
                dispute_timeout: U64(14 * 86_400),
                unstake_delay: U64(30 * 86_400),
            }),
            policies: LookupMap::new(StorageKey::Policies),
            seller_exposure: LookupMap::new(StorageKey::SellerExposure),
            token_total: LookupMap::new(StorageKey::TokenTotal),
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
        hex32(&args.w0, "w0");
        hex32(&args.issuer_pk, "issuer_pk");
        hex32(&args.lei_commit, "lei_commit");
        hex32(&args.ecr_commit, "ecr_commit");
        require!(!self.used_amcs.contains_key(&args.amc_said), "AMC_ALREADY_USED");
        require!(!self.used_keys.contains(&args.agent_pk), "KEY_IN_USE");

        // 謂詞 1：鏈有效 —— 白名單驗證者的簽章
        let vpk_hex = self.verifiers.get(&args.verifier).unwrap_or_else(|| env::panic_str("UNKNOWN_VERIFIER"));
        let vpk = hex32(vpk_hex, "verifier_pk");
        let sig: [u8; 64] = hex::decode(&args.signature)
            .ok()
            .and_then(|v| v.as_slice().try_into().ok())
            .unwrap_or_else(|| env::panic_str("BAD_SIGNATURE_ENCODING"));
        let msg = attestation_message(&args, &funder, &env::current_account_id());
        require!(env::ed25519_verify(&sig, msg.as_bytes(), &vpk), "BAD_ATTESTATION");

        // NEAR 格：附帶的 NEAR 扣掉開格費進金庫。代幣格：金庫用 ft_transfer_call 入金；
        // 有信用條款的代幣格，多的 NEAR 留作準備（付單據儲存與雇用費），沒有的退回。
        let vault = if args.asset.is_none() { deposit.as_yoctonear() - fee } else { 0 };
        let reserve = if args.asset.is_some() && args.credit.is_some() { deposit.as_yoctonear() - fee } else { 0 };
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
            near_reserve: U128(reserve),
        };
        self.cells.insert(id, cell);
        self.key_to_cell.insert(args.agent_pk.clone(), id);
        self.used_keys.insert(args.agent_pk.clone());
        self.used_amcs.insert(args.amc_said.clone(), id);
        if let Some(cr) = &args.credit {
            require!(cr.asset == args.asset, "CREDIT_ASSET_MISMATCH");
            require!(cr.arbiter != args.verifier && cr.arbiter != funder, "ARBITER_NOT_INDEPENDENT");
            require!(cr.bond_bps <= 10_000 && cr.premium_bps <= 2_000 && cr.seller_cap_bps <= 10_000 && cr.min_tenor.0 <= cr.max_tenor.0, "BAD_CREDIT_TERMS");
            hex32(&cr.terms_hash, "terms_hash");
            require!(hex::decode(&cr.terms_sig).map(|v| v.len() == 64).unwrap_or(false), "BAD_TERMS_SIG");
            self.terms.insert(id, CreditTerms {
                args: cr.clone(),
                guarantor: args.verifier.clone(),
                terms_ecr_commit: args.ecr_commit.clone(),
                outstanding: U128(0),
                bond_locked: U128(0),
                open_debts: 0,
            });
            let key = Self::entity_key(&args.verifier, &cr.entity_tag);
            if !self.entities.contains_key(&key) {
                self.entities.insert(key, EntityRecord { first_seen: U64(env::block_timestamp()), ..Default::default() });
            }
            // 驗證者簽過這種代幣才開質押帳：ft_on_transfer 的呼叫者誰都能假冒代幣，假代幣不能灌儲存
            let sk = (args.verifier.clone(), args.asset.clone());
            if args.asset.is_some() && !self.stakes.contains_key(&sk) {
                self.stakes.insert(sk, Stake::default());
            }
        }
        self.vault_total += vault + reserve;
        self.stats.cells += 1;
        event(
            "registered",
            serde_json::json!({"cell": id.to_string(), "amc_said": args.amc_said, "agent_pk": String::from(&args.agent_pk),
                               "verifier": args.verifier, "vault": vault.to_string(), "near_reserve": reserve.to_string(), "n": args.n, "unit": args.unit.0.to_string()}),
        );
        if args.asset.is_some() && args.credit.is_none() && deposit.as_yoctonear() > fee {
            // 沒有信用條款的代幣格用不到 NEAR，超過開格費的退回
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
        let d = env::attached_deposit().as_yoctonear();
        if c.asset.is_some() {
            // 代幣樹的根格：附的 NEAR 補進準備；代幣本身走 ft_transfer_call
            require!(c.parent.is_none() && self.terms.contains_key(&cell.0), "TOKEN_CELL_USE_FT_TRANSFER_CALL");
            c.near_reserve = U128(c.near_reserve.0 + d);
        } else {
            c.vault = U128(c.vault.0 + d);
        }
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

        // 發票在整棵樹只能付一次，不是每格一次
        let invoice_key = Self::invoice_key(c.root, &invoice_hash);
        let free = self.free_vault(id, &c);
        // 依序檢查：過期 → 上層停權 → 對手 → 發票 → 單筆上限 → 額度（鏈長）→ 雜湊鏈 → 速率 → 金庫
        let reason: Option<&str> = if now > c.valid_until.0 {
            Some("EXPIRED")
        } else if self.suspended(&c) {
            Some("SUSPENDED")
        } else if self.owes_guarantor(c.root) {
            Some("FROZEN")
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
        } else if free < (j as u128) * c.unit.0 {
            Some("FUNDS")
        } else {
            None
        };

        if let Some(r) = reason {
            event("rejected", serde_json::json!({"cell": id.to_string(), "reason": r, "to": to, "j": j, "strikes": c.strikes + u32::from(r != "FROZEN")}));
            return PromiseOrValue::Value(self.reject(id, c, pk, r));
        }

        // 通過：推進鏈頭、扣額度、扣金庫，然後轉帳
        let amount = (j as u128) * c.unit.0;
        // 錢真的到了才算付款；轉帳途中發票已占用，但還不是「已付」
        let ik = invoice_key.unwrap();
        self.paid_invoices.insert(ik.clone());
        self.pending_invoices.insert(ik);
        c.w_cur = preimage.to_lowercase();
        c.idx += j;
        c.day_used += j;
        c.vault = U128(c.vault.0 - amount);
        c.spends += 1;
        c.strikes = 0;
        let idx = c.idx;
        let remaining = c.n - c.idx;
        let asset = c.asset.clone();
        self.cells.insert(id, c);
        self.sub_total(&asset, amount);

        // 跨 receipt 沒有原子回滾：先扣（預留），callback 失敗再退回金庫
        // 代幣格：合約自己發 receipt 附 1 yocto 呼叫 ft_transfer（agent 的 FC key 不能附存款，合約可以）
        let payout = Self::send(&asset, to.clone(), amount, format!("writ cell {}", id));
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
        let token_tree = c.asset.is_some();
        let funded = if token_tree {
            // 代幣樹：預算是代幣，雇用費是 NEAR，從根格的準備扣
            let reserve = root_cell.as_ref().map(|r| r.near_reserve.0).unwrap_or(c.near_reserve.0);
            self.free_vault(id, &c) >= amount && reserve >= fee
        } else {
            match &root_cell {
                None => self.free_vault(id, &c) >= amount.saturating_add(fee),
                Some(r) => c.vault.0 >= amount && self.free_vault(c.root, r) >= fee,
            }
        };
        let w0_ok = hex::decode(&child.w0).map(|v| v.len() == 32).unwrap_or(false);
        let reason: Option<&str> = if now > c.valid_until.0 {
            Some("EXPIRED")
        } else if self.suspended(&c) {
            Some("SUSPENDED")
        } else if self.owes_guarantor(c.root) {
            Some("FROZEN")
        } else if token_tree && !self.terms.contains_key(&c.root) {
            Some("HIRE_TOKEN")
        } else if child.scope.is_empty() || child.scope.len() > MAX_SCOPE || !child.scope.iter().all(|s| c.scope.contains(s)) {
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
        } else if self.used_keys.contains(&child.agent_pk) {
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
            event("rejected", serde_json::json!({"cell": id.to_string(), "reason": r, "j": j, "strikes": c.strikes + u32::from(r != "FROZEN")}));
            return self.reject(id, c, pk, r);
        }

        c.w_cur = preimage.to_lowercase();
        c.idx += j;
        c.day_used += j;
        c.strikes = 0;
        c.vault = U128(c.vault.0 - amount - if root_cell.is_none() && !token_tree { fee } else { 0 });
        if root_cell.is_none() && token_tree {
            c.near_reserve = U128(c.near_reserve.0 - fee);
        }
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
            asset: c.asset.clone(),
            root: c.root,
            parent: Some(id),
            depth: c.depth + 1,
            children: vec![],
            tree_size: 0,
            near_reserve: U128(0),
        };
        self.cells.insert(child_id, cell);
        self.key_to_cell.insert(child.agent_pk.clone(), child_id);
        self.used_keys.insert(child.agent_pk.clone());
        self.stats.cells += 1;
        let remaining = c.n - c.idx;
        match root_cell {
            None => {
                c.tree_size += 1;
                self.cells.insert(id, c);
            }
            Some(mut r) => {
                r.tree_size += 1;
                if token_tree {
                    r.near_reserve = U128(r.near_reserve.0 - fee);
                } else {
                    r.vault = U128(r.vault.0 - fee);
                }
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

    /// 這格往上任何一層被 tripwire 停權或已關閉，它就不能動錢（公司 reinstate 上層後恢復）。
    fn suspended(&self, c: &Cell) -> bool {
        let mut cur = c.parent;
        while let Some(p) = cur {
            match self.cells.get(&p) {
                Some(up) if up.status == Status::Active => cur = up.parent,
                _ => return true,
            }
        }
        false
    }

    fn owes_guarantor(&self, root: u64) -> bool {
        self.terms.get(&root).map(|t| t.open_debts > 0).unwrap_or(false)
    }

    /// 這格能動用的錢：根格要扣掉已鎖給賣方的保證金。
    fn free_vault(&self, id: u64, c: &Cell) -> u128 {
        if c.root == id {
            let locked = self.terms.get(&id).map(|t| t.bond_locked.0).unwrap_or(0);
            c.vault.0.saturating_sub(locked)
        } else {
            c.vault.0
        }
    }

    /// 政策拒絕：計 strike，連續太多次刪鑰匙。回傳 Rejected，交易本身成功。
    fn reject(&mut self, id: u64, mut c: Cell, pk: PublicKey, r: &str) -> Verdict {
        c.rejects += 1;
        // 凍結是公司的債，不是 agent 被騙：不計 strike，還清後 agent 不必逐格復職
        if r != "FROZEN" {
            c.strikes += 1;
        }
        self.stats.rejected += 1;
        let tripped = r != "FROZEN" && c.max_strikes > 0 && c.strikes >= c.max_strikes;
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
            if let Some(k) = Self::invoice_key(c.root, &invoice_hash) {
                self.pending_invoices.remove(&k);
            }
            event("paid", serde_json::json!({"cell": cell.0.to_string(), "to": to, "amount": amount.0.to_string(), "idx": idx, "invoice": invoice_hash}));
            return Verdict::Paid { cell, amount, idx, remaining_links: remaining };
        }
        // 沒付成：這張發票還能再付；鏈節已消耗不退（防重放）；錢退回金庫
        if let Some(k) = Self::invoice_key(c.root, &invoice_hash) {
            self.paid_invoices.remove(&k);
            self.pending_invoices.remove(&k);
        }
        c.spends = c.spends.saturating_sub(1);
        let strikes = c.strikes;
        let mut retained = false;
        if matches!(c.status, Status::Revoked { .. }) {
            // 轉帳途中格已被撤銷：關閉的格不能再領錢，直接退給法人
            let (asset, funder, root_id) = (c.asset.clone(), c.funder.clone(), c.root);
            self.cells.insert(cell.0, c);
            let retain = self.terms.get(&root_id).map(|t| t.outstanding.0 > 0 || t.open_debts > 0).unwrap_or(false);
            if retain {
                // 公司還欠錢：這筆錢和其他金庫一樣留在根格，先付欠款
                let mut r = self.cells.get(&root_id).cloned().unwrap();
                r.vault = U128(r.vault.0 + amount.0);
                self.cells.insert(root_id, r);
                self.add_total(&asset, amount.0);
                retained = true;
            } else {
                self.pay_out(cell.0, &asset, funder, amount.0, format!("writ cell {} closed", cell.0));
            }
        } else {
            c.vault = U128(c.vault.0 + amount.0);
            let asset = c.asset.clone();
            self.cells.insert(cell.0, c);
            self.add_total(&asset, amount.0);
        }
        event(if retained { "retained" } else { "refunded" }, serde_json::json!({"cell": cell.0.to_string(), "amount": amount.0.to_string()}));
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
        let mut reserve = 0u128;
        let mut keys: Vec<PublicKey> = vec![];
        // 公司還欠錢時金庫留在根格，事件要照實說沒有退款
        let holds = self.terms.get(&c.root).map(|t| t.outstanding.0 > 0 || t.open_debts > 0).unwrap_or(false);
        let mut stack: Vec<(u64, Cell, Status)> = vec![(id, c, status)];
        while let Some((cid, mut cell, st)) = stack.pop() {
            if cell.status == Status::Active {
                keys.push(cell.agent_pk.clone()); // tripped 的格鑰匙已刪過；再刪會失敗
            }
            let part = cell.vault.0;
            refund += part;
            cell.vault = U128(0);
            // NEAR 準備不是賠款的資產，也不會再開新單：關格就還給法人
            reserve += cell.near_reserve.0;
            cell.near_reserve = U128(0);
            cell.status = st.clone();
            self.key_to_cell.remove(&cell.agent_pk);
            self.stats.revoked += 1;
            event("revoked", serde_json::json!({"cell": cid.to_string(), "status": st, "refund": if holds { 0 } else { part }.to_string(), "retained": if holds { part } else { 0 }.to_string()}));
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
        // 整棵樹還有未結清的信用：金庫留在根格付欠款，靠撤銷賴不了帳；結清後才可領回
        let root_id = self.cells.get(&id).map(|c| c.root).unwrap_or(id);
        let keep = refund > 0 && self.terms.get(&root_id).map(|t| t.outstanding.0 > 0 || t.open_debts > 0).unwrap_or(false);
        if keep {
            if let Some(mut r) = self.cells.get(&root_id).cloned() {
                r.vault = U128(r.vault.0 + refund);
                self.cells.insert(root_id, r);
            }
            refund = 0;
        } else {
            self.sub_total(&asset, refund);
        }
        self.credit_seller(&funder, &None, reserve);
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
        Self::send(asset, to, amount, memo)
            .then(Self::ext(env::current_account_id()).with_static_gas(GAS_FOR_REFUND_CB).on_refund(U64(cell), U128(amount)))
            .detach();
    }

    /// 轉出 NEAR 或 NEP-141（合約自己附 1 yocto 呼叫 ft_transfer）。
    fn send(asset: &Option<AccountId>, to: AccountId, amount: u128, memo: String) -> Promise {
        match asset {
            None => Promise::new(to).transfer(NearToken::from_yoctonear(amount)),
            Some(token) => Promise::new(token.clone()).function_call(
                "ft_transfer".to_string(),
                serde_json::to_vec(&serde_json::json!({"receiver_id": to, "amount": amount.to_string(), "memo": memo})).unwrap(),
                NearToken::from_yoctonear(1),
                GAS_FOR_FT,
            ),
        }
    }

    fn add_total(&mut self, asset: &Option<AccountId>, amount: u128) {
        match asset {
            None => self.vault_total += amount,
            Some(t) => {
                let cur = self.token_total.get(t).copied().unwrap_or(0);
                self.token_total.insert(t.clone(), cur + amount);
            }
        }
    }

    fn sub_total(&mut self, asset: &Option<AccountId>, amount: u128) {
        match asset {
            None => self.vault_total -= amount,
            Some(t) => {
                let cur = self.token_total.get(t).copied().unwrap_or(0);
                self.token_total.insert(t.clone(), cur - amount);
            }
        }
    }

    #[private]
    pub fn on_refund(&mut self, cell: U64, amount: U128, #[callback_result] r: Result<(), PromiseError>) {
        if r.is_ok() {
            return;
        }
        if let Some(mut c) = self.cells.get(&cell.0).cloned() {
            c.unclaimed = U128(c.unclaimed.0 + amount.0);
            let asset = c.asset.clone();
            self.cells.insert(cell.0, c);
            self.add_total(&asset, amount.0);
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
        let (asset, funder) = (c.asset.clone(), c.funder.clone());
        self.cells.insert(cell.0, c);
        self.sub_total(&asset, amount);
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

    /// NEP-141 進來的唯一入口，msg 決定用途（都和 NEAR 的 payable 路徑共用邏輯）：
    ///   "<cell id>" 或 "fund:<cell id>"       入金到這格；不是該格的代幣、不是法人、格已關閉就退回
    ///   "stake"                               保證人質押
    ///   "settle:<credit id>"                  公司結清
    ///   "dispute:<credit id>:<reason_hash>"   公司附全額押金提出爭議
    ///   "reimburse:<credit id>"               公司償還保證人
    /// 多付的記進寄件人的可提領。條件不符會 panic：NEP-141 的 ft_resolve_transfer 會把代幣全數退回寄件人，帳也不會動。
    /// 呼叫者就是「代幣」：任何帳號都能假冒，所以一律比對這棵樹簽過的資產，假代幣只碰得到自己的帳。
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> U128 {
        let token = env::predecessor_account_id();
        let m = msg.trim();
        let (cmd, rest) = m.split_once(':').unwrap_or((m, ""));
        let via = Some(token.clone());
        let id = |s: &str| U64(s.parse::<u64>().unwrap_or_else(|_| env::panic_str("BAD_MSG")));
        match cmd {
            "stake" => self.stake_in(sender_id, via, amount.0),
            "settle" => self.funder_settles(id(rest), sender_id, amount.0, via),
            "reimburse" => self.funder_repays(id(rest), sender_id, amount.0, via),
            "dispute" => {
                let (k, reason) = rest.split_once(':').unwrap_or_else(|| env::panic_str("BAD_MSG"));
                self.funder_disputes(id(k), sender_id, amount.0, reason.to_string(), via);
            }
            "fund" => return self.fund_cell(token, sender_id, amount, rest),
            _ => return self.fund_cell(token, sender_id, amount, m),
        }
        U128(0)
    }

    /// 入金只收「該格綁定的代幣」且「寄件人是該格的法人」；其他一律退回（回傳 amount），不 panic。
    fn fund_cell(&mut self, token: AccountId, sender_id: AccountId, amount: U128, cell: &str) -> U128 {
        let Ok(id) = cell.parse::<u64>() else { return amount };
        let Some(mut c) = self.cells.get(&id).cloned() else { return amount };
        if c.asset.as_ref() != Some(&token) || c.funder != sender_id || c.status != Status::Active {
            event("deposit_refused", serde_json::json!({"cell": id.to_string(), "token": token, "sender": sender_id}));
            return amount;
        }
        c.vault = U128(c.vault.0 + amount.0);
        self.cells.insert(id, c);
        self.add_total(&Some(token.clone()), amount.0);
        event("deposited", serde_json::json!({"cell": id.to_string(), "token": token, "amount": amount.0.to_string()}));
        U128(0)
    }

    /// 付款資產要對：代幣樹不能用 NEAR 付（1 NEAR 的 yocto 數會被當成一大筆代幣），NEAR 樹也不收代幣。
    fn check_payment_asset(asset: &Option<AccountId>, via: &Option<AccountId>, attached: u128) {
        match via {
            Some(_) => require!(asset == via, "WRONG_ASSET"),
            None => require!(attached == 0 || asset.is_none(), "USE_FT_TRANSFER_CALL"),
        }
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
        let root = self.cells.get(&cell.0).map(|c| c.root).unwrap_or(cell.0);
        Self::invoice_key(root, &invoice_hash).is_some_and(|k| self.paid_invoices.contains(&k) && !self.pending_invoices.contains(&k))
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
            "credit": self.terms.contains_key(&c.root),
            "verifier": c.verifier,
            "not_revoked": c.status == Status::Active,
            "not_expired": now <= c.valid_until.0,
            "within_limit": { "used": c.idx, "of": c.n, "unit": c.unit.0.to_string(), "max_links_per_payment": c.max_links },
            "scope": c.scope,
            "amc_said": c.amc_said,
            "lei": self.unseals.get(&cell.0).or_else(|| self.unseals.get(&c.root)).and_then(|u| u.lei.clone()).unwrap_or_else(|| "sealed".to_string()),
            "lei_commit": c.lei_commit,
            "status": c.status,
            "parent": c.parent.map(|p| p.to_string()),
            "children": c.children.iter().map(|k| k.to_string()).collect::<Vec<_>>(),
            "depth": c.depth,
        }))
    }

    pub fn credit_of(&self, credit: U64) -> Option<Credit> {
        self.credits.get(&credit.0).cloned()
    }

    /// asset 省略 = NEAR 的質押。
    pub fn stake_of(&self, account: AccountId, asset: Option<AccountId>) -> Option<Stake> {
        self.stakes.get(&(account, asset)).cloned()
    }

    /// 保證人的帳簿：承擔多少、賺多少、賠多少、追回多少。
    /// net_loss = 已賠 - 已追回；loss_ratio_bps = net_loss / 累計費用，還沒賺過費用時是 null。
    pub fn guarantor_book(&self, account: AccountId, asset: Option<AccountId>) -> Option<Value> {
        let st = self.stakes.get(&(account.clone(), asset.clone()))?;
        let net_loss = st.claims_paid.0.saturating_sub(st.recovered.0);
        let utilisation = if st.amount.0 == 0 { 0 } else { st.exposure.0.saturating_mul(10_000) / st.amount.0 };
        let loss_ratio = if st.earned.0 == 0 { None } else { Some(net_loss.saturating_mul(10_000) / st.earned.0) };
        let mut top: Vec<(u128, &AccountId)> = st.sellers.iter().map(|s| (self.seller_exposure_of(&account, &asset, s), s)).filter(|x| x.0 > 0).collect();
        top.sort_by(|a, b| b.0.cmp(&a.0));
        top.truncate(TOP_SELLERS);
        Some(serde_json::json!({
            "asset": asset, "stake": st.amount, "exposure": st.exposure, "utilisation_bps": utilisation.min(u64::MAX as u128) as u64,
            "earned": st.earned, "claims_paid": st.claims_paid, "recovered": st.recovered, "net_loss": U128(net_loss),
            "loss_ratio_bps": loss_ratio.map(|r| r.min(u64::MAX as u128) as u64),
            "top_sellers": top.iter().map(|(e, s)| serde_json::json!({"seller": s, "exposure": U128(*e)})).collect::<Vec<_>>(),
        }))
    }

    /// asset 省略 = NEAR。
    pub fn claimable_of(&self, account: AccountId, asset: Option<AccountId>) -> U128 {
        U128(self.claimable.get(&(account, asset)).copied().unwrap_or(0))
    }

    /// 這種代幣在帳上的總額；合約在該代幣的餘額必須 >= 這個數（任何人都能核對）。
    pub fn token_total(&self, asset: AccountId) -> U128 {
        U128(self.token_total.get(&asset).copied().unwrap_or(0))
    }

    /// 賣方決定要不要賒之前看的卡：公司名封存，保證人具名。
    pub fn risk_card(&self, cell: U64) -> Option<Value> {
        let c = self.cells.get(&cell.0)?;
        let t = self.terms.get(&c.root)?;
        let root = self.cells.get(&c.root)?;
        let stake = self.stake_get(&t.guarantor, &t.args.asset);
        let rec = self.entities.get(&Self::entity_key(&t.guarantor, &t.args.entity_tag)).cloned().unwrap_or_default();
        Some(serde_json::json!({
            "asset": t.args.asset,
            "near_reserve": root.near_reserve,
            "legal_entity": self.unseals.get(&c.root).and_then(|u| u.lei.clone()).unwrap_or_else(|| "sealed".to_string()),
            "lei_commit": c.lei_commit,
            "guarantor": t.guarantor,
            "guarantor_listed": self.verifiers.contains_key(&t.guarantor),
            "guarantor_stake": stake.amount,
            "guarantor_exposure": stake.exposure,
            "guarantor_unstake_at": stake.unstake_at,
            "credit_limit": t.args.limit,
            "outstanding": t.outstanding,
            "bond_bps": t.args.bond_bps,
            "premium_bps": t.args.premium_bps,
            "fee_payer": t.args.fee_payer,
            "seller_cap_bps": t.args.seller_cap_bps,
            "guarantor_earned": stake.earned,
            "bond_available": U128(root.vault.0.saturating_sub(t.bond_locked.0)),
            "min_tenor": t.args.min_tenor,
            "max_tenor": t.args.max_tenor,
            "terms_hash": t.args.terms_hash,
            "arbiter": t.args.arbiter,
            "entity_tag": t.args.entity_tag,
            "settled": rec.settled,
            "settled_amount": rec.settled_amount,
            "defaults": rec.defaults,
            "first_seen": rec.first_seen,
            "frozen": t.open_debts > 0,
            "status": root.status,
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

// ================= 信用：Who pays is named before the agent buys =================
#[near]
impl Contract {
    /// 保證人質押 NEAR。有曝險不得提領。代幣的質押走 ft_on_transfer("stake")。
    #[payable]
    pub fn stake(&mut self) {
        self.stake_in(env::predecessor_account_id(), None, env::attached_deposit().as_yoctonear());
    }

    fn stake_in(&mut self, who: AccountId, asset: Option<AccountId>, amount: u128) {
        require!(self.verifiers.contains_key(&who), "NOT_A_VERIFIER");
        // 代幣的質押帳在驗證者簽過第一棵這種代幣的樹時開好（register）：假代幣開不了帳
        require!(asset.is_none() || self.stakes.contains_key(&(who.clone(), asset.clone())), "STAKE_ASSET_UNKNOWN");
        let mut st = self.stake_get(&who, &asset);
        st.amount = U128(st.amount.0 + amount);
        self.stake_put(&who, &asset, st);
        self.add_total(&asset, amount);
        event("staked", serde_json::json!({"guarantor": who, "amount": amount.to_string(), "asset": asset}));
    }

    pub fn request_unstake(&mut self, asset: Option<AccountId>) {
        let who = env::predecessor_account_id();
        let mut st = self.stakes.get(&(who.clone(), asset.clone())).cloned().unwrap_or_else(|| env::panic_str("NO_STAKE"));
        st.unstake_at = U64(env::block_timestamp() + self.windows.unstake_delay.0 * 1_000_000_000);
        self.stake_put(&who, &asset, st);
    }

    pub fn withdraw_stake(&mut self, amount: U128, asset: Option<AccountId>) -> Promise {
        let who = env::predecessor_account_id();
        let mut st = self.stakes.get(&(who.clone(), asset.clone())).cloned().unwrap_or_else(|| env::panic_str("NO_STAKE"));
        require!(st.unstake_at.0 > 0 && env::block_timestamp() >= st.unstake_at.0, "UNSTAKE_TOO_EARLY");
        require!(st.amount.0.saturating_sub(st.exposure.0) >= amount.0, "STAKE_EXPOSED");
        st.amount = U128(st.amount.0 - amount.0);
        st.unstake_at = U64(0); // 每次提領都要重新申請並等待
        self.stake_put(&who, &asset, st);
        self.sub_total(&asset, amount.0);
        Self::send(&asset, who.clone(), amount.0, "writ stake".to_string())
            .then(Self::ext(env::current_account_id()).with_static_gas(GAS_FOR_REFUND_CB).on_withdraw(who, amount, asset))
    }

    /// agent 下單賒帳：花鏈節（人授權的額度），不動錢。賣方接受前沒有任何人受拘束。
    pub fn open_credit(&mut self, preimage: String, j: u32, to: AccountId, invoice_hash: String, due_at: U64) -> Verdict {
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
        let terms = self.terms.get(&c.root).cloned();
        let amount = (j as u128).saturating_mul(c.unit.0);
        let invoice_key = Self::invoice_key(c.root, &invoice_hash);
        let root_vault = if c.root == id { c.vault.0 } else { self.cells.get(&c.root).map(|r| r.vault.0).unwrap_or(0) };
        let root_reserve = if c.root == id { c.near_reserve.0 } else { self.cells.get(&c.root).map(|r| r.near_reserve.0).unwrap_or(0) };
        // 單據儲存是 NEAR：NEAR 樹從根格可用金庫付，代幣樹從根格的 NEAR 準備付
        let token_tree = c.asset.is_some();
        let storage_free = if token_tree { root_reserve } else { root_vault.saturating_sub(terms.as_ref().map(|t| t.bond_locked.0).unwrap_or(0)) };
        let reason: Option<&str> = if terms.is_none() {
            Some("NO_CREDIT")
        } else if now > c.valid_until.0 {
            Some("EXPIRED")
        } else if self.suspended(&c) {
            Some("SUSPENDED")
        } else if terms.as_ref().unwrap().open_debts > 0 {
            Some("FROZEN")
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
        } else if terms.as_ref().unwrap().outstanding.0.saturating_add(amount) > terms.as_ref().unwrap().args.limit.0 {
            Some("CREDIT_LIMIT")
        } else if due_at.0 < now.saturating_add(terms.as_ref().unwrap().args.min_tenor.0 * 1_000_000_000)
            || due_at.0 > now.saturating_add(terms.as_ref().unwrap().args.max_tenor.0 * 1_000_000_000)
        {
            Some("TENOR")
        } else if storage_free < CREDIT_STORAGE {
            Some("FUNDS")
        } else {
            None
        };
        if let Some(r) = reason {
            event("rejected", serde_json::json!({"cell": id.to_string(), "reason": r, "to": to, "j": j, "strikes": c.strikes + u32::from(r != "FROZEN")}));
            return self.reject(id, c, pk, r);
        }
        let mut t = terms.unwrap();
        t.outstanding = U128(t.outstanding.0 + amount);
        let ik = invoice_key.unwrap();
        self.paid_invoices.insert(ik.clone());
        self.pending_invoices.insert(ik);
        c.w_cur = preimage.to_lowercase();
        c.idx += j;
        c.day_used += j;
        c.strikes = 0;
        let root_id = c.root;
        let asset = c.asset.clone();
        self.cells.insert(id, c);
        let mut r = self.cells.get(&root_id).cloned().unwrap();
        if token_tree {
            r.near_reserve = U128(r.near_reserve.0 - CREDIT_STORAGE);
        } else {
            r.vault = U128(r.vault.0 - CREDIT_STORAGE);
        }
        self.cells.insert(root_id, r);
        self.vault_total -= CREDIT_STORAGE;
        self.terms.insert(root_id, t);
        let credit = self.next_credit;
        self.next_credit += 1;
        self.credits.insert(credit, Credit {
            id: U64(credit),
            cell: U64(id),
            root: U64(root_id),
            seller: to.clone(),
            amount: U128(amount),
            original_amount: U128(amount),
            asset,
            invoice_hash,
            opened_at: U64(now),
            due_at,
            status: CreditStatus::Open,
            bond_locked: U128(0),
            exposure: U128(0),
            fee: U128(0),
            fee_periods: 0,
            delivery_hash: None,
            delivered_at: U64(0),
            dispute_escrow: U128(0),
            debt: U128(0),
            recourse_until: U64(0),
        });
        event("credit_opened", serde_json::json!({"credit": credit.to_string(), "cell": id.to_string(), "seller": to, "amount": amount.to_string(), "due_at": due_at.0.to_string()}));
        Verdict::CreditOpened { cell: U64(id), credit: U64(credit), amount: U128(amount), due_at }
    }

    /// 賣方接受：逐筆鎖定保證金與保證人曝險，別的賣方搶不走。
    pub fn accept_credit(&mut self, credit: U64) {
        let mut cr = self.credits.get(&credit.0).cloned().unwrap_or_else(|| env::panic_str("NO_CREDIT"));
        require!(env::predecessor_account_id() == cr.seller, "ONLY_SELLER");
        let now = env::block_timestamp();
        let mut t = self.terms.get(&cr.root.0).cloned().unwrap();
        let mut root = self.cells.get(&cr.root.0).cloned().unwrap();
        let cell = self.cells.get(&cr.cell.0).cloned().unwrap();
        if let Some(r) = self.accept_state_failures(&cr, &t, &root, &cell, now).first() {
            env::panic_str(r);
        }
        // 賣方自己設的規則；沒設就不檢查
        if let Some(p) = self.policies.get(&cr.seller) {
            if let Some(r) = self.policy_failures(p, &cr, &t, now).first() {
                env::panic_str(&format!("POLICY:{}", r));
            }
        }
        let q = self.quote(&cr, &t, &root, now);
        if let Some(r) = q.failures.first() {
            env::panic_str(r);
        }
        root.vault = U128(root.vault.0 - q.charge);
        self.cells.insert(cr.root.0, root);
        let asset = t.args.asset.clone();
        let mut st = self.stake_get(&t.guarantor, &asset);
        st.amount = U128(st.amount.0 + q.charge);
        st.earned = U128(st.earned.0 + q.charge);
        st.exposure = U128(st.exposure.0 + q.exposure);
        self.add_seller_exposure(&t.guarantor, &asset, &cr.seller, q.exposure);
        if q.exposure > 0 {
            self.note_seller(&mut st, &t.guarantor, &asset, &cr.seller);
        }
        self.stake_put(&t.guarantor, &asset, st);
        t.bond_locked = U128(t.bond_locked.0 + q.bond);
        self.terms.insert(cr.root.0, t);
        cr.bond_locked = U128(q.bond);
        cr.exposure = U128(q.exposure);
        cr.fee = U128(q.fee);
        cr.fee_periods = q.periods as u32;
        cr.status = CreditStatus::Accepted;
        self.credits.insert(credit.0, cr);
        event("credit_accepted", serde_json::json!({"credit": credit.0.to_string(), "bond": q.bond.to_string(), "premium": q.charge.to_string(), "fee": q.fee.to_string(), "guarantor_exposure": q.exposure.to_string()}));
    }

    /// 這張單的狀態本身能不能被接受。順序就是 accept_credit 報錯的順序。
    fn accept_state_failures(&self, cr: &Credit, t: &CreditTerms, root: &Cell, cell: &Cell, now: u64) -> Vec<String> {
        let mut out: Vec<String> = vec![];
        let mut no = |bad: bool, r: &str| {
            if bad {
                out.push(r.to_string());
            }
        };
        no(cr.status != CreditStatus::Open, "NOT_OPEN");
        no(now > cr.opened_at.0 + self.windows.accept_ttl.0 * 1_000_000_000, "OFFER_EXPIRED");
        // 公司已撤銷或停權、已凍結、期限已過：這張報價不能再成立，否則是拿保證人的錢墊
        no(cell.status != Status::Active || self.suspended(cell), "AGENT_NOT_ACTIVE");
        no(t.open_debts != 0, "COMPANY_FROZEN");
        no(now > cell.valid_until.0, "MANDATE_EXPIRED");
        no(cr.seller == t.args.arbiter, "ARBITER_NOT_INDEPENDENT");
        // 保證人或公司自己當賣方，等於自己製造違約：前者可走到揭露，後者把質押領給自己
        no(cr.seller == t.guarantor || cr.seller == root.funder, "SELLER_NOT_INDEPENDENT");
        out
    }

    /// 賣方規則逐條核對，回報每一條不符合的。
    fn policy_failures(&self, p: &SellerPolicy, cr: &Credit, t: &CreditTerms, now: u64) -> Vec<String> {
        let mut out: Vec<String> = vec![];
        let mut no = |bad: bool, r: &str| {
            if bad {
                out.push(r.to_string());
            }
        };
        no(cr.amount.0 > p.max_amount.0, "ORDER_TOO_LARGE");
        no(cr.due_at.0.saturating_sub(now) > p.max_tenor_secs.0.saturating_mul(1_000_000_000), "TENOR_TOO_LONG");
        no(t.args.bond_bps < p.min_bond_bps, "BOND_TOO_LOW");
        let defaults = self.entities.get(&Self::entity_key(&t.guarantor, &t.args.entity_tag)).map(|r| r.defaults).unwrap_or(0);
        no(defaults > p.max_defaults, "TOO_MANY_DEFAULTS");
        no(!p.guarantors.is_empty() && !p.guarantors.contains(&t.guarantor), "GUARANTOR_NOT_APPROVED");
        out
    }

    /// 這張單現在接受要多少錢、鎖多少。
    fn quote(&self, cr: &Credit, t: &CreditTerms, root: &Cell, now: u64) -> Quote {
        // 保證費：這是保證人肯做的理由。買方付的接受當下收，之後怎麼結束都不退（曝險已經承擔）；賣方付的等收款時扣
        let periods = fee_periods(cr.due_at.0, now);
        let fee = guarantee_fee(cr.amount.0, t.args.premium_bps, periods);
        let charge = if t.args.fee_payer == FeePayer::Buyer { fee } else { 0 };
        let free = root.vault.0.saturating_sub(t.bond_locked.0);
        // 保證金是硬性要求：風險卡寫幾成就鎖幾成，付不出來這張單就不成立，差額不會靜默轉給保證人
        let bond = cr.amount.0 * (t.args.bond_bps as u128) / 10_000;
        let exposure = cr.amount.0 - bond;
        let st = self.stake_get(&t.guarantor, &t.args.asset);
        let mut failures: Vec<String> = vec![];
        if free < charge {
            failures.push("PREMIUM_SHORT".to_string());
        }
        if free.saturating_sub(charge) < bond {
            failures.push("BOND_SHORT".to_string());
        }
        if st.amount.0.saturating_add(charge).saturating_sub(st.exposure.0) < exposure {
            failures.push("GUARANTOR_CAPACITY".to_string());
        }
        // 串通的賣方最多領走質押的這個比例。分母是收這筆費用之前的質押，比較保守
        let to_seller = self.seller_exposure_of(&t.guarantor, &t.args.asset, &cr.seller) + exposure;
        if t.args.seller_cap_bps > 0 && to_seller.saturating_mul(10_000) > st.amount.0.saturating_mul(t.args.seller_cap_bps as u128) {
            failures.push("SELLER_CONCENTRATION".to_string());
        }
        Quote { fee, periods, charge, bond, exposure, failures }
    }

    /// 賣方設定自己的自動授信規則。第一次要付儲存押金，之後改規則不用；多付的記進可提領。
    /// 傳 None 刪除規則，押金不退（再設一次要再付）。
    #[payable]
    pub fn set_seller_policy(&mut self, policy: Option<SellerPolicy>) {
        let who = env::predecessor_account_id();
        let attached = env::attached_deposit().as_yoctonear();
        let mut owed = 0;
        if let Some(p) = &policy {
            require!(p.guarantors.len() <= MAX_POLICY_GUARANTORS, "POLICY_TOO_LONG");
            require!(p.min_bond_bps <= 10_000, "BAD_POLICY");
            if !self.policies.contains_key(&who) {
                owed = SELLER_POLICY_STORAGE;
            }
        }
        require!(attached >= owed, "POLICY_STORAGE");
        match policy {
            Some(p) => {
                self.policies.insert(who.clone(), p);
            }
            None => {
                self.policies.remove(&who);
            }
        }
        if attached > owed {
            self.vault_total += attached - owed;
            self.credit_seller(&who, &None, attached - owed);
        }
        event("seller_policy_set", serde_json::json!({"seller": who}));
    }

    pub fn seller_policy(&self, seller: AccountId) -> Option<SellerPolicy> {
        self.policies.get(&seller).cloned()
    }

    /// 賣方決定要不要出貨之前問一次：用傳入的規則，或（None）自己存的規則，回報所有不符合的理由。
    /// ok = 現在呼叫 accept_credit 會成功，所以錢不夠、單據狀態不對也會列出來。
    pub fn check_order(&self, credit: U64, policy: Option<SellerPolicy>) -> OrderCheck {
        let cr = self.credits.get(&credit.0).unwrap_or_else(|| env::panic_str("NO_CREDIT"));
        let now = env::block_timestamp();
        let t = self.terms.get(&cr.root.0).unwrap();
        let root = self.cells.get(&cr.root.0).unwrap();
        let cell = self.cells.get(&cr.cell.0).unwrap();
        let rule = policy.or_else(|| self.policies.get(&cr.seller).cloned());
        let mut reasons = match &rule {
            Some(p) => self.policy_failures(p, cr, t, now),
            None => vec![],
        };
        reasons.extend(self.accept_state_failures(cr, t, root, cell, now));
        let q = self.quote(cr, t, root, now);
        reasons.extend(q.failures.iter().cloned());
        let st = self.stake_get(&t.guarantor, &t.args.asset);
        let rec = self.entities.get(&Self::entity_key(&t.guarantor, &t.args.entity_tag)).cloned().unwrap_or_default();
        let seller_fee = if t.args.fee_payer == FeePayer::Seller { q.fee.min(cr.amount.0) } else { 0 };
        OrderCheck {
            ok: reasons.is_empty(),
            reasons,
            order: serde_json::json!({
                "credit": cr.id, "cell": cr.cell, "seller": cr.seller, "status": cr.status, "asset": cr.asset,
                "amount": cr.amount, "original_amount": cr.original_amount,
                "seller_receives": U128(cr.amount.0 - seller_fee),
                "due_at": cr.due_at, "tenor_secs": U64(cr.due_at.0.saturating_sub(now) / 1_000_000_000),
                "fee": U128(q.fee), "fee_periods": q.periods as u32, "fee_payer": t.args.fee_payer,
                "bond": U128(q.bond), "bond_bps": t.args.bond_bps, "exposure": U128(q.exposure),
                "guarantor": t.guarantor, "guarantor_listed": self.verifiers.contains_key(&t.guarantor),
                "guarantor_stake": st.amount, "guarantor_total_exposure": st.exposure,
                "entity_tag": t.args.entity_tag, "settled": rec.settled, "defaults": rec.defaults,
                "terms_hash": t.args.terms_hash, "arbiter": t.args.arbiter,
                "policy_applied": rule.is_some(),
            }),
        }
    }

    /// 取消：沒人接受的報價逾時後任何人可取消，公司或保證人隨時可取消；
    /// 賣方接受了卻過期沒交貨，也可取消，免得一直卡住保證人的曝險。額度放回，鏈節不退。
    pub fn cancel_open(&mut self, credit: U64) {
        let mut cr = self.credits.get(&credit.0).cloned().unwrap_or_else(|| env::panic_str("NO_CREDIT"));
        let now = env::block_timestamp();
        let t = self.terms.get(&cr.root.0).cloned().unwrap();
        let root = self.cells.get(&cr.root.0).cloned().unwrap();
        let who = env::predecessor_account_id();
        match cr.status {
            CreditStatus::Open => require!(
                who == root.funder || who == t.guarantor || now > cr.opened_at.0 + self.windows.accept_ttl.0 * 1_000_000_000,
                "OFFER_LIVE"
            ),
            CreditStatus::Accepted => require!(now > cr.due_at.0 + self.windows.grace.0 * 1_000_000_000, "NOT_DUE"),
            _ => env::panic_str("NOT_CANCELLABLE"),
        }
        self.release(&mut cr, CreditStatus::Cancelled, 0);
        // 取消的單沒人收到錢也沒人裁定過：發票放回去，公司可以重開或付款
        if let Some(k) = Self::invoice_key(cr.root.0, &cr.invoice_hash) {
            self.paid_invoices.remove(&k);
            self.pending_invoices.remove(&k);
        }
        self.credits.insert(credit.0, cr);
    }

    /// 賣方交貨，提交憑據。沒交貨就沒有違約。
    /// final_amount：用量單的實際金額（> 0 且不超過開單金額），只能在已接受、尚未爭議時給。
    /// 單據縮成實際金額，保證金與曝險照原比例縮小，買方付過的費用不退，鏈節不退。
    pub fn mark_delivered(&mut self, credit: U64, delivery_hash: String, final_amount: Option<U128>) {
        let mut cr = self.credits.get(&credit.0).cloned().unwrap_or_else(|| env::panic_str("NO_CREDIT"));
        require!(env::predecessor_account_id() == cr.seller, "ONLY_SELLER");
        // 公司搶先提出爭議時，賣方仍然可以留下交貨憑據，仲裁逾時才不會一律退給公司
        require!(matches!(cr.status, CreditStatus::Accepted | CreditStatus::Disputed) && cr.delivery_hash.is_none(), "NOT_ACCEPTED");
        hex32(&delivery_hash, "delivery_hash");
        if let Some(f) = final_amount {
            require!(cr.status == CreditStatus::Accepted, "FINAL_AMOUNT_NEEDS_ACCEPTED");
            require!(f.0 > 0 && f.0 <= cr.amount.0, "BAD_FINAL_AMOUNT");
            self.shrink_order(&mut cr, f.0);
        }
        let now = env::block_timestamp();
        cr.delivery_hash = Some(delivery_hash);
        cr.delivered_at = U64(now);
        if cr.status == CreditStatus::Accepted {
            cr.status = CreditStatus::Delivered;
        } else {
            // 爭議逾時後不能補；爭議中補交，仲裁人至少還有一段驗收期可以看
            require!(now <= cr.recourse_until.0, "DISPUTE_CLOSED");
            cr.recourse_until = U64(cr.recourse_until.0.max(now + self.windows.inspect.0 * 1_000_000_000));
        }
        let (cr_amount, cr_original) = (cr.amount.0, cr.original_amount.0);
        self.credits.insert(credit.0, cr);
        event("credit_delivered", serde_json::json!({"credit": credit.0.to_string(), "final_amount": cr_amount.to_string(), "original_amount": cr_original.to_string()}));
    }

    /// agent 從自己的金庫結清。agent 鑰匙不受過期影響；被撤銷後由公司結清。
    pub fn settle(&mut self, credit: U64) -> Verdict {
        require!(env::signer_account_id() == env::current_account_id(), "NOT_AGENT_KEY");
        let pk = env::signer_account_pk();
        let id = *self.key_to_cell.get(&pk).unwrap_or_else(|| env::panic_str("NO_CELL"));
        let mut cr = self.credits.get(&credit.0).cloned().unwrap_or_else(|| env::panic_str("NO_CREDIT"));
        require!(cr.cell.0 == id, "NOT_YOUR_CREDIT");
        require!(matches!(cr.status, CreditStatus::Accepted | CreditStatus::Delivered), "NOT_SETTLEABLE");
        let mut c = self.cells.get(&id).cloned().unwrap();
        require!(!self.suspended(&c), "SUSPENDED");
        require!(!self.owes_guarantor(cr.root.0), "REPAY_GUARANTOR_FIRST");
        // 付這一筆時，這筆自己鎖的保證金可以用
        let usable = if id == cr.root.0 { self.free_vault(id, &c) + cr.bond_locked.0 } else { c.vault.0 };
        require!(usable >= cr.amount.0, "VAULT_SHORT");
        c.vault = U128(c.vault.0 - cr.amount.0);
        self.cells.insert(id, c);
        let amount = cr.amount;
        self.pay_seller(&cr);
        self.finish_settled(&mut cr);
        self.credits.insert(credit.0, cr);
        Verdict::CreditSettled { credit, amount }
    }

    /// 公司結清：附上金額，或不附錢時從根格金庫扣。撤銷、過期之後也能用。代幣樹帶錢走 ft_on_transfer("settle:<id>")。
    #[payable]
    pub fn settle_by_funder(&mut self, credit: U64) {
        self.funder_settles(credit, env::predecessor_account_id(), env::attached_deposit().as_yoctonear(), None);
    }

    fn funder_settles(&mut self, credit: U64, who: AccountId, attached: u128, via: Option<AccountId>) {
        let mut cr = self.credits.get(&credit.0).cloned().unwrap_or_else(|| env::panic_str("NO_CREDIT"));
        let root = self.cells.get(&cr.root.0).cloned().unwrap();
        require!(who == root.funder, "ONLY_FUNDER");
        Self::check_payment_asset(&root.asset, &via, attached);
        require!(matches!(cr.status, CreditStatus::Accepted | CreditStatus::Delivered), "NOT_SETTLEABLE");
        if attached >= cr.amount.0 {
            self.add_total(&root.asset, attached);
            self.credit_seller(&root.funder, &root.asset, attached - cr.amount.0);
        } else {
            require!(attached == 0, "PARTIAL_DEPOSIT");
            // 欠保證人時金庫要先還保證人，別筆單要另外帶錢來付
            require!(!self.owes_guarantor(cr.root.0), "REPAY_GUARANTOR_FIRST");
            // 被鎖的這筆保證金可以用來付這一筆
            let t = self.terms.get(&cr.root.0).unwrap();
            let usable = root.vault.0.saturating_sub(t.bond_locked.0 - cr.bond_locked.0);
            require!(usable >= cr.amount.0, "VAULT_SHORT");
            let mut r = root.clone();
            r.vault = U128(r.vault.0 - cr.amount.0);
            self.cells.insert(cr.root.0, r);
        }
        self.pay_seller(&cr);
        self.finish_settled(&mut cr);
        self.credits.insert(credit.0, cr);
    }

    /// 賣方提領。先記帳後提領：賣方刪帳號也不會讓公司被判違約。asset 省略 = NEAR。
    pub fn withdraw(&mut self, asset: Option<AccountId>) -> Promise {
        let who = env::predecessor_account_id();
        let key = (who.clone(), asset.clone());
        let amount = self.claimable.get(&key).copied().unwrap_or(0);
        require!(amount > 0, "NOTHING_TO_WITHDRAW");
        self.claimable.remove(&key);
        self.sub_total(&asset, amount);
        Self::send(&asset, who.clone(), amount, "writ withdraw".to_string())
            .then(Self::ext(env::current_account_id()).with_static_gas(GAS_FOR_REFUND_CB).on_withdraw(who, U128(amount), asset))
    }

    /// 轉帳失敗（帳號不見了、沒在代幣註冊）：把錢記回 claimable，帳號回來還能領。
    #[private]
    pub fn on_withdraw(&mut self, who: AccountId, amount: U128, asset: Option<AccountId>, #[callback_result] r: Result<(), PromiseError>) {
        if r.is_err() {
            self.add_total(&asset, amount.0);
            self.credit_seller(&who, &asset, amount.0);
        }
    }

    /// 公司對貨有意見：附全額押金提出爭議，這時不算違約，也不揭露。賴帳者靠這招省不了錢。
    /// 代幣樹走 ft_on_transfer("dispute:<id>:<reason_hash>")。
    #[payable]
    pub fn dispute(&mut self, credit: U64, reason_hash: String) {
        self.funder_disputes(credit, env::predecessor_account_id(), env::attached_deposit().as_yoctonear(), reason_hash, None);
    }

    fn funder_disputes(&mut self, credit: U64, who: AccountId, attached: u128, reason_hash: String, via: Option<AccountId>) {
        let mut cr = self.credits.get(&credit.0).cloned().unwrap_or_else(|| env::panic_str("NO_CREDIT"));
        let root = self.cells.get(&cr.root.0).cloned().unwrap();
        require!(who == root.funder, "ONLY_FUNDER");
        Self::check_payment_asset(&root.asset, &via, attached);
        require!(matches!(cr.status, CreditStatus::Accepted | CreditStatus::Delivered), "NOT_DISPUTABLE");
        require!(attached >= cr.amount.0, "ESCROW_FULL_AMOUNT");
        hex32(&reason_hash, "reason_hash");
        cr.dispute_escrow = U128(attached);
        self.add_total(&root.asset, attached);
        cr.status = CreditStatus::Disputed;
        cr.recourse_until = U64(env::block_timestamp() + self.windows.dispute_timeout.0 * 1_000_000_000);
        self.credits.insert(credit.0, cr);
        event("credit_disputed", serde_json::json!({"credit": credit.0.to_string(), "reason_hash": reason_hash}));
    }

    /// 仲裁人裁定。不得是保證人（開格時已檢查）。
    pub fn resolve_dispute(&mut self, credit: U64, to_seller: bool) {
        let cr = self.credits.get(&credit.0).cloned().unwrap_or_else(|| env::panic_str("NO_CREDIT"));
        let t = self.terms.get(&cr.root.0).cloned().unwrap();
        require!(env::predecessor_account_id() == t.args.arbiter, "ONLY_ARBITER");
        self.finish_dispute(cr, to_seller);
    }

    /// 仲裁人逾時：有交貨憑據就給賣方，沒有就退公司。
    pub fn resolve_timeout(&mut self, credit: U64) {
        let cr = self.credits.get(&credit.0).cloned().unwrap_or_else(|| env::panic_str("NO_CREDIT"));
        require!(cr.status == CreditStatus::Disputed, "NOT_DISPUTED");
        require!(env::block_timestamp() > cr.recourse_until.0, "ARBITER_STILL_HAS_TIME");
        let delivered = cr.delivery_hash.is_some();
        let key = Self::invoice_key(cr.root.0, &cr.invoice_hash);
        self.finish_dispute(cr, delivered);
        // 仲裁人沒裁定、也沒交貨：沒人判過這張發票，放回去
        if let (false, Some(k)) = (delivered, key) {
            self.paid_invoices.remove(&k);
            self.pending_invoices.remove(&k);
        }
    }

    /// 違約：到期加寬限期仍未付，條件全是鏈上狀態，不問買賣糾紛。
    /// 賠付順序：該格金庫 → 根格可用金庫 → 這筆鎖定的保證金 → 保證人質押。之後公司的 agent 全部凍結（不能賒帳、付款、雇用、結清），但鑰匙還在。
    pub fn claim_default(&mut self, credit: U64) {
        let mut cr = self.credits.get(&credit.0).cloned().unwrap_or_else(|| env::panic_str("NO_CREDIT"));
        let who = env::predecessor_account_id();
        let now = env::block_timestamp();
        let mut t = self.terms.get(&cr.root.0).cloned().unwrap();
        // 賣方一直不請求時曝險會卡住：再過一段追償期，保證人可以代為觸發，錢仍然給賣方
        let stale = now > cr.due_at.0 + (self.windows.grace.0 + self.windows.recourse.0) * 1_000_000_000
            && now > cr.delivered_at.0 + (self.windows.inspect.0 + self.windows.recourse.0) * 1_000_000_000;
        require!(who == cr.seller || (who == t.guarantor && stale), "ONLY_SELLER");
        require!(cr.status == CreditStatus::Delivered, "NOT_DELIVERED");
        require!(now > cr.due_at.0 + self.windows.grace.0 * 1_000_000_000, "NOT_DUE");
        require!(now > cr.delivered_at.0 + self.windows.inspect.0 * 1_000_000_000, "INSPECTION_OPEN");
        let mut left = cr.amount.0;
        if cr.cell.0 != cr.root.0 {
            let mut c = self.cells.get(&cr.cell.0).cloned().unwrap();
            let take = left.min(c.vault.0);
            c.vault = U128(c.vault.0 - take);
            left -= take;
            self.cells.insert(cr.cell.0, c);
        }
        let mut r = self.cells.get(&cr.root.0).cloned().unwrap();
        // 根格金庫：別筆鎖定的保證金不能動，這筆的可以
        let usable = r.vault.0.saturating_sub(t.bond_locked.0 - cr.bond_locked.0);
        let take = left.min(usable);
        r.vault = U128(r.vault.0 - take);
        left -= take;
        self.cells.insert(cr.root.0, r);
        let asset = t.args.asset.clone();
        let mut st = self.stake_get(&t.guarantor, &asset);
        st.exposure = U128(st.exposure.0 - cr.exposure.0);
        require!(st.amount.0 >= left, "GUARANTOR_SHORT");
        st.amount = U128(st.amount.0 - left);
        st.claims_paid = U128(st.claims_paid.0 + left);
        self.stake_put(&t.guarantor, &asset, st);
        self.sub_seller_exposure(&t.guarantor, &asset, &cr.seller, cr.exposure.0);
        self.pay_seller(&cr);
        t.outstanding = U128(t.outstanding.0 - cr.amount.0);
        t.bond_locked = U128(t.bond_locked.0 - cr.bond_locked.0);
        cr.debt = U128(left);
        cr.recourse_until = U64(now + self.windows.recourse.0 * 1_000_000_000);
        cr.status = CreditStatus::Defaulted;
        self.close_invoice(&cr);
        if left > 0 {
            t.open_debts += 1;
        }
        let key = Self::entity_key(&t.guarantor, &t.args.entity_tag);
        let mut rec = self.entities.get(&key).cloned().unwrap_or_default();
        rec.defaults += 1;
        self.entities.insert(key, rec);
        self.terms.insert(cr.root.0, t);
        self.credits.insert(credit.0, cr.clone());
        event("credit_defaulted", serde_json::json!({"credit": credit.0.to_string(), "guarantor_paid": left.to_string(), "recourse_until": cr.recourse_until.0.to_string()}));
        self.release_retained(cr.root.0);
    }

    /// 公司償還保證人：解凍，維持封存。代幣樹帶錢走 ft_on_transfer("reimburse:<id>")。
    #[payable]
    pub fn reimburse(&mut self, credit: U64) {
        self.funder_repays(credit, env::predecessor_account_id(), env::attached_deposit().as_yoctonear(), None);
    }

    fn funder_repays(&mut self, credit: U64, who: AccountId, attached: u128, via: Option<AccountId>) {
        let mut cr = self.credits.get(&credit.0).cloned().unwrap_or_else(|| env::panic_str("NO_CREDIT"));
        let root = self.cells.get(&cr.root.0).cloned().unwrap();
        require!(who == root.funder, "ONLY_FUNDER");
        Self::check_payment_asset(&root.asset, &via, attached);
        require!(matches!(cr.status, CreditStatus::Defaulted | CreditStatus::Enforced) && cr.debt.0 > 0, "NO_DEBT");
        let mut t = self.terms.get(&cr.root.0).cloned().unwrap();
        // 金庫裡沒被鎖的錢先抵，不足的才要帶錢來
        let mut r = root.clone();
        let from_vault = r.vault.0.saturating_sub(t.bond_locked.0).min(cr.debt.0);
        let due = cr.debt.0 - from_vault;
        require!(attached >= due, "PAY_FULL_DEBT");
        r.vault = U128(r.vault.0 - from_vault);
        self.cells.insert(cr.root.0, r);
        let asset = root.asset.clone();
        let mut st = self.stake_get(&t.guarantor, &asset);
        st.amount = U128(st.amount.0 + cr.debt.0);
        st.recovered = U128(st.recovered.0 + cr.debt.0);
        self.stake_put(&t.guarantor, &asset, st);
        self.add_total(&asset, attached);
        self.credit_seller(&root.funder, &asset, attached - due);
        t.open_debts -= 1;
        self.terms.insert(cr.root.0, t);
        cr.debt = U128(0);
        cr.status = CreditStatus::Reimbursed;
        let root_id = cr.root.0;
        self.credits.insert(credit.0, cr);
        self.release_retained(root_id);
        event("credit_reimbursed", serde_json::json!({"credit": credit.0.to_string()}));
    }

    /// 追償期滿公司仍不還：保證人斷整棵樹的電。
    pub fn enforce_recourse(&mut self, credit: U64) {
        let mut cr = self.credits.get(&credit.0).cloned().unwrap_or_else(|| env::panic_str("NO_CREDIT"));
        let t = self.terms.get(&cr.root.0).cloned().unwrap();
        require!(env::predecessor_account_id() == t.guarantor, "ONLY_GUARANTOR");
        // 已斷電的也可以再收一次：別筆單結束後釋放的保證金要先還保證人
        require!(matches!(cr.status, CreditStatus::Defaulted | CreditStatus::Enforced) && cr.debt.0 > 0, "NO_DEBT");
        require!(env::block_timestamp() > cr.recourse_until.0, "RECOURSE_OPEN");
        let root = self.cells.get(&cr.root.0).cloned().unwrap();
        if root.status == Status::Active || matches!(root.status, Status::Tripped) {
            self.close(cr.root.0, root, Status::Revoked { by: env::predecessor_account_id(), evidence: format!("recourse on credit {}", credit.0) });
        }
        // 樹裡還有錢（子格金庫都已收回根格）：先還保證人，這筆還清就不必揭露
        let mut t = self.terms.get(&cr.root.0).cloned().unwrap();
        let mut root = self.cells.get(&cr.root.0).cloned().unwrap();
        let usable = root.vault.0.saturating_sub(t.bond_locked.0);
        let pay = usable.min(cr.debt.0);
        if pay > 0 {
            root.vault = U128(root.vault.0 - pay);
            self.cells.insert(cr.root.0, root);
            let asset = t.args.asset.clone();
            let mut st = self.stake_get(&t.guarantor, &asset);
            st.amount = U128(st.amount.0 + pay);
            st.recovered = U128(st.recovered.0 + pay);
            self.stake_put(&t.guarantor, &asset, st);
            cr.debt = U128(cr.debt.0 - pay);
        }
        if cr.debt.0 == 0 {
            t.open_debts -= 1;
            cr.status = CreditStatus::Reimbursed;
        } else {
            cr.status = CreditStatus::Enforced;
        }
        self.terms.insert(cr.root.0, t);
        self.credits.insert(credit.0, cr.clone());
        self.release_retained(cr.root.0);
        let name = if cr.debt.0 == 0 { "credit_reimbursed" } else { "credit_enforced" };
        event(name, serde_json::json!({"credit": credit.0.to_string()}));
    }

    /// 最後一步：公開公司身分。驗 LEI 承諾、ECR 承諾，以及打開的 LE 鑰匙對這份條款與 LEI 的簽章。
    /// 這擋得住「套用別家 LEI 但沒有對方鑰匙」的栽贓；LE 鑰匙和那個 LEI 的關係要靠鏈下驗憑證鏈，合約驗不到。
    /// 不看現行白名單，owner 擋不掉。
    pub fn credit_unseal(&mut self, credit: U64, lei: String, salt: String, ecr: EcrOpening) {
        let cr = self.credits.get(&credit.0).cloned().unwrap_or_else(|| env::panic_str("NO_CREDIT"));
        let t = self.terms.get(&cr.root.0).cloned().unwrap();
        require!(env::predecessor_account_id() == t.guarantor, "ONLY_GUARANTOR");
        require!(cr.status == CreditStatus::Enforced, "NOT_ENFORCED");
        let root = self.cells.get(&cr.root.0).cloned().unwrap();
        let digest = hex::encode(env::sha256(format!("{}|{}", lei, salt).as_bytes()));
        require!(digest == root.lei_commit, "COMMIT_MISMATCH");
        let open = hex::encode(env::sha256(format!("{}|{}|{}|{}", ecr.le_aid, ecr.le_pk, ecr.ecr_said, ecr.salt).as_bytes()));
        // 條款是開格當時的 LE 鑰匙簽的；之後換鑰（update_signers）不影響這裡
        require!(open == t.terms_ecr_commit, "BAD_ECR_OPENING");
        let sig: [u8; 64] = hex::decode(&t.args.terms_sig).ok().and_then(|v| v.as_slice().try_into().ok()).unwrap_or_else(|| env::panic_str("BAD_TERMS_SIG"));
        let msg = format!("writ:terms:v1\ncontract={}\namc={}\nterms={}\nlei={}", env::current_account_id(), root.amc_said, t.args.terms_hash, lei);
        require!(env::ed25519_verify(&sig, msg.as_bytes(), &hex32(&ecr.le_pk, "le_pk")), "LE_DID_NOT_SIGN");
        self.unseals.insert(cr.root.0, Unseal { requester: cr.seller.clone(), reason_hash: t.args.terms_hash.clone(), requested_at: U64(env::block_timestamp()), objected: false, lei: Some(lei.clone()) });
        event("credit_unsealed", serde_json::json!({"credit": credit.0.to_string(), "lei": lei, "le_aid": ecr.le_aid}));
    }

    /// 有名有姓的責任收據：這筆單是誰的 agent 下的、依據哪份條款、誰擔保。
    pub fn liability_receipt(&self, credit: U64) -> Option<Value> {
        let cr = self.credits.get(&credit.0)?;
        let t = self.terms.get(&cr.root.0)?;
        let root = self.cells.get(&cr.root.0)?;
        let mut path = vec![cr.cell.0];
        let mut cur = self.cells.get(&cr.cell.0)?;
        while let Some(p) = cur.parent {
            path.push(p);
            cur = self.cells.get(&p)?;
        }
        Some(serde_json::json!({
            "credit": cr.id, "status": cr.status, "seller": cr.seller, "amount": cr.amount, "asset": cr.asset, "due_at": cr.due_at,
            "invoice_hash": cr.invoice_hash, "agent_path": path.iter().map(|k| k.to_string()).collect::<Vec<_>>(),
            "amc_said": root.amc_said, "guarantor": t.guarantor, "terms_hash": t.args.terms_hash, "entity_tag": t.args.entity_tag,
            "lei_commit": root.lei_commit, "legal_entity": self.unseals.get(&cr.root.0).and_then(|u| u.lei.clone()).unwrap_or_else(|| "sealed".to_string()),
        }))
    }

    /// 假名只在同一個保證人底下有意義；別的保證人不能冒用這份紀錄。
    fn entity_key(guarantor: &AccountId, tag: &str) -> String {
        format!("{}:{}", guarantor, tag)
    }

    /// 用量單縮小：額度、保證金、曝險一起放回去，保證金維持條款承諾的比例。
    fn shrink_order(&mut self, cr: &mut Credit, final_amount: u128) {
        let mut t = self.terms.get(&cr.root.0).cloned().unwrap();
        let bond = final_amount * (t.args.bond_bps as u128) / 10_000;
        let exposure = final_amount - bond;
        t.outstanding = U128(t.outstanding.0 - (cr.amount.0 - final_amount));
        t.bond_locked = U128(t.bond_locked.0 - (cr.bond_locked.0 - bond));
        let cut = cr.exposure.0 - exposure;
        if cut > 0 {
            let asset = t.args.asset.clone();
            let mut st = self.stake_get(&t.guarantor, &asset);
            st.exposure = U128(st.exposure.0 - cut);
            self.stake_put(&t.guarantor, &asset, st);
            self.sub_seller_exposure(&t.guarantor, &asset, &cr.seller, cut);
        }
        if t.args.fee_payer == FeePayer::Seller {
            cr.fee = U128(guarantee_fee(final_amount, t.args.premium_bps, cr.fee_periods as u128));
        }
        self.terms.insert(cr.root.0, t);
        cr.amount = U128(final_amount);
        cr.bond_locked = U128(bond);
        cr.exposure = U128(exposure);
    }

    /// 帳簿記下這個賣方。滿了就換掉曝險最小的，前提是它比這個賣方小。
    fn note_seller(&self, st: &mut Stake, guarantor: &AccountId, asset: &Option<AccountId>, seller: &AccountId) {
        if st.sellers.contains(seller) {
            return;
        }
        if st.sellers.len() < MAX_BOOK_SELLERS {
            st.sellers.push(seller.clone());
            return;
        }
        let cur = self.seller_exposure_of(guarantor, asset, seller);
        let low = st.sellers.iter().enumerate().map(|(i, s)| (self.seller_exposure_of(guarantor, asset, s), i)).min();
        if let Some((e, i)) = low {
            if e < cur {
                st.sellers[i] = seller.clone();
            }
        }
    }

    fn stake_get(&self, who: &AccountId, asset: &Option<AccountId>) -> Stake {
        self.stakes.get(&(who.clone(), asset.clone())).cloned().unwrap_or_default()
    }

    fn stake_put(&mut self, who: &AccountId, asset: &Option<AccountId>, st: Stake) {
        self.stakes.insert((who.clone(), asset.clone()), st);
    }

    fn seller_exposure_of(&self, guarantor: &AccountId, asset: &Option<AccountId>, seller: &AccountId) -> u128 {
        self.seller_exposure.get(&(guarantor.clone(), asset.clone(), seller.clone())).copied().unwrap_or(0)
    }

    fn add_seller_exposure(&mut self, guarantor: &AccountId, asset: &Option<AccountId>, seller: &AccountId, amount: u128) {
        if amount > 0 {
            let cur = self.seller_exposure_of(guarantor, asset, seller);
            self.seller_exposure.insert((guarantor.clone(), asset.clone(), seller.clone()), cur + amount);
        }
    }

    fn sub_seller_exposure(&mut self, guarantor: &AccountId, asset: &Option<AccountId>, seller: &AccountId, amount: u128) {
        let left = self.seller_exposure_of(guarantor, asset, seller) - amount;
        let key = (guarantor.clone(), asset.clone(), seller.clone());
        if left == 0 {
            self.seller_exposure.remove(&key);
        } else {
            self.seller_exposure.insert(key, left);
        }
    }

    fn credit_seller(&mut self, seller: &AccountId, asset: &Option<AccountId>, amount: u128) {
        if amount == 0 {
            return;
        }
        let key = (seller.clone(), asset.clone());
        let cur = self.claimable.get(&key).copied().unwrap_or(0);
        self.claimable.insert(key, cur + amount);
    }

    /// 賣方收款的唯一入口（結清、公司代付、違約、爭議勝）。賣方付費時從貨款扣，記進保證人的質押與累計收入。
    /// 費用可能超過貨款（天期很長）：最多扣到貨款為零。
    fn pay_seller(&mut self, cr: &Credit) {
        let t = self.terms.get(&cr.root.0).cloned().unwrap();
        let asset = t.args.asset.clone();
        let fee = if t.args.fee_payer == FeePayer::Seller { cr.fee.0.min(cr.amount.0) } else { 0 };
        self.credit_seller(&cr.seller, &asset, cr.amount.0 - fee);
        if fee > 0 {
            let mut st = self.stake_get(&t.guarantor, &asset);
            st.amount = U128(st.amount.0 + fee);
            st.earned = U128(st.earned.0 + fee);
            self.stake_put(&t.guarantor, &asset, st);
        }
    }

    /// 解除這筆的鎖定與額度。keep_bps 不用於現況，保留簡單的呼叫形狀。
    fn release(&mut self, cr: &mut Credit, status: CreditStatus, _unused: u8) {
        let mut t = self.terms.get(&cr.root.0).cloned().unwrap();
        t.outstanding = U128(t.outstanding.0 - cr.amount.0);
        t.bond_locked = U128(t.bond_locked.0 - cr.bond_locked.0);
        if cr.exposure.0 > 0 {
            let asset = t.args.asset.clone();
            let mut st = self.stake_get(&t.guarantor, &asset);
            st.exposure = U128(st.exposure.0 - cr.exposure.0);
            self.stake_put(&t.guarantor, &asset, st);
            self.sub_seller_exposure(&t.guarantor, &asset, &cr.seller, cr.exposure.0);
        }
        self.terms.insert(cr.root.0, t);
        cr.status = status;
        self.close_invoice(cr);
        self.release_retained(cr.root.0);
    }

    /// 賒帳單結束而且賣方拿到錢：發票算已付。沒拿到錢的（取消、仲裁判公司勝）維持待付，
    /// 所以 invoice_paid 是 false，而發票仍然占用：仲裁判掉的不能換條路再付。
    fn close_invoice(&mut self, cr: &Credit) {
        if cr.status == CreditStatus::Cancelled {
            return;
        }
        if let Some(k) = Self::invoice_key(cr.root.0, &cr.invoice_hash) {
            self.pending_invoices.remove(&k);
        }
    }

    fn finish_settled(&mut self, cr: &mut Credit) {
        let t = self.terms.get(&cr.root.0).unwrap();
        let tag = Self::entity_key(&t.guarantor, &t.args.entity_tag);
        let mut rec = self.entities.get(&tag).cloned().unwrap_or_default();
        rec.settled += 1;
        rec.settled_amount = U128(rec.settled_amount.0 + cr.amount.0);
        self.entities.insert(tag, rec);
        self.release(cr, CreditStatus::Settled, 0);
        event("credit_settled", serde_json::json!({"credit": cr.id.0.to_string(), "amount": cr.amount.0.to_string()}));
    }

    fn finish_dispute(&mut self, mut cr: Credit, to_seller: bool) {
        require!(cr.status == CreditStatus::Disputed, "NOT_DISPUTED");
        let root = self.cells.get(&cr.root.0).cloned().unwrap();
        let escrow = cr.dispute_escrow.0;
        let amount = cr.amount.0;
        cr.dispute_escrow = U128(0);
        if to_seller {
            self.pay_seller(&cr);
            self.credit_seller(&root.funder, &root.asset, escrow - amount);
            self.finish_settled(&mut cr);
        } else {
            self.credit_seller(&root.funder, &root.asset, escrow);
            self.release(&mut cr, CreditStatus::Cancelled, 0);
        }
        event("credit_resolved", serde_json::json!({"credit": cr.id.0.to_string(), "to_seller": to_seller}));
        self.credits.insert(cr.id.0, cr);
    }

    /// 樹已關閉且沒有未結清：留在根格的金庫轉成法人可領（claim_refund）。
    fn release_retained(&mut self, root_id: u64) {
        let Some(t) = self.terms.get(&root_id) else { return };
        if t.outstanding.0 > 0 || t.open_debts > 0 {
            return;
        }
        let Some(mut r) = self.cells.get(&root_id).cloned() else { return };
        if matches!(r.status, Status::Revoked { .. }) && r.vault.0 > 0 {
            r.unclaimed = U128(r.unclaimed.0 + r.vault.0);
            r.vault = U128(0);
            self.cells.insert(root_id, r);
        }
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
        let mut w = Contract::new(writ.clone(), None, None);
        let pk: PublicKey = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp".parse().unwrap();
        let cell = |status: Status| Cell {
            amc_said: "E".into(), issuer_aid: String::new(), issuer_pk: String::new(), agent_pk: pk.clone(), verifier: writ.clone(), funder: funder.clone(),
            lei_commit: String::new(), ecr_commit: String::new(), scope: vec![], valid_until: U64(0), unit: U128(1), n: 1, idx: 1, unclaimed: U128(0),
            root: 1, parent: None, depth: 0, children: vec![], tree_size: 1, near_reserve: U128(0), w_cur: String::new(), daily_links: 1, max_links: 1, max_strikes: 3, day: 0, day_used: 1, vault: U128(0), spends: 1, rejects: 0, strikes: 0, status, asset: None,
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

        // 公司還欠錢：撤銷中轉帳失敗的錢留在根格，不退給公司
        let args = CreditArgs { limit: U128(1), bond_bps: 0, premium_bps: 0, min_tenor: U64(0), max_tenor: U64(1), terms_hash: String::new(), terms_sig: String::new(), entity_tag: String::new(), arbiter: writ.clone(), fee_payer: FeePayer::Buyer, seller_cap_bps: 0, asset: None };
        w.terms.insert(1, CreditTerms { args, guarantor: writ.clone(), terms_ecr_commit: String::new(), outstanding: U128(0), bond_locked: U128(0), open_debts: 1 });
        ctx(vec![PromiseResult::Failed]);
        assert!(matches!(w.on_transfer(U64(1), U128(5), "00".repeat(32), funder.clone(), 1, 0, Err(PromiseError::Failed)), Verdict::Rejected { .. }));
        assert_eq!(w.cells.get(&1).unwrap().vault.0, 5, "the money stays for the guarantor");
        assert_eq!(w.vault_total, 10);
        assert!(!get_created_receipts().iter().any(|r| r.receiver_id == funder), "nothing goes back to a company that owes");
    }
}

#[cfg(test)]
include!("fuzz.rs");
