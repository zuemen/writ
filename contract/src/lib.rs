//! Writ: the on-chain enforcement layer for the GLEIF Agent Mandate Credential (AMC).
//!
//! In one line: verify once at credential time, one hash check per payment at runtime, and a revocation takes effect in the next block.
//!
//! Roles
//!   - owner: the deployer. Its one job is to maintain the whitelist of verifiers (account + Ed25519 public key).
//!   - verifier: checks the whole chain off-chain (LE vLEI -> ECR (a person) -> AMC -> the agent's delegated AID) and signs an attestation.
//!   - funder: the legal entity's funding account. Calls register with the attestation and funds the cell; can revoke its own mandate at any time.
//!   - agent: holds one Ed25519 key, which is both the signing key of its delegated KERI AID and a function-call key on this contract's account.
//!
//! Every spend checks five predicates (the four AMC items in Annex A, p.44 of the GLEIF discussion paper, plus revocation):
//!   1. Valid chain     - the verifier's signature was checked on-chain at register (verified once)
//!   2. Not revoked     - the key is still on the contract account (guaranteed by the protocol; a deleted key cannot sign)
//!   3. Within budget   - PayWord: sha256^j(preimage) == w_cur and idx + j <= n; also a daily link rate
//!   4. Counterparty in scope - to is in scope
//!   5. Not expired     - block_timestamp <= valid_until
//!
//! A policy refusal does not panic: it returns Verdict::Rejected, the transaction succeeds with a hash, and the event and counters stay on chain.
//! After too many refusals in a row the contract deletes the agent's key (max_strikes, signed into the attestation).

use near_sdk::json_types::{Base64VecU8, U128, U64};
use near_sdk::serde_json::{self, Value};
use near_sdk::store::{IterableMap, LookupMap, LookupSet};
use near_sdk::{
    env, near, require, AccountId, Allowance, BorshStorageKey, Gas, NearToken, PanicOnDefault, Promise,
    PromiseError, PromiseOrValue, PublicKey,
};

/// Default gas allowance of an agent key. Agent transactions burn gas from the contract account; this caps what one key can burn.
pub const DEFAULT_ALLOWANCE: NearToken = NearToken::from_millinear(250);
/// Cell opening fee = the key's whole gas allowance + storage. A cell that burns its allowance cannot touch another cell's vault.
pub const REGISTER_FEE: NearToken = NearToken::from_millinear(350);
/// Prepaid storage for one invoice record per link (n links allow at most n payments).
const STORAGE_PER_INVOICE: u128 = 1_000_000_000_000_000_000_000;
/// How long after signing an attestation can be used to open a cell: a verifier's "not revoked" cannot be relied on indefinitely.
pub const MAX_ATTESTATION_AGE_NS: u64 = 3_600_000_000_000;

/// Gas allowance of a sub-agent. The hire fee comes from the tree, so the tree pays for the gas its sub-agents burn.
pub const CHILD_ALLOWANCE: NearToken = NearToken::from_millinear(100);
const CHILD_STORAGE: u128 = 20_000_000_000_000_000_000_000;
/// Maximum depth and size of a tree. One transaction must be able to delete a whole tree on revocation, so its size is bounded.
pub const MAX_DEPTH: u32 = 3;
pub const MAX_TREE: u32 = 16;

fn hire_fee(n: u32) -> u128 {
    CHILD_ALLOWANCE.as_yoctonear() + CHILD_STORAGE + (n as u128) * STORAGE_PER_INVOICE
}

fn register_fee(n: u32) -> u128 {
    REGISTER_FEE.as_yoctonear() + (n as u128) * STORAGE_PER_INVOICE
}

/// How many periods an order pays: max(1, ceil((due_at - now) / 30 days)). A started period counts in full; a past due date counts as one.
fn fee_periods(due_at: u64, now: u64) -> u128 {
    let left = due_at.saturating_sub(now) as u128;
    let period = NS_PER_PERIOD as u128;
    ((left + period - 1) / period).max(1)
}

/// Guarantee fee = amount x rate per period x periods / 10000, and never more than the amount.
fn guarantee_fee(amount: u128, premium_bps: u32, periods: u128) -> u128 {
    (amount * (premium_bps as u128) * periods / 10_000).min(amount)
}

/// Refusals that are not the agent being fooled, so they cost no strike: FROZEN is the company's debt, RESERVE is a reserve other agents used up.
fn no_strike(reason: &str) -> bool {
    reason == "FROZEN" || reason == "RESERVE"
}

/// A required Option. Serde would read a missing field as None; a rule must say which asset it accepts (null means NEAR).
fn named_asset<'de, D: near_sdk::serde::Deserializer<'de>>(d: D) -> Result<Option<AccountId>, D::Error> {
    <Option<AccountId> as near_sdk::serde::Deserialize>::deserialize(d)
}
/// The methods an agent key can call.
pub const AGENT_METHODS: &str = "spend,hire,dismiss,open_credit,settle";
/// Maximum number of payees in a scope.
pub const MAX_SCOPE: usize = 16;
const NS_PER_DAY: u64 = 86_400_000_000_000;
/// The guarantee fee is priced by tenor: premium_bps is the rate per period of 30 days.
pub const NS_PER_PERIOD: u64 = 30 * NS_PER_DAY;
const GAS_FOR_CALLBACK: Gas = Gas::from_tgas(35); // 要付得起撤銷後的 ft_transfer（20）＋ on_refund（5）
const GAS_FOR_REFUND_CB: Gas = Gas::from_tgas(5);
const MAX_EVIDENCE: usize = 128;
/// Storage of one credit record (about 430 bytes for the order and 250 for a per-seller exposure record). Charged at open, from the root's vault or NEAR reserve; not refunded.
const CREDIT_STORAGE: u128 = 7_000_000_000_000_000_000_000;
const GAS_FOR_FT: Gas = Gas::from_tgas(20);
/// Storage deposit for a seller rule (1500 bytes, enough for both lists at their maximum). Charged the first time; not refunded when the rule is deleted.
pub const SELLER_POLICY_STORAGE: u128 = 15_000_000_000_000_000_000_000;
/// Maximum length of each list in a rule: guarantors and arbiters.
pub const MAX_POLICY_GUARANTORS: usize = 8;
/// Maximum signed tenor, 10 years. A due date plus the time windows must not overflow, or cancelling and claiming would fail forever.
pub const MAX_TENOR_SECS: u64 = 10 * 365 * 86_400;
/// Maximum sellers kept in a guarantor's book. When full, the smallest exposure is replaced, so top_sellers shows the largest sellers and is not a complete list.
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

/// Status of a cell. After Revoked or Tripped the key is no longer on the contract account.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub enum Status {
    Active,
    /// Revoked. by: who triggered it; evidence: the SAID of the KERI rev event, or "manual".
    Revoked { by: AccountId, evidence: String },
    /// Tripwire: too many refusals in a row, so the contract deleted the key.
    Tripped,
}

/// A mandate cell: the on-chain execution state of one AMC.
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
    /// None = native NEAR; Some(token) = a NEP-141 such as a stablecoin, with the vault counted in that token's smallest unit.
    pub asset: Option<AccountId>,
    pub root: u64,                 // 這棵樹的根格（根格指向自己）
    pub parent: Option<u64>,       // 雇用它的格
    pub depth: u32,                // 根格 = 0
    pub children: Vec<u64>,        // 它雇用的格
    pub tree_size: u32,            // 整棵樹幾格（只在根格維護）
    pub near_reserve: U128,        // 代幣樹的根格才有：開格時留下的 NEAR，付單據儲存與雇用費
}

/// The verdict of a spend. Being refused is a normal result, not an error.
#[near(serializers = [json])]
#[derive(Debug, PartialEq)]
pub enum Verdict {
    Paid { cell: U64, amount: U128, idx: u32, remaining_links: u32 },
    Hired { cell: U64, child: U64, links: u32, remaining_links: u32 },
    CreditOpened { cell: U64, credit: U64, amount: U128, due_at: U64 },
    CreditSettled { credit: U64, amount: U128 },
    Rejected { cell: U64, reason: String, strikes: u32, tripped: bool },
}

/// Arguments of register. The verifier signs the canonical string of these fields; see attestation_message.
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
    /// When the verifier checked the chain (ns). Too old and the cell cannot be opened.
    pub attested_at: U64,
    /// The verifier's Ed25519 signature over attestation_message (hex, 64 bytes).
    pub signature: String,
    /// Settlement asset: omitted = NEAR; a NEP-141 contract account = paid in that token (bound by the attestation).
    #[serde(default)]
    pub asset: Option<AccountId>,
    /// Credit terms: omitted = this cell cannot buy on credit.
    #[serde(default)]
    pub credit: Option<CreditArgs>,
}

/// Who pays the guarantee fee. Buyer: charged to the root's vault when the seller accepts. Seller: taken from the amount when the seller is paid; a cancelled order pays nothing.
#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FeePayer {
    Buyer,
    Seller,
}

/// Credit terms. The verifier, who is also the named guarantor, signs them into the attestation; they cannot change after the cell opens.
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

/// The credit state of a tree (kept on the root only).
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

/// A guarantor's stake, per asset.
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

/// A seller's automatic credit rule: an order that fits ships, one that does not comes back with reasons.
#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct SellerPolicy {
    pub max_amount: U128,
    pub max_tenor_secs: U64,
    pub min_bond_bps: u32,
    pub max_defaults: u32,            // 公司假名最多幾筆違約紀錄
    pub guarantors: Vec<AccountId>,   // 核准的保證人；空 = 都接受
    #[serde(deserialize_with = "named_asset")]
    pub asset: Option<AccountId>,     // 這條規則收的資產（必填，null = NEAR）；max_amount 就是這個資產的單位
    pub max_fee_bps: u32,             // 保證費最多占金額的萬分比；不論誰付
    pub arbiters: Vec<AccountId>,     // 核准的仲裁人；空 = 都接受
}

/// Result of check_order. ok: the rule asked about (the stored rule if none was passed), the order's state and the money all pass.
/// would_accept: calling accept_credit now would succeed. It always uses the seller's stored rule.
#[near(serializers = [json])]
pub struct OrderCheck {
    pub ok: bool,
    pub would_accept: bool,
    pub reasons: Vec<String>,
    pub order: Value,
}

/// The money needed to accept an order, and why it falls short or breaches a limit.
struct Quote {
    fee: u128,
    periods: u128,
    charge: u128, // 接受當下從根格金庫收的費用：買方付 = fee，賣方付 = 0
    bond: u128,
    exposure: u128,
    failures: Vec<String>,
}

/// The payment record of a pseudonym, shown on the risk card.
#[near(serializers = [borsh, json])]
#[derive(Clone, Default)]
pub struct EntityRecord {
    pub settled: u32,
    pub settled_amount: U128,
    pub defaults: u32,
    pub first_seen: U64,
}

/// Time windows, in seconds. Short in demos; the defaults are for production.
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

/// Terms for hiring a sub-agent. Each can only be narrower than the parent's; the contract checks them one by one.
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

/// Opening of ecr_commit, used when HR (the legal entity) revokes an ECR. The LE public key and the ECR SAID are normally not on chain.
#[near(serializers = [json])]
#[derive(Clone)]
pub struct EcrOpening {
    pub le_aid: String,
    pub le_pk: String,
    pub ecr_said: String,
    pub salt: String,
}

/// Global counters.
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

/// A supervisor's request for disclosure (tier 1: reveals only the LEI). The disclosure is itself a public transaction.
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

/// The canonical attestation string: the verifier signs these bytes off-chain, and the contract rebuilds and verifies them.
/// Fixed field order, separated by \n; agent_pk uses the NEAR string format (ed25519:<base58>).
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
    /// owner: the account that maintains the verifier and supervisor whitelists. It should be another account, so this account can delete its full-access key.
    /// Deploy, init and delete the full-access key in one batch (as `make testnet` does); #[private] stops anyone initialising first.
    /// unseal_delay_secs: the public wait between a supervisor's request and the verifier's disclosure (default 2 minutes).
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

    /// Called by the funder with the verifier's attestation. On a NEAR cell the deposit minus the fee goes to the vault; on a token cell with credit terms it becomes the NEAR reserve.
    /// The contract adds a function-call key for the agent on its own account (the Keypom pattern).
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
            require!(cr.bond_bps <= 10_000 && cr.premium_bps <= 2_000 && cr.seller_cap_bps <= 10_000 && cr.min_tenor.0 <= cr.max_tenor.0 && cr.max_tenor.0 <= MAX_TENOR_SECS, "BAD_CREDIT_TERMS");
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
            let key = Self::entity_key(&args.verifier, &args.asset, &cr.entity_tag);
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

    /// The funder adds money: the vault on a NEAR cell, the NEAR reserve on the root of a token tree with credit terms.
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

    /// Callable only by an agent's function-call key: signer and predecessor must both be the contract account.
    /// preimage: the link a person released to the agent (hex); j: links to spend; amount = j x unit.
    /// invoice_hash: sha256 of this payment's invoice (hex). A tree cannot pay the same invoice twice; it is also the basis for reconciliation.
    pub fn spend(&mut self, preimage: String, j: u32, to: AccountId, invoice_hash: String) -> PromiseOrValue<Verdict> {
        require!(env::signer_account_id() == env::current_account_id() && env::predecessor_account_id() == env::current_account_id(), "NOT_AGENT_KEY");
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
            event("rejected", serde_json::json!({"cell": id.to_string(), "reason": r, "to": to, "j": j, "strikes": c.strikes + u32::from(!no_strike(r))}));
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

    /// An agent hires a sub-agent, exchanging its own links for a budget.
    /// A sub-agent's money always comes from links an employee already released to its parent. Counterparties, expiry, rate and per-payment cap can only narrow.
    /// Policy refusals work as in spend: Rejected is returned, recorded, and counted as a strike.
    pub fn hire(&mut self, preimage: String, j: u32, child: HireArgs) -> Verdict {
        require!(env::signer_account_id() == env::current_account_id() && env::predecessor_account_id() == env::current_account_id(), "NOT_AGENT_KEY");
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
            self.free_vault(id, &c) >= amount
        } else {
            match &root_cell {
                None => self.free_vault(id, &c) >= amount.saturating_add(fee),
                Some(r) => c.vault.0 >= amount && self.free_vault(c.root, r) >= fee,
            }
        };
        // 代幣樹：預算是代幣，雇用費是 NEAR，從根格的準備扣
        let reserve = root_cell.as_ref().map(|r| r.near_reserve.0).unwrap_or(c.near_reserve.0);
        let reserve_ok = !token_tree || reserve >= fee;
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
        } else if !reserve_ok {
            Some("RESERVE")
        } else {
            None
        };
        if let Some(r) = reason {
            event("rejected", serde_json::json!({"cell": id.to_string(), "reason": r, "j": j, "strikes": c.strikes + u32::from(!no_strike(r))}));
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

    /// An agent dismisses a sub-agent it hired, with the tree below it. What is left goes back to the funder.
    pub fn dismiss(&mut self, child: U64) {
        require!(env::signer_account_id() == env::current_account_id() && env::predecessor_account_id() == env::current_account_id(), "NOT_AGENT_KEY");
        let pk = env::signer_account_pk();
        let id = *self.key_to_cell.get(&pk).unwrap_or_else(|| env::panic_str("NO_CELL"));
        let c = self.cells.get(&child.0).cloned().unwrap_or_else(|| env::panic_str("NO_CELL"));
        require!(c.parent == Some(id), "NOT_PARENT");
        self.close(child.0, c, Status::Revoked { by: env::current_account_id(), evidence: format!("dismissed by cell {}", id) });
    }

    /// If any cell above this one is tripped or closed, this cell cannot move money (it recovers when the company reinstates the parent).
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

    /// Money this cell can use: a root excludes the bond locked for sellers.
    fn free_vault(&self, id: u64, c: &Cell) -> u128 {
        if c.root == id {
            let locked = self.terms.get(&id).map(|t| t.bond_locked.0).unwrap_or(0);
            c.vault.0.saturating_sub(locked)
        } else {
            c.vault.0
        }
    }

    /// Policy refusal: counts a strike and deletes the key after too many in a row. Returns Rejected; the transaction succeeds.
    fn reject(&mut self, id: u64, mut c: Cell, pk: PublicKey, r: &str) -> Verdict {
        c.rejects += 1;
        // 凍結是公司的債，不是 agent 被騙：不計 strike，還清後 agent 不必逐格復職
        if !no_strike(r) {
            c.strikes += 1;
        }
        self.stats.rejected += 1;
        let tripped = !no_strike(r) && c.max_strikes > 0 && c.strikes >= c.max_strikes;
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

    /// Manual revocation, by the funder, this cell's verifier, or the owner.
    /// evidence: the SAID of the KERI rev event (supplied by a watcher) or "manual".
    pub fn revoke(&mut self, cell: U64, evidence: String) {
        let c = self.cells.get(&cell.0).cloned().unwrap_or_else(|| env::panic_str("NO_CELL"));
        let who = env::predecessor_account_id();
        require!(evidence.len() <= MAX_EVIDENCE, "EVIDENCE_TOO_LONG");
        require!(who == c.funder || (who == c.verifier && self.verifiers.contains_key(&who)) || who == self.owner, "NOT_AUTHORIZED");
        self.close(cell.0, c, Status::Revoked { by: who, evidence });
    }

    /// Trustless revocation: anyone submits the ixn event (raw bytes) anchoring the revocation on the AMC issuer's KEL, with its signature.
    /// The contract verifies the signature and checks seal = {i: this cell's AMC SAID, s: "1"} (simple TEL: sn 0 = iss, sn 1 can only be rev).
    /// Limit: if the issuer rotates keys, the verifier must update issuer_pk (see update_signers).
    ///
    /// ecr omitted: the employee (the AMC issuer) revokes the AMC.
    /// ecr given: HR (the legal entity) revokes the employee's ECR, with no help needed from the employee; opening the commitment reveals the LE's public key.
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

    /// Close a cell: delete the key and return what is left in the vault to the funder.
    /// Also closes the whole subtree it hired: one transaction deletes every key and returns all the money, unless the tree still owes.
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

    /// Return NEAR or NEP-141 to the funder. A failure is recorded in unclaimed, so nothing disappears.
    fn pay_out(&self, cell: u64, asset: &Option<AccountId>, to: AccountId, amount: u128, memo: String) {
        Self::send(asset, to, amount, memo)
            .then(Self::ext(env::current_account_id()).with_static_gas(GAS_FOR_REFUND_CB).on_refund(U64(cell), U128(amount)))
            .detach();
    }

    /// Send NEAR or NEP-141 (the contract attaches the 1 yocto for ft_transfer itself).
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

    /// After a failed refund (for example the funder was not registered with the token), the funder fixes that and claims again.
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

    /// Refresh: when the gas allowance runs out, the funder or verifier re-adds the same key (delete then add, in one batch).
    /// The caller pays for the new allowance. Otherwise a colluding agent could burn the contract's balance without limit, which means other cells' vaults.
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

    /// The funder recovers a tripped cell: three malicious invoices should not void a whole mandate. It pays the new key's gas allowance, on the public record.
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

    /// After an issuer rotates keys, this cell's verifier re-checks the KEL and updates the revocation keys (otherwise events signed by the new key are refused).
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

    /// The only way in for NEP-141 tokens. msg picks the purpose, and each shares its logic with the NEAR payable path:
    ///   "<cell id>" or "fund:<cell id>"       fund this cell; refused if it is not the cell's token, not the funder, or the cell is closed
    ///   "stake"                               a guarantor stakes
    ///   "settle:<credit id>"                  the company settles
    ///   "dispute:<credit id>:<reason_hash>"   the company disputes with a full escrow
    ///   "reimburse:<credit id>"               the company repays the guarantor
    /// Any excess goes to the sender's claimable balance. A failed check panics: NEP-141's ft_resolve_transfer returns all the tokens to the sender and nothing changes.
    /// The caller is the "token", and any account can pose as one. So the asset a tree signed is always compared; a fake token only reaches its own books.
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

    /// Funding accepts only the cell's own token from the cell's funder. Anything else is returned (by returning amount), with no panic.
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

    /// The payment asset must match: a token tree cannot be paid in NEAR (a yocto count would read as a large token amount), and a NEAR tree takes no tokens.
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

    /// A whitelisted supervisor requests disclosure. From now on anyone can see who asked, why (as a hash), and when.
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

    /// The funder can object before disclosure. It is on the public record for courts to handle off-chain; it does not stop the disclosure.
    pub fn object_unseal(&mut self, cell: U64) {
        let c = self.cells.get(&cell.0).unwrap_or_else(|| env::panic_str("NO_CELL"));
        require!(env::predecessor_account_id() == c.funder, "ONLY_FUNDER");
        let mut u = self.unseals.get(&cell.0).cloned().unwrap_or_else(|| env::panic_str("NO_REQUEST"));
        require!(u.lei.is_none(), "ALREADY_RELEASED");
        u.objected = true;
        self.unseals.insert(cell.0, u);
        event("unseal_objected", serde_json::json!({"cell": cell.0.to_string()}));
    }

    /// After the wait, this cell's verifier reveals (LEI, salt), and the contract checks sha256(LEI|salt) against the commitment made at register.
    /// A verifier cannot reveal a different LEI from the one it committed to: the reliance record of p.42 of the GLEIF discussion paper.
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

    /// The five predicates a merchant looks at (no LEI).
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

    /// asset omitted = the NEAR stake.
    pub fn stake_of(&self, account: AccountId, asset: Option<AccountId>) -> Option<Stake> {
        self.stakes.get(&(account, asset)).cloned()
    }

    /// A guarantor's book for one asset (omitted = NEAR): what it backs, earned, paid out and recovered.
    /// net_loss = claims paid - recovered; loss_ratio_bps = net_loss / total fees, null if nothing has been earned.
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

    /// asset omitted = NEAR.
    pub fn claimable_of(&self, account: AccountId, asset: Option<AccountId>) -> U128 {
        U128(self.claimable.get(&(account, asset)).copied().unwrap_or(0))
    }

    /// Total on the books for this token. The contract's balance of it must be at least this; anyone can compare them.
    pub fn token_total(&self, asset: AccountId) -> U128 {
        U128(self.token_total.get(&asset).copied().unwrap_or(0))
    }

    /// The card a seller reads before deciding on credit: the company's name sealed, the guarantor named.
    pub fn risk_card(&self, cell: U64) -> Option<Value> {
        let c = self.cells.get(&cell.0)?;
        let t = self.terms.get(&c.root)?;
        let root = self.cells.get(&c.root)?;
        let stake = self.stake_get(&t.guarantor, &t.args.asset);
        let rec = self.entities.get(&Self::entity_key(&t.guarantor, &t.args.asset, &t.args.entity_tag)).cloned().unwrap_or_default();
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

    /// Solvency in NEAR: the contract's balance must cover storage and all NEAR accounts (anyone can check). Tokens: see token_total.
    pub fn solvency(&self) -> Value {
        let balance = env::account_balance().as_yoctonear();
        let storage = (env::storage_usage() as u128) * env::storage_byte_cost().as_yoctonear();
        serde_json::json!({"vault_total": self.vault_total.to_string(), "balance": balance.to_string(), "storage": storage.to_string(),
                           "solvent": balance >= storage.saturating_add(self.vault_total)})
    }

    /// Lets a verifier confirm the bytes it will sign match what the contract rebuilds.
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
    /// A guarantor stakes NEAR; it cannot withdraw what is exposed. Token stakes go through ft_on_transfer("stake").
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

    /// An agent orders on credit: it spends links (the budget a person authorised) and moves no money. Nobody is bound until the seller accepts.
    pub fn open_credit(&mut self, preimage: String, j: u32, to: AccountId, invoice_hash: String, due_at: U64) -> Verdict {
        require!(env::signer_account_id() == env::current_account_id() && env::predecessor_account_id() == env::current_account_id(), "NOT_AGENT_KEY");
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
            Some(if token_tree { "RESERVE" } else { "FUNDS" })
        } else {
            None
        };
        if let Some(r) = reason {
            event("rejected", serde_json::json!({"cell": id.to_string(), "reason": r, "to": to, "j": j, "strikes": c.strikes + u32::from(!no_strike(r))}));
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

    /// A seller accepts: bond and guarantor exposure are locked per order, so another seller cannot take them. Enforces the seller's stored rule; panics POLICY:<first reason>.
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

    /// Whether the order's state allows accepting it. The order is the order accept_credit reports errors in.
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
        // 移出白名單是鎖定後唯一的緊急手段：這個保證人不再接新單，已接的照走
        no(!self.verifiers.contains_key(&t.guarantor), "GUARANTOR_DELISTED");
        no(now > cell.valid_until.0, "MANDATE_EXPIRED");
        no(cr.seller == t.args.arbiter, "ARBITER_NOT_INDEPENDENT");
        // 保證人或公司自己當賣方，等於自己製造違約：前者可走到揭露，後者把質押領給自己
        no(cr.seller == t.guarantor || cr.seller == root.funder, "SELLER_NOT_INDEPENDENT");
        out
    }

    /// Checks a seller's rule item by item and reports every failure.
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
        let defaults = self.entities.get(&Self::entity_key(&t.guarantor, &t.args.asset, &t.args.entity_tag)).map(|r| r.defaults).unwrap_or(0);
        no(defaults > p.max_defaults, "TOO_MANY_DEFAULTS");
        no(!p.guarantors.is_empty() && !p.guarantors.contains(&t.guarantor), "GUARANTOR_NOT_APPROVED");
        no(cr.asset != p.asset, "ASSET_NOT_APPROVED");
        let fee = guarantee_fee(cr.amount.0, t.args.premium_bps, fee_periods(cr.due_at.0, now));
        no(fee.saturating_mul(10_000) > cr.amount.0.saturating_mul(p.max_fee_bps as u128), "FEE_TOO_HIGH");
        no(!p.arbiters.is_empty() && !p.arbiters.contains(&t.args.arbiter), "ARBITER_NOT_APPROVED");
        out
    }

    /// What accepting this order would charge and lock now.
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

    /// A seller sets its automatic credit rule. The first time needs the storage deposit, later changes do not; any excess is sent straight back, leaving no record.
    /// None deletes the rule. The deposit is not refunded, and setting a rule again pays again.
    #[payable]
    pub fn set_seller_policy(&mut self, policy: Option<SellerPolicy>) {
        let who = env::predecessor_account_id();
        let attached = env::attached_deposit().as_yoctonear();
        let mut owed = 0;
        if let Some(p) = &policy {
            require!(p.guarantors.len() <= MAX_POLICY_GUARANTORS && p.arbiters.len() <= MAX_POLICY_GUARANTORS, "POLICY_TOO_LONG");
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
            Promise::new(who.clone()).transfer(NearToken::from_yoctonear(attached - owed)).detach();
        }
        event("seller_policy_set", serde_json::json!({"seller": who}));
    }

    pub fn seller_policy(&self, seller: AccountId) -> Option<SellerPolicy> {
        self.policies.get(&seller).cloned()
    }

    /// A seller asks before shipping, with the passed rule or (None) its stored rule, and gets every failing reason,
    /// including money and order state. A passed rule is only a what-if: accept_credit always uses the stored rule; see would_accept.
    /// After acceptance, fee, bond and exposure report the values fixed on the order, not a new quote.
    pub fn check_order(&self, credit: U64, policy: Option<SellerPolicy>) -> OrderCheck {
        let cr = self.credits.get(&credit.0).unwrap_or_else(|| env::panic_str("NO_CREDIT"));
        let now = env::block_timestamp();
        let t = self.terms.get(&cr.root.0).unwrap();
        let root = self.cells.get(&cr.root.0).unwrap();
        let cell = self.cells.get(&cr.cell.0).unwrap();
        let stored = self.policies.get(&cr.seller);
        let rule = policy.as_ref().or(stored);
        let mut reasons = match rule {
            Some(p) => self.policy_failures(p, cr, t, now),
            None => vec![],
        };
        let mut common = self.accept_state_failures(cr, t, root, cell, now);
        let q = self.quote(cr, t, root, now);
        common.extend(q.failures.iter().cloned());
        let would_accept = common.is_empty() && stored.map(|p| self.policy_failures(p, cr, t, now).is_empty()).unwrap_or(true);
        reasons.extend(common);
        // 接受之後回報單上定下來的值
        let (fee, periods, bond, exposure) = if cr.status != CreditStatus::Open {
            (cr.fee.0, cr.fee_periods as u128, cr.bond_locked.0, cr.exposure.0)
        } else {
            (q.fee, q.periods, q.bond, q.exposure)
        };
        let st = self.stake_get(&t.guarantor, &t.args.asset);
        let rec = self.entities.get(&Self::entity_key(&t.guarantor, &t.args.asset, &t.args.entity_tag)).cloned().unwrap_or_default();
        let seller_fee = if t.args.fee_payer == FeePayer::Seller { fee.min(cr.amount.0) } else { 0 };
        OrderCheck {
            ok: reasons.is_empty(),
            would_accept,
            reasons,
            order: serde_json::json!({
                "credit": cr.id, "cell": cr.cell, "seller": cr.seller, "status": cr.status, "asset": cr.asset,
                "amount": cr.amount, "original_amount": cr.original_amount,
                "seller_receives": U128(cr.amount.0 - seller_fee),
                "due_at": cr.due_at, "tenor_secs": U64(cr.due_at.0.saturating_sub(now) / 1_000_000_000),
                "fee": U128(fee), "fee_periods": periods as u32, "fee_payer": t.args.fee_payer,
                "bond": U128(bond), "bond_bps": t.args.bond_bps, "exposure": U128(exposure),
                "guarantor": t.guarantor, "guarantor_listed": self.verifiers.contains_key(&t.guarantor),
                "guarantor_stake": st.amount, "guarantor_total_exposure": st.exposure,
                "entity_tag": t.args.entity_tag, "settled": rec.settled, "defaults": rec.defaults,
                "terms_hash": t.args.terms_hash, "arbiter": t.args.arbiter,
                "policy_applied": rule.is_some(),
            }),
        }
    }

    /// Cancel. Anyone can cancel an unaccepted offer after it expires, and the company or guarantor at any time.
    /// An order accepted but undelivered past its due date can also be cancelled, so it cannot hold the guarantor's exposure. The credit limit comes back; links do not.
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

    /// The seller delivers and files a proof. No delivery, no default.
    /// final_amount: the actual amount of a usage order (> 0 and at most the order). Only while Accepted, not during a dispute.
    /// The order shrinks to that amount; bond and exposure shrink at the same ratio. A buyer-paid fee is not refunded and links stay spent.
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

    /// An agent settles from its own vault. Expiry does not stop it; after revocation the company settles.
    pub fn settle(&mut self, credit: U64) -> Verdict {
        require!(env::signer_account_id() == env::current_account_id() && env::predecessor_account_id() == env::current_account_id(), "NOT_AGENT_KEY");
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

    /// The company settles with money attached, or from the root's vault if none is. Works after revocation or expiry. In a token tree, bring money through ft_on_transfer("settle:<id>").
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

    /// A seller withdraws. Credited first and withdrawn later, so a seller deleting its account cannot put the company in default. asset omitted = NEAR.
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

    /// A failed transfer (account gone, or not registered with the token) goes back to claimable, to be withdrawn when the account returns.
    #[private]
    pub fn on_withdraw(&mut self, who: AccountId, amount: U128, asset: Option<AccountId>, #[callback_result] r: Result<(), PromiseError>) {
        if r.is_err() {
            self.add_total(&asset, amount.0);
            self.credit_seller(&who, &asset, amount.0);
        }
    }

    /// The company objects to the goods, with a full escrow. This is not a default and reveals nothing; a non-payer saves nothing this way.
    /// In a token tree, use ft_on_transfer("dispute:<id>:<reason_hash>").
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

    /// The arbiter rules. It cannot be the guarantor (checked at register).
    pub fn resolve_dispute(&mut self, credit: U64, to_seller: bool) {
        let cr = self.credits.get(&credit.0).cloned().unwrap_or_else(|| env::panic_str("NO_CREDIT"));
        let t = self.terms.get(&cr.root.0).cloned().unwrap();
        require!(env::predecessor_account_id() == t.args.arbiter, "ONLY_ARBITER");
        self.finish_dispute(cr, to_seller);
    }

    /// The arbiter ran out of time: to the seller if a delivery proof exists, otherwise back to the company.
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

    /// Default: unpaid after the due date plus grace. The conditions are all on-chain state, with no reference to the commercial dispute.
    /// Payment order: this cell's vault, the root's free vault, this order's bond, the guarantor's stake. The company's agents then freeze (no credit, payments, hiring or settling) but keep their keys.
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
        let key = Self::entity_key(&t.guarantor, &t.args.asset, &t.args.entity_tag);
        let mut rec = self.entities.get(&key).cloned().unwrap_or_default();
        rec.defaults += 1;
        self.entities.insert(key, rec);
        self.terms.insert(cr.root.0, t);
        self.credits.insert(credit.0, cr.clone());
        event("credit_defaulted", serde_json::json!({"credit": credit.0.to_string(), "guarantor_paid": left.to_string(), "recourse_until": cr.recourse_until.0.to_string()}));
        self.release_retained(cr.root.0);
    }

    /// The company repays the guarantor: unfrozen, and still sealed. In a token tree, bring money through ft_on_transfer("reimburse:<id>").
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

    /// The recourse period ended unpaid: the guarantor cuts power to the whole tree.
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

    /// The last step: name the company. Checks the LEI commitment, the ECR commitment, and the opened LE key's signature over these terms and the LEI.
    /// This stops a frame-up using another company's LEI without its key. The link between the LE key and that LEI needs the off-chain credential chain; the contract cannot see it.
    /// It ignores the current whitelist, so the owner cannot block it.
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

    /// A liability receipt: whose agent placed this order, under which terms, and who guarantees it.
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

    /// A pseudonym means something only under one guarantor and one asset: other guarantors cannot use it, and a fake token cannot write to a real token's record.
    fn entity_key(guarantor: &AccountId, asset: &Option<AccountId>, tag: &str) -> String {
        format!("{}:{}:{}", guarantor, asset.as_ref().map(|a| a.as_str()).unwrap_or("near"), tag)
    }

    /// A usage order shrinks: limit, bond and exposure come back together, and the bond stays at the promised ratio.
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

    /// Records this seller in the book. When full, replaces the smallest exposure if that is below this seller's.
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

    /// The only way a seller is credited (settle, funder settle, default, dispute won). A seller-paid fee is taken here and added to the guarantor's stake and earnings.
    /// The fee never exceeds the amount, so a seller can receive zero but never less.
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

    /// Releases this order's locks and credit limit. The last argument is unused and only keeps the call shape.
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

    /// The order ended and the seller was paid: the invoice counts as paid. One where the seller got nothing (cancelled, or ruled for the company) stays pending,
    /// so invoice_paid is false and the invoice stays taken: a ruling cannot be bypassed by paying another way.
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
        let tag = Self::entity_key(&t.guarantor, &t.args.asset, &t.args.entity_tag);
        let mut rec = self.entities.get(&tag).cloned().unwrap_or_default();
        rec.settled += 1;
        rec.settled_amount = U128(rec.settled_amount.0.saturating_add(cr.amount.0));
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

    /// A closed tree with nothing outstanding: money retained on the root becomes claimable by the funder (claim_refund).
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
