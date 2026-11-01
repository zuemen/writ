//! Sealed Mandate —— D1 spike 合約
//!
//! 這一版只驗證三件「整題成不成立」的事：
//!   1. Keypom 模式：合約對「自己的帳號」掛一把 function-call key 給 agent，
//!      agent 用那把 key 簽交易時 signer == 合約帳號，合約用 env::signer_account_pk() 認出是哪個 agent。
//!   2. 撤銷：合約對自己 delete_key，之後 agent 再簽 → 協定層拒絕（AccessKeyNotFound）。
//!   3. 主機函式：env::ed25519_verify（KERI 簽章）與 env::sha256 迴圈（PayWord 鏈）的可用性與 gas。
//!
//! 正式版（D2 起）會把 Cell 補齊成五謂詞（鏈有效／未撤銷／額度內／對手在範圍內／未過期）。

use near_sdk::store::LookupMap;
use near_sdk::{env, near, AccountId, Allowance, BorshStorageKey, NearToken, PanicOnDefault, Promise, PublicKey, Gas};
use near_sdk::json_types::Base64VecU8;

#[derive(BorshStorageKey)]
#[near]
enum StorageKey {
    Cells,
}

/// 一個「委任格」：一把 agent 鑰匙對應一份 mandate 的鏈上狀態。
#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct Cell {
    pub label: String,       // 人看的標籤（spike 用；正式版放 AMC 的 SAID）
    pub spends: u32,         // 已成功 spend 幾次（spike 用來證明狀態跟著鑰匙走）
    pub rejects: u32,        // 政策拒絕次數（tripwire 用）
}

/// spend 的判決：付了，或被政策擋下（擋下不是錯誤，是正常結果）。
#[near(serializers = [json])]
#[derive(Debug, PartialEq)]
pub enum Verdict {
    Paid { spends: u32 },
    Rejected { reason: String, rejects: u32 },
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    owner: AccountId,                    // spike：owner 扮演「白名單驗證者」
    cells: LookupMap<PublicKey, Cell>,   // key = agent 的 Ed25519 公鑰（同時也是 KERI 委派 AID 的簽章鑰）
}

/// 給 agent 的 function-call key 能呼叫的方法——只有這兩個。
const AGENT_METHODS: &str = "spend,present";

#[near]
impl Contract {
    #[init]
    pub fn new() -> Self {
        Self {
            owner: env::predecessor_account_id(),
            cells: LookupMap::new(StorageKey::Cells),
        }
    }

    fn assert_owner(&self) {
        assert_eq!(env::predecessor_account_id(), self.owner, "ONLY_OWNER");
    }

    /// 驗證者（owner）替一個 agent 開格：在「合約自己的帳號」上掛一把 FC key。
    /// allowance 只管 gas（限制 2.1），用固定額度，耗盡要靠 refresh_key。
    pub fn register(&mut self, agent_pk: PublicKey, label: String, allowance_yocto: Option<NearToken>) -> Promise {
        self.assert_owner();
        assert!(!self.cells.contains_key(&agent_pk), "CELL_EXISTS");
        self.cells.insert(agent_pk.clone(), Cell { label, spends: 0, rejects: 0 });
        let allowance = match allowance_yocto {
            Some(a) => Allowance::limited(a).expect("ALLOWANCE_ZERO"),
            None => Allowance::unlimited(),
        };
        Promise::new(env::current_account_id()).add_access_key_allowance(
            agent_pk,
            allowance,
            env::current_account_id(),
            AGENT_METHODS.to_string(),
        )
    }

    /// agent 用自己的 FC key 呼叫。signer_account_pk 就是那把 key —— 這是整題的支點。
    ///
    /// 政策拒絕**不 panic**（panic 會回滾狀態，rejects 計數器與 tripwire 就做不到），
    /// 而是回傳 Verdict::Rejected 並發 NEP-297 事件；交易本身成功、有 tx hash、explorer 看得到事件。
    pub fn spend(&mut self, to: AccountId, amount: NearToken) -> Verdict {
        // Keypom 模式的安全前提：只有合約帳號自己簽的交易才會進來（signer == current）
        assert_eq!(env::signer_account_id(), env::current_account_id(), "NOT_AGENT_KEY");
        let pk = env::signer_account_pk();
        let cell = self.cells.get_mut(&pk).expect("NO_CELL");
        // spike 的「政策」：收款人必須是 merchant.*，否則拒絕（正式版換成 AMC 的 scope）
        if !to.as_str().starts_with("merchant") {
            cell.rejects += 1;
            let rejects = cell.rejects;
            env::log_str(&format!("EVENT_JSON:{{\"standard\":\"sealed-mandate\",\"version\":\"0.1.0\",\"event\":\"policy_rejected\",\"data\":{{\"reason\":\"SCOPE\",\"to\":\"{}\",\"rejects\":{}}}}}", to, rejects));
            return Verdict::Rejected { reason: "SCOPE".to_string(), rejects };
        }
        cell.spends += 1;
        let n = cell.spends;
        env::log_str(&format!("EVENT_JSON:{{\"standard\":\"sealed-mandate\",\"version\":\"0.1.0\",\"event\":\"spent\",\"data\":{{\"to\":\"{}\",\"amount\":\"{}\",\"spends\":{}}}}}", to, amount.as_yoctonear(), n));
        // spike 不真的轉錢；正式版在這裡 Promise::new(to).transfer(amount)
        Verdict::Paid { spends: n }
    }

    /// 任何人都可 view：這把 agent 鑰匙的格現在長什麼樣。
    pub fn present(&self, agent_pk: PublicKey) -> Option<Cell> {
        self.cells.get(&agent_pk).cloned()
    }

    /// 撤銷：合約刪掉自己帳號上的那把 key。下一筆 agent 交易在協定層就死（AccessKeyNotFound）。
    pub fn revoke(&mut self, agent_pk: PublicKey) -> Promise {
        self.assert_owner();
        self.cells.remove(&agent_pk);
        Promise::new(env::current_account_id()).delete_key(agent_pk)
    }

    /// 續命：同一個 batch 內先刪後加，避開 AddKeyAlreadyExists；allowance 重置。
    pub fn refresh_key(&mut self, agent_pk: PublicKey, allowance_yocto: NearToken) -> Promise {
        self.assert_owner();
        assert!(self.cells.contains_key(&agent_pk), "NO_CELL");
        Promise::new(env::current_account_id())
            .delete_key(agent_pk.clone())
            .add_access_key_allowance(
                agent_pk,
                Allowance::limited(allowance_yocto).expect("ALLOWANCE_ZERO"),
                env::current_account_id(),
                AGENT_METHODS.to_string(),
            )
    }

    // ---------- 主機函式 spike ----------

    /// 驗 Ed25519：給 KERI 的 ixn 事件原始 bytes、附在 KEL 上的簽章、簽發者公鑰。
    pub fn verify_ed25519(&self, msg: Base64VecU8, sig: Base64VecU8, pk: Base64VecU8) -> bool {
        let sig: [u8; 64] = sig.0.as_slice().try_into().expect("SIG_LEN");
        let pk: [u8; 32] = pk.0.as_slice().try_into().expect("PK_LEN");
        env::ed25519_verify(&sig, &msg.0, &pk)
    }

    /// PayWord：sha256 迭代 j 次。回傳 hex，並記錄用了多少 gas（看 receipt 的 gas_burnt）。
    pub fn hash_chain(&self, preimage_hex: String, j: u32) -> String {
        let mut cur = hex::decode(preimage_hex).expect("HEX");
        for _ in 0..j {
            cur = env::sha256(&cur);
        }
        let used = env::used_gas();
        env::log_str(&format!("hash_chain j={} used_gas={}", j, used.as_gas()));
        hex::encode(cur)
    }

    pub fn owner(&self) -> AccountId { self.owner.clone() }
    pub fn gas_probe(&self) -> u64 { Gas::from_tgas(1).as_gas() }
}
